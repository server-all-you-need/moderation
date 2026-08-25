package moderation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/IBM/sarama"
)

type SaramaPublisher struct {
	producer sarama.SyncProducer
}

func NewSaramaPublisher(producer sarama.SyncProducer) *SaramaPublisher {
	return &SaramaPublisher{producer: producer}
}

func (p *SaramaPublisher) Publish(ctx context.Context, topic, key string, value []byte) error {
	if p == nil || p.producer == nil {
		return fmt.Errorf("sarama producer is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	_, _, err := p.producer.SendMessage(&sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(value),
	})
	return err
}

func (p *SaramaPublisher) Close() error {
	if p == nil || p.producer == nil {
		return nil
	}
	return p.producer.Close()
}

type TaskConsumer struct {
	worker *Worker
}

func NewTaskConsumer(worker *Worker) *TaskConsumer {
	return &TaskConsumer{worker: worker}
}

func (c *TaskConsumer) ProcessMessage(ctx context.Context, value []byte) error {
	var event TaskEvent
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTaskEvent, err)
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return fmt.Errorf("%w: multiple JSON values", ErrInvalidTaskEvent)
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %v", ErrInvalidTaskEvent, err)
	}
	if event.Version != 1 || event.TaskID == "" {
		return fmt.Errorf("%w: version and task_id are required", ErrInvalidTaskEvent)
	}
	return c.worker.ProcessTaskEvent(ctx, event)
}

type TaskConsumerGroupHandler struct {
	consumer        *TaskConsumer
	poisonPublisher Publisher
}

func NewTaskConsumerGroupHandler(consumer *TaskConsumer) *TaskConsumerGroupHandler {
	return &TaskConsumerGroupHandler{consumer: consumer}
}

func NewTaskConsumerGroupHandlerWithPoisonPublisher(consumer *TaskConsumer, poisonPublisher Publisher) *TaskConsumerGroupHandler {
	return &TaskConsumerGroupHandler{consumer: consumer, poisonPublisher: poisonPublisher}
}

func (h *TaskConsumerGroupHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *TaskConsumerGroupHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (h *TaskConsumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case <-session.Context().Done():
			return nil
		case message, ok := <-claim.Messages():
			if !ok {
				return nil
			}
			if err := h.consumer.ProcessMessage(session.Context(), message.Value); err != nil {
				if errors.Is(err, ErrInvalidTaskEvent) {
					if h.poisonPublisher != nil {
						value, marshalErr := json.Marshal(map[string]interface{}{"version": 1, "reason": "invalid_task_event"})
						if marshalErr != nil {
							return marshalErr
						}
						if publishErr := h.poisonPublisher.Publish(session.Context(), TopicModerationTaskDLQ, "invalid_task_event", value); publishErr != nil {
							return publishErr
						}
					}
					session.MarkMessage(message, "invalid_task_event")
					session.Commit()
					continue
				}
				return err
			}
			session.MarkMessage(message, "")
			session.Commit()
		}
	}
}

type ConsumerGroup interface {
	Consume(ctx context.Context, topics []string, handler sarama.ConsumerGroupHandler) error
	Close() error
}

func RunTaskConsumerGroup(ctx context.Context, group ConsumerGroup, worker *Worker, poisonPublisher ...Publisher) error {
	defer group.Close()
	var poison Publisher
	if len(poisonPublisher) > 0 {
		poison = poisonPublisher[0]
	}
	handler := NewTaskConsumerGroupHandlerWithPoisonPublisher(NewTaskConsumer(worker), poison)
	for ctx.Err() == nil {
		if err := group.Consume(ctx, []string{TopicModerationTasksV1}, handler); err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
	}
	return nil
}

type SaramaTopicAdmin struct {
	admin sarama.ClusterAdmin
}

func NewSaramaTopicAdmin(admin sarama.ClusterAdmin) *SaramaTopicAdmin {
	return &SaramaTopicAdmin{admin: admin}
}

func (a *SaramaTopicAdmin) Partitions(topic string) (int32, bool, error) {
	metadata, err := a.admin.DescribeTopics([]string{topic})
	if err != nil {
		return 0, false, err
	}
	if len(metadata) == 0 || metadata[0].Err == sarama.ErrUnknownTopicOrPartition {
		return 0, false, nil
	}
	if metadata[0].Err != sarama.ErrNoError {
		return 0, false, metadata[0].Err
	}
	return int32(len(metadata[0].Partitions)), true, nil
}

func (a *SaramaTopicAdmin) CreateTopic(topic string, partitions int32) error {
	return a.admin.CreateTopic(topic, &sarama.TopicDetail{NumPartitions: partitions, ReplicationFactor: 1}, false)
}

func (a *SaramaTopicAdmin) IncreasePartitions(topic string, partitions int32) error {
	return a.admin.CreatePartitions(topic, partitions, nil, false)
}

type SaramaLagReporter struct {
	admin   sarama.ClusterAdmin
	client  sarama.Client
	groupID string
	topic   string
}

func NewSaramaLagReporter(admin sarama.ClusterAdmin, client sarama.Client, groupID, topic string) *SaramaLagReporter {
	return &SaramaLagReporter{admin: admin, client: client, groupID: groupID, topic: topic}
}

func (r *SaramaLagReporter) ConsumerLag(ctx context.Context) (int64, error) {
	if r == nil || r.admin == nil || r.client == nil {
		return 0, fmt.Errorf("sarama lag reporter dependencies are required")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	partitions, err := r.client.Partitions(r.topic)
	if err != nil {
		return 0, err
	}
	offsets, err := r.admin.ListConsumerGroupOffsets(r.groupID, map[string][]int32{r.topic: partitions})
	if err != nil {
		return 0, err
	}
	var lag int64
	for _, partition := range partitions {
		newest, err := r.client.GetOffset(r.topic, partition, sarama.OffsetNewest)
		if err != nil {
			return 0, err
		}
		committed := int64(0)
		if topicOffsets := offsets.Blocks[r.topic]; topicOffsets != nil {
			if block := topicOffsets[partition]; block != nil && block.Offset >= 0 && block.Err == sarama.ErrNoError {
				committed = block.Offset
			}
		}
		if newest > committed {
			lag += newest - committed
		}
	}
	return lag, nil
}

package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

type recordingSyncProducer struct {
	msgs []*sarama.ProducerMessage
}

func (p *recordingSyncProducer) SendMessage(msg *sarama.ProducerMessage) (int32, int64, error) {
	p.msgs = append(p.msgs, msg)
	return 0, int64(len(p.msgs)), nil
}
func (p *recordingSyncProducer) SendMessages(msgs []*sarama.ProducerMessage) error {
	for _, msg := range msgs {
		p.msgs = append(p.msgs, msg)
	}
	return nil
}
func (p *recordingSyncProducer) Close() error                            { return nil }
func (p *recordingSyncProducer) TxnStatus() sarama.ProducerTxnStatusFlag { return 0 }
func (p *recordingSyncProducer) IsTransactional() bool                   { return false }
func (p *recordingSyncProducer) BeginTxn() error                         { return nil }
func (p *recordingSyncProducer) CommitTxn() error                        { return nil }
func (p *recordingSyncProducer) AbortTxn() error                         { return nil }
func (p *recordingSyncProducer) AddOffsetsToTxn(map[string][]*sarama.PartitionOffsetMetadata, string) error {
	return nil
}
func (p *recordingSyncProducer) AddMessageToTxn(*sarama.ConsumerMessage, string, *string) error {
	return nil
}

func TestSaramaPublisherWritesTaskIDOnlyModerationEvents(t *testing.T) {
	producer := &recordingSyncProducer{}
	publisher := NewSaramaPublisher(producer)

	value, err := MarshalTaskEvent(TaskEvent{Version: 1, TaskID: "task-1"})
	if err != nil {
		t.Fatalf("marshal task event: %v", err)
	}
	if err := publisher.Publish(context.Background(), TopicModerationTasksV1, "task-1", value); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(producer.msgs) != 1 {
		t.Fatalf("published messages = %d, want 1", len(producer.msgs))
	}
	msg := producer.msgs[0]
	if msg.Topic != TopicModerationTasksV1 {
		t.Fatalf("topic = %s, want %s", msg.Topic, TopicModerationTasksV1)
	}
	encoded, err := msg.Value.Encode()
	if err != nil {
		t.Fatalf("encode value: %v", err)
	}
	var event map[string]interface{}
	if err := json.Unmarshal(encoded, &event); err != nil {
		t.Fatalf("unmarshal published value: %v", err)
	}
	for _, forbidden := range []string{"caller_id", "batch_id", "client_item_id", "content_type", "policy", "correlation_id", "text", "image_url", "content", "body"} {
		if _, ok := event[forbidden]; ok {
			t.Fatalf("published task event leaked %s: %s", forbidden, string(encoded))
		}
	}
	if len(event) != 2 || event["task_id"] != "task-1" || event["version"].(float64) != 1 {
		t.Fatalf("unexpected task event: %s", string(encoded))
	}
}

func TestTaskConsumerStrictlyRejectsNonMinimalEvents(t *testing.T) {
	worker := NewWorkerWithOptions(WorkerOptions{Store: NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)), Provider: &countingProvider{}, ProviderBudget: allowAllProviderBudget{}})
	consumer := NewTaskConsumer(worker)

	for _, payload := range [][]byte{
		[]byte(`{"version":1}`),
		[]byte(`{"version":2,"task_id":"task-1"}`),
		[]byte(`{"version":1,"task_id":"task-1","caller_id":"client-a"}`),
	} {
		if err := consumer.ProcessMessage(context.Background(), payload); !errors.Is(err, ErrInvalidTaskEvent) {
			t.Fatalf("ProcessMessage(%s) err=%v, want ErrInvalidTaskEvent", string(payload), err)
		}
	}
}

func TestTaskConsumerGroupPoisonDLQDoesNotForwardUntrustedKafkaKey(t *testing.T) {
	poisonPublisher := &recordingPublisher{}
	handler := NewTaskConsumerGroupHandlerWithPoisonPublisher(NewTaskConsumer(NewWorkerWithOptions(WorkerOptions{
		Store:          NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)),
		Provider:       &countingProvider{},
		ProviderBudget: allowAllProviderBudget{},
	})), poisonPublisher)
	messages := make(chan *sarama.ConsumerMessage, 1)
	messages <- &sarama.ConsumerMessage{Topic: TopicModerationTasksV1, Key: []byte("https://secret.example/raw"), Value: []byte(`{"version":1,"caller_id":"client-a"}`)}
	close(messages)
	session := &fakeConsumerGroupSession{ctx: context.Background()}

	if err := handler.ConsumeClaim(session, fakeConsumerGroupClaim{messages: messages}); err != nil {
		t.Fatalf("ConsumeClaim poison event: %v", err)
	}
	if len(poisonPublisher.records) != 1 {
		t.Fatalf("poison records = %d, want 1", len(poisonPublisher.records))
	}
	if poisonPublisher.records[0].key == "https://secret.example/raw" || poisonPublisher.records[0].key == "" {
		t.Fatalf("poison DLQ key must be fixed or irreversible, got %q", poisonPublisher.records[0].key)
	}
	if !session.marked {
		t.Fatalf("poison message must be marked consumed")
	}
}

func TestTaskConsumerGroupIgnoresDuplicateTerminalEvents(t *testing.T) {
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(context.Background(), CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:one",
		Input:          textInput("post-1", "hello"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	provider := &countingProvider{}
	worker := NewWorkerWithOptions(WorkerOptions{Store: store, Provider: provider, ProviderBudget: allowAllProviderBudget{}})
	consumer := NewTaskConsumer(worker)
	event := TaskEventFromTask(task)

	if err := consumer.ProcessMessage(context.Background(), mustTaskEventBytes(t, event)); err != nil {
		t.Fatalf("first process: %v", err)
	}
	if err := consumer.ProcessMessage(context.Background(), mustTaskEventBytes(t, event)); err != nil {
		t.Fatalf("duplicate process: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("duplicate terminal event must not call provider twice, calls=%d", provider.calls)
	}
}

type countingProvider struct{ calls int }

func (p *countingProvider) Moderate(_ context.Context, input auditplatform.ModerationInput) (auditplatform.ModerationResult, error) {
	p.calls++
	return auditplatform.ModerationResult{ClientItemID: input.ClientItemID, Decision: auditplatform.DecisionPass, RiskLevel: auditplatform.RiskLevelLow, ProviderName: "counting"}, nil
}
func (p *countingProvider) Name() string { return "counting" }

func mustTaskEventBytes(t *testing.T, event TaskEvent) []byte {
	t.Helper()
	data, err := MarshalTaskEvent(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return data
}

type publisherRecord struct {
	topic string
	key   string
	value []byte
}

type recordingPublisher struct {
	records []publisherRecord
}

func (p *recordingPublisher) Publish(_ context.Context, topic, key string, value []byte) error {
	p.records = append(p.records, publisherRecord{topic: topic, key: key, value: append([]byte(nil), value...)})
	return nil
}

type fakeConsumerGroupSession struct {
	ctx    context.Context
	marked bool
}

func (s *fakeConsumerGroupSession) Claims() map[string][]int32 { return nil }
func (s *fakeConsumerGroupSession) MemberID() string           { return "member" }
func (s *fakeConsumerGroupSession) GenerationID() int32        { return 1 }
func (s *fakeConsumerGroupSession) MarkOffset(string, int32, int64, string) {
}
func (s *fakeConsumerGroupSession) Commit() {}
func (s *fakeConsumerGroupSession) ResetOffset(string, int32, int64, string) {
}
func (s *fakeConsumerGroupSession) MarkMessage(*sarama.ConsumerMessage, string) {
	s.marked = true
}
func (s *fakeConsumerGroupSession) Context() context.Context { return s.ctx }

type fakeConsumerGroupClaim struct {
	messages <-chan *sarama.ConsumerMessage
}

func (c fakeConsumerGroupClaim) Topic() string              { return TopicModerationTasksV1 }
func (c fakeConsumerGroupClaim) Partition() int32           { return 0 }
func (c fakeConsumerGroupClaim) InitialOffset() int64       { return 0 }
func (c fakeConsumerGroupClaim) HighWaterMarkOffset() int64 { return 1 }
func (c fakeConsumerGroupClaim) Messages() <-chan *sarama.ConsumerMessage {
	return c.messages
}

package moderation

import (
	"context"
	"encoding/json"
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

	value, err := MarshalTaskEvent(TaskEvent{Version: 1, TaskID: "task-1", CallerID: "client-a", ClientItemID: "post-1", ContentType: "text", Policy: "text.general", CorrelationID: "corr-1"})
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
	for _, forbidden := range []string{"text", "image_url", "content", "body"} {
		if _, ok := event[forbidden]; ok {
			t.Fatalf("published task event leaked %s: %s", forbidden, string(encoded))
		}
	}
	if event["task_id"] != "task-1" || event["caller_id"] != "client-a" {
		t.Fatalf("unexpected task event: %s", string(encoded))
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

package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/server-all-you-need/moderation/internal/auditplatform"
)

type fakePublisher struct {
	failNext bool
	records  []publishedRecord
}

type publishedRecord struct {
	topic string
	key   string
	value []byte
}

func (p *fakePublisher) Publish(_ context.Context, topic, key string, value []byte) error {
	if p.failNext {
		p.failNext = false
		return errors.New("broker unavailable")
	}
	p.records = append(p.records, publishedRecord{topic: topic, key: key, value: append([]byte(nil), value...)})
	return nil
}

type fakeProvider struct {
	calls   int
	results []auditplatform.ModerationResult
	errors  []error
}

func (p *fakeProvider) Moderate(_ context.Context, input auditplatform.ModerationInput) (auditplatform.ModerationResult, error) {
	p.calls++
	if len(p.errors) > 0 {
		err := p.errors[0]
		p.errors = p.errors[1:]
		if err != nil {
			return auditplatform.ModerationResult{}, err
		}
	}
	if len(p.results) > 0 {
		result := p.results[0]
		p.results = p.results[1:]
		return result, nil
	}
	return auditplatform.ModerationResult{
		ClientItemID:      input.ClientItemID,
		Decision:          auditplatform.DecisionPass,
		RiskLevel:         auditplatform.RiskLevelLow,
		ProviderName:      "fake",
		ProviderRequestID: "req-1",
	}, nil
}

func (p *fakeProvider) Name() string { return "fake" }

type fakeDLQ struct {
	events []DLQEvent
}

func (d *fakeDLQ) SendDLQ(_ context.Context, event DLQEvent) error {
	d.events = append(d.events, event)
	return nil
}

func TestTaskEventSerializationContainsOnlyNonSensitiveTaskMetadata(t *testing.T) {
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(context.Background(), CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "secret source text"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	value, err := MarshalTaskEvent(TaskEventFromTask(task))
	if err != nil {
		t.Fatalf("marshal task event: %v", err)
	}
	var event TaskEvent
	if err := json.Unmarshal(value, &event); err != nil {
		t.Fatalf("unmarshal task event: %v", err)
	}
	if event.Version != 1 || event.TaskID != task.ID {
		t.Fatalf("unexpected event metadata: %#v", event)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(value, &raw); err != nil {
		t.Fatalf("unmarshal raw event: %v", err)
	}
	for _, forbiddenKey := range []string{"caller_id", "batch_id", "client_item_id", "content_type", "policy", "correlation_id"} {
		if _, ok := raw[forbiddenKey]; ok {
			t.Fatalf("task event must contain only version and task_id, got %s", string(value))
		}
	}
	for _, forbidden := range []string{"secret source text", "api-key", "provider-secret", "webhook-secret"} {
		if strings.Contains(string(value), forbidden) {
			t.Fatalf("task event leaked sensitive value %q in %s", forbidden, string(value))
		}
	}
}

func TestOutboxPublisherKeepsUnsentRowsClaimableAfterPublishFailure(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	publisher := &fakePublisher{failNext: true}
	if err := PublishTaskOutbox(ctx, store, publisher, 10, 30*time.Second); err == nil {
		t.Fatalf("expected first publish to fail")
	}
	rows := store.TaskOutboxRows()
	if len(rows) != 1 || rows[0].PublishedAt != nil || rows[0].LastError == "" || rows[0].ClaimedUntil != nil {
		t.Fatalf("failed publish should keep row unsent and claimable: %#v", rows)
	}

	if err := PublishTaskOutbox(ctx, store, publisher, 10, 30*time.Second); err != nil {
		t.Fatalf("recover publish: %v", err)
	}
	if len(publisher.records) != 1 || publisher.records[0].topic != TopicModerationTasksV1 || publisher.records[0].key != task.ID {
		t.Fatalf("unexpected publish records: %#v", publisher.records)
	}
	rows = store.TaskOutboxRows()
	if rows[0].PublishedAt == nil {
		t.Fatalf("successful publish should mark row published: %#v", rows[0])
	}
}

func TestWorkerDoesNotCallProviderForTerminalOrActivelyClaimedDuplicateEvents(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	provider := &fakeProvider{}
	worker := NewWorker(store, provider, allowAllProviderBudget{})

	if _, claimed, err := store.ClaimTaskForProcessing(ctx, task.ID, 30*time.Second); err != nil || !claimed {
		t.Fatalf("pre-claim task: claimed=%v err=%v", claimed, err)
	}
	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("duplicate active event: %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("actively claimed duplicate must not call provider, calls=%d", provider.calls)
	}

	if err := store.FailTask(ctx, task.ID, TaskError{Code: "manual", Message: "terminal"}); err != nil {
		t.Fatalf("make terminal: %v", err)
	}
	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("duplicate terminal event: %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("terminal duplicate must not call provider, calls=%d", provider.calls)
	}
}

func TestWorkerRetriesRetryableFailuresThenSendsContentFreeDLQWhenExhausted(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "sensitive text"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	provider := &fakeProvider{errors: []error{
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 1"},
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 2"},
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 3"},
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 4"},
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 5"},
	}}
	worker := NewWorker(store, provider, allowAllProviderBudget{})

	expectedDelays := []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	for i, delay := range expectedDelays {
		if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
			t.Fatalf("process retryable attempt %d: %v", i+1, err)
		}
		updated, _ := store.Task(task.ID)
		if updated.Status != TaskStatusQueued || updated.NextAttemptAt == nil || !updated.NextAttemptAt.Equal(store.Now().Add(delay)) {
			t.Fatalf("attempt %d should schedule retry after %s: %#v", i+1, delay, updated)
		}
		store.AdvanceClock(delay)
	}
	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("process exhausted attempt: %v", err)
	}
	updated, _ := store.Task(task.ID)
	dlqRows := store.DLQOutboxRows()
	if updated.Status != TaskStatusFailed || len(dlqRows) != 1 {
		t.Fatalf("exhausted retries should fail task and persist DLQ: task=%#v dlq=%#v", updated, dlqRows)
	}
	if strings.Contains(string(dlqRows[0].Value), "sensitive text") || strings.Contains(string(dlqRows[0].Value), "provider-secret") {
		t.Fatalf("DLQ event leaked content or secret: %s", string(dlqRows[0].Value))
	}
}

func TestWorkerPermanentProviderFailureFailsWithoutRetry(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          imageInput("avatar-1", "https://cdn.example.com/a.png"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	worker := NewWorker(store, &fakeProvider{errors: []error{
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Retryable: false, Message: "bad request"},
	}}, allowAllProviderBudget{})

	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("process permanent failure: %v", err)
	}
	updated, _ := store.Task(task.ID)
	if updated.Status != TaskStatusFailed || updated.NextAttemptAt != nil || len(store.DLQOutboxRows()) != 1 {
		t.Fatalf("permanent failure should terminally fail and persist DLQ once: task=%#v dlq=%#v", updated, store.DLQOutboxRows())
	}
}

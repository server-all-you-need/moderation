package moderation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/server-all-you-need/moderation/internal/auditplatform"
)

type fakeWebhookHTTP struct {
	status int
	err    error
	calls  []webhookCall
}

type webhookCall struct {
	url     string
	headers http.Header
	body    []byte
}

func (h *fakeWebhookHTTP) DoWebhook(_ context.Context, url string, headers http.Header, body []byte) (int, error) {
	h.calls = append(h.calls, webhookCall{url: url, headers: headers.Clone(), body: append([]byte(nil), body...)})
	if h.err != nil {
		return 0, h.err
	}
	return h.status, nil
}

func countWebhookRows(rows []WebhookOutboxRow, resourceType, resourceID string) int {
	count := 0
	for _, row := range rows {
		if row.ResourceType == resourceType && row.ResourceID == resourceID {
			count++
		}
	}
	return count
}

func TestWebhookDestinationMustExactlyMatchCallerAllowlist(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}

	_, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
		WebhookURL:     "https://hooks.example.com/moderation/",
	})
	if !errors.Is(err, ErrWebhookNotAllowed) {
		t.Fatalf("expected exact allowlist rejection, got %v", err)
	}
	if len(store.Tasks()) != 0 || len(store.WebhookOutboxRows()) != 0 {
		t.Fatalf("rejected webhook destination should not create task/webhook rows")
	}
}

func TestWebhookOutboxUsesExactRawBodySignatureAndSchedule(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(now)
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	store.SetWebhookSecret("client-a", "secret-1", "top-secret")
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "sensitive text"),
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := store.CompleteTask(ctx, task.ID, auditplatform.ModerationResult{
		ClientItemID: "post-1",
		Decision:     auditplatform.DecisionPass,
		RiskLevel:    auditplatform.RiskLevelLow,
		ProviderName: "fake",
	}); err != nil {
		t.Fatalf("complete task: %v", err)
	}
	rows := store.WebhookOutboxRows()
	if len(rows) != 1 || rows[0].NextAttemptAt != now {
		t.Fatalf("expected immediate webhook row, got %#v", rows)
	}

	signature := SignWebhook("top-secret", now, rows[0].RawBody)
	mac := hmac.New(sha256.New, []byte("top-secret"))
	mac.Write([]byte(now.Format(time.RFC3339)))
	mac.Write([]byte("."))
	mac.Write(rows[0].RawBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if signature != want {
		t.Fatalf("unexpected signature: got %s want %s", signature, want)
	}
	if string(rows[0].RawBody) == "" || string(rows[0].RawBody) == "sensitive text" {
		t.Fatalf("webhook body should be structured and content-free: %q", string(rows[0].RawBody))
	}
	var event struct {
		EventVersion int    `json:"event_version"`
		EventID      string `json:"event_id"`
		Type         string `json:"type"`
		ID           string `json:"id"`
		ClientItemID string `json:"client_item_id"`
	}
	if err := json.Unmarshal(rows[0].RawBody, &event); err != nil {
		t.Fatalf("decode webhook event: %v", err)
	}
	if event.EventVersion != WebhookEventVersion || event.EventID != rows[0].ID || event.Type != "task" || event.ID != task.ID || event.ClientItemID != "post-1" {
		t.Fatalf("webhook row should persist v2 task event body tied to row id, row=%#v event=%#v", rows[0], event)
	}
	if got := WebhookAttemptSchedule(); len(got) != 6 || got[0] != 0 || got[1] != time.Minute || got[5] != 12*time.Hour {
		t.Fatalf("unexpected webhook schedule: %#v", got)
	}
}

func TestWebhookDeliveryFailurePersistsAttemptAndDoesNotChangeModerationResult(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(now)
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	store.SetWebhookSecret("client-a", "secret-1", "top-secret")
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := store.FailTask(ctx, task.ID, TaskError{Code: "provider_response", Message: "blocked"}); err != nil {
		t.Fatalf("fail task: %v", err)
	}
	httpClient := &fakeWebhookHTTP{err: errors.New("timeout")}
	dispatcher := NewWebhookDispatcher(store, httpClient)

	if err := dispatcher.DispatchDueWebhooks(ctx, 10); err != nil {
		t.Fatalf("dispatch webhooks: %v", err)
	}
	rows := store.WebhookOutboxRows()
	if len(rows) != 1 || rows[0].Attempts != 1 || rows[0].LastError == "" || !rows[0].NextAttemptAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("failure should persist attempt and next retry: %#v", rows)
	}
	deliveries := store.WebhookDeliveries()
	if len(deliveries) != 1 || deliveries[0].Attempt != 1 || deliveries[0].Error == "" {
		t.Fatalf("expected one failed delivery record, got %#v", deliveries)
	}
	updated, _ := store.Task(task.ID)
	if updated.Status != TaskStatusFailed || updated.Error == nil || updated.Error.Message != "blocked" {
		t.Fatalf("webhook failure must not change moderation result/status: %#v", updated)
	}
}

func TestBatchWebhookCreatesTaskEventsForEachTerminalItemAndBatchSummaryAtTerminal(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(now)
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	store.SetWebhookSecret("client-a", "secret-1", "top-secret")
	batch, tasks, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch",
		Inputs: []auditplatform.ModerationInput{
			textInput("post-1", "hello"),
			textInput("post-2", "world"),
		},
		WebhookURL: "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create batch: %v", err)
	}

	if err := store.CompleteTask(ctx, tasks[0].ID, auditplatform.ModerationResult{
		ClientItemID: "post-1",
		Decision:     auditplatform.DecisionPass,
		RiskLevel:    auditplatform.RiskLevelLow,
		ProviderName: "fake",
	}); err != nil {
		t.Fatalf("complete first task: %v", err)
	}
	rows := store.WebhookOutboxRows()
	if countWebhookRows(rows, "task", tasks[0].ID) != 1 || countWebhookRows(rows, "batch", batch.ID) != 0 {
		t.Fatalf("first terminal item rows = %#v", rows)
	}

	if err := store.FailTask(ctx, tasks[1].ID, TaskError{Code: "provider_response", Message: "failed"}); err != nil {
		t.Fatalf("fail second task: %v", err)
	}
	rows = store.WebhookOutboxRows()
	if len(rows) != 3 || countWebhookRows(rows, "task", tasks[1].ID) != 1 || countWebhookRows(rows, "batch", batch.ID) != 1 {
		t.Fatalf("terminal batch rows = %#v", rows)
	}
}

func TestWebhookExhaustionIsNotClaimableOrPending(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(now)
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := store.FailTask(ctx, task.ID, TaskError{Code: "provider_response", Message: "blocked"}); err != nil {
		t.Fatalf("fail task: %v", err)
	}

	schedule := WebhookAttemptSchedule()
	for attempt := range schedule {
		if attempt > 0 {
			store.AdvanceClock(schedule[attempt] - schedule[attempt-1])
		}
		rows := store.ClaimDueWebhooks(ctx, 1, 30*time.Second)
		if len(rows) != 1 {
			t.Fatalf("attempt %d due rows = %#v", attempt+1, rows)
		}
		if !store.RecordWebhookAttempt(ctx, rows[0].ID, rows[0].ClaimToken, 503, errors.New("temporary outage")) {
			t.Fatalf("record attempt %d", attempt+1)
		}
	}

	if rows := store.ClaimDueWebhooks(ctx, 1, 30*time.Second); len(rows) != 0 {
		t.Fatalf("exhausted webhook rows must not be claimable, got %#v", rows)
	}
	stats, err := store.AdminStats(ctx)
	if err != nil {
		t.Fatalf("admin stats: %v", err)
	}
	if stats.PendingWebhookOutbox != 0 {
		t.Fatalf("exhausted webhook rows must not count as pending, stats=%#v rows=%#v", stats, store.WebhookOutboxRows())
	}
}

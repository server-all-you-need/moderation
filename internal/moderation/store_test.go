package moderation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

func textInput(id, text string) auditplatform.ModerationInput {
	return auditplatform.ModerationInput{
		ClientItemID: id,
		ContentType:  auditplatform.ContentTypeText,
		Policy:       auditplatform.PolicyTextGeneral,
		Text:         text,
	}
}

func imageInput(id, url string) auditplatform.ModerationInput {
	return auditplatform.ModerationInput{
		ClientItemID: id,
		ContentType:  auditplatform.ContentTypeImage,
		Policy:       auditplatform.PolicyImageGeneral,
		ImageURL:     url,
	}
}

func TestPostgresMigrationsCoverModerationDurabilityWithoutMutatingLegacyTables(t *testing.T) {
	migrations := PostgresMigrations()
	if len(migrations) < 2 {
		t.Fatalf("expected ordered service-owned migrations, got %d", len(migrations))
	}

	var joined strings.Builder
	previous := 0
	for _, migration := range migrations {
		if migration.Version <= previous {
			t.Fatalf("migration versions must increase: %d after %d", migration.Version, previous)
		}
		previous = migration.Version
		joined.WriteString(strings.ToLower(migration.SQL))
		joined.WriteByte('\n')
	}
	sql := joined.String()

	requiredTables := []string{
		"moderation_api_clients",
		"moderation_webhook_endpoints",
		"moderation_tasks",
		"moderation_batches",
		"moderation_batch_tasks",
		"moderation_idempotency_keys",
		"moderation_task_outbox",
		"moderation_dlq_outbox",
		"moderation_webhook_outbox",
		"moderation_webhook_deliveries",
	}
	for _, table := range requiredTables {
		if !strings.Contains(sql, "create table if not exists "+table) {
			t.Fatalf("missing table %s in migrations:\n%s", table, sql)
		}
	}

	for _, needle := range []string{
		"create extension if not exists pgcrypto",
		"status in ('queued','processing','succeeded','failed')",
		"status in ('queued','processing','completed','partially_failed','failed')",
		"create index if not exists idx_moderation_tasks_owner_status",
		"create index if not exists idx_moderation_tasks_cursor",
		"create unique index if not exists idx_moderation_idempotency_scope",
		"create unique index if not exists idx_moderation_webhook_terminal_resource",
		"body_bytes bytea not null",
		"event_body bytea not null",
		"claim_token text",
		"claimed_until timestamptz",
		"for update skip locked",
	} {
		if !strings.Contains(sql, needle) {
			t.Fatalf("missing schema invariant %q", needle)
		}
	}
	for _, forbidden := range []string{"drop table audit_tasks", "alter table audit_tasks", "drop topic", "body_json jsonb"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("migration must not mutate legacy artifacts: found %q", forbidden)
		}
	}
}

func TestCreateTaskPersistsTaskOutboxAndIdempotencyAtomically(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))

	created, replayed, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload-a",
		Input:          textInput("post-1", "hello"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if replayed {
		t.Fatalf("first create must not be replayed")
	}
	if created.Status != TaskStatusQueued || created.Text == nil || *created.Text != "hello" || created.ImageURL != nil {
		t.Fatalf("unexpected created task: %#v", created)
	}
	if outbox := store.TaskOutboxRows(); len(outbox) != 1 || outbox[0].TaskID != created.ID {
		t.Fatalf("expected one task outbox row for %s, got %#v", created.ID, outbox)
	}

	replayedTask, replayed, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload-a",
		Input:          textInput("post-1", "hello"),
	})
	if err != nil {
		t.Fatalf("replay task: %v", err)
	}
	if !replayed || replayedTask.ID != created.ID {
		t.Fatalf("expected replay of %s, got replayed=%v task=%#v", created.ID, replayed, replayedTask)
	}
	if _, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:different",
		Input:          textInput("post-1", "hello"),
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	if tasks := store.Tasks(); len(tasks) != 1 {
		t.Fatalf("conflict must not create task, got %#v", tasks)
	}
}

func TestCreateBatchRejectsInvalidMembersWithoutOrphanRows(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))

	_, _, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch",
		Inputs: []auditplatform.ModerationInput{
			textInput("post-1", "hello"),
			imageInput("avatar-1", "http://example.com/a.png"),
		},
	})
	if err == nil {
		t.Fatalf("expected invalid image URL to reject the batch")
	}
	if len(store.Tasks()) != 0 || len(store.Batches()) != 0 || len(store.TaskOutboxRows()) != 0 {
		t.Fatalf("failed batch create left orphan rows: tasks=%#v batches=%#v outbox=%#v", store.Tasks(), store.Batches(), store.TaskOutboxRows())
	}
}

func TestBatchStatusAndCountsAreDerivedFromMemberTasks(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))

	batch, tasks, replayed, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch",
		Inputs: []auditplatform.ModerationInput{
			textInput("post-1", "hello"),
			imageInput("avatar-1", "https://cdn.example.com/a.png"),
		},
	})
	if err != nil {
		t.Fatalf("create batch: %v", err)
	}
	if replayed {
		t.Fatalf("first batch create must not be replayed")
	}
	if batch.Status != BatchStatusQueued || batch.Total != 2 || batch.Queued != 2 {
		t.Fatalf("unexpected initial batch: %#v", batch)
	}

	result := auditplatform.ModerationResult{
		ClientItemID: "post-1",
		Decision:     auditplatform.DecisionPass,
		RiskLevel:    auditplatform.RiskLevelLow,
		ProviderName: "fake",
	}
	if err := store.CompleteTask(ctx, tasks[0].ID, result); err != nil {
		t.Fatalf("complete first task: %v", err)
	}
	if err := store.FailTask(ctx, tasks[1].ID, TaskError{Code: auditplatform.ErrorCodeProviderResponse, Message: "provider rejected"}); err != nil {
		t.Fatalf("fail second task: %v", err)
	}

	updated, ok := store.Batch(batch.ID)
	if !ok {
		t.Fatalf("missing batch %s", batch.ID)
	}
	if updated.Status != BatchStatusPartiallyFailed || updated.Succeeded != 1 || updated.Failed != 1 || updated.Queued != 0 || updated.Processing != 0 {
		t.Fatalf("batch status/counts were not derived from members: %#v", updated)
	}
}

func TestTerminalTaskScrubsRawInputInSameStateChange(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload-a",
		Input:          textInput("post-1", "sensitive text"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	err = store.CompleteTask(ctx, task.ID, auditplatform.ModerationResult{
		ClientItemID: "post-1",
		Decision:     auditplatform.DecisionBlock,
		RiskLevel:    auditplatform.RiskLevelHigh,
		ProviderName: "fake",
	})
	if err != nil {
		t.Fatalf("complete task: %v", err)
	}
	updated, ok := store.Task(task.ID)
	if !ok {
		t.Fatalf("missing task %s", task.ID)
	}
	if updated.Status != TaskStatusSucceeded || updated.Text != nil || updated.ImageURL != nil || updated.Result == nil {
		t.Fatalf("terminal task did not scrub input and store result atomically: %#v", updated)
	}
}

func TestCleanupExpiredMetadataIsBoundedAndKeepsFreshRows(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(now)

	oldTask, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "old",
		PayloadHash:    "sha256:old",
		Input:          textInput("old", "old text"),
	})
	if err != nil {
		t.Fatalf("create old task: %v", err)
	}
	if err := store.FailTask(ctx, oldTask.ID, TaskError{Code: "failed", Message: "old"}); err != nil {
		t.Fatalf("fail old task: %v", err)
	}
	store.AdvanceClock(31 * 24 * time.Hour)
	freshTask, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "fresh",
		PayloadHash:    "sha256:fresh",
		Input:          textInput("fresh", "fresh text"),
	})
	if err != nil {
		t.Fatalf("create fresh task: %v", err)
	}
	if err := store.FailTask(ctx, freshTask.ID, TaskError{Code: "failed", Message: "fresh"}); err != nil {
		t.Fatalf("fail fresh task: %v", err)
	}

	deleted := store.CleanupExpired(ctx, 30*24*time.Hour, 1)
	if deleted != 1 {
		t.Fatalf("expected bounded cleanup to delete one row, deleted %d", deleted)
	}
	if _, ok := store.Task(oldTask.ID); ok {
		t.Fatalf("old terminal task should be removed")
	}
	if _, ok := store.Task(freshTask.ID); !ok {
		t.Fatalf("fresh terminal task should remain")
	}
}

func TestCleanupExpiredMetadataDeletesWebhookRowsAndIdempotencyReplay(t *testing.T) {
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
		IdempotencyKey: "old",
		PayloadHash:    "sha256:old",
		Input:          textInput("old", "old text"),
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := store.FailTask(ctx, task.ID, TaskError{Code: "failed", Message: "old"}); err != nil {
		t.Fatalf("fail task: %v", err)
	}
	dispatcher := NewWebhookDispatcher(store, &fakeWebhookHTTP{status: 200})
	if err := dispatcher.DispatchDueWebhooks(ctx, 10); err != nil {
		t.Fatalf("dispatch webhook: %v", err)
	}

	store.AdvanceClock(31 * 24 * time.Hour)
	if deleted := store.CleanupExpired(ctx, 30*24*time.Hour, 10); deleted != 1 {
		t.Fatalf("expected cleanup to delete old task, deleted %d", deleted)
	}
	if len(store.WebhookOutboxRows()) != 0 || len(store.WebhookDeliveries()) != 0 {
		t.Fatalf("cleanup should delete webhook metadata, rows=%#v deliveries=%#v", store.WebhookOutboxRows(), store.WebhookDeliveries())
	}
	recreated, replayed, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "old",
		PayloadHash:    "sha256:old",
		Input:          textInput("old", "old text"),
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("recreate after cleanup: %v", err)
	}
	if replayed || recreated.ID == task.ID {
		t.Fatalf("cleanup should remove idempotency replay of old resource: replayed=%v recreated=%#v old=%s", replayed, recreated, task.ID)
	}
}

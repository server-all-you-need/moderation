package moderation

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

type denyBudget struct {
	outcome LimitOutcome
	err     error
	calls   int
}

func (b *denyBudget) AcquireAsyncProvider(ctx context.Context) (LimitOutcome, error) {
	b.calls++
	return b.outcome, b.err
}

func TestWorkerUsesStoreInterfaceAndLimiterBeforeProvider(t *testing.T) {
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
	budget := &denyBudget{outcome: LimitOutcome{Allowed: false, Reason: LimitDeniedAsync}}
	worker := NewWorkerWithOptions(WorkerOptions{
		Store:          store,
		Provider:       provider,
		DLQ:            store,
		ProviderBudget: budget,
		ClaimFor:       30 * time.Second,
	})

	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("process limited event: %v", err)
	}
	if provider.calls != 0 || budget.calls != 1 {
		t.Fatalf("worker must acquire provider budget before provider call, provider=%d budget=%d", provider.calls, budget.calls)
	}
	updated, _ := store.Task(task.ID)
	if updated.Status != TaskStatusQueued || updated.NextAttemptAt == nil {
		t.Fatalf("limit denial should schedule retry without provider call: %#v", updated)
	}
}

func TestWorkerRedisFailureDoesNotCallProviderOrSilentlyBypassLimit(t *testing.T) {
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
	worker := NewWorkerWithOptions(WorkerOptions{
		Store:          store,
		Provider:       provider,
		DLQ:            store,
		ProviderBudget: &denyBudget{outcome: LimitOutcome{Allowed: false, Reason: LimitRedisFailure}, err: errors.New("redis down")},
		ClaimFor:       30 * time.Second,
	})

	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("redis failure should be handled as stable retry, got %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("redis failure must not bypass limiter and call provider")
	}
	updated, _ := store.Task(task.ID)
	if updated.Status != TaskStatusQueued || updated.Error == nil || updated.Error.Code != "rate_limiter_unavailable" {
		t.Fatalf("redis failure should be recorded as retryable limiter state: %#v", updated)
	}
}

func TestRetryScannerRequeuesDueTasksThroughTaskOutbox(t *testing.T) {
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
	worker := NewWorkerWithOptions(WorkerOptions{
		Store:    store,
		Provider: &fakeProvider{errors: []error{&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary"}}},
		DLQ:      store,
		ClaimFor: 30 * time.Second,
	})
	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("process retryable: %v", err)
	}
	before := len(store.TaskOutboxRows())
	store.AdvanceClock(5 * time.Second)
	requeued, err := RequeueDueRetries(ctx, store, 10)
	if err != nil {
		t.Fatalf("requeue due retries: %v", err)
	}
	if requeued != 1 || len(store.TaskOutboxRows()) != before+1 {
		t.Fatalf("due retry should create a new task outbox row: requeued=%d before=%d rows=%#v", requeued, before, store.TaskOutboxRows())
	}
}

func TestTerminalFailureCreatesDurableDLQOutboxEvenWhenPublisherFails(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "sensitive"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	worker := NewWorkerWithOptions(WorkerOptions{
		Store:    store,
		Provider: &fakeProvider{errors: []error{&auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Retryable: false, Message: "bad"}}},
		DLQ:      store,
		ClaimFor: 30 * time.Second,
	})
	if err := worker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
		t.Fatalf("terminal failure: %v", err)
	}
	if rows := store.DLQOutboxRows(); len(rows) != 1 || rows[0].PublishedAt != nil {
		t.Fatalf("terminal failure should persist unsent DLQ outbox row: %#v", rows)
	}

	publisher := &fakePublisher{failNext: true}
	if err := PublishDLQOutbox(ctx, store, publisher, 10, 30*time.Second); err == nil {
		t.Fatalf("expected first DLQ publish failure")
	}
	if rows := store.DLQOutboxRows(); len(rows) != 1 || rows[0].PublishedAt != nil || rows[0].LastError == "" {
		t.Fatalf("failed DLQ publish should remain retryable: %#v", rows)
	}
	if err := PublishDLQOutbox(ctx, store, publisher, 10, 30*time.Second); err != nil {
		t.Fatalf("retry DLQ publish: %v", err)
	}
	if rows := store.DLQOutboxRows(); rows[0].PublishedAt == nil {
		t.Fatalf("successful DLQ publish should mark row published: %#v", rows[0])
	}
}

func TestStandaloneTerminalTransitionCreatesWebhookOnce(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
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
	result := auditplatform.ModerationResult{ClientItemID: "post-1", Decision: auditplatform.DecisionPass, RiskLevel: auditplatform.RiskLevelLow, ProviderName: "fake"}
	if err := store.CompleteTask(ctx, task.ID, result); err != nil {
		t.Fatalf("complete task: %v", err)
	}
	if err := store.CompleteTask(ctx, task.ID, result); err != nil {
		t.Fatalf("duplicate complete should be idempotent: %v", err)
	}
	if rows := store.WebhookOutboxRows(); len(rows) != 1 {
		t.Fatalf("terminal transition should create one webhook row, got %#v", rows)
	}
}

func TestWebhookClaimLeasePreventsDuplicateAttemptAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
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
	first := store.ClaimDueWebhooks(ctx, 10, 30*time.Second)
	second := store.ClaimDueWebhooks(ctx, 10, 30*time.Second)
	if len(first) != 1 || len(second) != 0 {
		t.Fatalf("webhook lease should hide claimed row from another replica: first=%#v second=%#v", first, second)
	}
}

func TestCleanupExpiredMetadataCoversTerminalBatchesDLQAndBatchWebhooks(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	store.SetWebhookSecret("client-a", "secret-1", "top-secret")
	batch, tasks, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch",
		Inputs:         []auditplatform.ModerationInput{textInput("post-1", "hello")},
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create batch: %v", err)
	}
	if err := store.FailTaskWithDLQ(ctx, tasks[0].ID, TaskError{Code: "provider_response", Message: "failed"}, "provider_failure"); err != nil {
		t.Fatalf("fail with dlq: %v", err)
	}
	store.AdvanceClock(31 * 24 * time.Hour)
	if deleted := store.CleanupExpired(ctx, 30*24*time.Hour, 10); deleted != 1 {
		t.Fatalf("expected bounded cleanup to delete one terminal task, deleted %d", deleted)
	}
	if _, ok := store.Batch(batch.ID); ok {
		t.Fatalf("terminal batch should be cleaned up when all member tasks expire")
	}
	if len(store.DLQOutboxRows()) != 0 || len(store.WebhookOutboxRows()) != 0 || len(store.WebhookDeliveries()) != 0 {
		t.Fatalf("cleanup should remove DLQ/webhook metadata, dlq=%#v webhook=%#v deliveries=%#v", store.DLQOutboxRows(), store.WebhookOutboxRows(), store.WebhookDeliveries())
	}
}

func TestPostgresMigrationRunnerAppliesOrderedMigrationsInTransaction(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	for range PostgresMigrations() {
		mock.ExpectExec("create table if not exists moderation_api_clients|create table if not exists moderation_webhook_outbox").WillReturnResult(sqlmockResult(0, 0))
	}
	mock.ExpectCommit()

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresCreateTaskTransactionCommitsTaskIdempotencyAndOutbox(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	mock.ExpectQuery("select payload_hash, resource_type, resource_id from moderation_idempotency_keys").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("select 1 from moderation_webhook_endpoints").WillReturnRows(sqlmockRows("exists").AddRow(1))
	mock.ExpectExec("insert into moderation_tasks").WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("insert into moderation_task_outbox").WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("insert into moderation_idempotency_keys").WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectCommit()

	_, replayed, err := store.CreateTask(context.Background(), CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil || replayed {
		t.Fatalf("create task: replayed=%v err=%v", replayed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresCreateTaskConflictRollsBack(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	mock.ExpectQuery("select payload_hash, resource_type, resource_id from moderation_idempotency_keys").WillReturnRows(sqlmockRows("payload_hash", "resource_type", "resource_id").AddRow("sha256:old", "task", "task-1"))
	mock.ExpectRollback()

	_, _, err := store.CreateTask(context.Background(), CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:new",
		Input:          textInput("post-1", "hello"),
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresClaimQueriesUseSkipLockedAndConditionalLease(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	mock.ExpectQuery("for update skip locked").WillReturnRows(sqlmockRows(
		"id", "task_id", "caller_id", "batch_id", "client_item_id", "content_type", "policy", "correlation_id", "attempts", "created_at", "updated_at",
	).AddRow("outbox-1", "task-1", "client-a", nil, "post-1", "text", "text.general", "corr-1", 0, time.Now(), time.Now()))
	mock.ExpectExec("update moderation_task_outbox set claimed_until").WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectCommit()

	rows := store.ClaimTaskOutbox(context.Background(), 10, 30*time.Second)
	if len(rows) != 1 {
		t.Fatalf("expected one claimed row, got %#v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresIdempotencyReplayReturnsFullTaskAndRejectsWrongResourceType(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	mock.ExpectQuery("select payload_hash, resource_type, resource_id from moderation_idempotency_keys").
		WillReturnRows(sqlmockRows("payload_hash", "resource_type", "resource_id").AddRow("sha256:payload", "batch", "batch-1"))
	mock.ExpectRollback()
	_, _, err := store.CreateTask(context.Background(), CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("wrong replay resource type must conflict, got %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery("select payload_hash, resource_type, resource_id from moderation_idempotency_keys").
		WillReturnRows(sqlmockRows("payload_hash", "resource_type", "resource_id").AddRow("sha256:payload", "task", "task-1"))
	mock.ExpectQuery("select id, caller_id, coalesce\\(batch_id::text, ''\\), client_item_id, content_type, policy").
		WillReturnRows(sqlmockRows("id", "caller_id", "batch_id", "client_item_id", "content_type", "policy", "status", "text_content", "image_url", "attempts", "correlation_id", "webhook_url", "created_at", "updated_at").
			AddRow("task-1", "client-a", "", "post-1", "text", "text.general", "queued", "hello", "", 0, "corr-1", "", time.Now(), time.Now()))
	mock.ExpectCommit()
	task, replayed, err := store.CreateTask(context.Background(), CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "async_task",
		IdempotencyKey: "idem-1",
		PayloadHash:    "sha256:payload",
		Input:          textInput("post-1", "hello"),
	})
	if err != nil || !replayed || task.ClientItemID != "post-1" || task.Text == nil || *task.Text != "hello" {
		t.Fatalf("expected full replayed task, replayed=%v task=%#v err=%v", replayed, task, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresBatchReplayReturnsBatchWithOrderedMembers(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	mock.ExpectQuery("select payload_hash, resource_type, resource_id from moderation_idempotency_keys").
		WillReturnRows(sqlmockRows("payload_hash", "resource_type", "resource_id").AddRow("sha256:batch", "batch", "batch-1"))
	mock.ExpectQuery("select id, caller_id, status, total_count, queued_count, processing_count, succeeded_count, failed_count").
		WillReturnRows(sqlmockRows("id", "caller_id", "status", "total_count", "queued_count", "processing_count", "succeeded_count", "failed_count", "webhook_url", "created_at", "updated_at").AddRow("batch-1", "client-a", "processing", 2, 1, 1, 0, 0, "", time.Now(), time.Now()))
	mock.ExpectQuery("select t.id, t.caller_id, coalesce\\(t.batch_id::text, ''\\), t.client_item_id").
		WillReturnRows(sqlmockRows("id", "caller_id", "batch_id", "client_item_id", "content_type", "policy", "status", "text_content", "image_url", "attempts", "correlation_id", "webhook_url", "created_at", "updated_at").
			AddRow("task-1", "client-a", "batch-1", "post-1", "text", "text.general", "processing", "hello", "", 0, "corr-1", "", time.Now(), time.Now()).
			AddRow("task-2", "client-a", "batch-1", "post-2", "text", "text.general", "queued", "world", "", 0, "corr-2", "", time.Now(), time.Now()))
	mock.ExpectCommit()
	batch, tasks, replayed, err := store.CreateBatch(context.Background(), CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch",
		Inputs:         []auditplatform.ModerationInput{textInput("post-1", "hello")},
	})
	if err != nil || !replayed || batch.Status != BatchStatusProcessing || batch.Total != 2 || len(tasks) != 2 || tasks[0].ClientItemID != "post-1" || tasks[1].ClientItemID != "post-2" {
		t.Fatalf("expected full replayed batch/members, replayed=%v batch=%#v tasks=%#v err=%v", replayed, batch, tasks, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestMemoryLimitDenialDoesNotConsumeProviderAttempts(t *testing.T) {
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
	deniedWorker := NewWorkerWithOptions(WorkerOptions{
		Store:          store,
		Provider:       &fakeProvider{},
		ProviderBudget: &denyBudget{outcome: LimitOutcome{Allowed: false, Reason: LimitDeniedAsync}},
		ClaimFor:       30 * time.Second,
	})
	for i := 0; i < 5; i++ {
		if err := deniedWorker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
			t.Fatalf("limited attempt %d: %v", i+1, err)
		}
		store.AdvanceClock(5 * time.Second)
		if _, err := RequeueDueRetries(ctx, store, 10); err != nil {
			t.Fatalf("requeue limited attempt %d: %v", i+1, err)
		}
	}
	afterLimits, _ := store.Task(task.ID)
	if afterLimits.Attempts != 0 {
		t.Fatalf("limiter denials must not consume provider attempts, got %d", afterLimits.Attempts)
	}

	provider := &fakeProvider{errors: []error{
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 1"},
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 2"},
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 3"},
		&auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: "temporary 4"},
	}, results: []auditplatform.ModerationResult{{ClientItemID: "post-1", Decision: auditplatform.DecisionPass, RiskLevel: auditplatform.RiskLevelLow, ProviderName: "fake"}}}
	allowedWorker := NewWorkerWithOptions(WorkerOptions{Store: store, Provider: provider, ClaimFor: 30 * time.Second})
	for i := 0; i < 5; i++ {
		if err := allowedWorker.ProcessTaskEvent(ctx, TaskEventFromTask(task)); err != nil {
			t.Fatalf("provider attempt %d: %v", i+1, err)
		}
		if i < 4 {
			store.AdvanceClock(RetryDelays[i])
			if _, err := RequeueDueRetries(ctx, store, 10); err != nil {
				t.Fatalf("requeue provider attempt %d: %v", i+1, err)
			}
		}
	}
	finalTask, _ := store.Task(task.ID)
	if provider.calls != 5 || finalTask.Status != TaskStatusSucceeded || finalTask.Attempts != 5 {
		t.Fatalf("provider should receive full five-call budget after limit denials, calls=%d task=%#v", provider.calls, finalTask)
	}
}

func TestPostgresClaimAndRetryRefreshBatchCountsInTransaction(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	mock.ExpectQuery("from moderation_tasks\\s+where id = \\$1").
		WillReturnRows(sqlmockRows("id", "caller_id", "batch_id", "client_item_id", "content_type", "policy", "text_content", "image_url", "attempts", "correlation_id", "webhook_url").
			AddRow("task-1", "client-a", "batch-1", "post-1", "text", "text.general", "hello", "", 0, "corr-1", ""))
	mock.ExpectExec("update moderation_tasks set status = 'processing'").WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("with counts as").WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectCommit()
	if _, claimed, err := store.ClaimTaskForProcessing(context.Background(), "task-1", 30*time.Second); err != nil || !claimed {
		t.Fatalf("claim task: claimed=%v err=%v", claimed, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery("select coalesce\\(batch_id::text, ''\\) from moderation_tasks").
		WillReturnRows(sqlmockRows("batch_id").AddRow("batch-1"))
	mock.ExpectExec("update moderation_tasks set status = 'queued'").WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectExec("with counts as").WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectCommit()
	if err := store.ScheduleTaskRetry(context.Background(), "task-1", 5*time.Second, "temporary"); err != nil {
		t.Fatalf("schedule retry: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestWebhookClaimTokenPreventsStaleOwnerAttemptWrite(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
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
	first := store.ClaimDueWebhooks(ctx, 1, time.Second)
	if len(first) != 1 || first[0].ClaimToken == "" {
		t.Fatalf("expected claim token, got %#v", first)
	}
	store.AdvanceClock(2 * time.Second)
	second := store.ClaimDueWebhooks(ctx, 1, time.Second)
	if len(second) != 1 || second[0].ClaimToken == first[0].ClaimToken {
		t.Fatalf("expected new owner token after lease expiry, first=%#v second=%#v", first, second)
	}
	if store.RecordWebhookAttempt(ctx, first[0].ID, first[0].ClaimToken, 200, nil) {
		t.Fatalf("stale owner must not record delivery")
	}
	if !store.RecordWebhookAttempt(ctx, second[0].ID, second[0].ClaimToken, 200, nil) {
		t.Fatalf("current owner should record delivery")
	}
	if deliveries := store.WebhookDeliveries(); len(deliveries) != 1 {
		t.Fatalf("only current owner attempt should be persisted, got %#v", deliveries)
	}
}

func TestPostgresWebhookAttemptRequiresClaimToken(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	mock.ExpectQuery("where id = \\$1 and claim_token = \\$2").
		WillReturnRows(sqlmockRows("attempts", "created_at").AddRow(0, time.Now()))
	mock.ExpectExec("insert into moderation_webhook_deliveries").WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("update moderation_webhook_outbox set attempts").WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectCommit()
	if ok := store.RecordWebhookAttempt(context.Background(), "webhook-1", "owner-1", 200, nil); !ok {
		t.Fatalf("current owner token should record webhook attempt")
	}

	mock.ExpectBegin()
	mock.ExpectQuery("where id = \\$1 and claim_token = \\$2").WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	if ok := store.RecordWebhookAttempt(context.Background(), "webhook-1", "stale-owner", 200, nil); ok {
		t.Fatalf("stale owner token must not record webhook attempt")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresCleanupUsesBoundedDeletesInTransactionAndReportsErrors(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, func() time.Time { return time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC) })

	mock.ExpectBegin()
	for _, table := range []string{
		"moderation_webhook_deliveries",
		"moderation_webhook_outbox",
		"moderation_dlq_outbox",
		"moderation_task_outbox",
		"moderation_idempotency_keys",
		"moderation_tasks",
		"moderation_batches",
	} {
		mock.ExpectExec("delete from " + table + ".*limit \\$2").WillReturnResult(sqlmockResult(0, 1))
	}
	mock.ExpectCommit()
	deleted, err := store.CleanupExpiredWithError(context.Background(), 30*24*time.Hour, 10)
	if err != nil || deleted == 0 {
		t.Fatalf("cleanup should report bounded deletes, deleted=%d err=%v", deleted, err)
	}

	mock.ExpectBegin()
	mock.ExpectExec("delete from moderation_webhook_deliveries.*limit \\$2").WillReturnError(errors.New("delete failed"))
	mock.ExpectRollback()
	if _, err := store.CleanupExpiredWithError(context.Background(), 30*24*time.Hour, 10); err == nil {
		t.Fatalf("cleanup errors must be returned, not silently reported as success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresWebhookDispatcherRequiresExplicitSecretResolver(t *testing.T) {
	db, _, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, time.Now)
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatalf("default dispatcher must not silently use PostgresStore without explicit SecretResolver")
		}
	}()
	_ = NewWebhookDispatcher(store, &fakeWebhookHTTP{status: 200})
}

package moderation

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/server-all-you-need/moderation/internal/auditplatform"
)

func newSQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	return db, mock, func() { _ = db.Close() }
}

func TestPostgresAdminStatsReturnsOutboxCountErrors(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, nil)

	mock.ExpectQuery("select status, count\\(\\*\\) from moderation_tasks group by status").
		WillReturnRows(sqlmockRows("status", "count"))
	mock.ExpectQuery("select status, count\\(\\*\\) from moderation_batches group by status").
		WillReturnRows(sqlmockRows("status", "count"))
	mock.ExpectQuery("select result_json->>'risk_level', count\\(\\*\\) from moderation_tasks").
		WillReturnRows(sqlmockRows("risk", "count"))
	mock.ExpectQuery("select count\\(\\*\\) from moderation_task_outbox where published_at is null and \\(claimed_until is null or claimed_until < now\\(\\)\\)").
		WillReturnError(errors.New("db down"))

	if _, err := store.AdminStats(context.Background()); err == nil {
		t.Fatalf("AdminStats must return dependency errors from outbox counts")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresAdminStatsExcludesExhaustedWebhookRowsFromPending(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	store := NewPostgresStore(db, nil)

	mock.ExpectQuery("select status, count\\(\\*\\) from moderation_tasks group by status").
		WillReturnRows(sqlmockRows("status", "count"))
	mock.ExpectQuery("select status, count\\(\\*\\) from moderation_batches group by status").
		WillReturnRows(sqlmockRows("status", "count"))
	mock.ExpectQuery("select result_json->>'risk_level', count\\(\\*\\) from moderation_tasks").
		WillReturnRows(sqlmockRows("risk", "count"))
	mock.ExpectQuery("select count\\(\\*\\) from moderation_task_outbox where published_at is null and \\(claimed_until is null or claimed_until < now\\(\\)\\)").
		WillReturnRows(sqlmockRows("count").AddRow(0))
	mock.ExpectQuery("select count\\(\\*\\) from moderation_task_outbox where published_at is null and claimed_until >= now\\(\\)").
		WillReturnRows(sqlmockRows("count").AddRow(0))
	mock.ExpectQuery("select count\\(\\*\\) from moderation_webhook_outbox where delivered_at is null and attempts < 6 and next_attempt_at <= now\\(\\) and \\(claimed_until is null or claimed_until < now\\(\\)\\)").
		WillReturnRows(sqlmockRows("count").AddRow(0))
	mock.ExpectQuery("select count\\(\\*\\) from moderation_webhook_outbox where delivered_at is null and claimed_until >= now\\(\\)").
		WillReturnRows(sqlmockRows("count").AddRow(0))
	mock.ExpectQuery("select count\\(\\*\\) from moderation_dlq_outbox where published_at is null").
		WillReturnRows(sqlmockRows("count").AddRow(0))
	mock.ExpectQuery("select count\\(\\*\\) from moderation_dlq_outbox where published_at is not null").
		WillReturnRows(sqlmockRows("count").AddRow(0))

	stats, err := store.AdminStats(context.Background())
	if err != nil {
		t.Fatalf("admin stats: %v", err)
	}
	if stats.PendingWebhookOutbox != 0 {
		t.Fatalf("exhausted webhook rows should not be pending: %#v", stats)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestBatchFilterSQLCombinesTaskLevelPredicatesInOneMemberExists(t *testing.T) {
	where, args := batchFilterSQL(ListFilter{
		CallerID:    "client-a",
		BatchStatus: BatchStatusProcessing,
		ContentType: auditplatform.ContentTypeImage,
		TaskStatus:  TaskStatusSucceeded,
		Policy:      auditplatform.PolicyImageGeneral,
		RiskLevel:   auditplatform.RiskLevelHigh,
	})
	if strings.Count(where, "exists (select 1 from moderation_tasks t") != 1 {
		t.Fatalf("task-level predicates must share one correlated exists, got %s", where)
	}
	for _, clause := range []string{
		"caller_id = $1",
		"status = $2",
		"t.content_type = $3",
		"t.status = $4",
		"t.policy = $5",
		"t.result_json->>'risk_level' = $6",
	} {
		if !strings.Contains(where, clause) {
			t.Fatalf("where missing %q: %s", clause, where)
		}
	}
	if len(args) != 6 {
		t.Fatalf("args len = %d, want 6: %#v", len(args), args)
	}
}

func sqlmockRows(columns ...string) *sqlmock.Rows {
	return sqlmock.NewRows(columns)
}

func sqlmockResult(lastInsertID, rowsAffected int64) sql.Result {
	return sqlmock.NewResult(lastInsertID, rowsAffected)
}

func expectIdempotencyScopeLock(mock sqlmock.Sqlmock, scope string) {
	mock.ExpectExec("select pg_advisory_xact_lock\\(hashtextextended\\(\\$1, 0\\)\\)").
		WithArgs(scope).
		WillReturnResult(sqlmockResult(0, 1))
}

type capturedWebhookBody struct {
	eventID      *capturedWebhookID
	resourceType string
	resourceID   string
	status       string
	assert       func(map[string]interface{}) bool
	body         []byte
}

type capturedWebhookID struct {
	value string
}

func (m *capturedWebhookID) Match(value driver.Value) bool {
	id, ok := value.(string)
	if !ok || id == "" {
		return false
	}
	m.value = id
	return true
}

func (m *capturedWebhookBody) Match(value driver.Value) bool {
	body, ok := value.([]byte)
	if !ok {
		return false
	}
	var event map[string]interface{}
	if err := json.Unmarshal(body, &event); err != nil {
		return false
	}
	if m.eventID == nil || m.eventID.value == "" || event["event_id"] != m.eventID.value || event["type"] != m.resourceType || event["id"] != m.resourceID || event["status"] != m.status {
		return false
	}
	if got, ok := event["event_version"].(float64); !ok || int(got) != WebhookEventVersion {
		return false
	}
	if m.assert != nil && !m.assert(event) {
		return false
	}
	m.body = append([]byte(nil), body...)
	return true
}

func TestPostgresCreateBatchInheritsWebhookForItems(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewPostgresStore(db, func() time.Time { return now })

	mock.ExpectBegin()
	expectIdempotencyScopeLock(mock, "8:client-a5:batch7:batch-1")
	mock.ExpectQuery("select payload_hash, resource_type, resource_id from moderation_idempotency_keys").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("select 1 from moderation_webhook_endpoints").
		WithArgs("client-a", "https://hooks.example.com/moderation").
		WillReturnRows(sqlmockRows("exists").AddRow(1))
	mock.ExpectExec("insert into moderation_batches").
		WithArgs(sqlmock.AnyArg(), "client-a", BatchStatusQueued, 1, sqlmock.AnyArg(), now).
		WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("insert into moderation_tasks").
		WithArgs(sqlmock.AnyArg(), "client-a", sqlmock.AnyArg(), "post-1",
			auditplatform.ContentTypeText, auditplatform.PolicyTextGeneral, TaskStatusQueued,
			"hello", nil, sqlmock.AnyArg(), "https://hooks.example.com/moderation", now).
		WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("insert into moderation_batch_tasks").
		WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("insert into moderation_task_outbox").
		WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectExec("insert into moderation_idempotency_keys").
		WillReturnResult(sqlmockResult(1, 1))
	mock.ExpectCommit()

	_, tasks, replayed, err := store.CreateBatch(context.Background(), CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch",
		Inputs:         []auditplatform.ModerationInput{textInput("post-1", "hello")},
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil || replayed || len(tasks) != 1 || tasks[0].WebhookURL != "https://hooks.example.com/moderation" {
		t.Fatalf("create batch should persist item webhook destination, replayed=%v tasks=%#v err=%v", replayed, tasks, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresCompleteTaskWritesResultWebhookAtomically(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewPostgresStore(db, func() time.Time { return now })
	eventID := &capturedWebhookID{}
	body := &capturedWebhookBody{
		eventID:      eventID,
		resourceType: "task",
		resourceID:   "task-1",
		status:       string(TaskStatusSucceeded),
		assert: func(event map[string]interface{}) bool {
			if _, ok := event["risk_words"]; ok {
				return false
			}
			return event["client_item_id"] == "post-1" &&
				event["content_type"] == string(auditplatform.ContentTypeText) &&
				event["policy"] == string(auditplatform.PolicyTextGeneral) &&
				event["result"] != nil &&
				event["error"] == nil
		},
	}

	mock.ExpectBegin()
	mock.ExpectQuery("select id, caller_id, coalesce\\(batch_id::text, ''\\), client_item_id, content_type, policy, status, coalesce\\(webhook_url, ''\\) from moderation_tasks where id = \\$1 for update").
		WithArgs("task-1").
		WillReturnRows(sqlmockRows("id", "caller_id", "batch_id", "client_item_id", "content_type", "policy", "status", "webhook_url").
			AddRow("task-1", "client-a", "", "post-1", "text", "text.general", "processing", "https://hooks.example.com/moderation"))
	mock.ExpectExec("update moderation_tasks set status = 'succeeded'").
		WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectQuery("select secret_id from moderation_webhook_endpoints").
		WithArgs("client-a", "https://hooks.example.com/moderation").
		WillReturnRows(sqlmockRows("secret_id").AddRow("secret-1"))
	mock.ExpectExec("insert into moderation_webhook_outbox").
		WithArgs(eventID, "client-a", "task", "task-1", "https://hooks.example.com/moderation", "secret-1", body, now).
		WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectCommit()

	err := store.CompleteTask(context.Background(), "task-1", auditplatform.ModerationResult{
		ClientItemID: "post-1",
		Decision:     auditplatform.DecisionPass,
		RiskLevel:    auditplatform.RiskLevelLow,
		ProviderName: "fake",
		Labels: []auditplatform.LabelEntry{{
			Label:     "spam",
			RiskWords: []string{"private phrase"},
		}},
	})
	if err != nil {
		t.Fatalf("complete task: %v", err)
	}
	if len(body.body) == 0 {
		t.Fatalf("expected captured public webhook body")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresFailTaskWritesErrorWebhookAtomically(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewPostgresStore(db, func() time.Time { return now })
	eventID := &capturedWebhookID{}
	body := &capturedWebhookBody{
		eventID:      eventID,
		resourceType: "task",
		resourceID:   "task-2",
		status:       string(TaskStatusFailed),
		assert: func(event map[string]interface{}) bool {
			errValue, ok := event["error"].(map[string]interface{})
			return ok &&
				event["client_item_id"] == "post-2" &&
				event["content_type"] == string(auditplatform.ContentTypeText) &&
				event["policy"] == string(auditplatform.PolicyTextGeneral) &&
				event["result"] == nil &&
				errValue["code"] == "provider_response" &&
				errValue["message"] == "blocked"
		},
	}

	mock.ExpectBegin()
	mock.ExpectQuery("select id, caller_id, coalesce\\(batch_id::text, ''\\), client_item_id, content_type, policy, status, correlation_id, coalesce\\(webhook_url, ''\\) from moderation_tasks where id = \\$1 for update").
		WithArgs("task-2").
		WillReturnRows(sqlmockRows("id", "caller_id", "batch_id", "client_item_id", "content_type", "policy", "status", "correlation_id", "webhook_url").
			AddRow("task-2", "client-a", "", "post-2", "text", "text.general", "processing", "corr-2", "https://hooks.example.com/moderation"))
	mock.ExpectExec("update moderation_tasks set status = 'failed'").
		WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectQuery("select secret_id from moderation_webhook_endpoints").
		WithArgs("client-a", "https://hooks.example.com/moderation").
		WillReturnRows(sqlmockRows("secret_id").AddRow("secret-1"))
	mock.ExpectExec("insert into moderation_webhook_outbox").
		WithArgs(eventID, "client-a", "task", "task-2", "https://hooks.example.com/moderation", "secret-1", body, now).
		WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectCommit()

	if err := store.FailTask(context.Background(), "task-2", TaskError{Code: "provider_response", Message: "blocked"}); err != nil {
		t.Fatalf("fail task: %v", err)
	}
	if len(body.body) == 0 {
		t.Fatalf("expected captured public webhook body")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestPostgresTerminalBatchWritesSummaryWebhookAtomically(t *testing.T) {
	db, mock, cleanup := newSQLMock(t)
	defer cleanup()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := NewPostgresStore(db, func() time.Time { return now })
	terminalAt := now
	taskEventID := &capturedWebhookID{}
	batchEventID := &capturedWebhookID{}
	body := &capturedWebhookBody{
		eventID:      batchEventID,
		resourceType: "batch",
		resourceID:   "batch-1",
		status:       string(BatchStatusPartiallyFailed),
		assert: func(event map[string]interface{}) bool {
			summary, ok := event["summary"].(map[string]interface{})
			return ok &&
				int(summary["total"].(float64)) == 2 &&
				int(summary["queued"].(float64)) == 0 &&
				int(summary["processing"].(float64)) == 0 &&
				int(summary["succeeded"].(float64)) == 1 &&
				int(summary["failed"].(float64)) == 1
		},
	}

	mock.ExpectBegin()
	mock.ExpectQuery("select id, caller_id, coalesce\\(batch_id::text, ''\\), client_item_id, content_type, policy, status, correlation_id, coalesce\\(webhook_url, ''\\) from moderation_tasks where id = \\$1 for update").
		WithArgs("task-2").
		WillReturnRows(sqlmockRows("id", "caller_id", "batch_id", "client_item_id", "content_type", "policy", "status", "correlation_id", "webhook_url").
			AddRow("task-2", "client-a", "batch-1", "post-2", "text", "text.general", "processing", "corr-2", "https://hooks.example.com/moderation"))
	mock.ExpectExec("update moderation_tasks set status = 'failed'").
		WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectQuery("select secret_id from moderation_webhook_endpoints").
		WithArgs("client-a", "https://hooks.example.com/moderation").
		WillReturnRows(sqlmockRows("secret_id").AddRow("secret-1"))
	mock.ExpectExec("insert into moderation_webhook_outbox").
		WithArgs(taskEventID, "client-a", "task", "task-2", "https://hooks.example.com/moderation", "secret-1", sqlmock.AnyArg(), now).
		WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectQuery("with counts as").
		WithArgs("batch-1").
		WillReturnRows(sqlmockRows("id", "caller_id", "status", "total_count", "queued_count", "processing_count", "succeeded_count", "failed_count", "webhook_url", "created_at", "updated_at", "terminal_at").
			AddRow("batch-1", "client-a", "partially_failed", 2, 0, 0, 1, 1, "https://hooks.example.com/moderation", now, now, terminalAt))
	mock.ExpectQuery("select secret_id from moderation_webhook_endpoints").
		WithArgs("client-a", "https://hooks.example.com/moderation").
		WillReturnRows(sqlmockRows("secret_id").AddRow("secret-1"))
	mock.ExpectExec("insert into moderation_webhook_outbox").
		WithArgs(batchEventID, "client-a", "batch", "batch-1", "https://hooks.example.com/moderation", "secret-1", body, now).
		WillReturnResult(sqlmockResult(0, 1))
	mock.ExpectCommit()

	if err := store.FailTask(context.Background(), "task-2", TaskError{Code: "provider_response", Message: "blocked"}); err != nil {
		t.Fatalf("fail task: %v", err)
	}
	if len(body.body) == 0 {
		t.Fatalf("expected captured batch summary webhook body")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

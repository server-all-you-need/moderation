package moderation

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

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

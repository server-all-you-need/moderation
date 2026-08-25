package moderation

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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

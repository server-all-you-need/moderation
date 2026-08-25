package moderation

import (
	"database/sql"
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

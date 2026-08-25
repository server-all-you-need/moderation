package moderation

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPostgresLiveMigrationsApply(t *testing.T) {
	dsn := os.Getenv("POST_AUDIT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POST_AUDIT_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	store := NewPostgresStore(db, time.Now)
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	for _, table := range []string{
		"moderation_tasks",
		"moderation_batches",
		"moderation_task_outbox",
		"moderation_dlq_outbox",
		"moderation_webhook_outbox",
		"moderation_webhook_endpoints",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `select exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = $1)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("expected table %s to exist after migrations", table)
		}
	}
}

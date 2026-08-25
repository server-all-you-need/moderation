package moderation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
	_ "github.com/lib/pq"
)

func TestPostgresLiveClaimTaskOutbox(t *testing.T) {
	dsn := os.Getenv("POST_AUDIT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POST_AUDIT_TEST_POSTGRES_DSN is not set")
	}

	schema := fmt.Sprintf("moderation_outbox_%d", time.Now().UnixNano())
	adminDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer adminDB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := adminDB.ExecContext(ctx, `create schema `+schema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminDB.ExecContext(context.Background(), `drop schema `+schema+` cascade`)
	})

	isolatedDSN := postgresDSNWithSearchPath(t, dsn, schema)
	db, err := sql.Open("postgres", isolatedDSN)
	if err != nil {
		t.Fatalf("open isolated postgres: %v", err)
	}
	defer db.Close()
	store := NewPostgresStore(db, time.Now)
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into moderation_api_clients (id, name, key_hash) values ('outbox-client','Outbox Test','outbox-test-hash')`); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "outbox-client",
		Operation:      "async_task",
		IdempotencyKey: "outbox-key",
		PayloadHash:    "sha256:outbox",
		Input:          textInput("outbox-item", "hello"),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	rows := store.ClaimTaskOutbox(ctx, 1, 30*time.Second)
	if len(rows) != 1 || rows[0].TaskID != task.ID || rows[0].ClaimedUntil == nil {
		t.Fatalf("ClaimTaskOutbox() = %#v, want claimed row for task %s", rows, task.ID)
	}
}

func postgresDSNWithSearchPath(t *testing.T, dsn, schema string) string {
	t.Helper()
	if strings.Contains(dsn, "://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse postgres DSN: %v", err)
		}
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return dsn + " search_path=" + schema
}

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

func TestPostgresLiveConcurrentCreateIdempotency(t *testing.T) {
	dsn := os.Getenv("POST_AUDIT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POST_AUDIT_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	store := NewPostgresStore(db, time.Now)
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	callerID := "client-concurrent-" + time.Now().UTC().Format("20060102150405.000000000")
	if _, err := db.ExecContext(ctx, `insert into moderation_api_clients (id, name, key_hash) values ($1,$2,$3)`, callerID, "Concurrent Test", callerID+"-hash"); err != nil {
		t.Fatalf("insert client: %v", err)
	}

	taskKey := "task-key-" + callerID
	taskResults := make(chan struct {
		task     Task
		replayed bool
		err      error
	}, 2)
	var start sync.WaitGroup
	start.Add(1)
	for range 2 {
		go func() {
			start.Wait()
			task, replayed, err := store.CreateTask(ctx, CreateTaskRequest{
				CallerID:       callerID,
				Operation:      "async_task",
				IdempotencyKey: taskKey,
				PayloadHash:    "sha256:task",
				Input:          textInput("post-1", "hello"),
			})
			taskResults <- struct {
				task     Task
				replayed bool
				err      error
			}{task: task, replayed: replayed, err: err}
		}()
	}
	start.Done()
	firstTask := <-taskResults
	secondTask := <-taskResults
	if firstTask.err != nil || secondTask.err != nil {
		t.Fatalf("concurrent CreateTask returned error: first=%v second=%v", firstTask.err, secondTask.err)
	}
	if firstTask.task.ID == "" || firstTask.task.ID != secondTask.task.ID {
		t.Fatalf("concurrent CreateTask should return same task, first=%#v second=%#v", firstTask.task, secondTask.task)
	}
	if firstTask.replayed == secondTask.replayed {
		t.Fatalf("concurrent CreateTask should create once and replay once, first=%v second=%v", firstTask.replayed, secondTask.replayed)
	}
	_, _, err = store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       callerID,
		Operation:      "async_task",
		IdempotencyKey: taskKey,
		PayloadHash:    "sha256:different",
		Input:          textInput("post-1", "hello"),
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("CreateTask conflicting replay should return ErrIdempotencyConflict, got %v", err)
	}

	batchKey := "batch-key-" + callerID
	batchResults := make(chan struct {
		batch    Batch
		tasks    []Task
		replayed bool
		err      error
	}, 2)
	start = sync.WaitGroup{}
	start.Add(1)
	for range 2 {
		go func() {
			start.Wait()
			batch, tasks, replayed, err := store.CreateBatch(ctx, CreateBatchRequest{
				CallerID:       callerID,
				Operation:      "batch",
				IdempotencyKey: batchKey,
				PayloadHash:    "sha256:batch",
				Inputs: []auditplatform.ModerationInput{
					textInput("post-2", "world"),
				},
			})
			batchResults <- struct {
				batch    Batch
				tasks    []Task
				replayed bool
				err      error
			}{batch: batch, tasks: tasks, replayed: replayed, err: err}
		}()
	}
	start.Done()
	firstBatch := <-batchResults
	secondBatch := <-batchResults
	if firstBatch.err != nil || secondBatch.err != nil {
		t.Fatalf("concurrent CreateBatch returned error: first=%v second=%v", firstBatch.err, secondBatch.err)
	}
	if firstBatch.batch.ID == "" || firstBatch.batch.ID != secondBatch.batch.ID || len(firstBatch.tasks) != 1 || len(secondBatch.tasks) != 1 {
		t.Fatalf("concurrent CreateBatch should return same batch with members, first=%#v/%#v second=%#v/%#v", firstBatch.batch, firstBatch.tasks, secondBatch.batch, secondBatch.tasks)
	}
	if firstBatch.replayed == secondBatch.replayed {
		t.Fatalf("concurrent CreateBatch should create once and replay once, first=%v second=%v", firstBatch.replayed, secondBatch.replayed)
	}
	_, _, _, err = store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       callerID,
		Operation:      "batch",
		IdempotencyKey: batchKey,
		PayloadHash:    "sha256:different",
		Inputs: []auditplatform.ModerationInput{
			textInput("post-2", "world"),
		},
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("CreateBatch conflicting replay should return ErrIdempotencyConflict, got %v", err)
	}
}

package moderation

import (
	"context"
	"testing"
	"time"

	"github.com/server-all-you-need/moderation/internal/auditplatform"
)

func TestMemoryStoreCallerOwnedReadsCursorStatsAndSeededClients(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	if err := store.UpsertAPIClient(ctx, APIClient{ID: "client-a", Name: "Client A", TokenSHA256: "hash-a", Scopes: []string{"moderation:read"}}); err != nil {
		t.Fatalf("upsert client: %v", err)
	}
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	batch, tasks, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch",
		Inputs: []auditplatform.ModerationInput{
			textInput("post-1", "one"),
			imageInput("img-1", "https://cdn.example.com/a.png"),
		},
		WebhookURL: "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create batch: %v", err)
	}
	otherBatch, _, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-2",
		PayloadHash:    "sha256:batch-2",
		Inputs:         []auditplatform.ModerationInput{textInput("post-2", "two")},
	})
	if err != nil {
		t.Fatalf("create other batch: %v", err)
	}

	task, ok, err := store.GetTask(ctx, "client-a", tasks[0].ID)
	if err != nil || !ok || task.Text == nil {
		t.Fatalf("caller task lookup failed: task=%#v ok=%v err=%v", task, ok, err)
	}
	if _, ok, err = store.GetTask(ctx, "other", tasks[0].ID); err != nil || ok {
		t.Fatalf("other caller must not see task: ok=%v err=%v", ok, err)
	}

	page, err := store.ListBatchItems(ctx, "client-a", batch.ID, BatchItemCursor{Limit: 1})
	if err != nil {
		t.Fatalf("list items page1: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != tasks[0].ID || page.NextCursor == "" {
		t.Fatalf("unexpected first page: %#v", page)
	}
	page2, err := store.ListBatchItems(ctx, "client-a", batch.ID, BatchItemCursor{Limit: 1, Cursor: page.NextCursor})
	if err != nil {
		t.Fatalf("list items page2: %v", err)
	}
	if len(page2.Items) != 1 || page2.Items[0].ID != tasks[1].ID || page2.NextCursor != "" {
		t.Fatalf("unexpected second page: %#v", page2)
	}

	stats, err := store.AdminStats(ctx)
	if err != nil {
		t.Fatalf("admin stats: %v", err)
	}
	if stats.TaskStatusCounts[string(TaskStatusQueued)] != 3 || stats.BatchStatusCounts[string(BatchStatusQueued)] != 2 || stats.PendingTaskOutbox != 3 {
		t.Fatalf("unexpected stats: %#v", stats)
	}

	clients, err := store.ListAPIClients(ctx)
	if err != nil || len(clients) != 1 {
		t.Fatalf("list clients len=%d err=%v", len(clients), err)
	}
	if clients[0].TokenSHA256 != "" {
		t.Fatalf("client list must not expose token digest: %#v", clients[0])
	}

	filtered, err := store.ListBatches(ctx, ListFilter{CallerID: "client-a", ContentType: auditplatform.ContentTypeImage, Policy: auditplatform.PolicyImageGeneral})
	if err != nil {
		t.Fatalf("list filtered batches: %v", err)
	}
	if len(filtered.Items) != 1 || filtered.Items[0].ID != batch.ID || filtered.Items[0].ID == otherBatch.ID {
		t.Fatalf("batch filters must match member task metadata: %#v", filtered)
	}
}

func TestAdminTaskAndBatchListCursorsAreStableAcrossNewerInserts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	firstBatch, firstTasks, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-1",
		PayloadHash:    "sha256:batch-1",
		Inputs:         []auditplatform.ModerationInput{textInput("post-1", "one")},
	})
	if err != nil {
		t.Fatalf("create first batch: %v", err)
	}
	store.AdvanceClock(time.Second)
	secondBatch, secondTasks, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-2",
		PayloadHash:    "sha256:batch-2",
		Inputs:         []auditplatform.ModerationInput{textInput("post-2", "two")},
	})
	if err != nil {
		t.Fatalf("create second batch: %v", err)
	}

	taskPage1, err := store.ListTasks(ctx, ListFilter{Limit: 1})
	if err != nil {
		t.Fatalf("task page1: %v", err)
	}
	if len(taskPage1.Items) != 1 || taskPage1.Items[0].ID != secondTasks[0].ID || taskPage1.NextCursor == "" {
		t.Fatalf("unexpected task page1: %#v", taskPage1)
	}
	batchPage1, err := store.ListBatches(ctx, ListFilter{Limit: 1})
	if err != nil {
		t.Fatalf("batch page1: %v", err)
	}
	if len(batchPage1.Items) != 1 || batchPage1.Items[0].ID != secondBatch.ID || batchPage1.NextCursor == "" {
		t.Fatalf("unexpected batch page1: %#v", batchPage1)
	}

	store.AdvanceClock(time.Second)
	if _, _, _, err := store.CreateBatch(ctx, CreateBatchRequest{
		CallerID:       "client-a",
		Operation:      "batch",
		IdempotencyKey: "batch-3",
		PayloadHash:    "sha256:batch-3",
		Inputs:         []auditplatform.ModerationInput{textInput("post-3", "three")},
	}); err != nil {
		t.Fatalf("create newer batch: %v", err)
	}

	taskPage2, err := store.ListTasks(ctx, ListFilter{Limit: 1, Cursor: taskPage1.NextCursor})
	if err != nil {
		t.Fatalf("task page2: %v", err)
	}
	if len(taskPage2.Items) != 1 || taskPage2.Items[0].ID != firstTasks[0].ID {
		t.Fatalf("task keyset cursor should continue after original first page, got %#v", taskPage2)
	}
	batchPage2, err := store.ListBatches(ctx, ListFilter{Limit: 1, Cursor: batchPage1.NextCursor})
	if err != nil {
		t.Fatalf("batch page2: %v", err)
	}
	if len(batchPage2.Items) != 1 || batchPage2.Items[0].ID != firstBatch.ID {
		t.Fatalf("batch keyset cursor should continue after original first page, got %#v", batchPage2)
	}
}

func TestAdminStatsIncludesClaimedOutboxCounts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC))
	if err := store.RegisterWebhookEndpoint(ctx, "client-a", "https://hooks.example.com/moderation", "secret-1"); err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	task, _, err := store.CreateTask(ctx, CreateTaskRequest{
		CallerID:       "client-a",
		Operation:      "task",
		IdempotencyKey: "task-1",
		PayloadHash:    "sha256:task-1",
		Input:          textInput("post-1", "one"),
		WebhookURL:     "https://hooks.example.com/moderation",
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	_ = store.ClaimTaskOutbox(ctx, 1, time.Minute)
	if err := store.FailTask(ctx, task.ID, TaskError{Code: "provider_response", Message: "failed"}); err != nil {
		t.Fatalf("fail task: %v", err)
	}
	_ = store.ClaimDueWebhooks(ctx, 1, time.Minute)

	stats, err := store.AdminStats(ctx)
	if err != nil {
		t.Fatalf("admin stats: %v", err)
	}
	if stats.ClaimedTaskOutbox != 1 || stats.ClaimedWebhookOutbox != 1 {
		t.Fatalf("stats missing claimed outbox counts: %#v", stats)
	}
}

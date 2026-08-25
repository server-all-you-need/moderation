package moderation

import (
	"context"
	"testing"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
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

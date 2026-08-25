package moderation

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

type APIClient struct {
	ID          string
	Name        string
	TokenSHA256 string
	Scopes      []string
	CreatedAt   time.Time
	DisabledAt  *time.Time
}

type BatchItemCursor struct {
	Limit  int
	Cursor string
}

type BatchItemsPage struct {
	Items      []Task
	NextCursor string
}

type ListFilter struct {
	CallerID    string
	ContentType auditplatform.ContentType
	TaskStatus  TaskStatus
	BatchStatus BatchStatus
	RiskLevel   auditplatform.RiskLevel
	Policy      auditplatform.Policy
	Limit       int
	Cursor      string
}

type TaskPage struct {
	Items      []Task
	NextCursor string
}

type BatchPage struct {
	Items      []Batch
	NextCursor string
}

type AdminStatsSnapshot struct {
	TaskStatusCounts     map[string]int `json:"task_status_counts"`
	BatchStatusCounts    map[string]int `json:"batch_status_counts"`
	RiskCounts           map[string]int `json:"risk_counts"`
	KafkaConsumerLag     int64          `json:"kafka_consumer_lag"`
	PendingTaskOutbox    int            `json:"pending_task_outbox"`
	PendingWebhookOutbox int            `json:"pending_webhook_outbox"`
	PendingDLQOutbox     int            `json:"pending_dlq_outbox"`
	PublishedDLQOutbox   int            `json:"published_dlq_outbox"`
}

func (s *MemoryStore) UpsertAPIClient(_ context.Context, client APIClient) error {
	if client.ID == "" {
		return fmt.Errorf("client id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = s.now
	}
	client.Scopes = append([]string(nil), client.Scopes...)
	s.clients[client.ID] = client
	return nil
}

func (s *MemoryStore) GetTask(_ context.Context, callerID, taskID string) (Task, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, ok := s.tasks[taskID]
	if !ok || task.CallerID != callerID {
		return Task{}, false, nil
	}
	return cloneTask(task), true, nil
}

func (s *MemoryStore) GetBatch(_ context.Context, callerID, batchID string) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch, ok := s.batches[batchID]
	if !ok || batch.CallerID != callerID {
		return Batch{}, false, nil
	}
	return cloneBatch(batch), true, nil
}

func (s *MemoryStore) GetAdminTask(_ context.Context, taskID string) (Task, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, ok := s.tasks[taskID]
	if !ok {
		return Task{}, false, nil
	}
	return cloneTask(task), true, nil
}

func (s *MemoryStore) GetAdminBatch(_ context.Context, batchID string) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch, ok := s.batches[batchID]
	if !ok {
		return Batch{}, false, nil
	}
	return cloneBatch(batch), true, nil
}

func (s *MemoryStore) ListBatchItems(_ context.Context, callerID, batchID string, cursor BatchItemCursor) (BatchItemsPage, error) {
	limit := cursor.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset, err := decodePositionCursor(cursor.Cursor)
	if err != nil {
		return BatchItemsPage{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	batch, ok := s.batches[batchID]
	if !ok || batch.CallerID != callerID {
		return BatchItemsPage{}, ErrNotFound
	}
	ids := s.batchTasks[batchID]
	if offset >= len(ids) {
		return BatchItemsPage{}, nil
	}
	end := offset + limit
	if end > len(ids) {
		end = len(ids)
	}
	items := make([]Task, 0, end-offset)
	for _, id := range ids[offset:end] {
		if task, ok := s.tasks[id]; ok {
			items = append(items, cloneTask(task))
		}
	}
	next := ""
	if end < len(ids) {
		next = encodePositionCursor(end)
	}
	return BatchItemsPage{Items: items, NextCursor: next}, nil
}

func (s *MemoryStore) ListTasks(_ context.Context, filter ListFilter) (TaskPage, error) {
	limit := normalizeListLimit(filter.Limit)
	offset, err := decodePositionCursor(filter.Cursor)
	if err != nil {
		return TaskPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		if !taskMatchesFilter(task, filter) {
			continue
		}
		items = append(items, cloneTask(task))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if offset >= len(items) {
		return TaskPage{}, nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	page := items[offset:end]
	next := ""
	if end < len(items) {
		next = encodePositionCursor(end)
	}
	return TaskPage{Items: page, NextCursor: next}, nil
}

func (s *MemoryStore) ListBatches(_ context.Context, filter ListFilter) (BatchPage, error) {
	limit := normalizeListLimit(filter.Limit)
	offset, err := decodePositionCursor(filter.Cursor)
	if err != nil {
		return BatchPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]Batch, 0, len(s.batches))
	for _, batch := range s.batches {
		if filter.CallerID != "" && batch.CallerID != filter.CallerID {
			continue
		}
		if filter.BatchStatus != "" && batch.Status != filter.BatchStatus {
			continue
		}
		if !s.batchMatchesMemberFilterLocked(batch.ID, filter) {
			continue
		}
		items = append(items, cloneBatch(batch))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if offset >= len(items) {
		return BatchPage{}, nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	page := items[offset:end]
	next := ""
	if end < len(items) {
		next = encodePositionCursor(end)
	}
	return BatchPage{Items: page, NextCursor: next}, nil
}

func (s *MemoryStore) batchMatchesMemberFilterLocked(batchID string, filter ListFilter) bool {
	if filter.ContentType == "" && filter.Policy == "" && filter.RiskLevel == "" && filter.TaskStatus == "" {
		return true
	}
	for _, taskID := range s.batchTasks[batchID] {
		task, ok := s.tasks[taskID]
		if !ok {
			continue
		}
		if taskMatchesFilter(task, ListFilter{
			ContentType: filter.ContentType,
			TaskStatus:  filter.TaskStatus,
			RiskLevel:   filter.RiskLevel,
			Policy:      filter.Policy,
		}) {
			return true
		}
	}
	return false
}

func (s *MemoryStore) ListAPIClients(context.Context) ([]APIClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clients := make([]APIClient, 0, len(s.clients))
	for _, client := range s.clients {
		client.TokenSHA256 = ""
		client.Scopes = append([]string(nil), client.Scopes...)
		clients = append(clients, client)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	return clients, nil
}

func (s *MemoryStore) AdminStats(context.Context) (AdminStatsSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := AdminStatsSnapshot{
		TaskStatusCounts:  map[string]int{},
		BatchStatusCounts: map[string]int{},
		RiskCounts:        map[string]int{},
	}
	for _, task := range s.tasks {
		stats.TaskStatusCounts[string(task.Status)]++
		if task.Result != nil {
			stats.RiskCounts[string(task.Result.RiskLevel)]++
		}
	}
	for _, batch := range s.batches {
		stats.BatchStatusCounts[string(batch.Status)]++
	}
	for _, row := range s.outbox {
		if row.PublishedAt == nil {
			stats.PendingTaskOutbox++
		}
	}
	for _, row := range s.webhookRows {
		if row.DeliveredAt == nil {
			stats.PendingWebhookOutbox++
		}
	}
	for _, row := range s.dlqOutbox {
		if row.PublishedAt == nil {
			stats.PendingDLQOutbox++
		} else {
			stats.PublishedDLQOutbox++
		}
	}
	return stats, nil
}

func encodePositionCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("pos:%d", offset)))
}

func decodePositionCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("invalid cursor")
	}
	text := string(raw)
	if !strings.HasPrefix(text, "pos:") {
		return 0, fmt.Errorf("invalid cursor")
	}
	offset, err := strconv.Atoi(strings.TrimPrefix(text, "pos:"))
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("invalid cursor")
	}
	return offset, nil
}

func normalizeListLimit(limit int) int {
	if limit <= 0 || limit > 100 {
		return 50
	}
	return limit
}

func taskMatchesFilter(task Task, filter ListFilter) bool {
	if filter.CallerID != "" && task.CallerID != filter.CallerID {
		return false
	}
	if filter.ContentType != "" && task.ContentType != filter.ContentType {
		return false
	}
	if filter.TaskStatus != "" && task.Status != filter.TaskStatus {
		return false
	}
	if filter.Policy != "" && task.Policy != filter.Policy {
		return false
	}
	if filter.RiskLevel != "" {
		if task.Result == nil || task.Result.RiskLevel != filter.RiskLevel {
			return false
		}
	}
	return true
}

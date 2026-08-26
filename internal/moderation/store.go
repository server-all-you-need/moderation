package moderation

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/server-all-you-need/moderation/internal/auditplatform"
)

type idempotencyRecord struct {
	payloadHash  string
	resourceType string
	resourceID   string
	createdAt    time.Time
}

type MemoryStore struct {
	mu          sync.Mutex
	now         time.Time
	tasks       map[string]Task
	batches     map[string]Batch
	outbox      map[string]TaskOutboxRow
	dlqOutbox   map[string]DLQOutboxRow
	idem        map[string]idempotencyRecord
	batchTasks  map[string][]string
	webhooks    map[string]WebhookEndpoint
	webhookRows map[string]WebhookOutboxRow
	deliveries  []WebhookDelivery
	clients     map[string]APIClient
}

func NewMemoryStore(now time.Time) *MemoryStore {
	return &MemoryStore{
		now:         now,
		tasks:       map[string]Task{},
		batches:     map[string]Batch{},
		outbox:      map[string]TaskOutboxRow{},
		dlqOutbox:   map[string]DLQOutboxRow{},
		idem:        map[string]idempotencyRecord{},
		batchTasks:  map[string][]string{},
		webhooks:    map[string]WebhookEndpoint{},
		webhookRows: map[string]WebhookOutboxRow{},
		clients:     map[string]APIClient{},
	}
}

func (s *MemoryStore) AdvanceClock(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

func (s *MemoryStore) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

func (s *MemoryStore) CreateTask(_ context.Context, req CreateTaskRequest) (Task, bool, error) {
	if err := req.Input.Validate(); err != nil {
		return Task{}, false, err
	}
	key := idemKey(req.CallerID, req.Operation, req.IdempotencyKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	if req.WebhookURL != "" && !s.webhookAllowedLocked(req.CallerID, req.WebhookURL) {
		return Task{}, false, ErrWebhookNotAllowed
	}
	if existing, ok := s.idem[key]; ok {
		if existing.payloadHash != req.PayloadHash {
			return Task{}, false, ErrIdempotencyConflict
		}
		task, ok := s.tasks[existing.resourceID]
		if !ok || existing.resourceType != "task" {
			return Task{}, false, ErrNotFound
		}
		return cloneTask(task), true, nil
	}

	task := s.newTaskLocked(req.CallerID, "", req.Input, req.WebhookURL)
	s.tasks[task.ID] = task
	outboxRow := taskOutboxFromTask(task, s.now)
	s.outbox[outboxRow.ID] = outboxRow
	s.idem[key] = idempotencyRecord{payloadHash: req.PayloadHash, resourceType: "task", resourceID: task.ID, createdAt: s.now}
	return cloneTask(task), false, nil
}

func (s *MemoryStore) CreateBatch(_ context.Context, req CreateBatchRequest) (Batch, []Task, bool, error) {
	if len(req.Inputs) < 1 || len(req.Inputs) > 100 {
		return Batch{}, nil, false, fmt.Errorf("batch size must be 1-100")
	}
	for _, input := range req.Inputs {
		if err := input.Validate(); err != nil {
			return Batch{}, nil, false, err
		}
	}
	key := idemKey(req.CallerID, req.Operation, req.IdempotencyKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	if req.WebhookURL != "" && !s.webhookAllowedLocked(req.CallerID, req.WebhookURL) {
		return Batch{}, nil, false, ErrWebhookNotAllowed
	}
	if existing, ok := s.idem[key]; ok {
		if existing.payloadHash != req.PayloadHash {
			return Batch{}, nil, false, ErrIdempotencyConflict
		}
		batch, ok := s.batches[existing.resourceID]
		if !ok || existing.resourceType != "batch" {
			return Batch{}, nil, false, ErrNotFound
		}
		tasks := s.tasksForBatchLocked(batch.ID)
		return cloneBatch(batch), tasks, true, nil
	}

	batch := Batch{
		ID:         uuid.NewString(),
		CallerID:   req.CallerID,
		Status:     BatchStatusQueued,
		Total:      len(req.Inputs),
		Queued:     len(req.Inputs),
		CreatedAt:  s.now,
		UpdatedAt:  s.now,
		WebhookURL: req.WebhookURL,
	}
	s.batches[batch.ID] = batch

	tasks := make([]Task, 0, len(req.Inputs))
	for _, input := range req.Inputs {
		task := s.newTaskLocked(req.CallerID, batch.ID, input, req.WebhookURL)
		s.tasks[task.ID] = task
		s.batchTasks[batch.ID] = append(s.batchTasks[batch.ID], task.ID)
		outboxRow := taskOutboxFromTask(task, s.now)
		s.outbox[outboxRow.ID] = outboxRow
		tasks = append(tasks, cloneTask(task))
	}
	s.idem[key] = idempotencyRecord{payloadHash: req.PayloadHash, resourceType: "batch", resourceID: batch.ID, createdAt: s.now}
	return cloneBatch(batch), tasks, false, nil
}

func (s *MemoryStore) CompleteTask(_ context.Context, taskID string, result auditplatform.ModerationResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[taskID]
	if !ok {
		return ErrNotFound
	}
	if task.Status == TaskStatusSucceeded || task.Status == TaskStatusFailed {
		return nil
	}
	originalTask := task
	now := s.now
	task.Status = TaskStatusSucceeded
	task.Text = nil
	task.ImageURL = nil
	task.Error = nil
	task.Result = &result
	task.ClaimedUntil = nil
	task.NextAttemptAt = nil
	task.UpdatedAt = now
	task.TerminalAt = &now
	taskWebhookRow, hasTaskWebhook, err := s.webhookRowForTerminalTaskLocked(task)
	if err != nil {
		return err
	}
	s.tasks[taskID] = task
	batchWebhookRow, hasBatchWebhook, err := s.deriveBatchLocked(task.BatchID)
	if err != nil {
		s.tasks[taskID] = originalTask
		return err
	}
	if hasTaskWebhook {
		s.webhookRows[taskWebhookRow.ID] = taskWebhookRow
	}
	if hasBatchWebhook {
		s.webhookRows[batchWebhookRow.ID] = batchWebhookRow
	}
	return nil
}

func (s *MemoryStore) FailTask(_ context.Context, taskID string, taskErr TaskError) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[taskID]
	if !ok {
		return ErrNotFound
	}
	if task.Status == TaskStatusSucceeded || task.Status == TaskStatusFailed {
		return nil
	}
	originalTask := task
	now := s.now
	task.Status = TaskStatusFailed
	task.Text = nil
	task.ImageURL = nil
	task.Result = nil
	task.Error = &taskErr
	task.ClaimedUntil = nil
	task.NextAttemptAt = nil
	task.UpdatedAt = now
	task.TerminalAt = &now
	taskWebhookRow, hasTaskWebhook, err := s.webhookRowForTerminalTaskLocked(task)
	if err != nil {
		return err
	}
	s.tasks[taskID] = task
	batchWebhookRow, hasBatchWebhook, err := s.deriveBatchLocked(task.BatchID)
	if err != nil {
		s.tasks[taskID] = originalTask
		return err
	}
	if hasTaskWebhook {
		s.webhookRows[taskWebhookRow.ID] = taskWebhookRow
	}
	if hasBatchWebhook {
		s.webhookRows[batchWebhookRow.ID] = batchWebhookRow
	}
	return nil
}

func (s *MemoryStore) FailTaskWithDLQ(ctx context.Context, taskID string, taskErr TaskError, reason string) error {
	s.mu.Lock()
	task, ok := s.tasks[taskID]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	alreadyTerminal := task.Status == TaskStatusSucceeded || task.Status == TaskStatusFailed
	s.mu.Unlock()
	if err := s.FailTask(ctx, taskID, taskErr); err != nil {
		return err
	}
	if alreadyTerminal {
		return nil
	}
	return s.CreateDLQOutbox(ctx, taskID, reason)
}

func (s *MemoryStore) Task(id string) (Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, ok := s.tasks[id]
	return cloneTask(task), ok
}

func (s *MemoryStore) Batch(id string) (Batch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch, ok := s.batches[id]
	return cloneBatch(batch), ok
}

func (s *MemoryStore) Tasks() []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		out = append(out, cloneTask(task))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) || out[i].ID < out[j].ID })
	return out
}

func (s *MemoryStore) Batches() []Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Batch, 0, len(s.batches))
	for _, batch := range s.batches {
		out = append(out, cloneBatch(batch))
	}
	return out
}

func (s *MemoryStore) TaskOutboxRows() []TaskOutboxRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TaskOutboxRow, 0, len(s.outbox))
	for _, row := range s.outbox {
		out = append(out, cloneOutbox(row))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) || out[i].ID < out[j].ID })
	return out
}

func (s *MemoryStore) RegisterWebhookEndpoint(_ context.Context, callerID, destinationURL, secretID string) error {
	if err := validateWebhookURL(destinationURL); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks[webhookKey(callerID, destinationURL)] = WebhookEndpoint{
		CallerID: callerID,
		URL:      destinationURL,
		SecretID: secretID,
	}
	return nil
}

func (s *MemoryStore) SetWebhookSecret(callerID, secretID, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, endpoint := range s.webhooks {
		if endpoint.CallerID == callerID && endpoint.SecretID == secretID {
			endpoint.secret = secret
			s.webhooks[key] = endpoint
		}
	}
}

func (s *MemoryStore) WebhookOutboxRows() []WebhookOutboxRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WebhookOutboxRow, 0, len(s.webhookRows))
	for _, row := range s.webhookRows {
		out = append(out, cloneWebhookOutbox(row))
	}
	sortWebhookRows(out)
	return out
}

func (s *MemoryStore) WebhookDeliveries() []WebhookDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WebhookDelivery, len(s.deliveries))
	copy(out, s.deliveries)
	return out
}

func (s *MemoryStore) DueWebhookOutbox(limit int) []WebhookOutboxRow {
	return s.ClaimDueWebhooks(context.Background(), limit, 0)
}

func (s *MemoryStore) ClaimDueWebhooks(_ context.Context, limit int, lockFor time.Duration) []WebhookOutboxRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		return nil
	}
	rows := make([]WebhookOutboxRow, 0, len(s.webhookRows))
	for _, row := range s.webhookRows {
		if row.DeliveredAt != nil || row.Attempts >= len(WebhookAttemptSchedule()) || row.NextAttemptAt.After(s.now) {
			continue
		}
		if row.ClaimedUntil != nil && row.ClaimedUntil.After(s.now) {
			continue
		}
		rows = append(rows, cloneWebhookOutbox(row))
	}
	sortWebhookRows(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	if lockFor > 0 {
		claimedUntil := s.now.Add(lockFor)
		for i := range rows {
			row := s.webhookRows[rows[i].ID]
			row.ClaimToken = uuid.NewString()
			row.ClaimedUntil = &claimedUntil
			row.UpdatedAt = s.now
			s.webhookRows[row.ID] = row
			rows[i] = cloneWebhookOutbox(row)
		}
	}
	return rows
}

func (s *MemoryStore) RecordWebhookAttempt(_ context.Context, id, claimToken string, statusCode int, attemptErr error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.webhookRows[id]
	if !ok {
		return false
	}
	if row.ClaimToken == "" || row.ClaimToken != claimToken {
		return false
	}
	row.Attempts++
	delivery := WebhookDelivery{
		WebhookID:  id,
		Attempt:    row.Attempts,
		StatusCode: statusCode,
		CreatedAt:  s.now,
	}
	if attemptErr != nil {
		delivery.Error = attemptErr.Error()
		row.LastError = attemptErr.Error()
		row.ClaimedUntil = nil
		schedule := WebhookAttemptSchedule()
		if row.Attempts < len(schedule) {
			row.NextAttemptAt = row.CreatedAt.Add(schedule[row.Attempts])
		}
	} else {
		deliveredAt := s.now
		row.DeliveredAt = &deliveredAt
		row.LastError = ""
		row.ClaimedUntil = nil
	}
	row.UpdatedAt = s.now
	s.webhookRows[id] = row
	s.deliveries = append(s.deliveries, delivery)
	return true
}

func (s *MemoryStore) ClaimTaskOutbox(_ context.Context, limit int, lockFor time.Duration) []TaskOutboxRow {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		return nil
	}
	rows := make([]TaskOutboxRow, 0, len(s.outbox))
	for _, row := range s.outbox {
		if row.PublishedAt != nil {
			continue
		}
		if row.ClaimedUntil != nil && row.ClaimedUntil.After(s.now) {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt.Before(rows[j].CreatedAt) || rows[i].ID < rows[j].ID })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	claimedUntil := s.now.Add(lockFor)
	for i := range rows {
		row := s.outbox[rows[i].ID]
		row.ClaimedUntil = &claimedUntil
		row.Attempts++
		row.UpdatedAt = s.now
		s.outbox[row.ID] = row
		rows[i] = cloneOutbox(row)
	}
	return rows
}

func (s *MemoryStore) MarkTaskOutboxPublished(_ context.Context, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row, ok := s.outbox[id]
	if !ok {
		return
	}
	now := s.now
	row.PublishedAt = &now
	row.ClaimedUntil = nil
	row.LastError = ""
	row.UpdatedAt = now
	s.outbox[id] = row
}

func (s *MemoryStore) MarkTaskOutboxFailed(_ context.Context, id, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row, ok := s.outbox[id]
	if !ok {
		return
	}
	row.ClaimedUntil = nil
	row.LastError = message
	row.UpdatedAt = s.now
	s.outbox[id] = row
}

func (s *MemoryStore) RequeueDueRetries(_ context.Context, limit int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		return 0, nil
	}
	tasks := make([]Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		if task.Status != TaskStatusQueued || task.NextAttemptAt == nil || task.NextAttemptAt.After(s.now) {
			continue
		}
		tasks = append(tasks, task)
	}
	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].NextAttemptAt.Equal(*tasks[j].NextAttemptAt) {
			return tasks[i].ID < tasks[j].ID
		}
		return tasks[i].NextAttemptAt.Before(*tasks[j].NextAttemptAt)
	})
	if len(tasks) > limit {
		tasks = tasks[:limit]
	}
	for _, task := range tasks {
		task.NextAttemptAt = nil
		task.UpdatedAt = s.now
		s.tasks[task.ID] = task
		row := taskOutboxFromTask(task, s.now)
		s.outbox[row.ID] = row
	}
	return len(tasks), nil
}

func (s *MemoryStore) ClaimTaskForProcessing(_ context.Context, taskID string, lockFor time.Duration) (Task, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[taskID]
	if !ok {
		return Task{}, false, ErrNotFound
	}
	if task.Status == TaskStatusSucceeded || task.Status == TaskStatusFailed {
		return cloneTask(task), false, nil
	}
	if task.Status == TaskStatusProcessing && task.ClaimedUntil != nil && task.ClaimedUntil.After(s.now) {
		return cloneTask(task), false, nil
	}
	if task.NextAttemptAt != nil && task.NextAttemptAt.After(s.now) {
		return cloneTask(task), false, nil
	}

	claimedUntil := s.now.Add(lockFor)
	task.Status = TaskStatusProcessing
	task.ClaimedUntil = &claimedUntil
	task.UpdatedAt = s.now
	s.tasks[taskID] = task
	_, _, _ = s.deriveBatchLocked(task.BatchID)
	return cloneTask(task), true, nil
}

func (s *MemoryStore) BeginProviderAttempt(_ context.Context, taskID string) (Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, ok := s.tasks[taskID]
	if !ok {
		return Task{}, ErrNotFound
	}
	if task.Status != TaskStatusProcessing {
		return Task{}, ErrConflict
	}
	task.Attempts++
	task.UpdatedAt = s.now
	s.tasks[taskID] = task
	return cloneTask(task), nil
}

func (s *MemoryStore) ScheduleTaskRetry(_ context.Context, taskID string, delay time.Duration, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[taskID]
	if !ok {
		return ErrNotFound
	}
	nextAttemptAt := s.now.Add(delay)
	task.Status = TaskStatusQueued
	task.NextAttemptAt = &nextAttemptAt
	task.ClaimedUntil = nil
	task.Error = retryTaskError(message)
	task.UpdatedAt = s.now
	s.tasks[taskID] = task
	_, _, _ = s.deriveBatchLocked(task.BatchID)
	return nil
}

func (s *MemoryStore) CreateDLQOutbox(_ context.Context, taskID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, ok := s.tasks[taskID]
	if !ok {
		return ErrNotFound
	}
	event := DLQEvent{
		Version:       1,
		TaskID:        task.ID,
		CallerID:      task.CallerID,
		CorrelationID: task.CorrelationID,
		Reason:        reason,
	}
	value, err := marshalDLQEvent(event)
	if err != nil {
		return err
	}
	row := DLQOutboxRow{
		ID:            uuid.NewString(),
		TaskID:        task.ID,
		CallerID:      task.CallerID,
		CorrelationID: task.CorrelationID,
		Reason:        reason,
		Value:         value,
		CreatedAt:     s.now,
		UpdatedAt:     s.now,
	}
	s.dlqOutbox[row.ID] = row
	return nil
}

func (s *MemoryStore) DLQOutboxRows() []DLQOutboxRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DLQOutboxRow, 0, len(s.dlqOutbox))
	for _, row := range s.dlqOutbox {
		out = append(out, cloneDLQOutbox(row))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) || out[i].ID < out[j].ID })
	return out
}

func (s *MemoryStore) ClaimDLQOutbox(_ context.Context, limit int, lockFor time.Duration) []DLQOutboxRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		return nil
	}
	rows := make([]DLQOutboxRow, 0, len(s.dlqOutbox))
	for _, row := range s.dlqOutbox {
		if row.PublishedAt != nil {
			continue
		}
		if row.ClaimedUntil != nil && row.ClaimedUntil.After(s.now) {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt.Before(rows[j].CreatedAt) || rows[i].ID < rows[j].ID })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	claimedUntil := s.now.Add(lockFor)
	for i := range rows {
		row := s.dlqOutbox[rows[i].ID]
		row.ClaimedUntil = &claimedUntil
		row.Attempts++
		row.UpdatedAt = s.now
		s.dlqOutbox[row.ID] = row
		rows[i] = cloneDLQOutbox(row)
	}
	return rows
}

func (s *MemoryStore) MarkDLQOutboxPublished(_ context.Context, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.dlqOutbox[id]
	if !ok {
		return
	}
	now := s.now
	row.PublishedAt = &now
	row.ClaimedUntil = nil
	row.LastError = ""
	row.UpdatedAt = now
	s.dlqOutbox[id] = row
}

func (s *MemoryStore) MarkDLQOutboxFailed(_ context.Context, id, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.dlqOutbox[id]
	if !ok {
		return
	}
	row.ClaimedUntil = nil
	row.LastError = message
	row.UpdatedAt = s.now
	s.dlqOutbox[id] = row
}

func (s *MemoryStore) CleanupExpired(_ context.Context, retention time.Duration, limit int) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		return 0
	}
	cutoff := s.now.Add(-retention)
	type candidate struct {
		id string
		at time.Time
	}
	var candidates []candidate
	for id, task := range s.tasks {
		if task.TerminalAt != nil && task.TerminalAt.Before(cutoff) {
			candidates = append(candidates, candidate{id: id, at: *task.TerminalAt})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].at.Before(candidates[j].at) })

	deleted := 0
	for _, c := range candidates {
		if deleted >= limit {
			break
		}
		task := s.tasks[c.id]
		delete(s.tasks, c.id)
		for outboxID, row := range s.outbox {
			if row.TaskID == c.id {
				delete(s.outbox, outboxID)
			}
		}
		for dlqID, row := range s.dlqOutbox {
			if row.TaskID == c.id {
				delete(s.dlqOutbox, dlqID)
			}
		}
		deletedWebhookIDs := map[string]struct{}{}
		for webhookID, row := range s.webhookRows {
			if row.ResourceType == "task" && row.ResourceID == c.id {
				deletedWebhookIDs[webhookID] = struct{}{}
				delete(s.webhookRows, webhookID)
			}
		}
		for key, rec := range s.idem {
			if rec.resourceID == c.id {
				delete(s.idem, key)
			}
		}
		if task.BatchID != "" {
			s.removeBatchTaskLocked(task.BatchID, task.ID)
			_, _, _ = s.deriveBatchLocked(task.BatchID)
			if len(s.batchTasks[task.BatchID]) == 0 {
				for webhookID, row := range s.webhookRows {
					if row.ResourceType == "batch" && row.ResourceID == task.BatchID {
						deletedWebhookIDs[webhookID] = struct{}{}
						delete(s.webhookRows, webhookID)
					}
				}
				for key, rec := range s.idem {
					if rec.resourceID == task.BatchID {
						delete(s.idem, key)
					}
				}
				delete(s.batchTasks, task.BatchID)
				delete(s.batches, task.BatchID)
			}
		}
		if len(deletedWebhookIDs) > 0 {
			keptDeliveries := s.deliveries[:0]
			for _, delivery := range s.deliveries {
				if _, deletedWebhook := deletedWebhookIDs[delivery.WebhookID]; deletedWebhook {
					continue
				}
				keptDeliveries = append(keptDeliveries, delivery)
			}
			s.deliveries = keptDeliveries
		}
		deleted++
	}
	return deleted
}

func (s *MemoryStore) newTaskLocked(callerID, batchID string, input auditplatform.ModerationInput, webhookURL string) Task {
	task := Task{
		ID:            uuid.NewString(),
		CallerID:      callerID,
		BatchID:       batchID,
		ClientItemID:  input.ClientItemID,
		ContentType:   input.ContentType,
		Policy:        input.Policy,
		Status:        TaskStatusQueued,
		CreatedAt:     s.now,
		UpdatedAt:     s.now,
		CorrelationID: uuid.NewString(),
		WebhookURL:    webhookURL,
	}
	if text := input.Text; text != "" {
		value := text
		task.Text = &value
	}
	if imageURL := input.ImageURL; imageURL != "" {
		value := imageURL
		task.ImageURL = &value
	}
	return task
}

func (s *MemoryStore) tasksForBatchLocked(batchID string) []Task {
	ids := s.batchTasks[batchID]
	out := make([]Task, 0, len(ids))
	for _, id := range ids {
		if task, ok := s.tasks[id]; ok {
			out = append(out, cloneTask(task))
		}
	}
	return out
}

func (s *MemoryStore) deriveBatchLocked(batchID string) (WebhookOutboxRow, bool, error) {
	if batchID == "" {
		return WebhookOutboxRow{}, false, nil
	}
	batch, ok := s.batches[batchID]
	if !ok {
		return WebhookOutboxRow{}, false, nil
	}
	wasTerminal := batch.TerminalAt != nil
	batch.Queued, batch.Processing, batch.Succeeded, batch.Failed = 0, 0, 0, 0
	for _, taskID := range s.batchTasks[batchID] {
		switch s.tasks[taskID].Status {
		case TaskStatusQueued:
			batch.Queued++
		case TaskStatusProcessing:
			batch.Processing++
		case TaskStatusSucceeded:
			batch.Succeeded++
		case TaskStatusFailed:
			batch.Failed++
		}
	}
	switch {
	case batch.Failed == 0 && batch.Succeeded == batch.Total:
		batch.Status = BatchStatusCompleted
	case batch.Succeeded == 0 && batch.Failed == batch.Total:
		batch.Status = BatchStatusFailed
	case batch.Succeeded+batch.Failed == batch.Total:
		batch.Status = BatchStatusPartiallyFailed
	case batch.Processing > 0 || batch.Succeeded > 0 || batch.Failed > 0:
		batch.Status = BatchStatusProcessing
	default:
		batch.Status = BatchStatusQueued
	}
	now := s.now
	batch.UpdatedAt = now
	if batch.Status == BatchStatusCompleted || batch.Status == BatchStatusFailed || batch.Status == BatchStatusPartiallyFailed {
		batch.TerminalAt = &now
	}
	var webhookRow WebhookOutboxRow
	hasWebhookRow := false
	if !wasTerminal && batch.TerminalAt != nil {
		row, ok, err := s.webhookRowForTerminalBatchLocked(batch)
		if err != nil {
			return WebhookOutboxRow{}, false, err
		}
		webhookRow = row
		hasWebhookRow = ok
	}
	s.batches[batchID] = batch
	return webhookRow, hasWebhookRow, nil
}

func (s *MemoryStore) webhookRowForTerminalTaskLocked(task Task) (WebhookOutboxRow, bool, error) {
	if task.WebhookURL == "" {
		return WebhookOutboxRow{}, false, nil
	}
	endpoint, ok := s.webhooks[webhookKey(task.CallerID, task.WebhookURL)]
	if !ok {
		return WebhookOutboxRow{}, false, nil
	}
	eventID := uuid.NewString()
	body, err := marshalTaskWebhookEvent(eventID, task)
	if err != nil {
		return WebhookOutboxRow{}, false, err
	}
	row := WebhookOutboxRow{
		ID:             eventID,
		CallerID:       task.CallerID,
		ResourceType:   "task",
		ResourceID:     task.ID,
		DestinationURL: endpoint.URL,
		SecretID:       endpoint.SecretID,
		RawBody:        body,
		NextAttemptAt:  s.now,
		CreatedAt:      s.now,
		UpdatedAt:      s.now,
	}
	return row, true, nil
}

func (s *MemoryStore) webhookRowForTerminalBatchLocked(batch Batch) (WebhookOutboxRow, bool, error) {
	if batch.WebhookURL == "" {
		return WebhookOutboxRow{}, false, nil
	}
	endpoint, ok := s.webhooks[webhookKey(batch.CallerID, batch.WebhookURL)]
	if !ok {
		return WebhookOutboxRow{}, false, nil
	}
	eventID := uuid.NewString()
	body, err := marshalBatchWebhookEvent(eventID, batch)
	if err != nil {
		return WebhookOutboxRow{}, false, err
	}
	row := WebhookOutboxRow{
		ID:             eventID,
		CallerID:       batch.CallerID,
		ResourceType:   "batch",
		ResourceID:     batch.ID,
		DestinationURL: endpoint.URL,
		SecretID:       endpoint.SecretID,
		RawBody:        body,
		NextAttemptAt:  s.now,
		CreatedAt:      s.now,
		UpdatedAt:      s.now,
	}
	return row, true, nil
}

func (s *MemoryStore) webhookAllowedLocked(callerID, destinationURL string) bool {
	if err := validateWebhookURL(destinationURL); err != nil {
		return false
	}
	_, ok := s.webhooks[webhookKey(callerID, destinationURL)]
	return ok
}

func (s *MemoryStore) WebhookSecret(callerID, destinationURL string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	endpoint, ok := s.webhooks[webhookKey(callerID, destinationURL)]
	if !ok {
		return "", false
	}
	return endpoint.secret, true
}

func (s *MemoryStore) webhookSecret(callerID, destinationURL string) (string, bool) {
	return s.WebhookSecret(callerID, destinationURL)
}

func (s *MemoryStore) removeBatchTaskLocked(batchID, taskID string) {
	ids := s.batchTasks[batchID]
	for i, id := range ids {
		if id == taskID {
			s.batchTasks[batchID] = append(ids[:i], ids[i+1:]...)
			return
		}
	}
}

func idemKey(callerID, operation, key string) string {
	return callerID + "\x00" + operation + "\x00" + key
}

func webhookKey(callerID, url string) string {
	return callerID + "\x00" + url
}

func taskOutboxFromTask(task Task, now time.Time) TaskOutboxRow {
	return TaskOutboxRow{
		ID:            uuid.NewString(),
		TaskID:        task.ID,
		CallerID:      task.CallerID,
		BatchID:       task.BatchID,
		ClientItemID:  task.ClientItemID,
		ContentType:   task.ContentType,
		Policy:        task.Policy,
		CorrelationID: task.CorrelationID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func cloneTask(task Task) Task {
	if task.Text != nil {
		value := *task.Text
		task.Text = &value
	}
	if task.ImageURL != nil {
		value := *task.ImageURL
		task.ImageURL = &value
	}
	if task.Result != nil {
		value := *task.Result
		task.Result = &value
	}
	if task.Error != nil {
		value := *task.Error
		task.Error = &value
	}
	if task.NextAttemptAt != nil {
		value := *task.NextAttemptAt
		task.NextAttemptAt = &value
	}
	if task.ClaimedUntil != nil {
		value := *task.ClaimedUntil
		task.ClaimedUntil = &value
	}
	if task.TerminalAt != nil {
		value := *task.TerminalAt
		task.TerminalAt = &value
	}
	return task
}

func cloneBatch(batch Batch) Batch {
	if batch.TerminalAt != nil {
		value := *batch.TerminalAt
		batch.TerminalAt = &value
	}
	return batch
}

func cloneOutbox(row TaskOutboxRow) TaskOutboxRow {
	if row.ClaimedUntil != nil {
		value := *row.ClaimedUntil
		row.ClaimedUntil = &value
	}
	if row.PublishedAt != nil {
		value := *row.PublishedAt
		row.PublishedAt = &value
	}
	return row
}

func cloneWebhookOutbox(row WebhookOutboxRow) WebhookOutboxRow {
	row.RawBody = append([]byte(nil), row.RawBody...)
	if row.DeliveredAt != nil {
		value := *row.DeliveredAt
		row.DeliveredAt = &value
	}
	if row.ClaimedUntil != nil {
		value := *row.ClaimedUntil
		row.ClaimedUntil = &value
	}
	return row
}

func cloneDLQOutbox(row DLQOutboxRow) DLQOutboxRow {
	row.Value = append([]byte(nil), row.Value...)
	if row.ClaimedUntil != nil {
		value := *row.ClaimedUntil
		row.ClaimedUntil = &value
	}
	if row.PublishedAt != nil {
		value := *row.PublishedAt
		row.PublishedAt = &value
	}
	return row
}

package moderation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
	"github.com/google/uuid"
)

type PostgresStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewPostgresStore(db *sql.DB, now func() time.Time) *PostgresStore {
	if now == nil {
		now = time.Now
	}
	return &PostgresStore{db: db, now: now}
}

func (s *PostgresStore) Now() time.Time {
	return s.now()
}

func (s *PostgresStore) ApplyMigrations(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessDone(tx, &err)
	for _, migration := range PostgresMigrations() {
		if _, err = tx.ExecContext(ctx, migration.SQL); err != nil {
			return fmt.Errorf("apply migration %d %s: %w", migration.Version, migration.Name, err)
		}
	}
	err = tx.Commit()
	return err
}

func (s *PostgresStore) CreateTask(ctx context.Context, req CreateTaskRequest) (Task, bool, error) {
	if err := req.Input.Validate(); err != nil {
		return Task{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Task{}, false, err
	}
	defer rollbackUnlessDone(tx, &err)

	task, replayed, err := s.createTaskTx(ctx, tx, req)
	if err != nil {
		return Task{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Task{}, false, err
	}
	return task, replayed, nil
}

func (s *PostgresStore) createTaskTx(ctx context.Context, tx *sql.Tx, req CreateTaskRequest) (Task, bool, error) {
	var payloadHash, resourceType, resourceID string
	err := tx.QueryRowContext(ctx, `
select payload_hash, resource_type, resource_id
from moderation_idempotency_keys
where caller_id = $1 and operation = $2 and idempotency_key = $3
for update`, req.CallerID, req.Operation, req.IdempotencyKey).Scan(&payloadHash, &resourceType, &resourceID)
	if err == nil {
		if payloadHash != req.PayloadHash {
			return Task{}, false, ErrIdempotencyConflict
		}
		task := Task{ID: resourceID, CallerID: req.CallerID, Status: TaskStatusQueued}
		return task, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Task{}, false, err
	}
	if req.WebhookURL != "" {
		if err := s.requireWebhookEndpointTx(ctx, tx, req.CallerID, req.WebhookURL); err != nil {
			return Task{}, false, err
		}
	}

	now := s.now()
	task := Task{
		ID:            uuid.NewString(),
		CallerID:      req.CallerID,
		ClientItemID:  req.Input.ClientItemID,
		ContentType:   req.Input.ContentType,
		Policy:        req.Input.Policy,
		Status:        TaskStatusQueued,
		CreatedAt:     now,
		UpdatedAt:     now,
		CorrelationID: uuid.NewString(),
		WebhookURL:    req.WebhookURL,
	}
	if req.Input.Text != "" {
		task.Text = &req.Input.Text
	}
	if req.Input.ImageURL != "" {
		task.ImageURL = &req.Input.ImageURL
	}
	outbox := taskOutboxFromTask(task, now)
	if _, err := tx.ExecContext(ctx, `
insert into moderation_tasks
  (id, caller_id, batch_id, client_item_id, content_type, policy, status, text_content, image_url, correlation_id, webhook_url, created_at, updated_at)
values ($1,$2,null,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,
		task.ID, task.CallerID, task.ClientItemID, task.ContentType, task.Policy, task.Status, nullableString(task.Text), nullableString(task.ImageURL), task.CorrelationID, nullablePlainString(task.WebhookURL), now); err != nil {
		return Task{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
insert into moderation_task_outbox
  (id, task_id, caller_id, batch_id, client_item_id, content_type, policy, correlation_id, created_at, updated_at)
values ($1,$2,$3,null,$4,$5,$6,$7,$8,$8)`,
		outbox.ID, outbox.TaskID, outbox.CallerID, outbox.ClientItemID, outbox.ContentType, outbox.Policy, outbox.CorrelationID, now); err != nil {
		return Task{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
insert into moderation_idempotency_keys
  (caller_id, operation, idempotency_key, payload_hash, resource_type, resource_id, created_at)
values ($1,$2,$3,$4,'task',$5,$6)`,
		req.CallerID, req.Operation, req.IdempotencyKey, req.PayloadHash, task.ID, now); err != nil {
		return Task{}, false, err
	}
	return task, false, nil
}

func (s *PostgresStore) CreateBatch(ctx context.Context, req CreateBatchRequest) (Batch, []Task, bool, error) {
	if len(req.Inputs) < 1 || len(req.Inputs) > 100 {
		return Batch{}, nil, false, fmt.Errorf("batch size must be 1-100")
	}
	for _, input := range req.Inputs {
		if err := input.Validate(); err != nil {
			return Batch{}, nil, false, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Batch{}, nil, false, err
	}
	defer rollbackUnlessDone(tx, &err)

	var payloadHash, resourceType, resourceID string
	err = tx.QueryRowContext(ctx, `
select payload_hash, resource_type, resource_id
from moderation_idempotency_keys
where caller_id = $1 and operation = $2 and idempotency_key = $3
for update`, req.CallerID, req.Operation, req.IdempotencyKey).Scan(&payloadHash, &resourceType, &resourceID)
	if err == nil {
		if payloadHash != req.PayloadHash {
			return Batch{}, nil, false, ErrIdempotencyConflict
		}
		if err = tx.Commit(); err != nil {
			return Batch{}, nil, false, err
		}
		return Batch{ID: resourceID, CallerID: req.CallerID}, nil, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Batch{}, nil, false, err
	}
	if req.WebhookURL != "" {
		if err = s.requireWebhookEndpointTx(ctx, tx, req.CallerID, req.WebhookURL); err != nil {
			return Batch{}, nil, false, err
		}
	}

	now := s.now()
	batch := Batch{ID: uuid.NewString(), CallerID: req.CallerID, Status: BatchStatusQueued, Total: len(req.Inputs), Queued: len(req.Inputs), WebhookURL: req.WebhookURL, CreatedAt: now, UpdatedAt: now}
	if _, err = tx.ExecContext(ctx, `
insert into moderation_batches
  (id, caller_id, status, total_count, queued_count, processing_count, succeeded_count, failed_count, webhook_url, created_at, updated_at)
values ($1,$2,$3,$4,$4,0,0,0,$5,$6,$6)`,
		batch.ID, batch.CallerID, batch.Status, batch.Total, nullablePlainString(batch.WebhookURL), now); err != nil {
		return Batch{}, nil, false, err
	}
	tasks := make([]Task, 0, len(req.Inputs))
	for i, input := range req.Inputs {
		task := Task{ID: uuid.NewString(), CallerID: req.CallerID, BatchID: batch.ID, ClientItemID: input.ClientItemID, ContentType: input.ContentType, Policy: input.Policy, Status: TaskStatusQueued, CreatedAt: now, UpdatedAt: now, CorrelationID: uuid.NewString()}
		if input.Text != "" {
			task.Text = &input.Text
		}
		if input.ImageURL != "" {
			task.ImageURL = &input.ImageURL
		}
		outbox := taskOutboxFromTask(task, now)
		if _, err = tx.ExecContext(ctx, `
insert into moderation_tasks
  (id, caller_id, batch_id, client_item_id, content_type, policy, status, text_content, image_url, correlation_id, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,
			task.ID, task.CallerID, task.BatchID, task.ClientItemID, task.ContentType, task.Policy, task.Status, nullableString(task.Text), nullableString(task.ImageURL), task.CorrelationID, now); err != nil {
			return Batch{}, nil, false, err
		}
		if _, err = tx.ExecContext(ctx, `insert into moderation_batch_tasks (batch_id, task_id, position) values ($1,$2,$3)`, batch.ID, task.ID, i); err != nil {
			return Batch{}, nil, false, err
		}
		if _, err = tx.ExecContext(ctx, `
insert into moderation_task_outbox
  (id, task_id, caller_id, batch_id, client_item_id, content_type, policy, correlation_id, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
			outbox.ID, outbox.TaskID, outbox.CallerID, outbox.BatchID, outbox.ClientItemID, outbox.ContentType, outbox.Policy, outbox.CorrelationID, now); err != nil {
			return Batch{}, nil, false, err
		}
		tasks = append(tasks, task)
	}
	if _, err = tx.ExecContext(ctx, `
insert into moderation_idempotency_keys
  (caller_id, operation, idempotency_key, payload_hash, resource_type, resource_id, created_at)
values ($1,$2,$3,$4,'batch',$5,$6)`,
		req.CallerID, req.Operation, req.IdempotencyKey, req.PayloadHash, batch.ID, now); err != nil {
		return Batch{}, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return Batch{}, nil, false, err
	}
	return batch, tasks, false, nil
}

func (s *PostgresStore) ClaimTaskOutbox(ctx context.Context, limit int, lockFor time.Duration) []TaskOutboxRow {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil
	}
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback()
		}
	}()
	rows, err := tx.QueryContext(ctx, `
select id, task_id, caller_id, batch_id, client_item_id, content_type, policy, correlation_id, attempts, created_at, updated_at
from moderation_task_outbox
where published_at is null and (claimed_until is null or claimed_until < now())
order by created_at
limit $1
for update skip locked`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var claimed []TaskOutboxRow
	for rows.Next() {
		var row TaskOutboxRow
		var batchID sql.NullString
		if err := rows.Scan(&row.ID, &row.TaskID, &row.CallerID, &batchID, &row.ClientItemID, &row.ContentType, &row.Policy, &row.CorrelationID, &row.Attempts, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil
		}
		if batchID.Valid {
			row.BatchID = batchID.String
		}
		claimedUntil := s.now().Add(lockFor)
		if _, err := tx.ExecContext(ctx, `update moderation_task_outbox set claimed_until = $1, attempts = attempts + 1, updated_at = $2 where id = $3 and published_at is null`, claimedUntil, s.now(), row.ID); err != nil {
			return nil
		}
		row.ClaimedUntil = &claimedUntil
		claimed = append(claimed, row)
	}
	if err := rows.Err(); err != nil {
		return nil
	}
	if err := tx.Commit(); err != nil {
		return nil
	}
	ok = true
	return claimed
}

func (s *PostgresStore) MarkTaskOutboxPublished(ctx context.Context, id string) {
	_, _ = s.db.ExecContext(ctx, `update moderation_task_outbox set published_at = $1, claimed_until = null, last_error = null, updated_at = $1 where id = $2`, s.now(), id)
}

func (s *PostgresStore) MarkTaskOutboxFailed(ctx context.Context, id, message string) {
	_, _ = s.db.ExecContext(ctx, `update moderation_task_outbox set claimed_until = null, last_error = $1, updated_at = $2 where id = $3`, message, s.now(), id)
}

func (s *PostgresStore) ClaimTaskForProcessing(ctx context.Context, taskID string, lockFor time.Duration) (Task, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Task{}, false, err
	}
	defer rollbackUnlessDone(tx, &err)
	row := tx.QueryRowContext(ctx, `
select id, caller_id, coalesce(batch_id::text, ''), client_item_id, content_type, policy, coalesce(text_content, ''), coalesce(image_url, ''), attempts, correlation_id, coalesce(webhook_url, '')
from moderation_tasks
where id = $1
  and status in ('queued','processing')
  and (claimed_until is null or claimed_until < now())
  and (next_attempt_at is null or next_attempt_at <= now())
for update skip locked`, taskID)
	var task Task
	var textValue, imageURL string
	if err = row.Scan(&task.ID, &task.CallerID, &task.BatchID, &task.ClientItemID, &task.ContentType, &task.Policy, &textValue, &imageURL, &task.Attempts, &task.CorrelationID, &task.WebhookURL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Task{}, false, tx.Commit()
		}
		return Task{}, false, err
	}
	if textValue != "" {
		task.Text = &textValue
	}
	if imageURL != "" {
		task.ImageURL = &imageURL
	}
	claimedUntil := s.now().Add(lockFor)
	task.Attempts++
	task.Status = TaskStatusProcessing
	task.ClaimedUntil = &claimedUntil
	if _, err = tx.ExecContext(ctx, `update moderation_tasks set status = 'processing', attempts = attempts + 1, claimed_until = $1, updated_at = $2 where id = $3 and status in ('queued','processing')`, claimedUntil, s.now(), task.ID); err != nil {
		return Task{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Task{}, false, err
	}
	return task, true, nil
}

func (s *PostgresStore) CompleteTask(ctx context.Context, taskID string, result auditplatform.ModerationResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessDone(tx, &err)
	var task Task
	err = tx.QueryRowContext(ctx, `select id, caller_id, coalesce(batch_id::text, ''), status, coalesce(webhook_url, ''), client_item_id from moderation_tasks where id = $1 for update`, taskID).Scan(&task.ID, &task.CallerID, &task.BatchID, &task.Status, &task.WebhookURL, &task.ClientItemID)
	if err != nil {
		return err
	}
	if task.Status == TaskStatusSucceeded || task.Status == TaskStatusFailed {
		return tx.Commit()
	}
	now := s.now()
	if _, err = tx.ExecContext(ctx, `update moderation_tasks set status = 'succeeded', text_content = null, image_url = null, result_json = $1, error_json = null, claimed_until = null, next_attempt_at = null, terminal_at = $2, updated_at = $2 where id = $3`, body, now, task.ID); err != nil {
		return err
	}
	if err = s.createTerminalWebhookTx(ctx, tx, task.CallerID, "task", task.ID, task.WebhookURL, TaskStatusSucceeded); err != nil {
		return err
	}
	if task.BatchID != "" {
		if err = s.deriveBatchTx(ctx, tx, task.BatchID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) FailTask(ctx context.Context, taskID string, taskErr TaskError) error {
	return s.failTaskTxWrapper(ctx, taskID, taskErr, "")
}

func (s *PostgresStore) FailTaskWithDLQ(ctx context.Context, taskID string, taskErr TaskError, reason string) error {
	return s.failTaskTxWrapper(ctx, taskID, taskErr, reason)
}

func (s *PostgresStore) failTaskTxWrapper(ctx context.Context, taskID string, taskErr TaskError, dlqReason string) (err error) {
	body, err := json.Marshal(taskErr)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessDone(tx, &err)
	var task Task
	err = tx.QueryRowContext(ctx, `select id, caller_id, coalesce(batch_id::text, ''), status, correlation_id, coalesce(webhook_url, '') from moderation_tasks where id = $1 for update`, taskID).Scan(&task.ID, &task.CallerID, &task.BatchID, &task.Status, &task.CorrelationID, &task.WebhookURL)
	if err != nil {
		return err
	}
	if task.Status == TaskStatusSucceeded || task.Status == TaskStatusFailed {
		return tx.Commit()
	}
	now := s.now()
	if _, err = tx.ExecContext(ctx, `update moderation_tasks set status = 'failed', text_content = null, image_url = null, result_json = null, error_json = $1, claimed_until = null, next_attempt_at = null, terminal_at = $2, updated_at = $2 where id = $3`, body, now, task.ID); err != nil {
		return err
	}
	if dlqReason != "" {
		eventBody, err := marshalDLQEvent(DLQEvent{Version: 1, TaskID: task.ID, CallerID: task.CallerID, CorrelationID: task.CorrelationID, Reason: dlqReason})
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `insert into moderation_dlq_outbox (id, task_id, caller_id, correlation_id, reason, event_body, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$7)`, uuid.NewString(), task.ID, task.CallerID, task.CorrelationID, dlqReason, eventBody, now); err != nil {
			return err
		}
	}
	if err = s.createTerminalWebhookTx(ctx, tx, task.CallerID, "task", task.ID, task.WebhookURL, TaskStatusFailed); err != nil {
		return err
	}
	if task.BatchID != "" {
		if err = s.deriveBatchTx(ctx, tx, task.BatchID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) ScheduleTaskRetry(ctx context.Context, taskID string, delay time.Duration, message string) error {
	_, err := s.db.ExecContext(ctx, `update moderation_tasks set status = 'queued', next_attempt_at = $1, claimed_until = null, error_json = $2, updated_at = $3 where id = $4 and status = 'processing'`, s.now().Add(delay), []byte(fmt.Sprintf(`{"code":"provider_temporary","message":%q}`, message)), s.now(), taskID)
	return err
}

func (s *PostgresStore) RequeueDueRetries(ctx context.Context, limit int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer rollbackUnlessDone(tx, &err)
	res, err := tx.ExecContext(ctx, `
with due as (
  select id, caller_id, batch_id, client_item_id, content_type, policy, correlation_id
  from moderation_tasks
  where status = 'queued' and next_attempt_at <= now()
  order by next_attempt_at
  limit $1
  for update skip locked
), inserted as (
  insert into moderation_task_outbox (id, task_id, caller_id, batch_id, client_item_id, content_type, policy, correlation_id, created_at, updated_at)
  select gen_random_uuid(), id, caller_id, batch_id, client_item_id, content_type, policy, correlation_id, now(), now() from due
)
update moderation_tasks set next_attempt_at = null, updated_at = now() where id in (select id from due)`, limit)
	if err != nil {
		return 0, err
	}
	count, _ := res.RowsAffected()
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *PostgresStore) ClaimDLQOutbox(ctx context.Context, limit int, lockFor time.Duration) []DLQOutboxRow {
	rows, err := s.db.QueryContext(ctx, `
update moderation_dlq_outbox
set claimed_until = $1, attempts = attempts + 1, updated_at = $2
where id in (
  select id from moderation_dlq_outbox
  where published_at is null and (claimed_until is null or claimed_until < now())
  order by created_at
  limit $3
  for update skip locked
)
returning id, task_id, caller_id, correlation_id, reason, event_body, attempts, created_at, updated_at`, s.now().Add(lockFor), s.now(), limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var claimed []DLQOutboxRow
	for rows.Next() {
		var row DLQOutboxRow
		if err := rows.Scan(&row.ID, &row.TaskID, &row.CallerID, &row.CorrelationID, &row.Reason, &row.Value, &row.Attempts, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil
		}
		claimed = append(claimed, row)
	}
	return claimed
}

func (s *PostgresStore) MarkDLQOutboxPublished(ctx context.Context, id string) {
	_, _ = s.db.ExecContext(ctx, `update moderation_dlq_outbox set published_at = $1, claimed_until = null, last_error = null, updated_at = $1 where id = $2`, s.now(), id)
}

func (s *PostgresStore) MarkDLQOutboxFailed(ctx context.Context, id, message string) {
	_, _ = s.db.ExecContext(ctx, `update moderation_dlq_outbox set claimed_until = null, last_error = $1, updated_at = $2 where id = $3`, message, s.now(), id)
}

func (s *PostgresStore) RegisterWebhookEndpoint(ctx context.Context, callerID, destinationURL, secretID string) error {
	if err := validateWebhookURL(destinationURL); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `insert into moderation_webhook_endpoints (caller_id, destination_url, secret_id, created_at) values ($1,$2,$3,$4) on conflict (caller_id, destination_url) do update set secret_id = excluded.secret_id, disabled_at = null`, callerID, destinationURL, secretID, s.now())
	return err
}

func (s *PostgresStore) ClaimDueWebhooks(ctx context.Context, limit int, lockFor time.Duration) []WebhookOutboxRow {
	rows, err := s.db.QueryContext(ctx, `
update moderation_webhook_outbox
set claimed_until = $1, updated_at = $2
where id in (
  select id from moderation_webhook_outbox
  where delivered_at is null
    and attempts < 6
    and next_attempt_at <= now()
    and (claimed_until is null or claimed_until < now())
  order by next_attempt_at, created_at
  limit $3
  for update skip locked
)
returning id, caller_id, resource_type, resource_id, destination_url, secret_id, body_bytes, attempts, next_attempt_at, created_at, updated_at`, s.now().Add(lockFor), s.now(), limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var claimed []WebhookOutboxRow
	for rows.Next() {
		var row WebhookOutboxRow
		if err := rows.Scan(&row.ID, &row.CallerID, &row.ResourceType, &row.ResourceID, &row.DestinationURL, &row.SecretID, &row.RawBody, &row.Attempts, &row.NextAttemptAt, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil
		}
		claimed = append(claimed, row)
	}
	return claimed
}

func (s *PostgresStore) RecordWebhookAttempt(id string, statusCode int, attemptErr error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer rollbackUnlessDone(tx, &err)
	var attempts int
	var createdAt time.Time
	err = tx.QueryRowContext(ctx, `select attempts, created_at from moderation_webhook_outbox where id = $1 for update`, id).Scan(&attempts, &createdAt)
	if err != nil {
		return
	}
	attempts++
	errorMessage := ""
	if attemptErr != nil {
		errorMessage = attemptErr.Error()
	}
	if _, err = tx.ExecContext(ctx, `insert into moderation_webhook_deliveries (webhook_outbox_id, attempt, status_code, error, delivered_at, created_at) values ($1,$2,$3,$4,$5,$6)`, id, attempts, nullableInt(statusCode), nullablePlainString(errorMessage), deliveredAtFor(statusCode, attemptErr, s.now()), s.now()); err != nil {
		return
	}
	schedule := WebhookAttemptSchedule()
	nextAttempt := createdAt
	if attempts < len(schedule) {
		nextAttempt = createdAt.Add(schedule[attempts])
	}
	var deliveredAt sql.NullTime
	if attemptErr == nil && statusCode >= 200 && statusCode < 300 {
		deliveredAt = sql.NullTime{Time: s.now(), Valid: true}
	}
	_, err = tx.ExecContext(ctx, `update moderation_webhook_outbox set attempts = $1, claimed_until = null, next_attempt_at = $2, delivered_at = $3, last_error = $4, updated_at = $5 where id = $6`, attempts, nextAttempt, deliveredAt, nullablePlainString(errorMessage), s.now(), id)
	if err != nil {
		return
	}
	err = tx.Commit()
}

func (s *PostgresStore) WebhookSecret(string, string) (string, bool) {
	return "", false
}

func (s *PostgresStore) CleanupExpired(ctx context.Context, retention time.Duration, limit int) int {
	res, err := s.db.ExecContext(ctx, `
with old_tasks as (
  select id from moderation_tasks
  where terminal_at < $1
  order by terminal_at
  limit $2
), old_batches as (
  select b.id from moderation_batches b
  where b.terminal_at < $1
    and not exists (select 1 from moderation_tasks t where t.batch_id = b.id)
  limit $2
)
delete from moderation_tasks where id in (select id from old_tasks)`, s.now().Add(-retention), limit)
	if err != nil {
		return 0
	}
	count, _ := res.RowsAffected()
	_, _ = s.db.ExecContext(ctx, `delete from moderation_batches where terminal_at < $1 and not exists (select 1 from moderation_tasks where batch_id = moderation_batches.id)`, s.now().Add(-retention))
	_, _ = s.db.ExecContext(ctx, `delete from moderation_idempotency_keys where created_at < $1`, s.now().Add(-retention))
	_, _ = s.db.ExecContext(ctx, `delete from moderation_task_outbox where published_at < $1`, s.now().Add(-retention))
	_, _ = s.db.ExecContext(ctx, `delete from moderation_dlq_outbox where coalesce(published_at, created_at) < $1`, s.now().Add(-retention))
	_, _ = s.db.ExecContext(ctx, `delete from moderation_webhook_outbox where coalesce(delivered_at, created_at) < $1`, s.now().Add(-retention))
	return int(count)
}

func (s *PostgresStore) requireWebhookEndpointTx(ctx context.Context, tx *sql.Tx, callerID, destinationURL string) error {
	var exists int
	err := tx.QueryRowContext(ctx, `select 1 from moderation_webhook_endpoints where caller_id = $1 and destination_url = $2 and disabled_at is null`, callerID, destinationURL).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWebhookNotAllowed
	}
	return err
}

func (s *PostgresStore) createTerminalWebhookTx(ctx context.Context, tx *sql.Tx, callerID, resourceType, resourceID, destinationURL string, status interface{}) error {
	if destinationURL == "" {
		return nil
	}
	var secretID string
	if err := tx.QueryRowContext(ctx, `select secret_id from moderation_webhook_endpoints where caller_id = $1 and destination_url = $2 and disabled_at is null`, callerID, destinationURL).Scan(&secretID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWebhookNotAllowed
		}
		return err
	}
	body := []byte(fmt.Sprintf(`{"type":"%s","id":"%s","status":"%s"}`, resourceType, resourceID, status))
	_, err := tx.ExecContext(ctx, `
insert into moderation_webhook_outbox
  (id, caller_id, resource_type, resource_id, destination_url, secret_id, body_bytes, next_attempt_at, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8,$8,$8)
on conflict (resource_type, resource_id) do nothing`, uuid.NewString(), callerID, resourceType, resourceID, destinationURL, secretID, body, s.now())
	return err
}

func (s *PostgresStore) deriveBatchTx(ctx context.Context, tx *sql.Tx, batchID string) error {
	_, err := tx.ExecContext(ctx, `
with counts as (
  select
    count(*)::int as total_count,
    count(*) filter (where status = 'queued')::int as queued_count,
    count(*) filter (where status = 'processing')::int as processing_count,
    count(*) filter (where status = 'succeeded')::int as succeeded_count,
    count(*) filter (where status = 'failed')::int as failed_count
  from moderation_tasks
  where batch_id = $1
), updated as (
  update moderation_batches b
  set total_count = c.total_count,
      queued_count = c.queued_count,
      processing_count = c.processing_count,
      succeeded_count = c.succeeded_count,
      failed_count = c.failed_count,
      status = case
        when c.succeeded_count = c.total_count then 'completed'
        when c.failed_count = c.total_count then 'failed'
        when c.succeeded_count + c.failed_count = c.total_count then 'partially_failed'
        when c.processing_count > 0 or c.succeeded_count > 0 or c.failed_count > 0 then 'processing'
        else 'queued'
      end,
      terminal_at = case when c.succeeded_count + c.failed_count = c.total_count then now() else null end,
      updated_at = now()
  from counts c
  where b.id = $1
  returning b.id, b.caller_id, b.webhook_url, b.status, b.terminal_at
)
insert into moderation_webhook_outbox (id, caller_id, resource_type, resource_id, destination_url, secret_id, body_bytes, next_attempt_at, created_at, updated_at)
select gen_random_uuid(), u.caller_id, 'batch', u.id, u.webhook_url, e.secret_id,
       convert_to(format('{"type":"batch","id":"%s","status":"%s"}', u.id, u.status), 'utf8'),
       now(), now(), now()
from updated u
join moderation_webhook_endpoints e on e.caller_id = u.caller_id and e.destination_url = u.webhook_url and e.disabled_at is null
where u.terminal_at is not null and u.webhook_url is not null
on conflict (resource_type, resource_id) do nothing`, batchID)
	return err
}

func rollbackUnlessDone(tx *sql.Tx, err *error) {
	if *err != nil {
		_ = tx.Rollback()
	}
}

func nullableString(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

func nullablePlainString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func nullableInt(value int) sql.NullInt64 {
	if value == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(value), Valid: true}
}

func deliveredAtFor(statusCode int, err error, now time.Time) sql.NullTime {
	if err == nil && statusCode >= 200 && statusCode < 300 {
		return sql.NullTime{Time: now, Valid: true}
	}
	return sql.NullTime{}
}

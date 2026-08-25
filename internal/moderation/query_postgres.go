package moderation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
	"github.com/lib/pq"
)

func (s *PostgresStore) UpsertAPIClient(ctx context.Context, client APIClient) error {
	if client.ID == "" || client.TokenSHA256 == "" {
		return fmt.Errorf("client id and token digest are required")
	}
	_, err := s.db.ExecContext(ctx, `
insert into moderation_api_clients (id, name, key_hash, scopes, created_at)
values ($1,$2,$3,$4,$5)
on conflict (id) do update
set name = excluded.name,
    key_hash = excluded.key_hash,
    scopes = excluded.scopes,
    disabled_at = null`,
		client.ID, client.Name, client.TokenSHA256, pq.Array(client.Scopes), s.now())
	return err
}

func (s *PostgresStore) GetTask(ctx context.Context, callerID, taskID string) (Task, bool, error) {
	task, err := s.queryTask(ctx, `where id = $1 and caller_id = $2`, taskID, callerID)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, false, nil
	}
	if err != nil {
		return Task{}, false, err
	}
	return task, true, nil
}

func (s *PostgresStore) GetBatch(ctx context.Context, callerID, batchID string) (Batch, bool, error) {
	batch, err := s.queryBatch(ctx, `where id = $1 and caller_id = $2`, batchID, callerID)
	if errors.Is(err, sql.ErrNoRows) {
		return Batch{}, false, nil
	}
	if err != nil {
		return Batch{}, false, err
	}
	return batch, true, nil
}

func (s *PostgresStore) GetAdminTask(ctx context.Context, taskID string) (Task, bool, error) {
	task, err := s.queryTask(ctx, `where id = $1`, taskID)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, false, nil
	}
	if err != nil {
		return Task{}, false, err
	}
	return task, true, nil
}

func (s *PostgresStore) GetAdminBatch(ctx context.Context, batchID string) (Batch, bool, error) {
	batch, err := s.queryBatch(ctx, `where id = $1`, batchID)
	if errors.Is(err, sql.ErrNoRows) {
		return Batch{}, false, nil
	}
	if err != nil {
		return Batch{}, false, err
	}
	return batch, true, nil
}

func (s *PostgresStore) ListBatchItems(ctx context.Context, callerID, batchID string, cursor BatchItemCursor) (BatchItemsPage, error) {
	limit := normalizeListLimit(cursor.Limit)
	offset, err := decodePositionCursor(cursor.Cursor)
	if err != nil {
		return BatchItemsPage{}, err
	}
	var exists int
	err = s.db.QueryRowContext(ctx, `select 1 from moderation_batches where id = $1 and caller_id = $2`, batchID, callerID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return BatchItemsPage{}, ErrNotFound
	}
	if err != nil {
		return BatchItemsPage{}, err
	}
	return s.listBatchItems(ctx, batchID, offset, limit)
}

func (s *PostgresStore) listBatchItems(ctx context.Context, batchID string, offset, limit int) (BatchItemsPage, error) {
	rows, err := s.db.QueryContext(ctx, `
select t.id, t.caller_id, coalesce(t.batch_id::text, ''), t.client_item_id, t.content_type, t.policy, t.status,
       t.result_json, t.error_json, t.attempts, t.correlation_id, coalesce(t.webhook_url, ''),
       t.created_at, t.updated_at, t.terminal_at, bt.position
from moderation_batch_tasks bt
join moderation_tasks t on t.id = bt.task_id
where bt.batch_id = $1 and bt.position >= $2
order by bt.position
limit $3`, batchID, offset, limit+1)
	if err != nil {
		return BatchItemsPage{}, err
	}
	defer rows.Close()
	var items []Task
	next := ""
	for rows.Next() {
		var task Task
		var position int
		if err := scanTaskNoRaw(rows, &task, &position); err != nil {
			return BatchItemsPage{}, err
		}
		if len(items) == limit {
			next = encodePositionCursor(position)
			continue
		}
		items = append(items, task)
	}
	if err := rows.Err(); err != nil {
		return BatchItemsPage{}, err
	}
	return BatchItemsPage{Items: items, NextCursor: next}, nil
}

func (s *PostgresStore) ListAdminBatchItems(ctx context.Context, batchID string, cursor BatchItemCursor) (BatchItemsPage, error) {
	limit := normalizeListLimit(cursor.Limit)
	offset, err := decodePositionCursor(cursor.Cursor)
	if err != nil {
		return BatchItemsPage{}, err
	}
	var exists int
	err = s.db.QueryRowContext(ctx, `select 1 from moderation_batches where id = $1`, batchID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return BatchItemsPage{}, ErrNotFound
	}
	if err != nil {
		return BatchItemsPage{}, err
	}
	return s.listBatchItems(ctx, batchID, offset, limit)
}

func (s *PostgresStore) ListTasks(ctx context.Context, filter ListFilter) (TaskPage, error) {
	limit := normalizeListLimit(filter.Limit)
	cursor, err := decodeKeysetCursor(filter.Cursor)
	if err != nil {
		return TaskPage{}, err
	}
	where, args := taskFilterSQL(filter)
	where = appendTaskKeysetSQL(where, &args, cursor)
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `
select id, caller_id, coalesce(batch_id::text, ''), client_item_id, content_type, policy, status,
       result_json, error_json, attempts, correlation_id, coalesce(webhook_url, ''), created_at, updated_at, terminal_at, 0
from moderation_tasks
`+where+`
order by updated_at desc, id desc
limit $`+strconvArg(len(args)), args...)
	if err != nil {
		return TaskPage{}, err
	}
	defer rows.Close()
	var items []Task
	next := ""
	for rows.Next() {
		var task Task
		var position int
		if err := scanTaskNoRaw(rows, &task, &position); err != nil {
			return TaskPage{}, err
		}
		if len(items) == limit {
			next = encodeKeysetCursor(items[len(items)-1].UpdatedAt, items[len(items)-1].ID)
			continue
		}
		items = append(items, task)
	}
	return TaskPage{Items: items, NextCursor: next}, rows.Err()
}

func (s *PostgresStore) ListBatches(ctx context.Context, filter ListFilter) (BatchPage, error) {
	limit := normalizeListLimit(filter.Limit)
	cursor, err := decodeKeysetCursor(filter.Cursor)
	if err != nil {
		return BatchPage{}, err
	}
	where, args := batchFilterSQL(filter)
	where = appendBatchKeysetSQL(where, &args, cursor)
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `
select id, caller_id, status, total_count, queued_count, processing_count, succeeded_count, failed_count,
       coalesce(webhook_url, ''), created_at, updated_at, terminal_at, 0
from moderation_batches
`+where+`
order by updated_at desc, id desc
limit $`+strconvArg(len(args)), args...)
	if err != nil {
		return BatchPage{}, err
	}
	defer rows.Close()
	var items []Batch
	next := ""
	for rows.Next() {
		var batch Batch
		var webhook string
		var terminal sql.NullTime
		var position int
		if err := rows.Scan(&batch.ID, &batch.CallerID, &batch.Status, &batch.Total, &batch.Queued, &batch.Processing, &batch.Succeeded, &batch.Failed, &webhook, &batch.CreatedAt, &batch.UpdatedAt, &terminal, &position); err != nil {
			return BatchPage{}, err
		}
		batch.WebhookURL = webhook
		if terminal.Valid {
			batch.TerminalAt = &terminal.Time
		}
		if len(items) == limit {
			next = encodeKeysetCursor(items[len(items)-1].UpdatedAt, items[len(items)-1].ID)
			continue
		}
		items = append(items, batch)
	}
	return BatchPage{Items: items, NextCursor: next}, rows.Err()
}

func (s *PostgresStore) ListAPIClients(ctx context.Context) ([]APIClient, error) {
	rows, err := s.db.QueryContext(ctx, `select id, name, scopes, created_at, disabled_at from moderation_api_clients order by id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []APIClient
	for rows.Next() {
		var client APIClient
		var disabled sql.NullTime
		if err := rows.Scan(&client.ID, &client.Name, pq.Array(&client.Scopes), &client.CreatedAt, &disabled); err != nil {
			return nil, err
		}
		if disabled.Valid {
			client.DisabledAt = &disabled.Time
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (s *PostgresStore) AdminStats(ctx context.Context) (AdminStatsSnapshot, error) {
	stats := AdminStatsSnapshot{TaskStatusCounts: map[string]int{}, BatchStatusCounts: map[string]int{}, RiskCounts: map[string]int{}}
	var err error
	if err := scanCountRows(ctx, s.db, `select status, count(*) from moderation_tasks group by status`, stats.TaskStatusCounts); err != nil {
		return stats, err
	}
	if err := scanCountRows(ctx, s.db, `select status, count(*) from moderation_batches group by status`, stats.BatchStatusCounts); err != nil {
		return stats, err
	}
	if err := scanCountRows(ctx, s.db, `select result_json->>'risk_level', count(*) from moderation_tasks where result_json is not null group by result_json->>'risk_level'`, stats.RiskCounts); err != nil {
		return stats, err
	}
	if stats.PendingTaskOutbox, err = s.count(ctx, `select count(*) from moderation_task_outbox where published_at is null and (claimed_until is null or claimed_until < now())`); err != nil {
		return stats, err
	}
	if stats.ClaimedTaskOutbox, err = s.count(ctx, `select count(*) from moderation_task_outbox where published_at is null and claimed_until >= now()`); err != nil {
		return stats, err
	}
	if stats.PendingWebhookOutbox, err = s.count(ctx, `select count(*) from moderation_webhook_outbox where delivered_at is null and next_attempt_at <= now() and (claimed_until is null or claimed_until < now())`); err != nil {
		return stats, err
	}
	if stats.ClaimedWebhookOutbox, err = s.count(ctx, `select count(*) from moderation_webhook_outbox where delivered_at is null and claimed_until >= now()`); err != nil {
		return stats, err
	}
	if stats.PendingDLQOutbox, err = s.count(ctx, `select count(*) from moderation_dlq_outbox where published_at is null`); err != nil {
		return stats, err
	}
	if stats.PublishedDLQOutbox, err = s.count(ctx, `select count(*) from moderation_dlq_outbox where published_at is not null`); err != nil {
		return stats, err
	}
	return stats, nil
}

func (s *PostgresStore) queryTask(ctx context.Context, where string, args ...interface{}) (Task, error) {
	row := s.db.QueryRowContext(ctx, `
select id, caller_id, coalesce(batch_id::text, ''), client_item_id, content_type, policy, status,
       result_json, error_json, attempts, correlation_id, coalesce(webhook_url, ''),
       created_at, updated_at, terminal_at, 0
from moderation_tasks `+where, args...)
	var task Task
	var ignored int
	if err := scanTaskNoRaw(row, &task, &ignored); err != nil {
		return Task{}, err
	}
	return task, nil
}

func (s *PostgresStore) queryBatch(ctx context.Context, where string, args ...interface{}) (Batch, error) {
	row := s.db.QueryRowContext(ctx, `
select id, caller_id, status, total_count, queued_count, processing_count, succeeded_count, failed_count,
       coalesce(webhook_url, ''), created_at, updated_at, terminal_at
from moderation_batches `+where, args...)
	var batch Batch
	var webhook string
	var terminal sql.NullTime
	if err := row.Scan(&batch.ID, &batch.CallerID, &batch.Status, &batch.Total, &batch.Queued, &batch.Processing, &batch.Succeeded, &batch.Failed, &webhook, &batch.CreatedAt, &batch.UpdatedAt, &terminal); err != nil {
		return Batch{}, err
	}
	batch.WebhookURL = webhook
	if terminal.Valid {
		batch.TerminalAt = &terminal.Time
	}
	return batch, nil
}

type taskScanner interface {
	Scan(dest ...interface{}) error
}

func scanTaskNoRaw(row taskScanner, task *Task, position *int) error {
	var resultJSON, errorJSON []byte
	var webhook string
	var terminal sql.NullTime
	if err := row.Scan(&task.ID, &task.CallerID, &task.BatchID, &task.ClientItemID, &task.ContentType, &task.Policy, &task.Status, &resultJSON, &errorJSON, &task.Attempts, &task.CorrelationID, &webhook, &task.CreatedAt, &task.UpdatedAt, &terminal, position); err != nil {
		return err
	}
	task.WebhookURL = webhook
	if terminal.Valid {
		task.TerminalAt = &terminal.Time
	}
	if len(resultJSON) > 0 {
		var result auditplatform.ModerationResult
		if err := json.Unmarshal(resultJSON, &result); err != nil {
			return err
		}
		task.Result = &result
	}
	if len(errorJSON) > 0 {
		var taskErr TaskError
		if err := json.Unmarshal(errorJSON, &taskErr); err != nil {
			return err
		}
		task.Error = &taskErr
	}
	return nil
}

func taskFilterSQL(filter ListFilter) (string, []interface{}) {
	var clauses []string
	var args []interface{}
	add := func(sql string, value interface{}) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(sql, len(args)))
	}
	if filter.CallerID != "" {
		add("caller_id = $%d", filter.CallerID)
	}
	if filter.ContentType != "" {
		add("content_type = $%d", filter.ContentType)
	}
	if filter.TaskStatus != "" {
		add("status = $%d", filter.TaskStatus)
	}
	if filter.Policy != "" {
		add("policy = $%d", filter.Policy)
	}
	if filter.RiskLevel != "" {
		add("result_json->>'risk_level' = $%d", filter.RiskLevel)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "where " + strings.Join(clauses, " and "), args
}

func batchFilterSQL(filter ListFilter) (string, []interface{}) {
	var clauses []string
	var args []interface{}
	add := func(sql string, value interface{}) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(sql, len(args)))
	}
	var taskClauses []string
	addTask := func(sql string, value interface{}) {
		args = append(args, value)
		taskClauses = append(taskClauses, fmt.Sprintf(sql, len(args)))
	}
	if filter.CallerID != "" {
		add("caller_id = $%d", filter.CallerID)
	}
	if filter.BatchStatus != "" {
		add("status = $%d", filter.BatchStatus)
	}
	if filter.ContentType != "" {
		addTask("t.content_type = $%d", filter.ContentType)
	}
	if filter.TaskStatus != "" {
		addTask("t.status = $%d", filter.TaskStatus)
	}
	if filter.Policy != "" {
		addTask("t.policy = $%d", filter.Policy)
	}
	if filter.RiskLevel != "" {
		addTask("t.result_json->>'risk_level' = $%d", filter.RiskLevel)
	}
	if len(taskClauses) > 0 {
		clauses = append(clauses, "exists (select 1 from moderation_tasks t where t.batch_id = moderation_batches.id and "+strings.Join(taskClauses, " and ")+")")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "where " + strings.Join(clauses, " and "), args
}

func appendTaskKeysetSQL(where string, args *[]interface{}, cursor *keysetCursor) string {
	if cursor == nil {
		return where
	}
	*args = append(*args, cursor.UpdatedAt, cursor.ID)
	clause := fmt.Sprintf("(updated_at, id) < ($%d, $%d)", len(*args)-1, len(*args))
	return appendWhereClause(where, clause)
}

func appendBatchKeysetSQL(where string, args *[]interface{}, cursor *keysetCursor) string {
	if cursor == nil {
		return where
	}
	*args = append(*args, cursor.UpdatedAt, cursor.ID)
	clause := fmt.Sprintf("(updated_at, id) < ($%d, $%d)", len(*args)-1, len(*args))
	return appendWhereClause(where, clause)
}

func appendWhereClause(where, clause string) string {
	if where == "" {
		return "where " + clause
	}
	return where + " and " + clause
}

func (s *PostgresStore) count(ctx context.Context, query string, args ...interface{}) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func scanCountRows(ctx context.Context, db *sql.DB, query string, target map[string]int) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return err
		}
		target[key] = count
	}
	return rows.Err()
}

func strconvArg(index int) string {
	return fmt.Sprintf("%d", index)
}

var _ = time.Time{}

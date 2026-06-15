package kafka

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/sarama"
	"github.com/Xushengqwer/go-common/core"
	"github.com/Xushengqwer/go-common/models/kafkaevents"
	"go.uber.org/zap"
)

type AuditTaskRecord struct {
	ID                string
	EnvironmentKey    string
	Status            string
	OriginalID        string
	ProviderTaskID    string
	Suggestion        string
	ContentSummary    string
	FailureReason     string
	OriginalTopic     string
	OriginalPartition int32
	OriginalOffset    int64
	ResultTopic       string
	ResultPartition   int32
	ResultOffset      int64
}

type AuditRecorder interface {
	RecordPending(context.Context, AuditTaskRecord) error
	RecordResult(context.Context, AuditTaskRecord) error
	RecordDLQ(context.Context, AuditTaskRecord) error
}

type NopAuditRecorder struct{}

func (NopAuditRecorder) RecordPending(context.Context, AuditTaskRecord) error { return nil }
func (NopAuditRecorder) RecordResult(context.Context, AuditTaskRecord) error  { return nil }
func (NopAuditRecorder) RecordDLQ(context.Context, AuditTaskRecord) error     { return nil }

type PostgresAuditRecorder struct {
	db             *sql.DB
	environmentKey string
	logger         *core.ZapLogger
}

func NewPostgresAuditRecorder(db *sql.DB, environmentKey string, logger *core.ZapLogger) *PostgresAuditRecorder {
	return &PostgresAuditRecorder{db: db, environmentKey: environmentKey, logger: logger}
}

func (recorder *PostgresAuditRecorder) RecordPending(ctx context.Context, record AuditTaskRecord) error {
	record.Status = firstNonEmpty(record.Status, "pending")
	return recorder.upsert(ctx, record)
}

func (recorder *PostgresAuditRecorder) RecordResult(ctx context.Context, record AuditTaskRecord) error {
	return recorder.upsert(ctx, record)
}

func (recorder *PostgresAuditRecorder) RecordDLQ(ctx context.Context, record AuditTaskRecord) error {
	record.Status = firstNonEmpty(record.Status, "failed")
	return recorder.upsert(ctx, record)
}

func (recorder *PostgresAuditRecorder) upsert(ctx context.Context, record AuditTaskRecord) error {
	if recorder == nil || recorder.db == nil {
		return nil
	}
	if record.EnvironmentKey == "" {
		record.EnvironmentKey = recorder.environmentKey
	}
	if record.ID == "" {
		record.ID = record.EnvironmentKey + ":" + record.OriginalID
	}
	_, err := recorder.db.ExecContext(ctx, `
INSERT INTO audit_tasks (
  id, environment_key, status, original_id, provider_task_id, suggestion, content_summary, failure_reason,
  original_topic, original_partition, original_offset, result_topic, result_partition, result_offset, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now())
ON CONFLICT (id) DO UPDATE SET
  status = EXCLUDED.status,
  provider_task_id = COALESCE(NULLIF(EXCLUDED.provider_task_id, ''), audit_tasks.provider_task_id),
  suggestion = COALESCE(NULLIF(EXCLUDED.suggestion, ''), audit_tasks.suggestion),
  content_summary = COALESCE(NULLIF(EXCLUDED.content_summary, ''), audit_tasks.content_summary),
  failure_reason = COALESCE(NULLIF(EXCLUDED.failure_reason, ''), audit_tasks.failure_reason),
  result_topic = COALESCE(NULLIF(EXCLUDED.result_topic, ''), audit_tasks.result_topic),
  result_partition = EXCLUDED.result_partition,
  result_offset = EXCLUDED.result_offset,
  updated_at = now()`,
		record.ID, record.EnvironmentKey, record.Status, record.OriginalID, record.ProviderTaskID, record.Suggestion, record.ContentSummary, record.FailureReason,
		record.OriginalTopic, record.OriginalPartition, record.OriginalOffset, record.ResultTopic, record.ResultPartition, record.ResultOffset)
	if err != nil && recorder.logger != nil {
		recorder.logger.Error("record audit task failed", zap.Error(err), zap.String("task_id", record.ID))
	}
	return err
}

func pendingRecord(environmentKey string, message *sarama.ConsumerMessage, post kafkaevents.PostData) AuditTaskRecord {
	return AuditTaskRecord{
		ID:                auditTaskID(environmentKey, auditPostIDString(post.ID)),
		EnvironmentKey:    environmentKey,
		Status:            "pending",
		OriginalID:        auditPostIDString(post.ID),
		ContentSummary:    contentSummary(post),
		OriginalTopic:     message.Topic,
		OriginalPartition: message.Partition,
		OriginalOffset:    message.Offset,
	}
}

func auditPostIDString(id uint64) string {
	return strconv.FormatUint(id, 10)
}

func resultRecord(environmentKey string, message *sarama.ConsumerMessage, result ProcessedAuditResult) AuditTaskRecord {
	record := AuditTaskRecord{
		ID:                auditTaskID(environmentKey, result.OriginalDataID),
		EnvironmentKey:    environmentKey,
		OriginalID:        result.OriginalDataID,
		OriginalTopic:     message.Topic,
		OriginalPartition: message.Partition,
		OriginalOffset:    message.Offset,
	}
	if result.Error != nil {
		record.Status = "failed"
		record.FailureReason = result.Error.Error()
		return record
	}
	if result.ApprovedEvent != nil {
		record.Status = "approved"
		record.Suggestion = "pass"
		return record
	}
	if result.RejectedEvent != nil {
		record.Status = "rejected"
		record.Suggestion = "block"
		return record
	}
	record.Status = "processed"
	return record
}

func dlqRecord(environmentKey string, message *sarama.ConsumerMessage, reason string) AuditTaskRecord {
	originalID := fmt.Sprintf("%s:%d:%d", message.Topic, message.Partition, message.Offset)
	return AuditTaskRecord{
		ID:                auditTaskID(environmentKey, originalID),
		EnvironmentKey:    environmentKey,
		Status:            "failed",
		OriginalID:        originalID,
		FailureReason:     reason,
		OriginalTopic:     message.Topic,
		OriginalPartition: message.Partition,
		OriginalOffset:    message.Offset,
	}
}

func auditTaskID(environmentKey string, originalID string) string {
	return firstNonEmpty(environmentKey, "default") + ":" + originalID
}

func contentSummary(post kafkaevents.PostData) string {
	value := strings.TrimSpace(post.Title + "\n" + post.Content)
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func recordAuditFailure(logger *core.ZapLogger, operation string, err error) {
	if err == nil || logger == nil {
		return
	}
	logger.Warn("audit task recorder failed", zap.String("operation", operation), zap.Error(err), zap.Time("at", time.Now()))
}

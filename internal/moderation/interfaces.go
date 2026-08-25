package moderation

import (
	"context"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

type Clock interface {
	Now() time.Time
}

type WorkerStore interface {
	Clock
	ClaimTaskForProcessing(ctx context.Context, taskID string, lockFor time.Duration) (Task, bool, error)
	CompleteTask(ctx context.Context, taskID string, result auditplatform.ModerationResult) error
	ScheduleTaskRetry(ctx context.Context, taskID string, delay time.Duration, message string) error
	FailTaskWithDLQ(ctx context.Context, taskID string, taskErr TaskError, reason string) error
}

type TaskOutboxStore interface {
	ClaimTaskOutbox(ctx context.Context, limit int, lockFor time.Duration) []TaskOutboxRow
	MarkTaskOutboxPublished(ctx context.Context, id string)
	MarkTaskOutboxFailed(ctx context.Context, id, message string)
}

type RetryStore interface {
	RequeueDueRetries(ctx context.Context, limit int) (int, error)
}

type DLQOutboxStore interface {
	ClaimDLQOutbox(ctx context.Context, limit int, lockFor time.Duration) []DLQOutboxRow
	MarkDLQOutboxPublished(ctx context.Context, id string)
	MarkDLQOutboxFailed(ctx context.Context, id, message string)
}

type WebhookStore interface {
	Clock
	ClaimDueWebhooks(ctx context.Context, limit int, lockFor time.Duration) []WebhookOutboxRow
	RecordWebhookAttempt(id string, statusCode int, attemptErr error)
}

type SecretResolver interface {
	WebhookSecret(callerID, destinationURL string) (string, bool)
}

type ProviderBudget interface {
	AcquireAsyncProvider(ctx context.Context) (LimitOutcome, error)
}

type allowAllProviderBudget struct{}

func (allowAllProviderBudget) AcquireAsyncProvider(context.Context) (LimitOutcome, error) {
	return LimitOutcome{Allowed: true}, nil
}

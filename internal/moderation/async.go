package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

const (
	TopicModerationTasksV1    = "moderation_tasks_v1"
	TopicModerationTaskDLQ    = "moderation_tasks_dlq_v1"
	ModerationTopicPartitions = int32(12)
)

var RetryDelays = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}

type TaskEvent struct {
	Version       int                       `json:"version"`
	TaskID        string                    `json:"task_id"`
	CallerID      string                    `json:"caller_id"`
	BatchID       string                    `json:"batch_id,omitempty"`
	ClientItemID  string                    `json:"client_item_id"`
	ContentType   auditplatform.ContentType `json:"content_type"`
	Policy        auditplatform.Policy      `json:"policy"`
	CorrelationID string                    `json:"correlation_id"`
}

type DLQEvent struct {
	Version       int    `json:"version"`
	TaskID        string `json:"task_id"`
	CallerID      string `json:"caller_id"`
	CorrelationID string `json:"correlation_id"`
	Reason        string `json:"reason"`
	Value         []byte `json:"-"`
}

type Publisher interface {
	Publish(ctx context.Context, topic, key string, value []byte) error
}

type DLQSender interface {
	SendDLQ(ctx context.Context, event DLQEvent) error
}

func TaskEventFromTask(task Task) TaskEvent {
	return TaskEvent{
		Version:       1,
		TaskID:        task.ID,
		CallerID:      task.CallerID,
		BatchID:       task.BatchID,
		ClientItemID:  task.ClientItemID,
		ContentType:   task.ContentType,
		Policy:        task.Policy,
		CorrelationID: task.CorrelationID,
	}
}

func MarshalTaskEvent(event TaskEvent) ([]byte, error) {
	if event.Version == 0 {
		event.Version = 1
	}
	return json.Marshal(event)
}

func PublishTaskOutbox(ctx context.Context, store TaskOutboxStore, publisher Publisher, limit int, lockFor time.Duration) error {
	rows := store.ClaimTaskOutbox(ctx, limit, lockFor)
	var firstErr error
	for _, row := range rows {
		value, err := MarshalTaskEvent(TaskEvent{
			Version:       1,
			TaskID:        row.TaskID,
			CallerID:      row.CallerID,
			BatchID:       row.BatchID,
			ClientItemID:  row.ClientItemID,
			ContentType:   row.ContentType,
			Policy:        row.Policy,
			CorrelationID: row.CorrelationID,
		})
		if err == nil {
			err = publisher.Publish(ctx, TopicModerationTasksV1, row.TaskID, value)
		}
		if err != nil {
			store.MarkTaskOutboxFailed(ctx, row.ID, err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		store.MarkTaskOutboxPublished(ctx, row.ID)
	}
	return firstErr
}

type Worker struct {
	store          WorkerStore
	provider       auditplatform.Provider
	providerBudget ProviderBudget
	claimFor       time.Duration
}

func NewWorker(store *MemoryStore, provider auditplatform.Provider, dlq DLQSender) *Worker {
	_ = dlq
	return NewWorkerWithOptions(WorkerOptions{Store: store, Provider: provider, ClaimFor: 30 * time.Second})
}

type WorkerOptions struct {
	Store          WorkerStore
	Provider       auditplatform.Provider
	DLQ            DLQOutboxStore
	ProviderBudget ProviderBudget
	ClaimFor       time.Duration
}

func NewWorkerWithOptions(options WorkerOptions) *Worker {
	claimFor := options.ClaimFor
	if claimFor <= 0 {
		claimFor = 30 * time.Second
	}
	budget := options.ProviderBudget
	if budget == nil {
		budget = allowAllProviderBudget{}
	}
	return &Worker{store: options.Store, provider: options.Provider, providerBudget: budget, claimFor: claimFor}
}

func (w *Worker) ProcessTaskEvent(ctx context.Context, event TaskEvent) error {
	task, claimed, err := w.store.ClaimTaskForProcessing(ctx, event.TaskID, w.claimFor)
	if err != nil || !claimed {
		return err
	}

	outcome, budgetErr := w.providerBudget.AcquireAsyncProvider(ctx)
	if budgetErr != nil || !outcome.Allowed {
		code := "rate_limited"
		message := string(outcome.Reason)
		if budgetErr != nil {
			code = "rate_limiter_unavailable"
			message = budgetErr.Error()
		}
		return w.store.ScheduleTaskRetry(ctx, task.ID, retryDelayForAttempt(task.Attempts), messageWithCode(code, message))
	}

	input, err := inputFromTask(task)
	if err != nil {
		return w.failAndDLQ(ctx, task, TaskError{Code: auditplatform.ErrorCodeInvalidInput, Message: err.Error()}, "missing_input")
	}
	result, err := w.provider.Moderate(ctx, input)
	if err == nil {
		return w.store.CompleteTask(ctx, task.ID, result)
	}

	var providerErr *auditplatform.ProviderError
	if errors.As(err, &providerErr) && providerErr.Retryable && task.Attempts < 5 {
		return w.store.ScheduleTaskRetry(ctx, task.ID, retryDelayForAttempt(task.Attempts), providerErr.Error())
	}
	taskErr := TaskError{Code: auditplatform.ErrorCodeProviderResponse, Message: err.Error()}
	if providerErr != nil {
		taskErr.Code = providerErr.Code
	}
	return w.failAndDLQ(ctx, task, taskErr, "provider_failure")
}

func (w *Worker) failAndDLQ(ctx context.Context, task Task, taskErr TaskError, reason string) error {
	return w.store.FailTaskWithDLQ(ctx, task.ID, taskErr, reason)
}

func retryDelayForAttempt(attempt int) time.Duration {
	if attempt <= 0 {
		return RetryDelays[0]
	}
	index := attempt - 1
	if index >= len(RetryDelays) {
		return RetryDelays[len(RetryDelays)-1]
	}
	return RetryDelays[index]
}

func messageWithCode(code, message string) string {
	if message == "" {
		return code
	}
	return code + ": " + message
}

func RequeueDueRetries(ctx context.Context, store RetryStore, limit int) (int, error) {
	return store.RequeueDueRetries(ctx, limit)
}

func PublishDLQOutbox(ctx context.Context, store DLQOutboxStore, publisher Publisher, limit int, lockFor time.Duration) error {
	rows := store.ClaimDLQOutbox(ctx, limit, lockFor)
	var firstErr error
	for _, row := range rows {
		if err := publisher.Publish(ctx, TopicModerationTaskDLQ, row.TaskID, row.Value); err != nil {
			store.MarkDLQOutboxFailed(ctx, row.ID, err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		store.MarkDLQOutboxPublished(ctx, row.ID)
	}
	return firstErr
}

func marshalDLQEvent(event DLQEvent) ([]byte, error) {
	if event.Version == 0 {
		event.Version = 1
	}
	return json.Marshal(event)
}

func inputFromTask(task Task) (auditplatform.ModerationInput, error) {
	input := auditplatform.ModerationInput{
		ClientItemID: task.ClientItemID,
		ContentType:  task.ContentType,
		Policy:       task.Policy,
	}
	if task.Text != nil {
		input.Text = *task.Text
	}
	if task.ImageURL != nil {
		input.ImageURL = *task.ImageURL
	}
	if input.Text == "" && input.ImageURL == "" {
		return auditplatform.ModerationInput{}, fmt.Errorf("raw task input is unavailable")
	}
	return input, nil
}

type TopicAdmin interface {
	Partitions(topic string) (int32, bool, error)
	CreateTopic(topic string, partitions int32) error
	IncreasePartitions(topic string, partitions int32) error
}

func EnsureModerationTopics(admin TopicAdmin) error {
	for _, topic := range []string{TopicModerationTasksV1, TopicModerationTaskDLQ} {
		current, exists, err := admin.Partitions(topic)
		if err != nil {
			return err
		}
		if !exists {
			if err := admin.CreateTopic(topic, ModerationTopicPartitions); err != nil {
				return err
			}
			continue
		}
		if current < ModerationTopicPartitions {
			if err := admin.IncreasePartitions(topic, ModerationTopicPartitions); err != nil {
				return err
			}
		}
	}
	return nil
}

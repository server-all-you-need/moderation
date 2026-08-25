package moderation

import (
	"errors"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

type TaskStatus string

const (
	TaskStatusQueued     TaskStatus = "queued"
	TaskStatusProcessing TaskStatus = "processing"
	TaskStatusSucceeded  TaskStatus = "succeeded"
	TaskStatusFailed     TaskStatus = "failed"
)

type BatchStatus string

const (
	BatchStatusQueued          BatchStatus = "queued"
	BatchStatusProcessing      BatchStatus = "processing"
	BatchStatusCompleted       BatchStatus = "completed"
	BatchStatusPartiallyFailed BatchStatus = "partially_failed"
	BatchStatusFailed          BatchStatus = "failed"
)

var (
	ErrIdempotencyConflict = errors.New("idempotency key already used with different payload")
	ErrNotFound            = errors.New("moderation resource not found")
	ErrConflict            = errors.New("moderation resource conflict")
	ErrWebhookNotAllowed   = errors.New("webhook destination is not allowlisted")
)

type TaskError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Task struct {
	ID              string
	CallerID        string
	BatchID         string
	ClientItemID    string
	ContentType     auditplatform.ContentType
	Policy          auditplatform.Policy
	Status          TaskStatus
	Text            *string
	ImageURL        *string
	Result          *auditplatform.ModerationResult
	Error           *TaskError
	Attempts        int
	NextAttemptAt   *time.Time
	ClaimedUntil    *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	TerminalAt      *time.Time
	CorrelationID   string
	WebhookURL      string
	WebhookSecretID string
}

type Batch struct {
	ID         string
	CallerID   string
	Status     BatchStatus
	Total      int
	Queued     int
	Processing int
	Succeeded  int
	Failed     int
	CreatedAt  time.Time
	UpdatedAt  time.Time
	TerminalAt *time.Time
	WebhookURL string
}

type TaskOutboxRow struct {
	ID            string
	TaskID        string
	CallerID      string
	BatchID       string
	ClientItemID  string
	ContentType   auditplatform.ContentType
	Policy        auditplatform.Policy
	CorrelationID string
	Attempts      int
	ClaimedUntil  *time.Time
	PublishedAt   *time.Time
	LastError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type WebhookEndpoint struct {
	CallerID string
	URL      string
	SecretID string
	secret   string
}

type WebhookOutboxRow struct {
	ID             string
	CallerID       string
	ResourceType   string
	ResourceID     string
	DestinationURL string
	SecretID       string
	RawBody        []byte
	Attempts       int
	NextAttemptAt  time.Time
	DeliveredAt    *time.Time
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type WebhookDelivery struct {
	WebhookID  string
	Attempt    int
	StatusCode int
	Error      string
	CreatedAt  time.Time
}

type CreateTaskRequest struct {
	CallerID       string
	Operation      string
	IdempotencyKey string
	PayloadHash    string
	Input          auditplatform.ModerationInput
	WebhookURL     string
}

type CreateBatchRequest struct {
	CallerID       string
	Operation      string
	IdempotencyKey string
	PayloadHash    string
	Inputs         []auditplatform.ModerationInput
	WebhookURL     string
}

type Migration struct {
	Version int
	Name    string
	SQL     string
}

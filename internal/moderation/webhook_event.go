package moderation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/server-all-you-need/moderation/internal/auditplatform"
)

const WebhookEventVersion = 2

type taskWebhookEvent struct {
	EventVersion int                       `json:"event_version"`
	EventID      string                    `json:"event_id"`
	Type         string                    `json:"type"`
	ID           string                    `json:"id"`
	BatchID      string                    `json:"batch_id,omitempty"`
	ClientItemID string                    `json:"client_item_id"`
	ContentType  auditplatform.ContentType `json:"content_type"`
	Policy       auditplatform.Policy      `json:"policy"`
	Status       TaskStatus                `json:"status"`
	OccurredAt   time.Time                 `json:"occurred_at"`
	Result       *webhookModerationResult  `json:"result,omitempty"`
	Error        *TaskError                `json:"error,omitempty"`
}

type webhookModerationResult struct {
	ClientItemID      string                  `json:"client_item_id"`
	Decision          auditplatform.Decision  `json:"decision"`
	RiskLevel         auditplatform.RiskLevel `json:"risk_level"`
	ProviderName      string                  `json:"provider_name"`
	ProviderRequestID string                  `json:"provider_request_id,omitempty"`
	ProviderDataID    string                  `json:"provider_data_id,omitempty"`
	Labels            []webhookLabelEntry     `json:"labels,omitempty"`
}

type webhookLabelEntry struct {
	Label       string  `json:"label"`
	Confidence  float64 `json:"confidence,omitempty"`
	Description string  `json:"description,omitempty"`
}

type batchWebhookSummary struct {
	Total      int `json:"total"`
	Queued     int `json:"queued"`
	Processing int `json:"processing"`
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
}

type batchWebhookEvent struct {
	EventVersion int                 `json:"event_version"`
	EventID      string              `json:"event_id"`
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Status       BatchStatus         `json:"status"`
	OccurredAt   time.Time           `json:"occurred_at"`
	Summary      batchWebhookSummary `json:"summary"`
}

func marshalTaskWebhookEvent(eventID string, task Task) ([]byte, error) {
	if task.TerminalAt == nil {
		return nil, fmt.Errorf("task webhook event requires terminal timestamp")
	}

	event := taskWebhookEvent{
		EventVersion: WebhookEventVersion,
		EventID:      eventID,
		Type:         "task",
		ID:           task.ID,
		BatchID:      task.BatchID,
		ClientItemID: task.ClientItemID,
		ContentType:  task.ContentType,
		Policy:       task.Policy,
		Status:       task.Status,
		OccurredAt:   *task.TerminalAt,
	}

	switch task.Status {
	case TaskStatusSucceeded:
		if task.Result == nil || task.Error != nil {
			return nil, fmt.Errorf("succeeded task webhook event requires result only")
		}
		result := publicWebhookResult(*task.Result)
		event.Result = &result
	case TaskStatusFailed:
		if task.Error == nil || task.Result != nil {
			return nil, fmt.Errorf("failed task webhook event requires error only")
		}
		taskErr := *task.Error
		event.Error = &taskErr
	default:
		return nil, fmt.Errorf("task webhook event requires terminal status")
	}

	return json.Marshal(event)
}

func publicWebhookResult(result auditplatform.ModerationResult) webhookModerationResult {
	publicResult := webhookModerationResult{
		ClientItemID:      result.ClientItemID,
		Decision:          result.Decision,
		RiskLevel:         result.RiskLevel,
		ProviderName:      result.ProviderName,
		ProviderRequestID: result.ProviderRequestID,
		ProviderDataID:    result.ProviderDataID,
	}
	if len(result.Labels) > 0 {
		publicResult.Labels = make([]webhookLabelEntry, 0, len(result.Labels))
		for _, label := range result.Labels {
			publicResult.Labels = append(publicResult.Labels, webhookLabelEntry{
				Label:       label.Label,
				Confidence:  label.Confidence,
				Description: label.Description,
			})
		}
	}
	return publicResult
}

func marshalBatchWebhookEvent(eventID string, batch Batch) ([]byte, error) {
	if batch.TerminalAt == nil {
		return nil, fmt.Errorf("batch webhook event requires terminal timestamp")
	}
	switch batch.Status {
	case BatchStatusCompleted, BatchStatusPartiallyFailed, BatchStatusFailed:
	default:
		return nil, fmt.Errorf("batch webhook event requires terminal status")
	}

	return json.Marshal(batchWebhookEvent{
		EventVersion: WebhookEventVersion,
		EventID:      eventID,
		Type:         "batch",
		ID:           batch.ID,
		Status:       batch.Status,
		OccurredAt:   *batch.TerminalAt,
		Summary: batchWebhookSummary{
			Total:      batch.Total,
			Queued:     batch.Queued,
			Processing: batch.Processing,
			Succeeded:  batch.Succeeded,
			Failed:     batch.Failed,
		},
	})
}

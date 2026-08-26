package moderation

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/server-all-you-need/moderation/internal/auditplatform"
)

func TestMarshalTaskWebhookEventCarriesFullOutcomeWithoutRawInput(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	result := auditplatform.ModerationResult{
		ClientItemID:      "avatar-user-42",
		Decision:          auditplatform.DecisionPass,
		RiskLevel:         auditplatform.RiskLevelLow,
		ProviderName:      "aliyun",
		ProviderRequestID: "provider-request-id",
		ProviderDataID:    "provider-data-id",
	}
	raw := "sensitive text"
	task := Task{
		ID:           "task-1",
		BatchID:      "batch-1",
		ClientItemID: "avatar-user-42",
		ContentType:  auditplatform.ContentTypeImage,
		Policy:       auditplatform.PolicyImageAvatar,
		Status:       TaskStatusSucceeded,
		Text:         &raw,
		Result:       &result,
		TerminalAt:   &now,
	}

	body, err := marshalTaskWebhookEvent("event-1", task)
	if err != nil {
		t.Fatalf("marshal task event: %v", err)
	}
	if bytes.Contains(body, []byte(raw)) || bytes.Contains(body, []byte(`"caller_id"`)) || bytes.Contains(body, []byte(`"correlation_id"`)) {
		t.Fatalf("event leaked private data: %s", body)
	}

	var event taskWebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.EventVersion != 2 || event.EventID != "event-1" || event.Type != "task" || event.ID != "task-1" || event.BatchID != "batch-1" {
		t.Fatalf("unexpected identity fields: %#v", event)
	}
	if event.ClientItemID != "avatar-user-42" || event.ContentType != auditplatform.ContentTypeImage || event.Policy != auditplatform.PolicyImageAvatar {
		t.Fatalf("unexpected public task fields: %#v", event)
	}
	if event.Status != TaskStatusSucceeded || !event.OccurredAt.Equal(now) || event.Result == nil || event.Error != nil {
		t.Fatalf("unexpected outcome fields: %#v", event)
	}
	if !reflect.DeepEqual(*event.Result, result) {
		t.Fatalf("unexpected result: %#v", event.Result)
	}
}

func TestMarshalTaskWebhookEventCarriesFailedStandaloneTaskWithoutBatchID(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 30, 0, 0, time.UTC)
	taskErr := TaskError{Code: "provider_response", Message: "blocked"}
	raw := "https://cdn.example.com/private.png"
	task := Task{
		ID:           "task-2",
		ClientItemID: "image-user-7",
		ContentType:  auditplatform.ContentTypeImage,
		Policy:       auditplatform.PolicyImageGeneral,
		Status:       TaskStatusFailed,
		ImageURL:     &raw,
		Error:        &taskErr,
		TerminalAt:   &now,
	}

	body, err := marshalTaskWebhookEvent("event-2", task)
	if err != nil {
		t.Fatalf("marshal task event: %v", err)
	}
	if bytes.Contains(body, []byte(raw)) || bytes.Contains(body, []byte(`"batch_id"`)) {
		t.Fatalf("standalone event leaked private or optional fields: %s", body)
	}

	var event taskWebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.EventVersion != 2 || event.EventID != "event-2" || event.Type != "task" || event.ID != "task-2" {
		t.Fatalf("unexpected identity fields: %#v", event)
	}
	if event.BatchID != "" || event.Result != nil || event.Error == nil || *event.Error != taskErr {
		t.Fatalf("unexpected failed outcome fields: %#v", event)
	}
	if event.Status != TaskStatusFailed || !event.OccurredAt.Equal(now) {
		t.Fatalf("unexpected status/time fields: %#v", event)
	}
}

func TestMarshalTaskWebhookEventRejectsNonTerminalOrIncompleteTasks(t *testing.T) {
	now := time.Date(2026, 8, 26, 13, 0, 0, 0, time.UTC)
	result := auditplatform.ModerationResult{ClientItemID: "post-1", Decision: auditplatform.DecisionPass, RiskLevel: auditplatform.RiskLevelLow, ProviderName: "aliyun"}
	taskErr := TaskError{Code: "provider_response", Message: "blocked"}

	tests := []struct {
		name string
		task Task
	}{
		{
			name: "processing task",
			task: Task{ID: "task-processing", Status: TaskStatusProcessing, TerminalAt: &now, Result: &result},
		},
		{
			name: "succeeded task missing result",
			task: Task{ID: "task-no-result", Status: TaskStatusSucceeded, TerminalAt: &now},
		},
		{
			name: "failed task missing error",
			task: Task{ID: "task-no-error", Status: TaskStatusFailed, TerminalAt: &now},
		},
		{
			name: "succeeded task with error",
			task: Task{ID: "task-with-error", Status: TaskStatusSucceeded, TerminalAt: &now, Result: &result, Error: &taskErr},
		},
		{
			name: "failed task with result",
			task: Task{ID: "task-with-result", Status: TaskStatusFailed, TerminalAt: &now, Result: &result, Error: &taskErr},
		},
		{
			name: "terminal task missing timestamp",
			task: Task{ID: "task-no-time", Status: TaskStatusSucceeded, Result: &result},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := marshalTaskWebhookEvent("event-invalid", tt.task); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestMarshalBatchWebhookEventCarriesTerminalSummary(t *testing.T) {
	now := time.Date(2026, 8, 26, 14, 0, 0, 0, time.UTC)
	batch := Batch{
		ID:         "batch-1",
		Status:     BatchStatusPartiallyFailed,
		Total:      5,
		Queued:     0,
		Processing: 0,
		Succeeded:  3,
		Failed:     2,
		TerminalAt: &now,
	}

	body, err := marshalBatchWebhookEvent("event-3", batch)
	if err != nil {
		t.Fatalf("marshal batch event: %v", err)
	}
	if bytes.Contains(body, []byte(`"caller_id"`)) || bytes.Contains(body, []byte(`"webhook_url"`)) {
		t.Fatalf("batch event leaked private fields: %s", body)
	}

	var event batchWebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.EventVersion != 2 || event.EventID != "event-3" || event.Type != "batch" || event.ID != "batch-1" {
		t.Fatalf("unexpected identity fields: %#v", event)
	}
	if event.Status != BatchStatusPartiallyFailed || !event.OccurredAt.Equal(now) {
		t.Fatalf("unexpected status/time fields: %#v", event)
	}
	if event.Summary != (batchWebhookSummary{Total: 5, Queued: 0, Processing: 0, Succeeded: 3, Failed: 2}) {
		t.Fatalf("unexpected summary: %#v", event.Summary)
	}
}

func TestMarshalBatchWebhookEventRejectsNonTerminalOrIncompleteBatches(t *testing.T) {
	now := time.Date(2026, 8, 26, 15, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		batch Batch
	}{
		{
			name:  "queued batch",
			batch: Batch{ID: "batch-queued", Status: BatchStatusQueued, TerminalAt: &now},
		},
		{
			name:  "processing batch",
			batch: Batch{ID: "batch-processing", Status: BatchStatusProcessing, TerminalAt: &now},
		},
		{
			name:  "terminal batch missing timestamp",
			batch: Batch{ID: "batch-no-time", Status: BatchStatusCompleted},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := marshalBatchWebhookEvent("event-invalid", tt.batch)
			if err == nil || !strings.Contains(err.Error(), "terminal") {
				t.Fatalf("expected terminal error, got %v", err)
			}
		})
	}
}

package kafka

import (
	"context"
	"errors"
	"testing"

	"github.com/Xushengqwer/go-common/models/kafkaevents"
	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

func TestProcessBatchTreatsNonRetryableReviewErrorAsItemFailures(t *testing.T) {
	reviewer := &stubContentReviewer{
		reviewTextBatchFunc: func(context.Context, []auditplatform.TaskData) ([]auditplatform.ReviewResult, error) {
			return nil, errors.New("InvalidApi.ForbiddenInvoke")
		},
	}
	service := NewAuditProcessorService(testLogger(t), reviewer, &stubEventProducer{})

	results, err := service.ProcessBatch(context.Background(), []kafkaevents.PostData{
		{ID: 1001, Title: "title 1", Content: "content 1"},
		{ID: 1002, Title: "title 2", Content: "content 2"},
	})
	if err != nil {
		t.Fatalf("ProcessBatch() error = %v, want nil", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for i, result := range results {
		if result.Error == nil {
			t.Fatalf("results[%d].Error = nil, want item failure", i)
		}
	}
}

type stubContentReviewer struct {
	reviewTextBatchFunc func(context.Context, []auditplatform.TaskData) ([]auditplatform.ReviewResult, error)
}

func (s *stubContentReviewer) ReviewTextBatch(ctx context.Context, tasks []auditplatform.TaskData) ([]auditplatform.ReviewResult, error) {
	if s.reviewTextBatchFunc != nil {
		return s.reviewTextBatchFunc(ctx, tasks)
	}
	return nil, nil
}

func (s *stubContentReviewer) GetPlatformName() string {
	return "stub"
}

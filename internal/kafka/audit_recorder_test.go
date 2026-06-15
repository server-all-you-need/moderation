package kafka

import (
	"context"
	"errors"
	"testing"

	"github.com/IBM/sarama"
	"github.com/Xushengqwer/go-common/models/kafkaevents"
	"github.com/Xushengqwer/post_audit/internal/config"
)

func TestAuditRecorderFailureDoesNotBlockBatchProcessing(t *testing.T) {
	auditor := &stubPostAuditor{
		processBatchFunc: func(_ context.Context, posts []kafkaevents.PostData) ([]ProcessedAuditResult, error) {
			return []ProcessedAuditResult{{OriginalDataID: postIDString(posts[0].ID)}}, nil
		},
	}
	producer := &stubEventProducer{}
	recorder := failingAuditRecorder{}
	handler := NewAuditConsumerGroupHandlerWithRecorder(testLogger(t), auditor, producer, config.BatchConfig{}, recorder)
	session := newStubSession()
	message := &sarama.ConsumerMessage{Topic: "pending", Partition: 1, Offset: 10}
	post := kafkaevents.PostData{ID: 100, Title: "hello", Content: "world"}

	handler.processMessageBatch(context.Background(), session, []*sarama.ConsumerMessage{message}, []kafkaevents.PostData{post})

	if session.markedCount() != 1 {
		t.Fatalf("marked messages = %d, want 1", session.markedCount())
	}
}

type failingAuditRecorder struct{}

func (failingAuditRecorder) RecordPending(context.Context, AuditTaskRecord) error {
	return errors.New("record pending failed")
}

func (failingAuditRecorder) RecordResult(context.Context, AuditTaskRecord) error {
	return errors.New("record result failed")
}

func (failingAuditRecorder) RecordDLQ(context.Context, AuditTaskRecord) error {
	return errors.New("record dlq failed")
}

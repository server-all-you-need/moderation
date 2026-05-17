package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	commonconfig "github.com/Xushengqwer/go-common/config"
	"github.com/Xushengqwer/go-common/core"
	"github.com/Xushengqwer/go-common/models/kafkaevents"
	"github.com/Xushengqwer/post_audit/internal/config"
)

func TestConsumeClaimFlushesPendingBatchOnIdleTimeout(t *testing.T) {
	auditor := &stubPostAuditor{
		processBatchFunc: func(_ context.Context, posts []kafkaevents.PostData) ([]ProcessedAuditResult, error) {
			return []ProcessedAuditResult{
				{OriginalDataID: "1"},
			}, nil
		},
	}
	producer := &stubEventProducer{}
	handler := NewAuditConsumerGroupHandler(
		testLogger(t),
		auditor,
		producer,
		config.BatchConfig{
			MaxBatchSize: 10,
			IdleFlushMs:  20,
			MaxWaitMs:    200,
		},
	)

	session := newStubSession()
	claim := newStubClaim()
	done := make(chan error, 1)

	go func() {
		done <- handler.ConsumeClaim(session, claim)
	}()

	claim.messages <- validPendingAuditMessage(t, 1, 1)

	auditor.waitForCalls(t, 1, time.Second)
	close(claim.messages)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConsumeClaim() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ConsumeClaim() did not return after claim closed")
	}

	if got := auditor.callCount(); got != 1 {
		t.Fatalf("ProcessBatch call count = %d, want 1", got)
	}
	if got := session.markedCount(); got != 1 {
		t.Fatalf("marked count = %d, want 1", got)
	}
	if got := producer.dlqCount(); got != 0 {
		t.Fatalf("dlq count = %d, want 0", got)
	}
}

func TestProcessMessageBatchDoesNotMarkOffsetsOnBatchError(t *testing.T) {
	auditor := &stubPostAuditor{
		processBatchFunc: func(_ context.Context, posts []kafkaevents.PostData) ([]ProcessedAuditResult, error) {
			results := make([]ProcessedAuditResult, len(posts))
			for i, post := range posts {
				results[i] = ProcessedAuditResult{
					OriginalDataID: postIDString(post.ID),
					Error:          errors.New("batch failed"),
				}
			}
			return results, errors.New("batch failed")
		},
	}
	producer := &stubEventProducer{}
	handler := NewAuditConsumerGroupHandler(testLogger(t), auditor, producer, config.BatchConfig{})

	session := newStubSession()
	messageBatch := []*sarama.ConsumerMessage{
		testKafkaMessage(1),
		testKafkaMessage(2),
	}
	postBatch := []kafkaevents.PostData{
		{ID: 1},
		{ID: 2},
	}

	handler.processMessageBatch(context.Background(), session, messageBatch, postBatch)

	if got := session.markedCount(); got != 0 {
		t.Fatalf("marked count = %d, want 0", got)
	}
	if got := producer.dlqCount(); got != 0 {
		t.Fatalf("dlq count = %d, want 0", got)
	}
}

func TestProcessMessageBatchSendsPerItemFailureToDLQAndMarksMessages(t *testing.T) {
	auditor := &stubPostAuditor{
		processBatchFunc: func(_ context.Context, posts []kafkaevents.PostData) ([]ProcessedAuditResult, error) {
			return []ProcessedAuditResult{
				{
					OriginalDataID: postIDString(posts[0].ID),
					Error:          errors.New("reject first"),
				},
				{
					OriginalDataID: postIDString(posts[1].ID),
				},
			}, nil
		},
	}
	producer := &stubEventProducer{}
	handler := NewAuditConsumerGroupHandler(testLogger(t), auditor, producer, config.BatchConfig{})

	session := newStubSession()
	messageBatch := []*sarama.ConsumerMessage{
		testKafkaMessage(1),
		testKafkaMessage(2),
	}
	postBatch := []kafkaevents.PostData{
		{ID: 1},
		{ID: 2},
	}

	handler.processMessageBatch(context.Background(), session, messageBatch, postBatch)

	if got := session.markedCount(); got != 2 {
		t.Fatalf("marked count = %d, want 2", got)
	}
	if got := producer.dlqCount(); got != 1 {
		t.Fatalf("dlq count = %d, want 1", got)
	}
}

func TestConsumeClaimSendsBadPayloadToDLQAndMarksMessage(t *testing.T) {
	auditor := &stubPostAuditor{}
	producer := &stubEventProducer{}
	handler := NewAuditConsumerGroupHandler(testLogger(t), auditor, producer, config.BatchConfig{})

	session := newStubSession()
	claim := newStubClaim()
	done := make(chan error, 1)

	go func() {
		done <- handler.ConsumeClaim(session, claim)
	}()

	claim.messages <- &sarama.ConsumerMessage{
		Topic:     "post_pending_audit",
		Partition: 1,
		Offset:    99,
		Value:     []byte(`{"broken"`),
	}
	close(claim.messages)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConsumeClaim() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ConsumeClaim() did not return after bad payload test")
	}

	if got := auditor.callCount(); got != 0 {
		t.Fatalf("ProcessBatch call count = %d, want 0", got)
	}
	if got := producer.dlqCount(); got != 1 {
		t.Fatalf("dlq count = %d, want 1", got)
	}
	if got := session.markedCount(); got != 1 {
		t.Fatalf("marked count = %d, want 1", got)
	}
}

type stubPostAuditor struct {
	mu               sync.Mutex
	processBatchFunc func(context.Context, []kafkaevents.PostData) ([]ProcessedAuditResult, error)
	callCh           chan struct{}
	calls            [][]kafkaevents.PostData
}

func (s *stubPostAuditor) ProcessBatch(ctx context.Context, posts []kafkaevents.PostData) ([]ProcessedAuditResult, error) {
	s.mu.Lock()
	call := append([]kafkaevents.PostData(nil), posts...)
	s.calls = append(s.calls, call)
	if s.callCh == nil {
		s.callCh = make(chan struct{}, 10)
	}
	processBatchFunc := s.processBatchFunc
	callCh := s.callCh
	s.mu.Unlock()

	callCh <- struct{}{}

	if processBatchFunc != nil {
		return processBatchFunc(ctx, posts)
	}

	results := make([]ProcessedAuditResult, len(posts))
	for i, post := range posts {
		results[i] = ProcessedAuditResult{OriginalDataID: postIDString(post.ID)}
	}

	return results, nil
}

func (s *stubPostAuditor) waitForCalls(t *testing.T, want int, timeout time.Duration) {
	t.Helper()

	deadline := time.After(timeout)
	for {
		if s.callCount() >= want {
			return
		}

		s.mu.Lock()
		callCh := s.callCh
		s.mu.Unlock()
		if callCh == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}

		select {
		case <-callCh:
		case <-deadline:
			t.Fatalf("timed out waiting for %d ProcessBatch calls", want)
		}
	}
}

func (s *stubPostAuditor) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

type stubEventProducer struct {
	mu          sync.Mutex
	dlqMessages []*sarama.ConsumerMessage
}

func (s *stubEventProducer) SendApprovedEvent(context.Context, *kafkaevents.PostApprovedEvent) error {
	return nil
}

func (s *stubEventProducer) SendRejectedEvent(context.Context, *kafkaevents.PostRejectedEvent) error {
	return nil
}

func (s *stubEventProducer) SendToDLQ(_ context.Context, originalMessage *sarama.ConsumerMessage, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dlqMessages = append(s.dlqMessages, originalMessage)
	return nil
}

func (s *stubEventProducer) Close() error {
	return nil
}

func (s *stubEventProducer) dlqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dlqMessages)
}

type stubSession struct {
	ctx            context.Context
	markedMessages []*sarama.ConsumerMessage
	mu             sync.Mutex
}

func newStubSession() *stubSession {
	return &stubSession{ctx: context.Background()}
}

func (s *stubSession) Claims() map[string][]int32 {
	return map[string][]int32{"post_pending_audit": []int32{1}}
}

func (s *stubSession) MemberID() string {
	return "test-member"
}

func (s *stubSession) GenerationID() int32 {
	return 1
}

func (s *stubSession) MarkOffset(string, int32, int64, string) {}

func (s *stubSession) Commit() {}

func (s *stubSession) ResetOffset(string, int32, int64, string) {}

func (s *stubSession) MarkMessage(msg *sarama.ConsumerMessage, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.markedMessages = append(s.markedMessages, msg)
}

func (s *stubSession) Context() context.Context {
	return s.ctx
}

func (s *stubSession) markedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.markedMessages)
}

type stubClaim struct {
	messages chan *sarama.ConsumerMessage
}

func newStubClaim() *stubClaim {
	return &stubClaim{messages: make(chan *sarama.ConsumerMessage, 10)}
}

func (c *stubClaim) Topic() string {
	return "post_pending_audit"
}

func (c *stubClaim) Partition() int32 {
	return 1
}

func (c *stubClaim) InitialOffset() int64 {
	return 0
}

func (c *stubClaim) HighWaterMarkOffset() int64 {
	return 0
}

func (c *stubClaim) Messages() <-chan *sarama.ConsumerMessage {
	return c.messages
}

func testLogger(t *testing.T) *core.ZapLogger {
	t.Helper()

	logger, err := core.NewZapLogger(commonconfig.ZapConfig{
		Level:    "error",
		Encoding: "console",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	return logger
}

func validPendingAuditMessage(t *testing.T, offset int64, postID uint64) *sarama.ConsumerMessage {
	t.Helper()

	payload, err := json.Marshal(kafkaevents.PostPendingAuditEvent{
		EventID:   "event-id",
		Timestamp: time.Now(),
		Post: kafkaevents.PostData{
			ID:      postID,
			Title:   "title",
			Content: "content",
		},
	})
	if err != nil {
		t.Fatalf("marshal pending audit message: %v", err)
	}

	return &sarama.ConsumerMessage{
		Topic:     "post_pending_audit",
		Partition: 1,
		Offset:    offset,
		Value:     payload,
	}
}

func testKafkaMessage(offset int64) *sarama.ConsumerMessage {
	return &sarama.ConsumerMessage{
		Topic:     "post_pending_audit",
		Partition: 1,
		Offset:    offset,
		Value:     []byte(`{}`),
	}
}

func postIDString(id uint64) string {
	return strconv.FormatUint(id, 10)
}

package kafka

import (
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/Xushengqwer/go-common/models/kafkaevents"
	"github.com/Xushengqwer/post_audit/internal/config"
)

func TestMicroBatchShouldFlushByMaxBatchSize(t *testing.T) {
	now := time.Unix(100, 0)
	batch := newMicroBatch(config.BatchConfig{
		MaxBatchSize: 2,
		IdleFlushMs:  1000,
		MaxWaitMs:    3000,
	})

	batch.add(testMessage(1), testPostData(1), now)
	if batch.shouldFlush(now) {
		t.Fatal("shouldFlush() = true after first message, want false")
	}

	later := now.Add(100 * time.Millisecond)
	batch.add(testMessage(2), testPostData(2), later)

	if !batch.shouldFlush(later) {
		t.Fatal("shouldFlush() = false after reaching max batch size, want true")
	}
	if got := batch.flushReason(later); got != flushReasonMaxBatchSize {
		t.Fatalf("flushReason() = %q, want %q", got, flushReasonMaxBatchSize)
	}
}

func TestMicroBatchShouldFlushByIdleTimeout(t *testing.T) {
	now := time.Unix(200, 0)
	batch := newMicroBatch(config.BatchConfig{
		MaxBatchSize: 10,
		IdleFlushMs:  1000,
		MaxWaitMs:    3000,
	})

	batch.add(testMessage(1), testPostData(1), now)

	if batch.shouldFlush(now.Add(999 * time.Millisecond)) {
		t.Fatal("shouldFlush() = true before idle timeout, want false")
	}

	idleAt := now.Add(1000 * time.Millisecond)
	if !batch.shouldFlush(idleAt) {
		t.Fatal("shouldFlush() = false at idle timeout, want true")
	}
	if got := batch.flushReason(idleAt); got != flushReasonIdleTimeout {
		t.Fatalf("flushReason() = %q, want %q", got, flushReasonIdleTimeout)
	}
}

func TestMicroBatchShouldFlushByMaxWait(t *testing.T) {
	now := time.Unix(300, 0)
	batch := newMicroBatch(config.BatchConfig{
		MaxBatchSize: 10,
		IdleFlushMs:  1000,
		MaxWaitMs:    3000,
	})

	batch.add(testMessage(1), testPostData(1), now)
	batch.add(testMessage(2), testPostData(2), now.Add(2500*time.Millisecond))

	checkAt := now.Add(3000 * time.Millisecond)
	if !batch.shouldFlush(checkAt) {
		t.Fatal("shouldFlush() = false at max wait timeout, want true")
	}
	if got := batch.flushReason(checkAt); got != flushReasonMaxWait {
		t.Fatalf("flushReason() = %q, want %q", got, flushReasonMaxWait)
	}
}

func TestMicroBatchDrainResetsBufferState(t *testing.T) {
	now := time.Unix(400, 0)
	batch := newMicroBatch(config.BatchConfig{
		MaxBatchSize: 10,
		IdleFlushMs:  1000,
		MaxWaitMs:    3000,
	})

	batch.add(testMessage(1), testPostData(1), now)
	batch.add(testMessage(2), testPostData(2), now.Add(100*time.Millisecond))

	messageBatch, postBatch := batch.drain()
	if len(messageBatch) != 2 {
		t.Fatalf("len(messageBatch) = %d, want 2", len(messageBatch))
	}
	if len(postBatch) != 2 {
		t.Fatalf("len(postBatch) = %d, want 2", len(postBatch))
	}
	if batch.shouldFlush(now.Add(10 * time.Second)) {
		t.Fatal("shouldFlush() = true after drain, want false")
	}
	if got := batch.flushReason(now.Add(10 * time.Second)); got != flushReasonNone {
		t.Fatalf("flushReason() after drain = %q, want %q", got, flushReasonNone)
	}
	if len(batch.messages) != 0 {
		t.Fatalf("len(batch.messages) = %d after drain, want 0", len(batch.messages))
	}
	if len(batch.posts) != 0 {
		t.Fatalf("len(batch.posts) = %d after drain, want 0", len(batch.posts))
	}
	if !batch.firstBufferedAt.IsZero() {
		t.Fatalf("firstBufferedAt = %v after drain, want zero", batch.firstBufferedAt)
	}
	if !batch.lastBufferedAt.IsZero() {
		t.Fatalf("lastBufferedAt = %v after drain, want zero", batch.lastBufferedAt)
	}
}

func testMessage(offset int64) *sarama.ConsumerMessage {
	return &sarama.ConsumerMessage{
		Topic:     "post_pending_audit",
		Partition: 1,
		Offset:    offset,
		Value:     []byte(`{}`),
	}
}

func testPostData(id uint64) kafkaevents.PostData {
	return kafkaevents.PostData{ID: id}
}

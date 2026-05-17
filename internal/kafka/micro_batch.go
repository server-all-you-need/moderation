package kafka

import (
	"time"

	"github.com/IBM/sarama"
	"github.com/Xushengqwer/go-common/models/kafkaevents"
	"github.com/Xushengqwer/post_audit/internal/config"
)

type batchFlushReason string

const (
	flushReasonNone         batchFlushReason = ""
	flushReasonMaxBatchSize batchFlushReason = "max_batch_size"
	flushReasonIdleTimeout  batchFlushReason = "idle_timeout"
	flushReasonMaxWait      batchFlushReason = "max_wait"
)

type microBatch struct {
	config          config.BatchConfig
	messages        []*sarama.ConsumerMessage
	posts           []kafkaevents.PostData
	firstBufferedAt time.Time
	lastBufferedAt  time.Time
}

func newMicroBatch(batchConfig config.BatchConfig) *microBatch {
	effective := batchConfig.WithDefaults()

	return &microBatch{
		config:   effective,
		messages: make([]*sarama.ConsumerMessage, 0, effective.MaxBatchSize),
		posts:    make([]kafkaevents.PostData, 0, effective.MaxBatchSize),
	}
}

func (b *microBatch) add(message *sarama.ConsumerMessage, post kafkaevents.PostData, bufferedAt time.Time) {
	if len(b.messages) == 0 {
		b.firstBufferedAt = bufferedAt
	}

	b.messages = append(b.messages, message)
	b.posts = append(b.posts, post)
	b.lastBufferedAt = bufferedAt
}

func (b *microBatch) shouldFlush(now time.Time) bool {
	return b.flushReason(now) != flushReasonNone
}

func (b *microBatch) flushReason(now time.Time) batchFlushReason {
	if len(b.messages) == 0 {
		return flushReasonNone
	}
	if len(b.messages) >= b.config.MaxBatchSize {
		return flushReasonMaxBatchSize
	}
	if !b.lastBufferedAt.IsZero() && now.Sub(b.lastBufferedAt) >= b.config.IdleFlushDuration() {
		return flushReasonIdleTimeout
	}
	if !b.firstBufferedAt.IsZero() && now.Sub(b.firstBufferedAt) >= b.config.MaxWaitDuration() {
		return flushReasonMaxWait
	}

	return flushReasonNone
}

func (b *microBatch) drain() ([]*sarama.ConsumerMessage, []kafkaevents.PostData) {
	messageBatch := b.messages
	postBatch := b.posts

	b.messages = make([]*sarama.ConsumerMessage, 0, b.config.MaxBatchSize)
	b.posts = make([]kafkaevents.PostData, 0, b.config.MaxBatchSize)
	b.firstBufferedAt = time.Time{}
	b.lastBufferedAt = time.Time{}

	return messageBatch, postBatch
}

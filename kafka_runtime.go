package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"github.com/server-all-you-need/moderation/internal/config"
	"github.com/server-all-you-need/moderation/internal/moderation"
	"go.uber.org/zap"
)

var errKafkaNotReady = errors.New("kafka is not ready")

// kafkaResources groups the clients created by one bootstrap attempt.
type kafkaResources struct {
	admin         sarama.ClusterAdmin
	client        sarama.Client
	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup
}

type kafkaRuntimeOptions struct {
	bootstrap      func(context.Context) (*kafkaResources, error)
	consume        func(context.Context, *kafkaResources) error
	probe          func(context.Context, *kafkaResources) error
	logger         *zap.Logger
	initialBackoff time.Duration
	maxBackoff     time.Duration
	probeInterval  time.Duration
}

// kafkaRuntime owns Kafka bootstrap, consumer supervision and readiness
// reporting. It never terminates the process on Kafka errors; it retries with
// backoff and publishes its state through Ready.
type kafkaRuntime struct {
	opts kafkaRuntimeOptions

	mu        sync.RWMutex
	resources *kafkaResources
	readyErr  error

	cancel context.CancelFunc
	done   chan struct{}
}

func newKafkaRuntime(opts kafkaRuntimeOptions) *kafkaRuntime {
	if opts.logger == nil {
		opts.logger = zap.NewNop()
	}
	if opts.initialBackoff <= 0 {
		opts.initialBackoff = time.Second
	}
	if opts.maxBackoff <= 0 {
		opts.maxBackoff = 30 * time.Second
	}
	if opts.maxBackoff < opts.initialBackoff {
		opts.maxBackoff = opts.initialBackoff
	}
	if opts.probeInterval <= 0 {
		opts.probeInterval = 15 * time.Second
	}
	return &kafkaRuntime{opts: opts, readyErr: errKafkaNotReady}
}

func (r *kafkaRuntime) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		r.run(ctx)
	}()
}

func (r *kafkaRuntime) Close() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	<-r.done
}

// Ready reports whether Kafka is bootstrapped and the last probe succeeded.
func (r *kafkaRuntime) Ready() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.resources == nil {
		return errKafkaNotReady
	}
	return r.readyErr
}

func (r *kafkaRuntime) run(ctx context.Context) {
	backoff := r.opts.initialBackoff
	for ctx.Err() == nil {
		resources, err := r.opts.bootstrap(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.setReady(err)
			r.opts.logger.Error("kafka bootstrap failed",
				zap.Error(err),
				zap.Duration("retry_in", backoff),
			)
			if !sleepContext(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, r.opts.maxBackoff)
			continue
		}
		if ctx.Err() != nil {
			closeKafkaResources(resources)
			return
		}

		r.setResources(resources)
		r.setReady(nil)
		backoff = r.opts.initialBackoff

		cycleCtx, stopCycle := context.WithCancel(ctx)
		probeCtx, stopProbe := context.WithCancel(cycleCtx)
		go r.probeLoop(probeCtx, resources, stopCycle)

		err = r.opts.consume(cycleCtx, resources)
		recycled := cycleCtx.Err() != nil
		stopProbe()
		stopCycle()
		closeKafkaResources(resources)
		r.setResources(nil)
		if ctx.Err() != nil {
			return
		}

		if recycled {
			r.opts.logger.Error("kafka resources recycled after repeated probe failures",
				zap.Duration("retry_in", backoff),
			)
		} else {
			reason := errKafkaNotReady
			if err != nil {
				reason = fmt.Errorf("task consumer stopped: %w", err)
			}
			r.setReady(reason)
			r.opts.logger.Error("moderation task consumer stopped",
				zap.Error(err),
				zap.Duration("retry_in", backoff),
			)
		}
		if !sleepContext(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff, r.opts.maxBackoff)
	}
}

// probeFailureLimit is the number of consecutive failed probes after which the
// runtime rebuilds its Kafka resources. sarama keeps a broker's dead connection
// cached: Broker.Open is a no-op while the broker is still marked open, so a
// single broken pipe keeps every later request on that connection failing.
// Rebuilding the resources is the only way back to a healthy connection.
const probeFailureLimit = 2

func (r *kafkaRuntime) probeLoop(ctx context.Context, resources *kafkaResources, recycle context.CancelFunc) {
	ticker := time.NewTicker(r.opts.probeInterval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := r.opts.probe(ctx, resources)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				failures++
				r.setReady(err)
				r.opts.logger.Error("kafka health probe failed",
					zap.Error(err),
					zap.Int("consecutive_failures", failures),
				)
				if failures >= probeFailureLimit {
					recycle()
					return
				}
				continue
			}
			failures = 0
			r.setReady(nil)
		}
	}
}

func (r *kafkaRuntime) setResources(resources *kafkaResources) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resources = resources
	if resources == nil {
		r.readyErr = errKafkaNotReady
	}
}

func (r *kafkaRuntime) setReady(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.resources == nil {
		r.readyErr = errKafkaNotReady
		return
	}
	r.readyErr = err
}

func (r *kafkaRuntime) currentResources() *kafkaResources {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resources
}

// Publisher returns a stable publisher that forwards to the active producer.
func (r *kafkaRuntime) Publisher() moderation.Publisher {
	return kafkaRuntimePublisher{runtime: r}
}

type kafkaRuntimePublisher struct {
	runtime *kafkaRuntime
}

func (p kafkaRuntimePublisher) Publish(ctx context.Context, topic, key string, value []byte) error {
	resources := p.runtime.currentResources()
	if resources == nil || resources.producer == nil {
		return errKafkaNotReady
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	_, _, err := resources.producer.SendMessage(&sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(value),
	})
	return err
}

type kafkaRuntimeLagReporter struct {
	runtime *kafkaRuntime
	groupID string
	topic   string
}

func newKafkaRuntimeLagReporter(runtime *kafkaRuntime, groupID, topic string) *kafkaRuntimeLagReporter {
	return &kafkaRuntimeLagReporter{runtime: runtime, groupID: groupID, topic: topic}
}

func (l *kafkaRuntimeLagReporter) ConsumerLag(ctx context.Context) (int64, error) {
	resources := l.runtime.currentResources()
	if resources == nil || resources.admin == nil || resources.client == nil {
		return 0, errKafkaNotReady
	}
	return moderation.NewSaramaLagReporter(resources.admin, resources.client, l.groupID, l.topic).ConsumerLag(ctx)
}

// newKafkaBootstrap creates the production bootstrap function.
func newKafkaBootstrap(cfg config.KafkaConfig, saramaCfg *sarama.Config) func(context.Context) (*kafkaResources, error) {
	return func(ctx context.Context) (*kafkaResources, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		clusterAdmin, err := sarama.NewClusterAdmin(cfg.Brokers, saramaCfg)
		if err != nil {
			return nil, err
		}
		client, err := sarama.NewClient(cfg.Brokers, saramaCfg)
		if err != nil {
			_ = clusterAdmin.Close()
			return nil, err
		}
		if err := moderation.EnsureModerationTopics(moderation.NewSaramaTopicAdmin(clusterAdmin)); err != nil {
			_ = client.Close()
			_ = clusterAdmin.Close()
			return nil, err
		}
		producer, err := sarama.NewSyncProducer(cfg.Brokers, saramaCfg)
		if err != nil {
			_ = client.Close()
			_ = clusterAdmin.Close()
			return nil, err
		}
		consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.ConsumerGroupID, saramaCfg)
		if err != nil {
			_ = producer.Close()
			_ = client.Close()
			_ = clusterAdmin.Close()
			return nil, err
		}
		return &kafkaResources{
			admin:         clusterAdmin,
			client:        client,
			producer:      producer,
			consumerGroup: consumerGroup,
		}, nil
	}
}

// newKafkaProbe checks topic metadata with a bounded timeout. sarama does not
// accept a context, so the call runs in a goroutine and the timeout wins.
func newKafkaProbe(timeout time.Duration) func(context.Context, *kafkaResources) error {
	return func(ctx context.Context, resources *kafkaResources) error {
		if resources == nil || resources.admin == nil {
			return errKafkaNotReady
		}
		done := make(chan error, 1)
		go func() {
			_, err := resources.admin.DescribeTopics([]string{
				moderation.TopicModerationTasksV1,
				moderation.TopicModerationTaskDLQ,
			})
			done <- err
		}()
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			return fmt.Errorf("kafka metadata probe timed out after %s", timeout)
		}
	}
}

func closeKafkaResources(resources *kafkaResources) {
	if resources == nil {
		return
	}
	if resources.consumerGroup != nil {
		_ = resources.consumerGroup.Close()
	}
	if resources.producer != nil {
		_ = resources.producer.Close()
	}
	if resources.client != nil {
		_ = resources.client.Close()
	}
	if resources.admin != nil {
		_ = resources.admin.Close()
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

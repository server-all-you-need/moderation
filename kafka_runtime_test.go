package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testRuntimeOptions() kafkaRuntimeOptions {
	return kafkaRuntimeOptions{
		bootstrap:      func(context.Context) (*kafkaResources, error) { return &kafkaResources{}, nil },
		consume:        func(ctx context.Context, _ *kafkaResources) error { <-ctx.Done(); return ctx.Err() },
		probe:          func(context.Context, *kafkaResources) error { return nil },
		logger:         zap.NewNop(),
		initialBackoff: time.Millisecond,
		maxBackoff:     5 * time.Millisecond,
		probeInterval:  time.Millisecond,
	}
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestKafkaRuntimeRetriesBootstrapUntilReady(t *testing.T) {
	var attempts atomic.Int32
	consuming := make(chan struct{})
	opts := testRuntimeOptions()
	opts.bootstrap = func(context.Context) (*kafkaResources, error) {
		if attempts.Add(1) < 3 {
			return nil, errors.New("kafka unavailable")
		}
		return &kafkaResources{}, nil
	}
	opts.consume = func(ctx context.Context, _ *kafkaResources) error {
		close(consuming)
		<-ctx.Done()
		return ctx.Err()
	}
	runtime := newKafkaRuntime(opts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtime.Start(ctx)

	select {
	case <-consuming:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not start consuming")
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready() = %v, want nil", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("bootstrap attempts = %d, want 3", got)
	}
}

func TestKafkaRuntimeMarksNotReadyWhenConsumerStops(t *testing.T) {
	var bootstraps atomic.Int32
	stops := make(chan struct{}, 4)
	opts := testRuntimeOptions()
	opts.bootstrap = func(context.Context) (*kafkaResources, error) {
		bootstraps.Add(1)
		return &kafkaResources{}, nil
	}
	opts.consume = func(context.Context, *kafkaResources) error {
		stops <- struct{}{}
		return errors.New("consumer stopped")
	}
	opts.initialBackoff = 20 * time.Millisecond
	opts.maxBackoff = 20 * time.Millisecond
	runtime := newKafkaRuntime(opts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtime.Start(ctx)
	<-stops

	waitUntil(t, time.Second, func() bool { return runtime.Ready() != nil })
	waitUntil(t, time.Second, func() bool { return bootstraps.Load() >= 2 })
}

func TestKafkaRuntimeProbeFailureClearsReadiness(t *testing.T) {
	var probes atomic.Int32
	opts := testRuntimeOptions()
	opts.probe = func(context.Context, *kafkaResources) error {
		if probes.Add(1) >= 2 {
			return errors.New("topic metadata unavailable")
		}
		return nil
	}
	runtime := newKafkaRuntime(opts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtime.Start(ctx)
	waitUntil(t, time.Second, func() bool { return runtime.Ready() != nil })
}

func TestKafkaRuntimeStopsAfterContextCancel(t *testing.T) {
	var attempts atomic.Int32
	opts := testRuntimeOptions()
	opts.bootstrap = func(context.Context) (*kafkaResources, error) {
		attempts.Add(1)
		return nil, errors.New("kafka unavailable")
	}
	runtime := newKafkaRuntime(opts)
	ctx, cancel := context.WithCancel(context.Background())

	runtime.Start(ctx)
	waitUntil(t, time.Second, func() bool { return attempts.Load() > 0 })
	cancel()
	runtime.Close()

	settled := attempts.Load()
	time.Sleep(20 * time.Millisecond)
	if got := attempts.Load(); got != settled {
		t.Fatalf("bootstrap attempts after cancel = %d, want %d", got, settled)
	}
}

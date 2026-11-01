package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

func healthyPing(context.Context) error { return nil }

func TestReadyProbeCapsDependencyChecks(t *testing.T) {
	blocking := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	probe := newReadyProbe(blocking, healthyPing, func() error { return nil }, 50*time.Millisecond, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := probe(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("probe() = nil, want a timeout error")
	}
	if elapsed >= time.Second {
		t.Fatalf("probe took %s, want it bounded by the 50ms dependency timeout", elapsed)
	}
}

func TestReadyProbeReportsKafkaState(t *testing.T) {
	probe := newReadyProbe(healthyPing, healthyPing, func() error { return errKafkaNotReady }, time.Second, zap.NewNop())

	if err := probe(context.Background()); !errors.Is(err, errKafkaNotReady) {
		t.Fatalf("probe() = %v, want %v", err, errKafkaNotReady)
	}
}

func TestReadyProbePassesWhenDependenciesAreHealthy(t *testing.T) {
	probe := newReadyProbe(healthyPing, healthyPing, func() error { return nil }, time.Second, zap.NewNop())

	if err := probe(context.Background()); err != nil {
		t.Fatalf("probe() = %v, want nil", err)
	}
}

func TestReadyProbeStopsAtFirstFailingDependency(t *testing.T) {
	redisCalled := false
	probe := newReadyProbe(
		func(context.Context) error { return errors.New("postgres unavailable") },
		func(context.Context) error { redisCalled = true; return nil },
		func() error { return nil },
		time.Second,
		zap.NewNop(),
	)

	if err := probe(context.Background()); err == nil {
		t.Fatal("probe() = nil, want postgres error")
	}
	if redisCalled {
		t.Fatal("redis ping ran after postgres failed")
	}
}

package moderation

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRedisLimiterForTest(t *testing.T) (*RedisLimiter, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
		server.Close()
	})
	return NewRedisLimiter(client, RedisLimiterConfig{
		CallerPerSecond:   20,
		ProviderPerSecond: 80,
		AsyncPerSecond:    60,
		Window:            time.Second,
	}), server
}

func TestRedisLimiterEnforcesPerCallerBudget(t *testing.T) {
	ctx := context.Background()
	limiter, _ := newRedisLimiterForTest(t)

	for i := 0; i < 20; i++ {
		outcome, err := limiter.AcquireCaller(ctx, "client-a")
		if err != nil || !outcome.Allowed {
			t.Fatalf("caller request %d should be allowed, outcome=%#v err=%v", i+1, outcome, err)
		}
	}
	outcome, err := limiter.AcquireCaller(ctx, "client-a")
	if err != nil {
		t.Fatalf("caller denied path must not return redis error: %v", err)
	}
	if outcome.Allowed || outcome.Reason != LimitDeniedCaller {
		t.Fatalf("expected caller budget denial, got %#v", outcome)
	}
}

func TestRedisLimiterEnforcesProviderBudget(t *testing.T) {
	ctx := context.Background()
	limiter, _ := newRedisLimiterForTest(t)

	for i := 0; i < 80; i++ {
		outcome, err := limiter.AcquireProvider(ctx)
		if err != nil || !outcome.Allowed {
			t.Fatalf("provider request %d should be allowed, outcome=%#v err=%v", i+1, outcome, err)
		}
	}
	outcome, err := limiter.AcquireProvider(ctx)
	if err != nil {
		t.Fatalf("provider denied path must not return redis error: %v", err)
	}
	if outcome.Allowed || outcome.Reason != LimitDeniedProvider {
		t.Fatalf("expected provider budget denial, got %#v", outcome)
	}
}

func TestRedisLimiterAsyncPathConsumesAsyncAndProviderBudgetsAtomically(t *testing.T) {
	ctx := context.Background()
	limiter, server := newRedisLimiterForTest(t)

	for i := 0; i < 60; i++ {
		outcome, err := limiter.AcquireAsyncProvider(ctx)
		if err != nil || !outcome.Allowed {
			t.Fatalf("async request %d should be allowed, outcome=%#v err=%v", i+1, outcome, err)
		}
	}
	outcome, err := limiter.AcquireAsyncProvider(ctx)
	if err != nil {
		t.Fatalf("async denied path must not return redis error: %v", err)
	}
	if outcome.Allowed || outcome.Reason != LimitDeniedAsync {
		t.Fatalf("expected async subset denial, got %#v", outcome)
	}

	server.FastForward(time.Second)
	for i := 0; i < 80; i++ {
		if outcome, err := limiter.AcquireProvider(ctx); err != nil || !outcome.Allowed {
			t.Fatalf("provider prefill %d: outcome=%#v err=%v", i+1, outcome, err)
		}
	}
	outcome, err = limiter.AcquireAsyncProvider(ctx)
	if err != nil {
		t.Fatalf("provider denied path must not return redis error: %v", err)
	}
	if outcome.Allowed || outcome.Reason != LimitDeniedProvider {
		t.Fatalf("expected provider denial for async path, got %#v", outcome)
	}
}

func TestRedisLimiterReturnsRedisFailuresSeparatelyFromDeniedBudgets(t *testing.T) {
	ctx := context.Background()
	limiter, server := newRedisLimiterForTest(t)
	server.Close()

	outcome, err := limiter.AcquireCaller(ctx, "client-a")
	if err == nil {
		t.Fatalf("expected redis failure")
	}
	if outcome.Allowed || outcome.Reason != LimitRedisFailure {
		t.Fatalf("redis failure should be distinguishable from limit denial: outcome=%#v err=%v", outcome, err)
	}
}

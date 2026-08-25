package moderation

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type LimitReason string

const (
	LimitAllowed        LimitReason = ""
	LimitDeniedCaller   LimitReason = "caller"
	LimitDeniedProvider LimitReason = "provider"
	LimitDeniedAsync    LimitReason = "async"
	LimitRedisFailure   LimitReason = "redis_failure"
)

type LimitOutcome struct {
	Allowed bool
	Reason  LimitReason
}

type RedisLimiterConfig struct {
	CallerPerSecond   int
	ProviderPerSecond int
	AsyncPerSecond    int
	Window            time.Duration
}

type RedisLimiter struct {
	client *redis.Client
	cfg    RedisLimiterConfig
}

func NewRedisLimiter(client *redis.Client, cfg RedisLimiterConfig) *RedisLimiter {
	if cfg.Window <= 0 {
		cfg.Window = time.Second
	}
	return &RedisLimiter{client: client, cfg: cfg}
}

func (l *RedisLimiter) AcquireCaller(ctx context.Context, callerID string) (LimitOutcome, error) {
	return l.acquire(ctx, []limitBucket{{key: "moderation:limit:caller:" + callerID, limit: l.cfg.CallerPerSecond, reason: LimitDeniedCaller}})
}

func (l *RedisLimiter) AcquireProvider(ctx context.Context) (LimitOutcome, error) {
	return l.acquire(ctx, []limitBucket{{key: "moderation:limit:provider", limit: l.cfg.ProviderPerSecond, reason: LimitDeniedProvider}})
}

func (l *RedisLimiter) AcquireSyncProvider(ctx context.Context, callerID string) (LimitOutcome, error) {
	return l.acquire(ctx, []limitBucket{
		{key: "moderation:limit:caller:" + callerID, limit: l.cfg.CallerPerSecond, reason: LimitDeniedCaller},
		{key: "moderation:limit:provider", limit: l.cfg.ProviderPerSecond, reason: LimitDeniedProvider},
	})
}

func (l *RedisLimiter) AcquireAsyncProvider(ctx context.Context) (LimitOutcome, error) {
	return l.acquire(ctx, []limitBucket{
		{key: "moderation:limit:async", limit: l.cfg.AsyncPerSecond, reason: LimitDeniedAsync},
		{key: "moderation:limit:provider", limit: l.cfg.ProviderPerSecond, reason: LimitDeniedProvider},
	})
}

type limitBucket struct {
	key    string
	limit  int
	reason LimitReason
}

var acquireLimitScript = redis.NewScript(`
for i = 1, #KEYS do
  local current = tonumber(redis.call("GET", KEYS[i]) or "0")
  local limit = tonumber(ARGV[(i - 1) * 2 + 1])
  if current >= limit then
    return i
  end
end
for i = 1, #KEYS do
  local next_value = redis.call("INCR", KEYS[i])
  if next_value == 1 then
    redis.call("PEXPIRE", KEYS[i], tonumber(ARGV[(i - 1) * 2 + 2]))
  end
end
return 0
`)

func (l *RedisLimiter) acquire(ctx context.Context, buckets []limitBucket) (LimitOutcome, error) {
	keys := make([]string, 0, len(buckets))
	args := make([]interface{}, 0, len(buckets)*2)
	windowMS := int64(l.cfg.Window / time.Millisecond)
	for _, bucket := range buckets {
		keys = append(keys, bucket.key)
		args = append(args, bucket.limit, windowMS)
	}
	result, err := acquireLimitScript.Run(ctx, l.client, keys, args...).Int()
	if err != nil {
		return LimitOutcome{Allowed: false, Reason: LimitRedisFailure}, err
	}
	if result == 0 {
		return LimitOutcome{Allowed: true, Reason: LimitAllowed}, nil
	}
	return LimitOutcome{Allowed: false, Reason: buckets[result-1].reason}, nil
}

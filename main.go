package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/IBM/sarama"
	"github.com/Xushengqwer/go-common/core"
	"github.com/Xushengqwer/post_audit/internal/aliyunclient"
	"github.com/Xushengqwer/post_audit/internal/config"
	"github.com/Xushengqwer/post_audit/internal/httpapi"
	"github.com/Xushengqwer/post_audit/internal/moderation"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "internal/config/config.development.yaml", "config file path")
	flag.Parse()

	var cfg config.AppConfig
	if err := core.LoadConfig(configFile, &cfg); err != nil {
		log.Fatalf("load config %s: %v", configFile, err)
	}
	if err := cfg.ValidateV2(); err != nil {
		log.Fatalf("invalid runtime config: %v", err)
	}

	logger, err := core.NewZapLogger(cfg.ZapConfig)
	if err != nil {
		log.Fatalf("initialize logger: %v", err)
	}
	defer func() {
		if err := logger.Logger().Sync(); err != nil {
			log.Printf("logger sync failed: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Fatal("moderation service stopped", zap.Error(err))
	}
}

func run(ctx context.Context, cfg config.AppConfig, logger *core.ZapLogger) error {
	db, err := sql.Open("postgres", cfg.Database.URL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	store := moderation.NewPostgresStore(db, time.Now)
	if err := store.ApplyMigrations(ctx); err != nil {
		return err
	}

	redisClient := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB})
	defer redisClient.Close()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return err
	}
	limiter := moderation.NewRedisLimiter(redisClient, moderation.RedisLimiterConfig{
		CallerPerSecond:   20,
		ProviderPerSecond: 80,
		AsyncPerSecond:    60,
		Window:            time.Second,
	})

	aliClient, err := aliyunclient.NewAliyunModerationClient(aliyunclient.AliyunClientConfig{
		AccessKeyID:     cfg.AliyunAudit.AccessKeyID,
		AccessKeySecret: cfg.AliyunAudit.AccessKeySecret,
		Region:          cfg.AliyunAudit.RegionOrDefault(),
		Endpoint:        cfg.AliyunAudit.EndpointOrDefault(),
		ConnectTimeout:  time.Duration(cfg.AliyunAudit.TimeoutMs) * time.Millisecond,
		ReadTimeout:     time.Duration(cfg.AliyunAudit.TimeoutMs) * time.Millisecond,
	}, logger)
	if err != nil {
		return err
	}

	saramaCfg, err := newSaramaConfig(cfg.Kafka)
	if err != nil {
		return err
	}
	clusterAdmin, err := sarama.NewClusterAdmin(cfg.Kafka.Brokers, saramaCfg)
	if err != nil {
		return err
	}
	defer clusterAdmin.Close()
	kafkaClient, err := sarama.NewClient(cfg.Kafka.Brokers, saramaCfg)
	if err != nil {
		return err
	}
	defer kafkaClient.Close()
	if err := moderation.EnsureModerationTopics(moderation.NewSaramaTopicAdmin(clusterAdmin)); err != nil {
		return err
	}
	producer, err := sarama.NewSyncProducer(cfg.Kafka.Brokers, saramaCfg)
	if err != nil {
		return err
	}
	publisher := moderation.NewSaramaPublisher(producer)
	defer publisher.Close()
	consumerGroup, err := sarama.NewConsumerGroup(cfg.Kafka.Brokers, cfg.Kafka.ConsumerGroupID, saramaCfg)
	if err != nil {
		return err
	}

	worker := moderation.NewWorkerWithOptions(moderation.WorkerOptions{
		Store:          store,
		Provider:       aliClient,
		ProviderBudget: limiter,
		ClaimFor:       30 * time.Second,
	})
	webhookDispatcher := moderation.NewWebhookDispatcherWithSecretResolver(store, newRuntimeSecrets(cfg.APIClients, cfg.WebhookSecrets), moderation.NetWebhookClient{Client: http.DefaultClient})
	server, err := httpapi.NewServer(httpapi.Config{
		Store:            store,
		Provider:         aliClient,
		Limiter:          limiter,
		LagReporter:      moderation.NewSaramaLagReporter(clusterAdmin, kafkaClient, cfg.Kafka.ConsumerGroupID, moderation.TopicModerationTasksV1),
		Clients:          httpClients(cfg.APIClients),
		AdminTokenSHA256: cfg.Admin.TokenSHA256,
		Ready: func(readyCtx context.Context) error {
			if err := db.PingContext(readyCtx); err != nil {
				return err
			}
			if err := redisClient.Ping(readyCtx).Err(); err != nil {
				return err
			}
			_, err := clusterAdmin.DescribeTopics([]string{moderation.TopicModerationTasksV1, moderation.TopicModerationTaskDLQ})
			return err
		},
	})
	if err != nil {
		return err
	}

	go func() {
		if err := moderation.RunTaskConsumerGroup(ctx, consumerGroup, worker); err != nil {
			logger.Error("moderation task consumer stopped", zap.Error(err))
		}
	}()
	go runEvery(ctx, 500*time.Millisecond, func(loopCtx context.Context) {
		if err := moderation.PublishTaskOutbox(loopCtx, store, publisher, 100, 30*time.Second); err != nil {
			logger.Error("publish task outbox failed", zap.Error(err))
		}
	})
	go runEvery(ctx, time.Second, func(loopCtx context.Context) {
		if _, err := moderation.RequeueDueRetries(loopCtx, store, 100); err != nil {
			logger.Error("requeue moderation retry failed", zap.Error(err))
		}
	})
	go runEvery(ctx, time.Second, func(loopCtx context.Context) {
		if err := moderation.PublishDLQOutbox(loopCtx, store, publisher, 100, 30*time.Second); err != nil {
			logger.Error("publish dlq outbox failed", zap.Error(err))
		}
	})
	go runEvery(ctx, time.Second, func(loopCtx context.Context) {
		if err := webhookDispatcher.DispatchDueWebhooks(loopCtx, 100); err != nil {
			logger.Error("dispatch webhook failed", zap.Error(err))
		}
	})
	go runEvery(ctx, time.Hour, func(loopCtx context.Context) {
		_, err := store.CleanupExpiredWithError(loopCtx, 30*24*time.Hour, 500)
		if err != nil {
			logger.Error("cleanup expired moderation metadata failed", zap.Error(err))
		}
	})

	httpServer := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           server.Handler(),
		ReadTimeout:       timeoutMs(cfg.Server.ReadTimeoutMs, 5*time.Second),
		ReadHeaderTimeout: timeoutMs(cfg.Server.ReadHeaderTimeoutMs, 2*time.Second),
		WriteTimeout:      timeoutMs(cfg.Server.WriteTimeoutMs, 10*time.Second),
		IdleTimeout:       timeoutMs(cfg.Server.IdleTimeoutMs, time.Minute),
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("moderation HTTP service listening", zap.String("addr", cfg.Server.Addr))
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func newSaramaConfig(cfg config.KafkaConfig) (*sarama.Config, error) {
	version, err := sarama.ParseKafkaVersion(cfg.Version)
	if err != nil {
		return nil, err
	}
	saramaCfg := sarama.NewConfig()
	saramaCfg.Version = version
	saramaCfg.ClientID = "post-audit-pro-moderation"
	saramaCfg.Producer.RequiredAcks = sarama.WaitForAll
	saramaCfg.Producer.Return.Successes = true
	saramaCfg.Producer.Return.Errors = true
	saramaCfg.Producer.Idempotent = true
	saramaCfg.Net.MaxOpenRequests = 1
	saramaCfg.Consumer.Offsets.AutoCommit.Enable = cfg.Consumer.Offsets.AutoCommitEnable
	saramaCfg.Consumer.Offsets.Initial = sarama.OffsetOldest
	return saramaCfg, nil
}

func runEvery(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}

func httpClients(clients []config.APIClientConfig) []httpapi.ClientConfig {
	out := make([]httpapi.ClientConfig, 0, len(clients))
	for _, client := range clients {
		webhooks := map[string]string{}
		for _, endpoint := range client.WebhookEndpoints {
			webhooks[endpoint.URL] = endpoint.SecretID
		}
		out = append(out, httpapi.ClientConfig{ID: client.ID, Name: client.Name, TokenSHA256: client.TokenSHA256, Scopes: client.Scopes, Webhooks: webhooks})
	}
	return out
}

type runtimeSecrets map[string]string

func (s runtimeSecrets) WebhookSecret(callerID, destinationURL string) (string, bool) {
	value, ok := s[callerID+"\x00"+destinationURL]
	return value, ok
}

func newRuntimeSecrets(clients []config.APIClientConfig, secrets []config.WebhookSecret) runtimeSecrets {
	byID := map[string]string{}
	for _, secret := range secrets {
		if secret.Value != "" {
			byID[secret.CallerID+"\x00"+secret.SecretID] = secret.Value
		}
	}
	resolver := runtimeSecrets{}
	for _, client := range clients {
		for _, endpoint := range client.WebhookEndpoints {
			if value, ok := byID[client.ID+"\x00"+endpoint.SecretID]; ok {
				resolver[client.ID+"\x00"+endpoint.URL] = value
			}
		}
	}
	return resolver
}

func timeoutMs(value int64, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

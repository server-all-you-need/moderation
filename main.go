package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/xdg-go/scram"
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
	runtimeCtx, cancelRuntime := context.WithCancel(ctx)
	defer cancelRuntime()
	var consumerFailed atomic.Bool
	var consumerErr atomic.Value

	webhookDispatcher := moderation.NewWebhookDispatcherWithSecretResolver(store, newRuntimeSecrets(cfg.APIClients, cfg.WebhookSecrets), moderation.NetWebhookClient{Client: &http.Client{Timeout: timeoutMs(cfg.Server.WriteTimeoutMs, 10*time.Second)}})
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
			if consumerFailed.Load() {
				if value := consumerErr.Load(); value != nil {
					return fmt.Errorf("task consumer stopped: %v", value)
				}
				return fmt.Errorf("task consumer stopped")
			}
			_, err := clusterAdmin.DescribeTopics([]string{moderation.TopicModerationTasksV1, moderation.TopicModerationTaskDLQ})
			return err
		},
	})
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := moderation.RunTaskConsumerGroup(runtimeCtx, consumerGroup, worker, publisher); err != nil && runtimeCtx.Err() == nil {
			consumerFailed.Store(true)
			consumerErr.Store(err.Error())
			logger.Error("moderation task consumer stopped", zap.Error(err))
			select {
			case errCh <- err:
			default:
			}
		}
	}()
	startLoop := func(interval time.Duration, fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runEvery(runtimeCtx, interval, fn)
		}()
	}
	startLoop(500*time.Millisecond, func(loopCtx context.Context) {
		if err := moderation.PublishTaskOutbox(loopCtx, store, publisher, 100, 30*time.Second); err != nil {
			logger.Error("publish task outbox failed", zap.Error(err))
		}
	})
	startLoop(time.Second, func(loopCtx context.Context) {
		if _, err := moderation.RequeueDueRetries(loopCtx, store, 100); err != nil {
			logger.Error("requeue moderation retry failed", zap.Error(err))
		}
	})
	startLoop(time.Second, func(loopCtx context.Context) {
		if err := moderation.PublishDLQOutbox(loopCtx, store, publisher, 100, 30*time.Second); err != nil {
			logger.Error("publish dlq outbox failed", zap.Error(err))
		}
	})
	startLoop(time.Second, func(loopCtx context.Context) {
		if err := webhookDispatcher.DispatchDueWebhooks(loopCtx, 100); err != nil {
			logger.Error("dispatch webhook failed", zap.Error(err))
		}
	})
	startLoop(time.Hour, func(loopCtx context.Context) {
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
	go func() {
		logger.Info("moderation HTTP service listening", zap.String("addr", cfg.Server.Addr))
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		cancelRuntime()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		wg.Wait()
		return err
	case err := <-errCh:
		cancelRuntime()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		wg.Wait()
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
	if err := applyKafkaSecurity(saramaCfg, cfg); err != nil {
		return nil, err
	}
	if err := applyKafkaProducer(saramaCfg, cfg.Producer); err != nil {
		return nil, err
	}
	applyKafkaConsumer(saramaCfg, cfg.Consumer)
	if err := saramaCfg.Validate(); err != nil {
		return nil, err
	}
	return saramaCfg, nil
}

func applyKafkaSecurity(saramaCfg *sarama.Config, cfg config.KafkaConfig) error {
	if cfg.EnableTLS {
		tlsCfg, err := buildTLSConfig(cfg)
		if err != nil {
			return err
		}
		saramaCfg.Net.TLS.Enable = true
		saramaCfg.Net.TLS.Config = tlsCfg
	}
	if !cfg.EnableSASL {
		return nil
	}
	if cfg.SASLUser == "" || cfg.SASLPassword == "" {
		return fmt.Errorf("kafka sasl_user and sasl_password are required when SASL is enabled")
	}
	saramaCfg.Net.SASL.Enable = true
	saramaCfg.Net.SASL.User = cfg.SASLUser
	saramaCfg.Net.SASL.Password = cfg.SASLPassword
	switch strings.ToUpper(cfg.SASLMechanism) {
	case "", "PLAIN":
		saramaCfg.Net.SASL.Mechanism = sarama.SASLTypePlaintext
	case "SCRAM-SHA-256", "SCRAM256":
		saramaCfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		saramaCfg.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &xdgSCRAMClient{hash: scram.SHA256}
		}
	case "SCRAM-SHA-512", "SCRAM512":
		saramaCfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		saramaCfg.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &xdgSCRAMClient{hash: scram.SHA512}
		}
	default:
		return fmt.Errorf("unsupported kafka sasl mechanism %q", cfg.SASLMechanism)
	}
	return nil
}

func buildTLSConfig(cfg config.KafkaConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TLSInsecureSkipVerify}
	if cfg.TLSCaFile != "" {
		caPEM, err := os.ReadFile(cfg.TLSCaFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("kafka tls_ca_file contains no PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("kafka tls_cert_file and tls_key_file must be configured together")
	}
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func applyKafkaProducer(saramaCfg *sarama.Config, cfg config.ProducerConfig) error {
	switch cfg.RequiredAcks {
	case "", "wait_for_all":
		saramaCfg.Producer.RequiredAcks = sarama.WaitForAll
		saramaCfg.Producer.Idempotent = true
		saramaCfg.Net.MaxOpenRequests = 1
	case "wait_for_local":
		saramaCfg.Producer.RequiredAcks = sarama.WaitForLocal
	case "no_response":
		return fmt.Errorf("kafka producer required_acks=no_response is not supported for sync publishing")
	default:
		return fmt.Errorf("unsupported kafka producer required_acks %q", cfg.RequiredAcks)
	}
	saramaCfg.Producer.Return.Successes = cfg.ReturnSuccesses
	saramaCfg.Producer.Return.Errors = cfg.ReturnErrors
	if cfg.TimeoutMs > 0 {
		saramaCfg.Producer.Timeout = cfg.TimeoutMs * time.Millisecond
	}
	if cfg.MaxMessageBytes > 0 {
		saramaCfg.Producer.MaxMessageBytes = cfg.MaxMessageBytes
	}
	return nil
}

func applyKafkaConsumer(saramaCfg *sarama.Config, cfg config.ConsumerConfig) {
	saramaCfg.Consumer.Offsets.AutoCommit.Enable = cfg.Offsets.AutoCommitEnable
	if cfg.Offsets.AutoCommitIntervalMs > 0 {
		saramaCfg.Consumer.Offsets.AutoCommit.Interval = cfg.Offsets.AutoCommitIntervalMs * time.Millisecond
	}
	if cfg.SessionTimeoutMs > 0 {
		saramaCfg.Consumer.Group.Session.Timeout = cfg.SessionTimeoutMs * time.Millisecond
	}
	if cfg.HeartbeatIntervalMs > 0 {
		saramaCfg.Consumer.Group.Heartbeat.Interval = cfg.HeartbeatIntervalMs * time.Millisecond
	}
	switch strings.ToLower(firstNonEmpty(cfg.Offsets.Initial, cfg.AutoOffsetReset)) {
	case "latest":
		saramaCfg.Consumer.Offsets.Initial = sarama.OffsetNewest
	default:
		saramaCfg.Consumer.Offsets.Initial = sarama.OffsetOldest
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type xdgSCRAMClient struct {
	hash         scram.HashGeneratorFcn
	client       *scram.Client
	conversation *scram.ClientConversation
}

func (c *xdgSCRAMClient) Begin(userName, password, authzID string) error {
	client, err := c.hash.NewClient(userName, password, authzID)
	if err != nil {
		return err
	}
	c.client = client
	c.conversation = client.NewConversation()
	return nil
}

func (c *xdgSCRAMClient) Step(challenge string) (string, error) {
	return c.conversation.Step(challenge)
}

func (c *xdgSCRAMClient) Done() bool {
	return c.conversation.Done()
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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Xushengqwer/go-common/core"
)

func TestKafkaConsumerBatchConfigDefaultsAndDecode(t *testing.T) {
	t.Run("uses defaults when batch config missing", func(t *testing.T) {
		cfg := loadAppConfigFromYAML(t, `
audit_platform: "aliyun"
kafka:
  brokers:
    - "localhost:9092"
  version: "2.8.1"
  consumer_group_id: "test-group"
  topics:
    moderation_tasks: "moderation_tasks_v1"
    moderation_dlq: "moderation_tasks_dlq_v1"
  producer:
    required_acks: "wait_for_all"
    timeout_ms: 5000
    return_successes: true
    return_errors: true
    max_message_bytes: 1048576
  consumer:
    session_timeout_ms: 30000
    heartbeat_interval_ms: 10000
    offsets:
      auto_commit_enable: false
      auto_commit_interval_ms: 5000
      initial: "earliest"
`)

		batch := cfg.Kafka.Consumer.EffectiveBatch()

		if batch.MaxBatchSize != DefaultKafkaConsumerBatchMaxSize {
			t.Fatalf("MaxBatchSize = %d, want %d", batch.MaxBatchSize, DefaultKafkaConsumerBatchMaxSize)
		}
		if batch.IdleFlushMs != DefaultKafkaConsumerBatchIdleFlushMs {
			t.Fatalf("IdleFlushMs = %v, want %v", batch.IdleFlushMs, DefaultKafkaConsumerBatchIdleFlushMs)
		}
		if batch.MaxWaitMs != DefaultKafkaConsumerBatchMaxWaitMs {
			t.Fatalf("MaxWaitMs = %v, want %v", batch.MaxWaitMs, DefaultKafkaConsumerBatchMaxWaitMs)
		}
	})

	t.Run("decodes explicit batch config", func(t *testing.T) {
		cfg := loadAppConfigFromYAML(t, `
audit_platform: "aliyun"
kafka:
  brokers:
    - "localhost:9092"
  version: "2.8.1"
  consumer_group_id: "test-group"
  topics:
    moderation_tasks: "moderation_tasks_v1"
    moderation_dlq: "moderation_tasks_dlq_v1"
  producer:
    required_acks: "wait_for_all"
    timeout_ms: 5000
    return_successes: true
    return_errors: true
    max_message_bytes: 1048576
  consumer:
    session_timeout_ms: 30000
    heartbeat_interval_ms: 10000
    batch:
      max_batch_size: 7
      idle_flush_ms: 1200
      max_wait_ms: 2600
    offsets:
      auto_commit_enable: false
      auto_commit_interval_ms: 5000
      initial: "earliest"
`)

		batch := cfg.Kafka.Consumer.EffectiveBatch()

		if batch.MaxBatchSize != 7 {
			t.Fatalf("MaxBatchSize = %d, want 7", batch.MaxBatchSize)
		}
		if batch.IdleFlushMs != 1200 {
			t.Fatalf("IdleFlushMs = %v, want 1200", batch.IdleFlushMs)
		}
		if batch.MaxWaitMs != 2600 {
			t.Fatalf("MaxWaitMs = %v, want 2600", batch.MaxWaitMs)
		}
	})
}

func loadAppConfigFromYAML(t *testing.T, content string) AppConfig {
	t.Helper()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	var cfg AppConfig
	if err := core.LoadConfig(configPath, &cfg); err != nil {
		t.Fatalf("load config: %v", err)
	}

	return cfg
}

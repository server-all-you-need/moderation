package config

import "time"

const (
	DefaultKafkaConsumerBatchMaxSize                   = 10
	DefaultKafkaConsumerBatchIdleFlushMs time.Duration = 1000
	DefaultKafkaConsumerBatchMaxWaitMs   time.Duration = 3000
)

// KafkaConfig 包含了 Kafka 相关的配置
type KafkaConfig struct {
	Brokers               []string       `mapstructure:"brokers"`                  // Kafka Broker 地址列表
	Version               string         `mapstructure:"version"`                  // Kafka 版本，例如 "2.8.1" (Sarama 需要)
	Topics                KafkaTopics    `mapstructure:"topics"`                   // 主题配置
	ConsumerGroupID       string         `mapstructure:"consumer_group_id"`        // 消费者组 ID
	Producer              ProducerConfig `mapstructure:"producer"`                 // 生产者特定配置
	Consumer              ConsumerConfig `mapstructure:"consumer"`                 // 消费者特定配置
	EnableSASL            bool           `mapstructure:"enable_sasl"`              // 是否启用 SASL 认证
	SASLUser              string         `mapstructure:"sasl_user"`                // SASL 用户名
	SASLPassword          string         `mapstructure:"sasl_password"`            // SASL 密码
	SASLMechanism         string         `mapstructure:"sasl_mechanism"`           // SASL 机制, 例如 "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"  <--- 添加此字段
	EnableTLS             bool           `mapstructure:"enable_tls"`               // 是否启用 TLS 加密
	TLSCaFile             string         `mapstructure:"tls_ca_file"`              // CA 证书文件路径 (可选)
	TLSCertFile           string         `mapstructure:"tls_cert_file"`            // 客户端证书文件路径 (可选, 用于双向TLS)
	TLSKeyFile            string         `mapstructure:"tls_key_file"`             // 客户端私钥文件路径 (可选, 用于双向TLS)
	TLSInsecureSkipVerify bool           `mapstructure:"tls_insecure_skip_verify"` // 是否跳过服务器证书链和主机名验证 (不推荐用于生产)
}

// KafkaTopics 定义了服务需要用到的 Kafka 主题名称
type KafkaTopics struct {
	ModerationTasks string `mapstructure:"moderation_tasks"` // V2 task-ID-only topic
	ModerationDLQ   string `mapstructure:"moderation_dlq"`   // V2 content-free DLQ topic
}

// ProducerConfig 包含生产者的特定配置
type ProducerConfig struct {
	RequiredAcks    string        `mapstructure:"required_acks"`     // "no_response", "wait_for_local", "wait_for_all"
	TimeoutMs       time.Duration `mapstructure:"timeout_ms"`        // 生产者请求超时 (毫秒)
	ReturnSuccesses bool          `mapstructure:"return_successes"`  // (对于 SyncProducer) 是否返回成功
	ReturnErrors    bool          `mapstructure:"return_errors"`     // (对于 SyncProducer) 是否返回错误
	MaxMessageBytes int           `mapstructure:"max_message_bytes"` // 生产者能发送的最大消息大小
	// 可以添加更多 Sarama 生产者配置项，例如 Compression, Retry 等
}

// ConsumerConfig 包含消费者的特定配置
type ConsumerConfig struct {
	AutoOffsetReset     string        `mapstructure:"auto_offset_reset"`     // "earliest", "latest" (注意：Sarama 中此行为主要通过 Offsets.Initial 控制)
	SessionTimeoutMs    time.Duration `mapstructure:"session_timeout_ms"`    // 消费者会话超时 (毫秒)
	HeartbeatIntervalMs time.Duration `mapstructure:"heartbeat_interval_ms"` // 消费者心跳间隔 (毫秒) <--- 添加此字段
	Batch               BatchConfig   `mapstructure:"batch"`
	Offsets             OffsetsConfig `mapstructure:"offsets"`
	// RebalanceStrategy string        `mapstructure:"rebalance_strategy"` // 可选: "range", "roundrobin", "sticky"
	// 可以添加更多 Sarama 消费者配置项，例如 FetchMin, FetchDefault, MaxWaitTime 等
}

type BatchConfig struct {
	MaxBatchSize int           `mapstructure:"max_batch_size"`
	IdleFlushMs  time.Duration `mapstructure:"idle_flush_ms"`
	MaxWaitMs    time.Duration `mapstructure:"max_wait_ms"`
}

func (cfg ConsumerConfig) EffectiveBatch() BatchConfig {
	return cfg.Batch.WithDefaults()
}

func (cfg BatchConfig) WithDefaults() BatchConfig {
	batch := cfg

	if batch.MaxBatchSize <= 0 {
		batch.MaxBatchSize = DefaultKafkaConsumerBatchMaxSize
	}
	if batch.IdleFlushMs <= 0 {
		batch.IdleFlushMs = DefaultKafkaConsumerBatchIdleFlushMs
	}
	if batch.MaxWaitMs <= 0 {
		batch.MaxWaitMs = DefaultKafkaConsumerBatchMaxWaitMs
	}

	return batch
}

func (cfg BatchConfig) IdleFlushDuration() time.Duration {
	return cfg.IdleFlushMs * time.Millisecond
}

func (cfg BatchConfig) MaxWaitDuration() time.Duration {
	return cfg.MaxWaitMs * time.Millisecond
}

// OffsetsConfig 包含消费者偏移量相关的配置
type OffsetsConfig struct {
	AutoCommitEnable     bool          `mapstructure:"auto_commit_enable"`      // 是否自动提交偏移量 (强烈建议 false，手动提交)
	AutoCommitIntervalMs time.Duration `mapstructure:"auto_commit_interval_ms"` // 如果自动提交启用，提交间隔 (毫秒)
	Initial              string        `mapstructure:"initial"`                 // "earliest", "latest" (Sarama 中通过 sarama.OffsetOldest/sarama.OffsetNewest 设置)
}

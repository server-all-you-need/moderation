package config

import (
	"net/url"

	commonconfig "github.com/Xushengqwer/go-common/config"
)

// AppConfig 是整个应用的配置结构体
type AppConfig struct {
	ZapConfig      commonconfig.ZapConfig    `mapstructure:"zapConfig" json:"zapConfig" config.development.yaml:"zapConfig"`
	TracerConfig   commonconfig.TracerConfig `mapstructure:"tracerConfig" json:"tracerConfig" yaml:"tracerConfig"`
	Server         ServerConfig              `mapstructure:"server"`
	Database       DatabaseConfig            `mapstructure:"database"`
	Redis          RedisConfig               `mapstructure:"redis"`
	Kafka          KafkaConfig               `mapstructure:"kafka"`
	AliyunAudit    AliyunConfig              `mapstructure:"aliyun_audit"`
	APIClients     []APIClientConfig         `mapstructure:"api_clients"`
	Admin          AdminConfig               `mapstructure:"admin"`
	WebhookSecrets []WebhookSecret           `mapstructure:"webhook_secrets"`
	Log            commonconfig.ZapConfig    `mapstructure:"log"`
}

type ServerConfig struct {
	Addr                string `mapstructure:"addr"`
	ReadTimeoutMs       int64  `mapstructure:"read_timeout_ms"`
	ReadHeaderTimeoutMs int64  `mapstructure:"read_header_timeout_ms"`
	WriteTimeoutMs      int64  `mapstructure:"write_timeout_ms"`
	IdleTimeoutMs       int64  `mapstructure:"idle_timeout_ms"`
}

type DatabaseConfig struct {
	URL string `mapstructure:"url"`
}

type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type APIClientConfig struct {
	ID               string                  `mapstructure:"id"`
	Name             string                  `mapstructure:"name"`
	TokenSHA256      string                  `mapstructure:"token_sha256"`
	Scopes           []string                `mapstructure:"scopes"`
	WebhookEndpoints []WebhookEndpointConfig `mapstructure:"webhook_endpoints"`
}

type WebhookEndpointConfig struct {
	URL      string `mapstructure:"url"`
	SecretID string `mapstructure:"secret_id"`
}

type AdminConfig struct {
	TokenSHA256 string `mapstructure:"token_sha256"`
}

type WebhookSecret struct {
	CallerID string `mapstructure:"caller_id"`
	SecretID string `mapstructure:"secret_id"`
	Value    string `mapstructure:"value"`
}

func (cfg AppConfig) ValidateV2() error {
	if cfg.Server.Addr == "" {
		return validationError("server.addr is required")
	}
	if cfg.Database.URL == "" {
		return validationError("database.url is required")
	}
	if cfg.Redis.Addr == "" {
		return validationError("redis.addr is required")
	}
	if len(cfg.Kafka.Brokers) == 0 || cfg.Kafka.Version == "" || cfg.Kafka.ConsumerGroupID == "" {
		return validationError("kafka brokers, version, and consumer_group_id are required")
	}
	if !cfg.Kafka.Producer.ReturnSuccesses || !cfg.Kafka.Producer.ReturnErrors {
		return validationError("kafka sync producer must return successes and errors")
	}
	if cfg.AliyunAudit.AccessKeyID == "" || cfg.AliyunAudit.AccessKeySecret == "" {
		return validationError("aliyun credentials are required")
	}
	if len(cfg.APIClients) == 0 {
		return validationError("at least one api client is required")
	}
	webhookSecrets := map[string]struct{}{}
	for _, secret := range cfg.WebhookSecrets {
		if secret.CallerID == "" || secret.SecretID == "" || secret.Value == "" {
			return validationError("webhook secret caller_id, secret_id, and value are required")
		}
		webhookSecrets[secret.CallerID+"\x00"+secret.SecretID] = struct{}{}
	}
	referencedSecrets := map[string]struct{}{}
	for _, client := range cfg.APIClients {
		if client.ID == "" || client.Name == "" || client.TokenSHA256 == "" || len(client.Scopes) == 0 {
			return validationError("api client id, name, token digest, and scopes are required")
		}
		for _, endpoint := range client.WebhookEndpoints {
			if endpoint.URL == "" || endpoint.SecretID == "" {
				return validationError("webhook endpoint url and secret_id are required")
			}
			parsed, err := url.Parse(endpoint.URL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
				return validationError("webhook endpoint url must be HTTPS")
			}
			key := client.ID + "\x00" + endpoint.SecretID
			if _, ok := webhookSecrets[key]; !ok {
				return validationError("webhook endpoint secret_id must match a same-caller webhook secret")
			}
			referencedSecrets[key] = struct{}{}
		}
	}
	for _, secret := range cfg.WebhookSecrets {
		key := secret.CallerID + "\x00" + secret.SecretID
		if _, ok := referencedSecrets[key]; !ok {
			return validationError("webhook secret must be referenced by a same-caller endpoint")
		}
	}
	if cfg.Admin.TokenSHA256 == "" {
		return validationError("admin token digest is required")
	}
	return nil
}

type validationError string

func (e validationError) Error() string {
	return string(e)
}

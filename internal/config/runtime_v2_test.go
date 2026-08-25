package config

import "testing"

func TestV2RuntimeConfigDecodesModerationServiceWithoutLegacyTopics(t *testing.T) {
	if err := ValidateV2RuntimeConfigYAML([]byte(`
aliyun_audit:
  text_moderation_service: "comment_detection"
`)); err == nil {
		t.Fatalf("legacy aliyun_audit.text_moderation_service must be rejected because provider policy mapping is fixed")
	}

	cfg := loadAppConfigFromYAML(t, `
server:
  addr: ":8080"
  read_timeout_ms: 5000
database:
  url: "postgres://moderation:placeholder@postgres/moderation?sslmode=disable"
redis:
  addr: "redis:6379"
kafka:
  brokers: ["kafka:9092"]
  version: "2.8.1"
  consumer_group_id: "moderation-worker"
  producer:
    required_acks: "wait_for_all"
    timeout_ms: 5000
    return_successes: true
    return_errors: true
  consumer:
    offsets:
      auto_commit_enable: false
      initial: "earliest"
aliyun_audit:
  access_key_id: "placeholder"
  access_key_secret: "placeholder"
api_clients:
  - id: "client-a"
    name: "Client A"
    token_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    scopes: ["moderation:check", "moderation:submit", "moderation:read"]
    webhook_endpoints:
      - url: "https://hooks.example.com/moderation"
        secret_id: "secret-1"
admin:
  token_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
webhook_secrets:
  - caller_id: "client-a"
    secret_id: "secret-1"
    value: "placeholder"
`)

	if cfg.Server.Addr != ":8080" {
		t.Fatalf("server addr = %q", cfg.Server.Addr)
	}
	if cfg.AliyunAudit.EndpointOrDefault() != "green-cip.cn-shanghai.aliyuncs.com" {
		t.Fatalf("default aliyun endpoint = %q", cfg.AliyunAudit.EndpointOrDefault())
	}
	if len(cfg.APIClients) != 1 || cfg.APIClients[0].WebhookEndpoints[0].SecretID != "secret-1" {
		t.Fatalf("api client/webhook decode failed: %#v", cfg.APIClients)
	}
	if err := cfg.ValidateV2(); err != nil {
		t.Fatalf("V2 config without legacy text_moderation_service rejected: %v", err)
	}
}

func TestV2RuntimeConfigValidationRejectsMissingProductionDependencies(t *testing.T) {
	cfg := AppConfig{}
	if err := cfg.ValidateV2(); err == nil {
		t.Fatalf("empty config must be rejected before production can fall back to in-memory dependencies")
	}
	cfg.Server.Addr = ":8080"
	cfg.Database.URL = "postgres://moderation:placeholder@postgres/moderation?sslmode=disable"
	cfg.Redis.Addr = "redis:6379"
	cfg.Kafka.Brokers = []string{"kafka:9092"}
	cfg.Kafka.Version = "2.8.1"
	cfg.Kafka.ConsumerGroupID = "moderation-worker"
	cfg.Kafka.Producer.ReturnSuccesses = true
	cfg.Kafka.Producer.ReturnErrors = true
	cfg.AliyunAudit.AccessKeyID = "placeholder"
	cfg.AliyunAudit.AccessKeySecret = "placeholder"
	cfg.APIClients = []APIClientConfig{{ID: "client-a", Name: "Client A", TokenSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Scopes: []string{"moderation:check"}}}
	cfg.Admin.TokenSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	if err := cfg.ValidateV2(); err != nil {
		t.Fatalf("valid V2 config rejected: %v", err)
	}
}

func TestV2RuntimeConfigValidationRejectsIncompleteWebhookRegistration(t *testing.T) {
	cfg := AppConfig{
		Server:   ServerConfig{Addr: ":8080"},
		Database: DatabaseConfig{URL: "postgres://moderation:placeholder@postgres/moderation?sslmode=disable"},
		Redis:    RedisConfig{Addr: "redis:6379"},
		Kafka: KafkaConfig{
			Brokers:         []string{"kafka:9092"},
			Version:         "2.8.1",
			ConsumerGroupID: "moderation-worker",
			Producer:        ProducerConfig{ReturnSuccesses: true, ReturnErrors: true},
		},
		AliyunAudit: AliyunConfig{AccessKeyID: "placeholder", AccessKeySecret: "placeholder"},
		APIClients: []APIClientConfig{{
			ID:          "client-a",
			Name:        "Client A",
			TokenSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Scopes:      []string{"moderation:submit"},
			WebhookEndpoints: []WebhookEndpointConfig{{
				URL:      "https://hooks.example.com/moderation",
				SecretID: "secret-1",
			}},
		}},
		Admin: AdminConfig{TokenSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}

	if err := cfg.ValidateV2(); err == nil {
		t.Fatalf("webhook endpoint without same-caller secret must be rejected")
	}

	cfg.WebhookSecrets = []WebhookSecret{{CallerID: "other-client", SecretID: "secret-1", Value: "runtime-webhook-secret-value"}}
	if err := cfg.ValidateV2(); err == nil {
		t.Fatalf("webhook secret for a different caller must be rejected")
	}

	cfg.WebhookSecrets = []WebhookSecret{{CallerID: "client-a", SecretID: "secret-1", Value: "runtime-webhook-secret-value"}}
	if err := cfg.ValidateV2(); err != nil {
		t.Fatalf("matching webhook endpoint and secret rejected: %v", err)
	}

	cfg.APIClients[0].WebhookEndpoints[0].URL = "http://hooks.example.com/moderation"
	if err := cfg.ValidateV2(); err == nil {
		t.Fatalf("webhook endpoint must require HTTPS")
	}
}

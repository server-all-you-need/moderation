package config

import "testing"

func TestV2RuntimeConfigDecodesModerationServiceWithoutLegacyTopics(t *testing.T) {
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
  topics:
    moderation_tasks: "moderation_tasks_v1"
    moderation_dlq: "moderation_tasks_dlq_v1"
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
	if cfg.Kafka.Topics.ModerationTasks != "moderation_tasks_v1" || cfg.Kafka.Topics.ModerationDLQ != "moderation_tasks_dlq_v1" {
		t.Fatalf("decoded wrong moderation topics: %#v", cfg.Kafka.Topics)
	}
	if cfg.AliyunAudit.EndpointOrDefault() != "green-cip.cn-shanghai.aliyuncs.com" {
		t.Fatalf("default aliyun endpoint = %q", cfg.AliyunAudit.EndpointOrDefault())
	}
	if len(cfg.APIClients) != 1 || cfg.APIClients[0].WebhookEndpoints[0].SecretID != "secret-1" {
		t.Fatalf("api client/webhook decode failed: %#v", cfg.APIClients)
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
	cfg.Kafka.Topics.ModerationTasks = "moderation_tasks_v1"
	cfg.Kafka.Topics.ModerationDLQ = "moderation_tasks_dlq_v1"
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

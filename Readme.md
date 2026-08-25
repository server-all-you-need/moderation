# PostAudit Pro

`post-audit-pro` is the moderation platform V2 service. It exposes authenticated HTTP APIs for synchronous checks, durable asynchronous tasks, mixed batches, and cluster-internal Admin visibility.

## Runtime

- HTTP listens on `server.addr`, default deployment port `8080`.
- `/healthz` is unauthenticated.
- `/readyz` checks PostgreSQL, Redis, and Kafka without returning internal configuration.
- `/openapi.json` serves the checked-in public API contract.
- Public APIs require `Authorization: Bearer <token>` and per-client scopes:
  - `moderation:check`
  - `moderation:submit`
  - `moderation:read`
- Async task and batch submissions require `Idempotency-Key`.

## Storage And Queues

- PostgreSQL owns moderation tasks, batches, idempotency, task outbox, webhook outbox, webhook deliveries, and cleanup metadata.
- Kafka V2 events use task-ID-only messages on `moderation_tasks_v1` and `moderation_tasks_dlq_v1`.
- Redis enforces caller and provider budgets.
- Terminal task and batch states clear raw text/image URLs while retaining normalized results and metadata.

## Provider

The provider boundary is `auditplatform.Provider.Moderate`. The current implementation uses Alibaba Cloud Green 20220302 TextModerationPlus and ImageModeration with `green-cip.cn-shanghai.aliyuncs.com` as the default endpoint.

## Local Configuration

`internal/config/config.development.yaml` is a placeholder-only example. Replace placeholders with runtime secrets outside git before running the service.

```bash
go build ./...
go run . --config=internal/config/config.development.yaml
```

For platform deployment, use the root repository Kubernetes delivery commands. This service does not require direct manual topic deletion or legacy table deletion during V2 rollout.

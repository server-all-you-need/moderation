# Moderation Platform V2

`moderation` 是平台统一内容审核服务。它通过带 Bearer 鉴权的 HTTP API 提供文本与图片同步审核、持久化异步任务、文本/图片混合批次、Webhook 通知，以及只允许集群内 Admin 使用的查询接口。

字段级请求与响应契约以 [`internal/httpapi/openapi.json`](internal/httpapi/openapi.json) 为准；运行中的服务也会在 `GET /openapi.json` 返回同一份公共契约。

## 能力边界

- 支持文本和图片 URL，不接收视频、音频或图片二进制上传。
- 同步检查直接调用审核 provider，适合调用方需要立即得到结果的场景。
- 异步任务和批次先持久化到 PostgreSQL，再通过 outbox 和 Kafka 驱动 worker；调用方可轮询结果或使用预登记的 Webhook。
- 公共接口只能访问当前 Bearer token 对应 caller 的资源；Admin 接口可跨 caller 查询，但不通过公共 Gateway 暴露。
- 当前 provider 是阿里云内容安全 Green 20220302：文本使用 `TextModerationPlus`，图片使用 `ImageModeration`。默认 endpoint 为 `green-cip.cn-shanghai.aliyuncs.com`。

## 内容类型与策略

`content_type`、`policy` 和内容字段必须相互匹配：文本只传 `text`，图片只传 `image_url`。

| Policy | Content type | 阿里云 service | 限制 |
| --- | --- | --- | --- |
| `text.comment` | `text` | `comment_detection_pro` | 最多 600 个 Unicode code point |
| `text.nickname` | `text` | `nickname_detection_pro` | 最多 600 个 Unicode code point |
| `text.general` | `text` | `ugc_moderation_byllm` | 最多 2000 个 Unicode code point |
| `image.comment` | `image` | `postImageCheck` | 公网 HTTPS 图片 URL |
| `image.avatar` | `image` | `profilePhotoCheck` | 公网 HTTPS 图片 URL |
| `image.general` | `image` | `baselineCheck_pro` | 公网 HTTPS 图片 URL |

`client_item_id` 长度为 1–64，只允许字母、数字、点、下划线和连字符。图片 URL 必须使用 HTTPS 和默认 443 端口，不能包含 userinfo、IP literal、`localhost`、`.local` 或 `.internal` hostname。

审核结果将 provider risk level 归一化为：

| `risk_level` | `decision` |
| --- | --- |
| `none`、`low` | `pass` |
| `medium` | `review` |
| `high` | `block` |

## 鉴权与接口

公共 API 使用 `Authorization: Bearer <token>`。服务配置只保存 token 的 SHA-256 摘要，并按 client 分配 scope：

| Scope | 允许的接口 |
| --- | --- |
| `moderation:check` | `POST /api/v1/moderations:check` |
| `moderation:submit` | `POST /api/v1/moderation-tasks`、`POST /api/v1/moderation-batches` |
| `moderation:read` | 三个任务/批次查询接口 |

公共接口共六个：

| Method | Path | 成功状态 | 用途 |
| --- | --- | --- | --- |
| `POST` | `/api/v1/moderations:check` | `200` | 同步审核单条内容 |
| `POST` | `/api/v1/moderation-tasks` | `202` | 提交单条异步任务 |
| `GET` | `/api/v1/moderation-tasks/{id}` | `200` | 查询单条异步任务 |
| `POST` | `/api/v1/moderation-batches` | `202` | 提交 1–100 条混合批次 |
| `GET` | `/api/v1/moderation-batches/{id}` | `200` | 查询批次汇总 |
| `GET` | `/api/v1/moderation-batches/{id}/items` | `200` | 分页查询批次任务 |

异步任务与批次提交必须包含 1–128 字符的 `Idempotency-Key`。同一 caller、操作和 key 使用相同 payload 时会重放原资源；使用不同 payload 时返回 `409`。

## 调用示例

开发和生产 Gateway 地址分别为：

- `https://moderation.dev.platform.internal`
- `https://moderation.platform.internal`

下面以开发地址和占位 token 为例：

```bash
BASE_URL=https://moderation.dev.platform.internal
TOKEN='<caller-bearer-token>'
```

### 同步文本审核

```bash
curl -sS -X POST "$BASE_URL/api/v1/moderations:check" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_item_id": "comment-20260826-001",
    "content_type": "text",
    "policy": "text.comment",
    "text": "待审核的示例文本"
  }'
```

成功响应包含归一化决策、风险等级和 provider 信息：

```json
{
  "client_item_id": "comment-20260826-001",
  "decision": "pass",
  "risk_level": "low",
  "provider_name": "aliyun",
  "provider_request_id": "<provider-request-id>",
  "labels": []
}
```

### 异步图片审核

`webhook_url` 是可选字段；传入时必须与当前 caller 在 `api_clients[].webhook_endpoints` 中预登记的 HTTPS URL 完全一致。

```bash
curl -sS -X POST "$BASE_URL/api/v1/moderation-tasks" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: avatar-user-42-v1' \
  -d '{
    "client_item_id": "avatar-user-42",
    "content_type": "image",
    "policy": "image.avatar",
    "image_url": "https://cdn.example.com/path/to/image.jpg",
    "webhook_url": "https://hooks.example.com/moderation"
  }'
```

提交成功返回 `task_id` 和初始 `queued` 状态。随后使用 `moderation:read` token 查询：

```bash
TASK_ID='<task-id>'
curl -sS "$BASE_URL/api/v1/moderation-tasks/$TASK_ID" \
  -H "Authorization: Bearer $TOKEN"
```

任务状态为 `queued`、`processing`、`succeeded` 或 `failed`。终态任务会返回审核结果或结构化 `error`。

### 文本/图片混合批次

```bash
curl -sS -X POST "$BASE_URL/api/v1/moderation-batches" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: profile-import-20260826-01' \
  -d '{
    "items": [
      {
        "client_item_id": "nickname-user-42",
        "content_type": "text",
        "policy": "text.nickname",
        "text": "示例昵称"
      },
      {
        "client_item_id": "avatar-user-42",
        "content_type": "image",
        "policy": "image.avatar",
        "image_url": "https://cdn.example.com/path/to/image.jpg"
      }
    ],
    "webhook_url": "https://hooks.example.com/moderation"
  }'
```

批次状态为 `queued`、`processing`、`completed`、`partially_failed` 或 `failed`。批次汇总提供 `total`、`queued`、`processing`、`succeeded` 和 `failed` 计数。条目查询支持 `limit=1..100` 和响应中的不透明 `next_cursor`：

```bash
BATCH_ID='<batch-id>'
curl -sS "$BASE_URL/api/v1/moderation-batches/$BATCH_ID/items?limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

## Webhook

Webhook 只发送到当前 caller 预登记的 HTTPS endpoint。`event_version` 当前固定为 `2`，`event_id` 是稳定事件 ID，接收方应按 `event_id` 去重。终态通知不包含 `caller_id`、`correlation_id`、原始文本、图片 URL、Webhook secret 或 provider risk words。

成功任务事件：

```json
{
  "event_version": 2,
  "event_id": "<webhook-event-id>",
  "type": "task",
  "id": "<task-id>",
  "batch_id": "<batch-id>",
  "client_item_id": "avatar-user-42",
  "content_type": "image",
  "policy": "image.avatar",
  "status": "succeeded",
  "occurred_at": "2026-08-26T12:00:00Z",
  "result": {
    "client_item_id": "avatar-user-42",
    "decision": "pass",
    "risk_level": "low",
    "provider_name": "aliyun",
    "provider_request_id": "<provider-request-id>",
    "provider_data_id": "<provider-data-id>",
    "labels": [
      {
        "label": "normal",
        "confidence": 99.8,
        "description": "normal content"
      }
    ]
  }
}
```

失败任务事件：

```json
{
  "event_version": 2,
  "event_id": "<webhook-event-id>",
  "type": "task",
  "id": "<task-id>",
  "client_item_id": "image-user-7",
  "content_type": "image",
  "policy": "image.general",
  "status": "failed",
  "occurred_at": "2026-08-26T12:30:00Z",
  "error": {
    "code": "provider_response",
    "message": "blocked"
  }
}
```

批次终态事件：

```json
{
  "event_version": 2,
  "event_id": "<webhook-event-id>",
  "type": "batch",
  "id": "<batch-id>",
  "status": "partially_failed",
  "occurred_at": "2026-08-26T14:00:00Z",
  "summary": {
    "total": 5,
    "queued": 0,
    "processing": 0,
    "succeeded": 3,
    "failed": 2
  }
}
```

包含 `N` 个条目的批次会产生 `N` 个 task 终态事件，批次整体终态后再产生 1 个 batch summary 事件。Webhook 是 at-least-once 投递；不同事件独立重试，接收顺序可能与任务完成顺序不同，也可能先收到批次 summary 再收到某个 task 事件的重试。接收方应把 `event_id` 去重、把 `id` 当作资源 ID，并在需要时回查公开查询接口。

请求包含：

- `Content-Type: application/json`
- `X-Moderation-Timestamp: <RFC3339 timestamp>`
- `X-Moderation-Signature: sha256=<hex hmac>`

签名原文是 `<timestamp>.<raw-body>`，算法为 HMAC-SHA256。接收方应使用登记 secret 验签，并返回任意 `2xx`。失败投递按立即、1 分钟、5 分钟、30 分钟、2 小时、12 小时的计划重试；第 6 次仍失败后停止领取并不再计入 pending。

## Admin 内部接口

Admin 使用独立 Bearer token，只能通过集群内 `http://moderation:8080` 访问：

- `GET /internal/v1/moderation/stats`
- `GET /internal/v1/moderation/clients`
- `GET /internal/v1/moderation/tasks`
- `GET /internal/v1/moderation/tasks/{id}`
- `GET /internal/v1/moderation/batches`
- `GET /internal/v1/moderation/batches/{id}`
- `GET /internal/v1/moderation/batches/{id}/items`

`/internal` 不在公共 `HTTPRoute` 中。列表接口支持 `caller_id`、`content_type`、`policy`、`risk`、`status` 过滤，以及 `limit=1..100` 和 cursor 分页；Admin DTO 会暴露 caller ID，但不会返回原始文本、图片 URL 或 secret。

## 数据与异步链路

- PostgreSQL 保存任务、批次、幂等记录、任务 outbox、Webhook outbox、投递记录和清理元数据，并在启动时执行内置 migration。
- Kafka topic 固定为 `moderation_tasks_v1` 和 `moderation_tasks_dlq_v1`；消息只携带 task ID，不携带原始审核内容。
- Redis 分别执行 caller 和同步 provider 限流。Redis 不可用时接口返回 `503`，不会绕过限流。
- 可重试 provider 错误最多进行 5 次 provider attempt，任务重试间隔为 5 秒、30 秒、2 分钟和 10 分钟；永久失败或重试耗尽后进入 DLQ outbox。
- 任务或批次进入终态后会清除原始文本和图片 URL，只保留归一化结果与必要元数据。终态元数据默认保留 30 天后分批清理。

## 健康检查与错误定位

- `GET /healthz`：只表示 HTTP 进程存活，不需要鉴权。
- `GET /readyz`：检查 PostgreSQL、Redis 和 Kafka；依赖异常时返回 `503`，响应不会泄露内部配置。
- `GET /openapi.json`：返回公共 API 契约，不需要鉴权。

常见响应：

| HTTP 状态 | 含义 |
| --- | --- |
| `400` | JSON、字段组合、策略、cursor、limit、幂等 key 或 Webhook 不合法 |
| `401` | Bearer token 缺失或无效 |
| `403` | token 缺少接口所需 scope |
| `404` | 资源不存在或不属于当前 caller |
| `409` | 幂等 key 被不同 payload 复用 |
| `429` | caller 或同步 provider 预算耗尽 |
| `502` | 同步审核收到不可用的 provider 响应 |
| `503` | PostgreSQL、Redis、Kafka 或限流依赖暂时不可用 |

排查时先区分 `/healthz` 与 `/readyz`，再查看任务 `error.code`、`attempts`、Admin stats 中的 Kafka consumer lag，以及对应依赖状态。日志不得记录 token、Webhook secret、原始审核文本或完整图片 URL。

## 配置与本地运行

[`internal/config/config.development.yaml`](internal/config/config.development.yaml) 只包含占位值。配置主结构为：

- `server`、`database`、`redis`、`kafka`
- `aliyun_audit`
- `api_clients`、`admin`、`webhook_secrets`
- `zapConfig` / `log`

Bearer token 以 SHA-256 摘要配置；Webhook secret 是运行时敏感值。不要把真实 token、Secret 或阿里云 AK 写入 Git。

准备好本地 PostgreSQL、Redis、Kafka 和有效运行时配置后：

```bash
cd moderation
go test ./...
go build ./...
go run . --config=internal/config/config.development.yaml
```

占位配置不能直接用于真实审核。平台环境应通过根仓 `.runtime/<env>` 资产和 Kubernetes Secret 注入配置。

## Kubernetes 部署

从根仓使用统一入口，不要在子模块中手工删除 topic、旧表或拼装 Secret：

```bash
make prepare-dev-runtime-assets SERVER=<ssh-target>
make deploy-moderation ENV=dev SERVER=<ssh-target>

make deploy-moderation ENV=prod SERVER=<ssh-target>
```

完整环境还可以使用 `make deploy-lively-dev` 或 `make deploy-satori-prod`。部署前后应分别通过 runtime preflight、rollout status、`/healthz`、`/readyz` 和带真实 caller transport 的受保护 API smoke 验证。

历史审核 Kafka topic 与 `audit_tasks` 表为回滚和审计连续性保留，但 moderation V2 不再读写 legacy payload-bearing topic，也不要求在切换时直接删除旧资产。

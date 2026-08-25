package moderation

func PostgresMigrations() []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "moderation_core_tables",
			SQL: `
create extension if not exists pgcrypto;

create table if not exists moderation_api_clients (
  id text primary key,
  name text not null,
  key_hash text not null unique,
  scopes text[] not null default '{}',
  created_at timestamptz not null default now(),
  disabled_at timestamptz
);

create table if not exists moderation_webhook_endpoints (
  caller_id text not null references moderation_api_clients(id),
  destination_url text not null,
  secret_id text not null,
  created_at timestamptz not null default now(),
  disabled_at timestamptz,
  primary key (caller_id, destination_url)
);

create table if not exists moderation_batches (
  id uuid primary key,
  caller_id text not null references moderation_api_clients(id),
  status text not null check (status in ('queued','processing','completed','partially_failed','failed')),
  total_count integer not null,
  queued_count integer not null,
  processing_count integer not null,
  succeeded_count integer not null,
  failed_count integer not null,
  webhook_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  terminal_at timestamptz
);

create table if not exists moderation_tasks (
  id uuid primary key,
  caller_id text not null references moderation_api_clients(id),
  batch_id uuid references moderation_batches(id),
  client_item_id text not null,
  content_type text not null check (content_type in ('text','image')),
  policy text not null,
  status text not null check (status in ('queued','processing','succeeded','failed')),
  text_content text,
  image_url text,
  result_json jsonb,
  error_json jsonb,
  attempts integer not null default 0,
  next_attempt_at timestamptz,
  claimed_until timestamptz,
  correlation_id text not null,
  webhook_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  terminal_at timestamptz,
  check ((text_content is null) or (image_url is null))
);

create table if not exists moderation_batch_tasks (
  batch_id uuid not null references moderation_batches(id) on delete cascade,
  task_id uuid not null references moderation_tasks(id) on delete cascade,
  position integer not null,
  primary key (batch_id, task_id),
  unique (batch_id, position)
);

create table if not exists moderation_idempotency_keys (
  id bigserial primary key,
  caller_id text not null references moderation_api_clients(id),
  operation text not null,
  idempotency_key text not null,
  payload_hash text not null,
  resource_type text not null check (resource_type in ('task','batch')),
  resource_id uuid not null,
  created_at timestamptz not null default now()
);

create table if not exists moderation_task_outbox (
  id uuid primary key,
  task_id uuid not null references moderation_tasks(id) on delete cascade,
  caller_id text not null,
  batch_id uuid,
  client_item_id text not null,
  content_type text not null,
  policy text not null,
  correlation_id text not null,
  attempts integer not null default 0,
  claimed_until timestamptz,
  published_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists moderation_dlq_outbox (
  id uuid primary key,
  task_id uuid not null references moderation_tasks(id) on delete cascade,
  caller_id text not null,
  correlation_id text not null,
  reason text not null,
  event_body bytea not null,
  attempts integer not null default 0,
  claimed_until timestamptz,
  published_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
`,
		},
		{
			Version: 2,
			Name:    "moderation_webhook_and_indexes",
			SQL: `
create table if not exists moderation_webhook_outbox (
  id uuid primary key,
  caller_id text not null references moderation_api_clients(id),
  resource_type text not null check (resource_type in ('task','batch')),
  resource_id uuid not null,
  destination_url text not null,
  secret_id text not null,
  body_bytes bytea not null,
  next_attempt_at timestamptz not null,
  attempts integer not null default 0,
  claimed_until timestamptz,
  delivered_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists moderation_webhook_deliveries (
  id bigserial primary key,
  webhook_outbox_id uuid not null references moderation_webhook_outbox(id) on delete cascade,
  attempt integer not null,
  status_code integer,
  error text,
  delivered_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_moderation_tasks_owner_status on moderation_tasks(caller_id, status, updated_at desc, id desc);
create index if not exists idx_moderation_tasks_cursor on moderation_tasks(updated_at desc, id desc);
create index if not exists idx_moderation_batches_owner_status on moderation_batches(caller_id, status, updated_at desc, id desc);
create index if not exists idx_moderation_task_outbox_claim on moderation_task_outbox(published_at, claimed_until, created_at);
create index if not exists idx_moderation_dlq_outbox_claim on moderation_dlq_outbox(published_at, claimed_until, created_at);
create index if not exists idx_moderation_webhook_outbox_due on moderation_webhook_outbox(delivered_at, next_attempt_at, created_at);
create unique index if not exists idx_moderation_idempotency_scope on moderation_idempotency_keys(caller_id, operation, idempotency_key);
create unique index if not exists idx_moderation_webhook_terminal_resource on moderation_webhook_outbox(resource_type, resource_id);

-- Claim query used by the transactional outbox publisher:
-- select id from moderation_task_outbox
-- where published_at is null and (claimed_until is null or claimed_until < now())
-- order by created_at
-- limit $1
-- for update skip locked;
`,
		},
	}
}

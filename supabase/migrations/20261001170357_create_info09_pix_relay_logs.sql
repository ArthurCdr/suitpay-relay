create table public.info09_pix_relay_logs (
  id uuid primary key,
  created_at timestamptz not null,
  completed_at timestamptz,
  method text not null,
  path text not null,
  query jsonb,
  peer_ip text,
  origin text,
  referer text,
  outcome text not null check (outcome in ('received','success','blocked','error','aborted','interrupted')),
  http_status integer,
  upstream_status integer,
  duration_ms bigint,
  request_body jsonb,
  response_body jsonb,
  error_code text
);
create index info09_pix_relay_logs_created_at_idx on public.info09_pix_relay_logs (created_at desc);
alter table public.info09_pix_relay_logs enable row level security;
revoke all on public.info09_pix_relay_logs from public, anon, authenticated;
grant select, insert, update on public.info09_pix_relay_logs to service_role;
comment on table public.info09_pix_relay_logs is 'HTTP relay audit. success means HTTP success, not settlement confirmation. Restricted to backend service_role.';

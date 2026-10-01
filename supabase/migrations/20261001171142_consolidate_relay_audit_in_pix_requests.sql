-- Keep existing payout validation and uniqueness; audit rows have no payout fields.
alter table public.info09_pix_requests
  add column record_type text not null default 'payout',
  add column completed_at timestamptz,
  add column method text,
  add column path text,
  add column query jsonb,
  add column peer_ip text,
  add column origin text,
  add column referer text,
  add column outcome text,
  add column http_status integer,
  add column upstream_status integer,
  add column duration_ms bigint,
  add column request_body jsonb,
  add column response_body jsonb,
  add column error_code text,
  alter column user_name drop not null,
  alter column pix_type drop not null,
  alter column pix_key_display drop not null,
  alter column pix_key_normalized drop not null,
  alter column source_url drop not null,
  alter column payout_status drop not null,
  add constraint info09_record_type_check check (record_type in ('payout','relay_request')),
  add constraint info09_record_fields_check check (
    (record_type = 'payout' and user_name is not null and pix_type is not null
      and pix_key_display is not null and pix_key_normalized is not null
      and source_url is not null and payout_status is not null)
    or
    (record_type = 'relay_request' and user_name is null and pix_type is null
      and pix_key_display is null and pix_key_normalized is null and source_url is null
      and payout_status is null and method is not null and path is not null and outcome is not null)
  ),
  add constraint info09_relay_outcome_check check (
    outcome in ('received','success','blocked','error','aborted','interrupted')
  );
create index info09_pix_requests_relay_created_at_idx
  on public.info09_pix_requests (created_at desc) where record_type = 'relay_request';
alter table public.info09_pix_requests enable row level security;
grant select, insert, update on public.info09_pix_requests to service_role;

-- Preserve any logs already synchronized before retiring the separate table.
lock table public.info09_pix_relay_logs in access exclusive mode;
insert into public.info09_pix_requests (
  session_id, record_type, created_at, payout_status, completed_at, method, path, query,
  peer_ip, origin, referer, outcome, http_status, upstream_status, duration_ms,
  request_body, response_body, error_code
)
select id, 'relay_request', created_at, null, completed_at, method, path, query,
  peer_ip, origin, referer, outcome, http_status, upstream_status, duration_ms,
  request_body, response_body, error_code
from public.info09_pix_relay_logs;
drop table public.info09_pix_relay_logs;
comment on column public.info09_pix_requests.record_type is
  'payout = existing business records; relay_request = HTTP audit only, never a pending payout.';

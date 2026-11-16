-- Circulars, Guidelines & Notifications module.
-- Safe to run more than once. Run in the Supabase SQL editor.
--
-- Security model
--   * Visibility is decided from the publisher's/reader's database record (never from client input).
--   * Row-level security is ON with no policies: the public (anon/authenticated) keys can read nothing;
--     only the API's service role can reach these tables.
--   * A trigger re-checks every publication against the issuer's real role and assignment, so even a
--     buggy or bypassed API call cannot publish outside the issuer's organisational scope.
--   * Audit rows are append-only (UPDATE/DELETE are rejected by trigger).
--   * Published content is never silently edited: every amendment snapshots the previous version first.

create table if not exists public.circulars (
  id uuid primary key default gen_random_uuid(),
  ref_no text not null,
  scope_type text not null check (scope_type in ('ALL','AREA','MINE')),
  area_id uuid references public.areas(id),
  mine_id uuid references public.mines(id),
  issuer_id uuid not null references public.users(id),
  issuer_role text not null,
  issuer_name text not null,
  category text not null check (category in ('Circular','Guideline','Instruction','Advisory','Safety Alert','Notification')),
  priority text not null default 'normal' check (priority in ('normal','important','urgent','critical')),
  title text not null check (char_length(title) between 3 and 200),
  subject text not null check (char_length(subject) between 3 and 300),
  body_html text not null default '' check (char_length(body_html) <= 60000),
  issue_date date not null default current_date,
  effective_date date,
  requires_ack boolean not null default true,
  status text not null default 'published' check (status in ('published','archived')),
  version integer not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  constraint circulars_scope_shape check (
    (scope_type = 'ALL'  and area_id is null and mine_id is null) or
    (scope_type = 'AREA' and area_id is not null and mine_id is null) or
    (scope_type = 'MINE' and area_id is not null and mine_id is not null))
);
create unique index if not exists circulars_ref_no_uidx on public.circulars (lower(ref_no));
create index if not exists circulars_scope_idx on public.circulars (scope_type, area_id, mine_id, created_at desc);
create index if not exists circulars_issuer_idx on public.circulars (issuer_id, created_at desc);

create table if not exists public.circular_versions (
  id uuid primary key default gen_random_uuid(),
  circular_id uuid not null references public.circulars(id) on delete restrict,
  version integer not null,
  title text not null, subject text not null, body_html text not null,
  priority text not null, effective_date date,
  edited_by uuid references public.users(id),
  amendment_note text,
  created_at timestamptz not null default now(),
  unique (circular_id, version)
);

create table if not exists public.circular_attachments (
  id uuid primary key default gen_random_uuid(),
  circular_id uuid not null references public.circulars(id) on delete restrict,
  file_name text not null check (char_length(file_name) between 1 and 200),
  mime_type text not null check (mime_type in ('application/pdf','application/vnd.openxmlformats-officedocument.wordprocessingml.document','image/png','image/jpeg','image/webp')),
  size_bytes integer not null check (size_bytes between 1 and 3145728),
  data_base64 text not null,
  added_in_version integer not null default 1,
  created_at timestamptz not null default now()
);
create index if not exists circular_attachments_circ_idx on public.circular_attachments (circular_id);

create table if not exists public.circular_recipients (
  circular_id uuid not null references public.circulars(id) on delete restrict,
  user_id uuid not null references public.users(id) on delete cascade,
  delivered_at timestamptz not null default now(),
  viewed_at timestamptz,
  viewed_version integer,
  acknowledged_at timestamptz,
  ack_version integer,
  primary key (circular_id, user_id)
);
create index if not exists circular_recipients_user_idx on public.circular_recipients (user_id, delivered_at desc);

create table if not exists public.circular_audit (
  id bigint generated always as identity primary key,
  circular_id uuid not null references public.circulars(id) on delete restrict,
  actor_id uuid references public.users(id),
  actor_role text,
  event text not null check (event in ('published','amended','viewed','acknowledged','archived')),
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists circular_audit_circ_idx on public.circular_audit (circular_id, created_at);

alter table public.circulars enable row level security;
alter table public.circular_versions enable row level security;
alter table public.circular_attachments enable row level security;
alter table public.circular_recipients enable row level security;
alter table public.circular_audit enable row level security;

-- Audit trail is append-only.
create or replace function public.circular_audit_immutable() returns trigger language plpgsql as $$
begin raise exception 'circular_audit is append-only'; end $$;
drop trigger if exists circular_audit_no_change on public.circular_audit;
create trigger circular_audit_no_change before update or delete on public.circular_audit
  for each row execute function public.circular_audit_immutable();

-- Publication scope is enforced by the database from the issuer's real record.
create or replace function public.circulars_enforce_scope() returns trigger language plpgsql as $$
declare u record; m_area uuid;
begin
  if tg_op = 'UPDATE' then
    if new.scope_type is distinct from old.scope_type or new.area_id is distinct from old.area_id
       or new.mine_id is distinct from old.mine_id or new.issuer_id is distinct from old.issuer_id
       or new.ref_no is distinct from old.ref_no then
      raise exception 'Scope, issuer and reference number of a published circular cannot be changed';
    end if;
    return new;
  end if;
  select role, is_active, assigned_area_id, assigned_mine_id into u from public.users where id = new.issuer_id;
  if not found or u.is_active is false then raise exception 'Issuer is not an active user'; end if;
  if new.scope_type = 'ALL' then
    if u.role <> 'HQ_SAFETY_HEAD' then raise exception 'Only HQ may publish to all Areas and Mines'; end if;
  elsif new.scope_type = 'AREA' then
    if u.role <> 'AREA_SAFETY_OFFICER' or u.assigned_area_id is distinct from new.area_id then
      raise exception 'An ASO may publish only to the Area they are assigned to'; end if;
  else
    if u.role not in ('MINE_MANAGER','MINE_SO_MINING','MINE_SO_EM') or u.assigned_mine_id is distinct from new.mine_id then
      raise exception 'Mine-level users may publish only to their own Mine'; end if;
    select area_id into m_area from public.mines where id = new.mine_id;
    if m_area is distinct from new.area_id then raise exception 'Mine does not belong to the stated Area'; end if;
  end if;
  new.issuer_role := u.role;
  return new;
end $$;
drop trigger if exists circulars_scope_guard on public.circulars;
create trigger circulars_scope_guard before insert or update on public.circulars
  for each row execute function public.circulars_enforce_scope();

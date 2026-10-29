-- Disposable legacy-schema fixture for migration integration tests only.
-- This is intentionally a minimal representative pre-migration schema, not a production dump.
create extension if not exists pgcrypto;
do $$ begin
  if not exists (select 1 from pg_roles where rolname='anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname='service_role') then create role service_role nologin; end if;
end $$;
create table public.users (
  id uuid primary key default gen_random_uuid(),
  worker_id text unique,
  name text,
  department text,
  password_hash text,
  role text not null default 'worker',
  created_at timestamptz not null default now()
);
create table public.incidents (
  id uuid primary key default gen_random_uuid(),
  incident_ref text,
  reporter_id uuid references public.users(id),
  reporter_worker_id text,
  reporter_name text,
  incident_type text,
  date_of_incident date,
  time_of_incident time,
  location_zone text,
  location_detail text,
  severity text,
  persons_injured integer,
  description text,
  immediate_actions text,
  ppe_worn text,
  sop_followed text,
  witnesses text,
  photos jsonb,
  status text default 'open',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
insert into public.users(worker_id,name,role) values
 ('TEST-ADMIN','Integration Test Admin','admin'),
 ('TEST-WORKER','Integration Test Worker','worker');
insert into public.incidents(incident_type,status,description) values
 ('Near Miss','New','legacy near-miss fixture'),
 ('Unsafe Act','under review','legacy unsafe-act fixture');

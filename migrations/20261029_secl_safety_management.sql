-- MineGuard SECL safety-management migration
-- Run in a non-production Supabase project first. Preserves existing data.
create extension if not exists pgcrypto;
create table if not exists public.areas (
 id uuid primary key default gen_random_uuid(), name text not null,
 normalized_name text not null unique, source_label text,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.mines (
 id uuid primary key default gen_random_uuid(),
 area_id uuid not null references public.areas(id) on update restrict on delete restrict,
 name text not null, normalized_name text not null, source_label text, source_area_label text,
 external_code text, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 constraint mines_area_normalized_name_key unique(area_id, normalized_name)
);
alter table public.users
 add column if not exists assigned_mine_id uuid references public.mines(id) on update restrict on delete restrict,
 add column if not exists assigned_area_id uuid references public.areas(id) on update restrict on delete restrict,
 add column if not exists is_active boolean not null default true,
 add column if not exists updated_at timestamptz not null default now();
do $$ declare c record; begin
 for c in select conname from pg_constraint where conrelid='public.users'::regclass and contype='c' and pg_get_constraintdef(oid) ilike '%role%'
 loop execute format('alter table public.users drop constraint %I',c.conname); end loop;
end $$;
alter table public.users alter column role set default 'worker';
do $ declare bad_roles text; begin
 select string_agg(distinct role, ', ' order by role) into bad_roles
 from public.users where role not in ('worker','admin','MINE_SO_MINING','MINE_SO_EM','MINE_MANAGER','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD','LOCAL_SUPERVISOR','LOCAL_ENGINEER');
 if bad_roles is not null then raise exception 'Unmapped legacy user roles require manual reconciliation before migration: %', bad_roles; end if;
end $;
alter table public.users add constraint users_role_allowed_check check
(role in ('worker','admin','MINE_SO_MINING','MINE_SO_EM','MINE_MANAGER','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD','LOCAL_SUPERVISOR','LOCAL_ENGINEER'));
create unique index if not exists users_one_active_mine_manager_per_mine on public.users(assigned_mine_id)
 where role='MINE_MANAGER' and is_active=true and assigned_mine_id is not null;
create unique index if not exists users_one_active_area_so_per_area on public.users(assigned_area_id)
 where role='AREA_SAFETY_OFFICER' and is_active=true and assigned_area_id is not null;
create unique index if not exists users_one_active_hq_safety_head on public.users(role)
 where role='HQ_SAFETY_HEAD' and is_active=true;
alter table public.incidents
 add column if not exists area_id uuid references public.areas(id) on update restrict on delete restrict,
 add column if not exists mine_id uuid references public.mines(id) on update restrict on delete restrict,
 add column if not exists category text, add column if not exists discipline text,
 add column if not exists assignee_id uuid references public.users(id) on update restrict on delete restrict,
 add column if not exists resolved_at timestamptz, add column if not exists closed_at timestamptz,
 add column if not exists version integer not null default 1, add column if not exists audit_metadata jsonb not null default '{}'::jsonb;
update public.incidents set category=case
 when lower(coalesce(incident_type,'')) like '%near%miss%' or lower(coalesce(incident_type,''))='nearmiss' then 'Near Miss'
 when lower(coalesce(incident_type,'')) like '%unsafe%act%' then 'Unsafe Act'
 when lower(coalesce(incident_type,'')) like '%unsafe%condition%' then 'Unsafe Condition'
 else category end where category is null;
create index if not exists incidents_area_created_idx on public.incidents(area_id,created_at desc);
create index if not exists incidents_mine_created_idx on public.incidents(mine_id,created_at desc);
create index if not exists incidents_status_created_idx on public.incidents(status,created_at desc);
create index if not exists incidents_category_discipline_idx on public.incidents(category,discipline);
create index if not exists incidents_assignee_idx on public.incidents(assignee_id);

-- Expand legacy lowercase statuses while retaining old rows and their history.
do $ declare c record; begin
 for c in select conname from pg_constraint where conrelid='public.incidents'::regclass
   and contype='c' and pg_get_constraintdef(oid) ilike '%status%'
 loop execute format('alter table public.incidents drop constraint %I',c.conname); end loop;
end $;
-- Normalize known historical status spellings. Unknown values are reported, never silently discarded.
update public.incidents set status=case
 when lower(trim(coalesce(status,''))) in ('open','new') then 'open'
 when lower(trim(coalesce(status,''))) in ('under_review','under review','in_review','in review','review') then 'under_review'
 when lower(trim(coalesce(status,''))) in ('action_assigned','action assigned','assigned') then 'action_assigned'
 when lower(trim(coalesce(status,''))) in ('escalated','escalate') then 'escalated'
 when lower(trim(coalesce(status,''))) in ('resolved','resolve') then 'resolved'
 when lower(trim(coalesce(status,''))) in ('closed','close') then 'closed'
 else status end;
do $ declare bad_statuses text; begin
 select string_agg(distinct coalesce(status,'<NULL>'), ', ' order by coalesce(status,'<NULL>')) into bad_statuses
 from public.incidents where status is null or status not in ('open','under_review','action_assigned','escalated','resolved','closed');
 if bad_statuses is not null then raise exception 'Unmapped legacy incident statuses require manual reconciliation before migration: %', bad_statuses; end if;
end $;
alter table public.incidents add constraint incidents_status_allowed_check
 check (status in ('open','under_review','action_assigned','escalated','resolved','closed'));
alter table public.incidents add constraint incidents_category_allowed_check
 check (category is null or category in ('Near Miss','Unsafe Act','Unsafe Condition'));
alter table public.incidents add constraint incidents_discipline_allowed_check
 check (discipline is null or discipline in ('Mining','Electrical & Mechanical'));
alter table public.users add constraint users_scope_required_check check (
 (role in ('MINE_SO_MINING','MINE_SO_EM','MINE_MANAGER','LOCAL_SUPERVISOR','LOCAL_ENGINEER')
   and assigned_mine_id is not null and assigned_area_id is null)
 or (role='AREA_SAFETY_OFFICER' and assigned_area_id is not null and assigned_mine_id is null)
 or (role='HQ_SAFETY_HEAD' and assigned_area_id is null and assigned_mine_id is null)
 or role in ('worker','admin')
);
create table if not exists public.incident_comments (
 id uuid primary key default gen_random_uuid(), incident_id uuid not null references public.incidents(id) on delete restrict,
 author_id uuid not null references public.users(id) on delete restrict,
 comment_text text not null check(length(trim(comment_text)) between 1 and 10000),
 context jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create index if not exists incident_comments_incident_created_idx on public.incident_comments(incident_id,created_at);
create table if not exists public.incident_forwarding_history (
 id uuid primary key default gen_random_uuid(), incident_id uuid not null references public.incidents(id) on delete restrict,
 actor_id uuid not null references public.users(id) on delete restrict,
 from_user_id uuid references public.users(id) on delete restrict,
 to_user_id uuid not null references public.users(id) on delete restrict,
 from_role text not null, to_role text not null,
 action text not null check(action in ('FORWARD','ESCALATE','ASSIGN','REASSIGN')),
 comments text, context jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create index if not exists incident_forwarding_incident_created_idx on public.incident_forwarding_history(incident_id,created_at);
create or replace function public.mineguard_reject_forward_history_mutation() returns trigger language plpgsql as $$
begin raise exception 'Forwarding history is append-only'; end $$;
drop trigger if exists incident_forward_history_immutable on public.incident_forwarding_history;
create trigger incident_forward_history_immutable before update or delete on public.incident_forwarding_history
for each row execute function public.mineguard_reject_forward_history_mutation();
create or replace function public.mineguard_validate_incident_hierarchy() returns trigger language plpgsql as $$
declare actual_area uuid;
begin
 if new.mine_id is null then return new; end if;
 select area_id into actual_area from public.mines where id=new.mine_id;
 if actual_area is null then raise exception 'Invalid mine_id'; end if;
 if new.area_id is null then new.area_id:=actual_area;
 elsif new.area_id<>actual_area then raise exception 'Incident area_id must match the selected mine parent Area'; end if;
 return new;
end $$;
drop trigger if exists incidents_hierarchy_guard on public.incidents;
create trigger incidents_hierarchy_guard before insert or update of mine_id,area_id on public.incidents
for each row execute function public.mineguard_validate_incident_hierarchy();

-- Atomic assignment + append-only history. The API performs identity and destination
-- authorization before calling this function; the row lock/version check prevents races.
create or replace function public.mineguard_forward_incident_atomic(
 p_incident_id uuid,
 p_expected_version integer,
 p_new_status text,
 p_assignee_id uuid,
 p_actor_id uuid,
 p_from_role text,
 p_to_role text,
 p_action text,
 p_comments text,
 p_context jsonb
) returns jsonb
language plpgsql
security invoker
set search_path = public
as $
declare
 current_incident public.incidents%rowtype;
 updated_incident public.incidents%rowtype;
 forwarding_event public.incident_forwarding_history%rowtype;
begin
 if p_action not in ('FORWARD','ESCALATE','ASSIGN','REASSIGN') then
   raise exception 'Invalid forwarding action' using errcode='22023';
 end if;
 if p_action='ESCALATE' and (p_new_status<>'escalated' or length(trim(coalesce(p_comments,'')))=0) then
   raise exception 'Escalation requires escalated status and comments' using errcode='22023';
 end if;
 select * into current_incident from public.incidents where id=p_incident_id for update;
 if not found then raise exception 'Incident not found' using errcode='P0002'; end if;
 if current_incident.version is distinct from p_expected_version then
   raise exception 'Incident changed concurrently' using errcode='40001';
 end if;
 if p_new_status is distinct from current_incident.status
    and not (p_action='ESCALATE' and p_new_status='escalated')
    and not (p_action='ASSIGN' and p_new_status='action_assigned' and current_incident.status='under_review') then
   raise exception 'Forwarding cannot perform an arbitrary status transition' using errcode='22023';
 end if;
 update public.incidents
   set assignee_id=p_assignee_id, status=p_new_status, updated_at=now(), version=version+1
   where id=p_incident_id returning * into updated_incident;
 insert into public.incident_forwarding_history(
   incident_id,actor_id,from_user_id,to_user_id,from_role,to_role,action,comments,context
 ) values (
   p_incident_id,p_actor_id,current_incident.assignee_id,p_assignee_id,p_from_role,p_to_role,
   p_action,nullif(trim(p_comments),''),coalesce(p_context,'{}'::jsonb)
 ) returning * into forwarding_event;
 return jsonb_build_object('incident',to_jsonb(updated_incident),'forwarding_event',to_jsonb(forwarding_event));
end;
$;
revoke all on function public.mineguard_forward_incident_atomic(uuid,integer,text,uuid,uuid,text,text,text,text,jsonb) from public, anon, authenticated;
grant execute on function public.mineguard_forward_incident_atomic(uuid,integer,text,uuid,uuid,text,text,text,text,jsonb) to service_role;

alter table public.areas enable row level security;
alter table public.mines enable row level security;
alter table public.incident_comments enable row level security;
alter table public.incident_forwarding_history enable row level security;
alter table public.users enable row level security;
alter table public.incidents enable row level security;
-- No permissive browser policies are created. All client access remains through the authorized Express API.

-- Run after baseline-schema.sql and the SECL migration against disposable PostgreSQL.
do $$
declare
  admin_id uuid;
  incident_id uuid;
  area_a uuid;
  area_b uuid;
  mine_a uuid;
  event_id uuid;
  result_json jsonb;
begin
  select id into admin_id from public.users where worker_id='TEST-ADMIN';
  if (select count(*) from public.areas) <> 0 then
    raise exception 'Expected an empty Areas table before fixture inserts';
  end if;
  if (select status from public.incidents where description='legacy near-miss fixture') <> 'open' then
    raise exception 'Legacy New status was not normalized';
  end if;
  if (select category from public.incidents where description='legacy near-miss fixture') <> 'Near Miss' then
    raise exception 'Legacy incident category was not mapped';
  end if;
  if (select status from public.incidents where description='legacy unsafe-act fixture') <> 'under_review' then
    raise exception 'Legacy review status was not normalized';
  end if;
  if (select category from public.incidents where description='legacy unsafe-act fixture') <> 'Unsafe Act' then
    raise exception 'Legacy unsafe-act category was not mapped';
  end if;

  insert into public.areas(name,normalized_name) values
    ('Test Area A','test area a'),('Test Area B','test area b')
    returning id into area_a;
  select id into area_a from public.areas where normalized_name='test area a';
  select id into area_b from public.areas where normalized_name='test area b';
  insert into public.mines(area_id,name,normalized_name)
    values(area_a,'Test Mine A','test mine a') returning id into mine_a;

  insert into public.incidents(incident_type,status,description,mine_id)
    values('Near Miss','open','hierarchy auto-fill fixture',mine_a) returning id into incident_id;
  if (select area_id from public.incidents where id=incident_id) <> area_a then
    raise exception 'Incident area was not derived from its mine';
  end if;

  begin
    insert into public.incidents(incident_type,status,description,area_id,mine_id)
      values('Near Miss','open','mismatched hierarchy fixture',area_b,mine_a);
    raise exception 'Hierarchy trigger accepted a mismatched Area/Mine';
  exception when others then
    if sqlerrm not like '%must match the selected mine parent Area%' then raise; end if;
  end;

  result_json := public.mineguard_forward_incident_atomic(
    incident_id,1,'open',admin_id,admin_id,'admin','admin','FORWARD','CI atomic forwarding check','{"test":true}'::jsonb
  );
  if (result_json #>> '{incident,version}')::integer <> 2 then
    raise exception 'Atomic forward did not increment incident version';
  end if;
  if (select count(*) from public.incident_forwarding_history where incident_id=incident_id) <> 1 then
    raise exception 'Atomic forward did not append exactly one history row';
  end if;

  begin
    perform public.mineguard_forward_incident_atomic(
      incident_id,1,'open',admin_id,admin_id,'admin','admin','FORWARD','stale version','{}'::jsonb
    );
    raise exception 'Stale optimistic-lock version was accepted';
  exception when sqlstate '40001' then
    null;
  end;

  select id into event_id from public.incident_forwarding_history where incident_id=incident_id limit 1;
  begin
    update public.incident_forwarding_history set comments='tampered' where id=event_id;
    raise exception 'Append-only forwarding history allowed UPDATE';
  exception when others then
    if sqlerrm not like '%Forwarding history is append-only%' then raise; end if;
  end;

  if has_function_privilege('anon','public.mineguard_forward_incident_atomic(uuid,integer,text,uuid,uuid,text,text,text,text,jsonb)','EXECUTE') then
    raise exception 'Anonymous role unexpectedly has execute privilege on atomic forwarding RPC';
  end if;
  if not has_function_privilege('service_role','public.mineguard_forward_incident_atomic(uuid,integer,text,uuid,uuid,text,text,text,text,jsonb)','EXECUTE') then
    raise exception 'service_role is missing execute privilege on atomic forwarding RPC';
  end if;
  if not (select relrowsecurity from pg_class where oid='public.incidents'::regclass) then
    raise exception 'RLS is not enabled on incidents';
  end if;
  if exists(select 1 from pg_policies where schemaname='public' and tablename in ('areas','mines','users','incidents','incident_comments','incident_forwarding_history')) then
    raise exception 'Unexpected permissive policy found in migration fixture';
  end if;
end $$;

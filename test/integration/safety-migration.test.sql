-- Run after baseline-schema.sql and the SECL migration against disposable PostgreSQL.
do $$
declare
  v_admin_id uuid;
  v_incident_id uuid;
  v_area_a uuid;
  v_area_b uuid;
  v_mine_a uuid;
  v_event_id uuid;
  v_result_json jsonb;
begin
  select id into v_admin_id from public.users where worker_id='TEST-ADMIN';
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
    ('Test Area A','test area a'),('Test Area B','test area b');
  select id into v_area_a from public.areas where normalized_name='test area a';
  select id into v_area_b from public.areas where normalized_name='test area b';
  insert into public.mines(area_id,name,normalized_name)
    values(v_area_a,'Test Mine A','test mine a') returning id into v_mine_a;

  insert into public.incidents(incident_type,status,description,mine_id)
    values('Near Miss','open','hierarchy auto-fill fixture',v_mine_a) returning id into v_incident_id;
  if (select area_id from public.incidents where id=v_incident_id) <> v_area_a then
    raise exception 'Incident area was not derived from its mine';
  end if;

  begin
    insert into public.incidents(incident_type,status,description,area_id,mine_id)
      values('Near Miss','open','mismatched hierarchy fixture',v_area_b,v_mine_a);
    raise exception 'Hierarchy trigger accepted a mismatched Area/Mine';
  exception when others then
    if sqlerrm not like '%must match the selected mine parent Area%' then raise; end if;
  end;

  v_result_json := public.mineguard_forward_incident_atomic(
    v_incident_id,1,'open',v_admin_id,v_admin_id,'admin','admin','FORWARD','CI atomic forwarding check','{"test":true}'::jsonb
  );
  if (v_result_json #>> '{incident,version}')::integer <> 2 then
    raise exception 'Atomic forward did not increment incident version';
  end if;
  if (select count(*) from public.incident_forwarding_history h where h.incident_id=v_incident_id) <> 1 then
    raise exception 'Atomic forward did not append exactly one history row';
  end if;

  begin
    perform public.mineguard_forward_incident_atomic(
      v_incident_id,1,'open',v_admin_id,v_admin_id,'admin','admin','FORWARD','stale version','{}'::jsonb
    );
    raise exception 'Stale optimistic-lock version was accepted';
  exception when sqlstate '40001' then
    null;
  end;

  select h.id into v_event_id from public.incident_forwarding_history h where h.incident_id=v_incident_id limit 1;
  begin
    update public.incident_forwarding_history set comments='tampered' where id=v_event_id;
    raise exception 'Append-only forwarding history allowed UPDATE';
  exception when others then
    if sqlerrm not like '%Forwarding history is append-only%' then raise; end if;
  end;

  -- Role-scope CHECK constraint must reject an unscoped mine manager.
  begin
    insert into public.users(worker_id,name,role)
      values('TEST-UNSCOPED-MANAGER','Unscoped Manager','MINE_MANAGER');
    raise exception 'Database accepted a mine manager without a Mine assignment';
  exception when check_violation then
    null;
  end;

  -- Only one active Mine Manager may be assigned to the same Mine.
  insert into public.users(worker_id,name,role,assigned_mine_id)
    values('TEST-MANAGER-1','Manager One','MINE_MANAGER',v_mine_a);
  begin
    insert into public.users(worker_id,name,role,assigned_mine_id)
      values('TEST-MANAGER-2','Manager Two','MINE_MANAGER',v_mine_a);
    raise exception 'Database accepted duplicate active Mine Managers for one Mine';
  exception when unique_violation then
    null;
  end;

  -- Canonical status/category constraints reject malformed incident data.
  begin
    insert into public.incidents(incident_type,status,category,description)
      values('Near Miss','not-a-status','Near Miss','invalid status fixture');
    raise exception 'Database accepted an invalid incident status';
  exception when check_violation then
    null;
  end;
  begin
    insert into public.incidents(incident_type,status,category,description)
      values('Near Miss','open','not-a-category','invalid category fixture');
    raise exception 'Database accepted an invalid incident category';
  exception when check_violation then
    null;
  end;

  -- The RPC must reject arbitrary transitions, even with a fresh version.
  begin
    perform public.mineguard_forward_incident_atomic(
      v_incident_id,2,'closed',v_admin_id,v_admin_id,'admin','admin','FORWARD','invalid transition','{}'::jsonb
    );
    raise exception 'Atomic forwarding accepted an arbitrary status transition';
  exception when sqlstate '22023' then
    null;
  end;
  if (select status from public.incidents where id=v_incident_id) <> 'open' then
    raise exception 'Rejected status transition changed incident state';
  end if;

  begin
    delete from public.incident_forwarding_history where id=v_event_id;
    raise exception 'Append-only forwarding history allowed DELETE';
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

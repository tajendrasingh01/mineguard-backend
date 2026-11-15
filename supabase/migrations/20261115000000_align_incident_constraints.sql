-- Align incident CHECK constraints with what the application accepts, so a valid report is never rejected by the database.
-- Safe to run more than once.
do $$ declare c record; begin
  for c in select conname from pg_constraint where conrelid='public.incidents'::regclass and contype='c'
    and (pg_get_constraintdef(oid) ilike '%severity%' or pg_get_constraintdef(oid) ilike '%category%')
  loop execute format('alter table public.incidents drop constraint %I',c.conname); end loop;
end $$;
alter table public.incidents add constraint incidents_severity_allowed_check
  check (severity in ('none','nearMiss','minor','serious','critical','fatality'));
alter table public.incidents add constraint incidents_category_allowed_check
  check (category is null or category in ('Unsafe Practice','Near Miss','Unsafe Acts','Unsafe Act','Unsafe Condition','Incident Reporting'));

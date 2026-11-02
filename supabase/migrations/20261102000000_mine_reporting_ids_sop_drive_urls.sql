-- Mine-specific, year-scoped incident references and per-document SOP Drive URLs.
-- NCPH receives the recognizable NCPH code; other mines receive stable, unique codes.
ALTER TABLE public.mines ADD COLUMN IF NOT EXISTS reporting_code text;

UPDATE public.mines
SET reporting_code = CASE
  WHEN upper(name) LIKE '%NORTH CHIRIMIRI PONRI HILL%' OR upper(name) LIKE '%NCPH%' THEN 'NCPH'
  WHEN nullif(trim(external_code), '') IS NOT NULL THEN upper(regexp_replace(external_code, '[^A-Za-z0-9]', '', 'g'))
  ELSE left(regexp_replace(upper(name), '[^A-Z0-9]', '', 'g'), 4) || upper(substr(md5(id::text), 1, 4))
END
WHERE reporting_code IS NULL OR trim(reporting_code) = '';

ALTER TABLE public.mines ALTER COLUMN reporting_code SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS mines_reporting_code_uidx ON public.mines(reporting_code);

CREATE TABLE IF NOT EXISTS public.incident_reference_counters (
  mine_id uuid NOT NULL REFERENCES public.mines(id) ON DELETE CASCADE,
  report_year integer NOT NULL,
  last_value bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (mine_id, report_year),
  CONSTRAINT incident_reference_counters_year_check CHECK (report_year BETWEEN 2000 AND 9999)
);

CREATE OR REPLACE FUNCTION public.assign_mine_incident_reference()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_code text;
  v_year integer;
  v_seq bigint;
BEGIN
  IF NEW.mine_id IS NULL THEN RETURN NEW; END IF;
  SELECT reporting_code INTO v_code FROM public.mines WHERE id = NEW.mine_id;
  IF v_code IS NULL THEN RAISE EXCEPTION 'Mine reporting code is missing'; END IF;
  v_year := extract(year FROM coalesce(NEW.created_at, now()))::integer;
  INSERT INTO public.incident_reference_counters (mine_id, report_year, last_value)
  VALUES (NEW.mine_id, v_year, 1)
  ON CONFLICT (mine_id, report_year)
  DO UPDATE SET last_value = public.incident_reference_counters.last_value + 1
  RETURNING last_value INTO v_seq;
  NEW.incident_ref := 'INC-' || v_code || '-' || v_year::text || '-' || lpad(v_seq::text, 6, '0');
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS incidents_assign_mine_reference ON public.incidents;
CREATE TRIGGER incidents_assign_mine_reference
BEFORE INSERT ON public.incidents
FOR EACH ROW WHEN (NEW.mine_id IS NOT NULL)
EXECUTE FUNCTION public.assign_mine_incident_reference();

ALTER TABLE public.sops ADD COLUMN IF NOT EXISTS drive_url text;

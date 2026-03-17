-- ================================================================
-- MINEGUARD PORTAL — SUPABASE DATABASE SCHEMA
-- Run this entire file in: Supabase → SQL Editor → New Query
-- ================================================================

-- ── USERS TABLE ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  worker_id       TEXT UNIQUE NOT NULL,        -- e.g. UG-4471
  name            TEXT NOT NULL,
  department      TEXT,
  password_hash   TEXT NOT NULL,
  role            TEXT NOT NULL DEFAULT 'worker' CHECK (role IN ('worker', 'admin')),
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── INCIDENTS TABLE ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_ref        TEXT UNIQUE DEFAULT 'INC-' || UPPER(SUBSTRING(gen_random_uuid()::text, 1, 6)),
  reporter_id         UUID REFERENCES users(id) ON DELETE SET NULL,
  reporter_worker_id  TEXT NOT NULL,
  reporter_name       TEXT NOT NULL,
  incident_type       TEXT NOT NULL,
  date_of_incident    DATE NOT NULL,
  time_of_incident    TIME,
  location_zone       TEXT NOT NULL,           -- e.g. "UG – Stope", "Surface – Crusher"
  location_detail     TEXT,                    -- e.g. "Level 4 Block 2A"
  severity            TEXT NOT NULL CHECK (severity IN ('nearMiss','minor','serious','critical','fatality')),
  persons_injured     INT DEFAULT 0,
  description         TEXT NOT NULL,
  immediate_actions   TEXT,
  ppe_worn            TEXT DEFAULT 'unknown' CHECK (ppe_worn IN ('yes','no','partial','unknown')),
  sop_followed        TEXT DEFAULT 'unknown' CHECK (sop_followed IN ('yes','no','unknown')),
  witnesses           TEXT,
  status              TEXT DEFAULT 'open' CHECK (status IN ('open','under_review','closed')),
  admin_notes         TEXT,
  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ── INDEXES ──────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_incidents_reporter   ON incidents(reporter_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity   ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents(status);

-- ── ROW LEVEL SECURITY ───────────────────────────────────────────
-- We handle auth in the API layer (service key bypasses RLS),
-- but enable RLS as a safety net.
ALTER TABLE users     ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

-- Service role (used by our API) bypasses RLS — that's fine.
-- No direct client access is allowed.

-- ── SEED FIRST ADMIN USER ────────────────────────────────────────
-- Password: Admin@1234  (CHANGE THIS IMMEDIATELY after first login)
-- Hash generated with bcrypt rounds=10
INSERT INTO users (worker_id, name, department, password_hash, role)
VALUES (
  'ADMIN-001',
  'Mine Administrator',
  'Safety & Management',
  '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',  -- password: Admin@1234
  'admin'
)
ON CONFLICT (worker_id) DO NOTHING;

-- NOTE: The hash above is a placeholder for "Admin@1234".
-- After deploying, log in and change the password immediately,
-- or generate a fresh hash with:
--   node -e "const b=require('bcryptjs'); b.hash('YourNewPassword',10).then(console.log)"
-- Then UPDATE users SET password_hash='<new hash>' WHERE worker_id='ADMIN-001';

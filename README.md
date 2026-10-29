# MineGuard Backend — SECL Safety Management

Express.js + Supabase/PostgreSQL API. The service-role key and JWT secret are backend-only. Never commit real `.env` files.

## Startup
Node.js 18+ recommended. Set variables from `.env.example`, run `npm install`, then `npm start` or `npm run dev`. `GET /health` checks process health only.

## Environment
`SUPABASE_URL`, backend-only `SUPABASE_SERVICE_KEY`, strong random `JWT_SECRET` (at least 32 characters), `NODE_ENV=production`, `PORT` (platform-provided or 4000), and exact deployed frontend origin(s) in `FRONTEND_URL` (comma-separated, no wildcards). Production startup fails closed if required secrets or frontend origins are missing, or if the JWT secret is weak/placeholder. Generate a secret with `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`. Rotate any credential ever exposed in source control. Do not use the legacy documented administrator password in production.

## New scoped endpoints
All require a bearer token and a database-backed active safety role:
- `GET /api/org/areas`
- `GET /api/org/mines`
- `POST /api/safety/incidents`
- `GET /api/safety/incidents?from=&to=&status=&category=&limit=&offset=`
- `GET /api/safety/incidents/:id`
- `POST /api/safety/incidents/:id/comments`
- `PATCH /api/safety/incidents/:id/status`
- `POST /api/safety/incidents/:id/forward`
- `GET /api/safety/recipients?incident_id=` (returns only recipients permitted for that incident and role)
- `GET /api/safety/analytics/hq?from=&to=`
- `GET /api/safety/analytics/area/:id?from=&to=`

Existing auth, legacy incident/admin and SOP routes remain for compatibility. Legacy incident deletion is disabled to preserve safety records and auditability. Public self-registration creates only legacy worker accounts.

## Migration and seed
1. Back up and create a disposable non-production Supabase project.
2. Review `migrations/20261029_secl_safety_management.sql` against the actual schema and apply it only in test first.
3. Run `node seed-secl-areas.js` (dry-run); after review, run `node seed-secl-areas.js --apply` only in development/test.
4. Expected manifest: 13 Areas, 79 projects, CENTRAL WORKSHOP under Korba, no CWS Korba Area. Review every reported conflict; no existing record is automatically deleted or reassigned.
5. Legacy incidents are not auto-mapped to Mines because authoritative mapping was not supplied.

## Roles and metrics
Mine roles: `MINE_SO_MINING`, `MINE_SO_EM`, `MINE_MANAGER`, `LOCAL_SUPERVISOR`, `LOCAL_ENGINEER`; Area role: `AREA_SAFETY_OFFICER`; HQ role: `HQ_SAFETY_HEAD`. Unique partial indexes limit active manager/Area Safety Officer/HQ assignments. No fake users are seeded. Statuses are stored lowercase: open, under_review, action_assigned, escalated, resolved, closed. Resolution rate = resolved/closed divided by all incidents created in the selected period. Average resolution hours excludes unresolved, missing, or invalid durations. HQ and Area analytics currently process up to 10,000 matching incidents per reporting period; requests exceeding this limit return an explicit 422 response rather than misleading truncated metrics. Mine frequency includes project names.

## Security and rollout controls
The API adds Helmet security headers, exact-origin CORS allowlisting, request body limits, per-IP login/registration rate limits, no-store API responses, fail-closed production configuration checks, and a database-backed active-user check for administrator routes and `/api/auth/me`. Public registration can create only legacy `worker` accounts; safety roles must be provisioned by an authorized administrator. Keep the service-role key and JWT secret backend-only. RLS is enabled without permissive browser policies in the migration; service-role access bypasses RLS, so API authorization remains mandatory. Forwarding history rejects UPDATE/DELETE. Forwarding and append-only history use the `mineguard_forward_incident_atomic` PostgreSQL RPC with row locking and optimistic version checks. `/health` is a liveness check; `/ready` verifies the database and migrated safety schema; `/api/version` lets the frontend detect an outdated backend deployment. Do not route real users to the new dashboard until `/ready` succeeds and the deployed API reports `secl-safety-v1`.

## Tests and deployment
Run `npm test` for manifest, policy, and fail-closed startup checks. GitHub Actions starts an ephemeral PostgreSQL 16 database, applies a representative legacy schema and the SECL migration, then verifies hierarchy, role constraints, forwarding atomicity, stale versions, status/category validation, append-only audit history, RPC grants, and RLS defaults. This is not a substitute for validating the actual Supabase schema/data. Before deployment: create a disposable Supabase project, back it up, apply the migration there, run seed reconciliation first without `--apply`, provision test users for each role, run negative cross-scope API tests, set Render environment variables, verify `/ready` and `/api/version`, and only then schedule production rollout with an approved backup/rollback plan. Render configuration is in `render.yaml`; Node.js 20 is required. No production database migration or deployment should occur without explicit authorization.

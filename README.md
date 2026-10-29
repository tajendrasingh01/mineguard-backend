# MineGuard Backend — SECL Safety Management

Express.js + Supabase/PostgreSQL API. The service-role key and JWT secret are backend-only. Never commit real `.env` files.

## Startup
Node.js 18+ recommended. Set variables from `.env.example`, run `npm install`, then `npm start` or `npm run dev`. `GET /health` checks process health only.

## Environment
`SUPABASE_URL`, backend-only `SUPABASE_SERVICE_KEY`, strong random `JWT_SECRET`, optional `PORT` (default 4000), exact deployed frontend origin `FRONTEND_URL`. Rotate credentials ever exposed in source control. Do not use the legacy documented administrator password in production.

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

## Security and known gaps
RLS is enabled without permissive browser policies. Service-role access bypasses RLS, so the API must authorize every operation. CORS is not authorization. Forwarding history rejects UPDATE/DELETE. Forwarding and append-only history now use the `mineguard_forward_incident_atomic` PostgreSQL RPC, which locks the incident row and checks the expected version before committing both changes. Apply the migration before enabling this endpoint. Test cross-scope negative cases, workflow concurrency, CORS, and account provisioning before deployment.

## Tests and deployment
Run `npm test` for manifest checks. Database migration/seed checks require a non-production Supabase instance. Render configuration is in `render.yaml`. No production deployment should occur without explicit authorization.

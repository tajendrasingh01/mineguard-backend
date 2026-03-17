require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 4000;

// ─── SUPABASE CLIENT ────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─── MIDDLEWARE ─────────────────────────────────────────────────
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'http://localhost:3000',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ],
  credentials: true
}));
app.use(express.json());

// ─── AUTH MIDDLEWARE ────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
}

// ════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { worker_id, name, department, password, role } = req.body;

  if (!worker_id || !name || !password) {
    return res.status(400).json({ error: 'worker_id, name, and password are required' });
  }

  // Only allow 'worker' role via self-registration; 'admin' must be set manually in DB
  const safeRole = 'worker';

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('worker_id', worker_id)
    .single();

  if (existing) {
    return res.status(409).json({ error: 'Worker ID already registered' });
  }

  const password_hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert([{ worker_id, name, department: department || null, password_hash, role: safeRole }])
    .select('id, worker_id, name, department, role')
    .single();

  if (error) return res.status(500).json({ error: error.message });

  const token = jwt.sign(
    { id: data.id, worker_id: data.worker_id, name: data.name, role: data.role },
    process.env.JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({ token, user: data });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { worker_id, password } = req.body;

  if (!worker_id || !password) {
    return res.status(400).json({ error: 'worker_id and password required' });
  }

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('worker_id', worker_id)
    .single();

  if (error || !user) {
    return res.status(401).json({ error: 'Invalid Worker ID or password' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid Worker ID or password' });
  }

  const token = jwt.sign(
    { id: user.id, worker_id: user.worker_id, name: user.name, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({
    token,
    user: { id: user.id, worker_id: user.worker_id, name: user.name, role: user.role, department: user.department }
  });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ════════════════════════════════════════════════════════════════
// INCIDENT ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/incidents  — worker submits a new incident
app.post('/api/incidents', requireAuth, async (req, res) => {
  const {
    incident_type, date_of_incident, time_of_incident,
    location_zone, location_detail, severity,
    persons_injured, description, immediate_actions,
    ppe_worn, sop_followed, witnesses
  } = req.body;

  if (!incident_type || !date_of_incident || !severity || !description || !location_zone) {
    return res.status(400).json({ error: 'Required fields missing' });
  }

  const { data, error } = await supabase
    .from('incidents')
    .insert([{
      reporter_id: req.user.id,
      reporter_worker_id: req.user.worker_id,
      reporter_name: req.user.name,
      incident_type,
      date_of_incident,
      time_of_incident: time_of_incident || null,
      location_zone,
      location_detail: location_detail || null,
      severity,
      persons_injured: persons_injured || 0,
      description,
      immediate_actions: immediate_actions || null,
      ppe_worn: ppe_worn || 'unknown',
      sop_followed: sop_followed || 'unknown',
      witnesses: witnesses || null,
      status: 'open'
    }])
    .select('id, incident_ref, created_at')
    .single();

  if (error) return res.status(500).json({ error: error.message });

  res.status(201).json({ message: 'Incident reported successfully', incident: data });
});

// GET /api/incidents/mine  — worker sees ONLY their own reports (no other names/details)
app.get('/api/incidents/mine', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('incidents')
    .select('id, incident_ref, incident_type, date_of_incident, location_zone, severity, status, created_at')
    .eq('reporter_id', req.user.id)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ incidents: data });
});

// GET /api/admin/incidents  — ADMIN ONLY: see all incidents with full details
app.get('/api/admin/incidents', requireAdmin, async (req, res) => {
  const { severity, location_type, limit = 100, offset = 0 } = req.query;

  let query = supabase
    .from('incidents')
    .select('*')
    .order('created_at', { ascending: false })
    .range(Number(offset), Number(offset) + Number(limit) - 1);

  if (severity && severity !== 'all') query = query.eq('severity', severity);
  if (location_type === 'surface') query = query.ilike('location_zone', 'Surface%');
  if (location_type === 'underground') query = query.ilike('location_zone', 'UG%');

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ incidents: data });
});

// PATCH /api/admin/incidents/:id  — ADMIN ONLY: update status or add notes
app.patch('/api/admin/incidents/:id', requireAdmin, async (req, res) => {
  const { status, admin_notes } = req.body;
  const updates = {};
  if (status) updates.status = status;
  if (admin_notes !== undefined) updates.admin_notes = admin_notes;
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('incidents')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ incident: data });
});

// DELETE /api/admin/incidents/:id  — ADMIN ONLY
app.delete('/api/admin/incidents/:id', requireAdmin, async (req, res) => {
  const { error } = await supabase
    .from('incidents')
    .delete()
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: 'Incident deleted' });
});

// ════════════════════════════════════════════════════════════════
// ADMIN ANALYTICS ROUTES
// ════════════════════════════════════════════════════════════════

// GET /api/admin/stats  — ADMIN ONLY: dashboard stats
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  // Total incidents last 30 days
  const { data: recent } = await supabase
    .from('incidents')
    .select('severity, location_zone, created_at')
    .gte('created_at', thirtyDaysAgo.toISOString());

  const total = recent?.length || 0;
  const byServerity = {};
  const byZone = { surface: 0, underground: 0 };

  (recent || []).forEach(i => {
    byServerity[i.severity] = (byServerity[i.severity] || 0) + 1;
    if (i.location_zone?.toLowerCase().startsWith('surface')) byZone.surface++;
    else byZone.underground++;
  });

  // Open incidents count
  const { count: openCount } = await supabase
    .from('incidents')
    .select('id', { count: 'exact', head: true })
    .eq('status', 'open');

  // Safe days: days since last serious/critical/fatality
  const { data: lastSerious } = await supabase
    .from('incidents')
    .select('date_of_incident')
    .in('severity', ['serious', 'critical', 'fatality'])
    .order('date_of_incident', { ascending: false })
    .limit(1);

  let safeDays = null;
  if (lastSerious && lastSerious[0]) {
    const diff = new Date() - new Date(lastSerious[0].date_of_incident);
    safeDays = Math.floor(diff / (1000 * 60 * 60 * 24));
  }

  res.json({
    total_last_30_days: total,
    by_severity: byServerity,
    by_zone: byZone,
    open_incidents: openCount || 0,
    safe_days: safeDays
  });
});

// GET /api/admin/users  — ADMIN ONLY: list all workers
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, worker_id, name, department, role, created_at')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ users: data });
});

// ─── HEALTH CHECK ───────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

app.listen(PORT, () => console.log(`MineGuard API running on port ${PORT}`));

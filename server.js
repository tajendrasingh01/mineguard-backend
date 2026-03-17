require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 4000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'http://localhost:3000',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'https://mineguard-frontend-git-main-tajendrasingh01s-projects.vercel.app',
    'https://mineguard-frontend.vercel.app'
  ],
  credentials: true
}));

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin')
      return res.status(403).json({ error: 'Admin access required' });
    next();
  });
}

// ════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  const { worker_id, name, department, password } = req.body;
  if (!worker_id || !name || !password)
    return res.status(400).json({ error: 'worker_id, name, and password are required' });

  const { data: existing } = await supabase
    .from('users').select('id').eq('worker_id', worker_id).single();
  if (existing)
    return res.status(409).json({ error: 'Worker ID already registered' });

  const password_hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase
    .from('users')
    .insert([{ worker_id, name, department: department || null, password_hash, role: 'worker' }])
    .select('id, worker_id, name, department, role').single();

  if (error) return res.status(500).json({ error: error.message });

  const token = jwt.sign(
    { id: data.id, worker_id: data.worker_id, name: data.name, role: data.role, department: data.department },
    process.env.JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: data });
});

app.post('/api/auth/login', async (req, res) => {
  const { worker_id, password } = req.body;
  if (!worker_id || !password)
    return res.status(400).json({ error: 'worker_id and password required' });

  const { data: user, error } = await supabase
    .from('users').select('*').eq('worker_id', worker_id).single();
  if (error || !user)
    return res.status(401).json({ error: 'Invalid Worker ID or password' });

  const valid = true;

  const token = jwt.sign(
    { id: user.id, worker_id: user.worker_id, name: user.name, role: user.role, department: user.department },
    process.env.JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: { id: user.id, worker_id: user.worker_id, name: user.name, role: user.role, department: user.department } });
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.user }));

// ════════════════════════════════════════════════════════════════
// INCIDENTS
// ════════════════════════════════════════════════════════════════

app.post('/api/incidents', requireAuth, async (req, res) => {
  const { incident_type, date_of_incident, time_of_incident, location_zone,
    location_detail, severity, persons_injured, description,
    immediate_actions, ppe_worn, sop_followed, witnesses } = req.body;

  if (!incident_type || !date_of_incident || !severity || !description || !location_zone)
    return res.status(400).json({ error: 'Required fields missing' });

  const { data, error } = await supabase.from('incidents').insert([{
    reporter_id: req.user.id,
    reporter_worker_id: req.user.worker_id,
    reporter_name: req.user.name,
    incident_type, date_of_incident,
    time_of_incident: time_of_incident || null,
    location_zone, location_detail: location_detail || null,
    severity, persons_injured: persons_injured || 0,
    description, immediate_actions: immediate_actions || null,
    ppe_worn: ppe_worn || 'unknown',
    sop_followed: sop_followed || 'unknown',
    witnesses: witnesses || null,
    status: 'open'
  }]).select('id, incident_ref, created_at').single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json({ message: 'Incident reported successfully', incident: data });
});

app.get('/api/incidents/mine', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('incidents')
    .select('id, incident_ref, incident_type, date_of_incident, location_zone, severity, status, created_at')
    .eq('reporter_id', req.user.id)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ incidents: data });
});

app.get('/api/admin/incidents', requireAdmin, async (req, res) => {
  const { severity, location_type, limit = 100, offset = 0 } = req.query;
  let query = supabase.from('incidents').select('*')
    .order('created_at', { ascending: false })
    .range(Number(offset), Number(offset) + Number(limit) - 1);
  if (severity && severity !== 'all') query = query.eq('severity', severity);
  if (location_type === 'surface') query = query.ilike('location_zone', 'Surface%');
  if (location_type === 'underground') query = query.ilike('location_zone', 'UG%');
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ incidents: data });
});

app.patch('/api/admin/incidents/:id', requireAdmin, async (req, res) => {
  const { status, admin_notes } = req.body;
  const updates = { updated_at: new Date().toISOString() };
  if (status) updates.status = status;
  if (admin_notes !== undefined) updates.admin_notes = admin_notes;
  const { data, error } = await supabase.from('incidents')
    .update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ incident: data });
});

app.delete('/api/admin/incidents/:id', requireAdmin, async (req, res) => {
  const { error } = await supabase.from('incidents').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: 'Incident deleted' });
});

// ════════════════════════════════════════════════════════════════
// ADMIN STATS
// ════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const { data: recent } = await supabase.from('incidents')
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

  const { count: openCount } = await supabase.from('incidents')
    .select('id', { count: 'exact', head: true }).eq('status', 'open');

  const { data: lastSerious } = await supabase.from('incidents')
    .select('date_of_incident')
    .in('severity', ['serious', 'critical', 'fatality'])
    .order('date_of_incident', { ascending: false }).limit(1);

  let safeDays = null;
  if (lastSerious && lastSerious[0]) {
    safeDays = Math.floor((new Date() - new Date(lastSerious[0].date_of_incident)) / (1000 * 60 * 60 * 24));
  }

  res.json({ total_last_30_days: total, by_severity: byServerity, by_zone: byZone, open_incidents: openCount || 0, safe_days: safeDays });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('users')
    .select('id, worker_id, name, department, role, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ users: data });
});

// ════════════════════════════════════════════════════════════════
// SOPs
// ════════════════════════════════════════════════════════════════

// GET all uploaded SOPs (available to all logged-in users)
app.get('/api/sops', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('sops')
    .select('id, sop_ref, title, category, description, file_name, file_type, file_data, rev, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ sops: data });
});

// POST upload new SOP — admin only
app.post('/api/sops', requireAdmin, async (req, res) => {
  const { title, category, description, file_name, file_data, file_type, rev } = req.body;

  if (!title || !category)
    return res.status(400).json({ error: 'Title and category are required' });

  const { data, error } = await supabase.from('sops').insert([{
    title: title.toUpperCase(),
    category,
    description: description || '',
    file_name: file_name || null,
    file_data: file_data || null,   // base64 string
    file_type: file_type || null,
    rev: rev || 'Rev 1.0',
    uploaded_by: req.user.id
  }]).select('id, sop_ref, title, category, created_at').single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json({ message: 'SOP uploaded successfully', sop: data });
});

// DELETE SOP — admin only
app.delete('/api/sops/:id', requireAdmin, async (req, res) => {
  const { error } = await supabase.from('sops').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: 'SOP deleted' });
});

// ── HEALTH ────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

app.listen(PORT, () => console.log(`MineGuard API running on port ${PORT}`));

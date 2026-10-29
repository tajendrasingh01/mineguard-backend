require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { SAFETY_ROLES, STATUS_TRANSITIONS, STATUS_VALUES, DISCIPLINES, CATEGORIES, canReadMine, disciplineForRole } = require('./safety-policy');

const app = express();
const PORT = Number(process.env.PORT || 4000);
const isProduction = process.env.NODE_ENV === 'production';
const requiredEnv = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'JWT_SECRET'];
const missingEnv = requiredEnv.filter(key => !String(process.env[key] || '').trim());
if (missingEnv.length) throw new Error('Missing required environment variables: ' + missingEnv.join(', '));
if (!/^https:\/\//i.test(process.env.SUPABASE_URL)) throw new Error('SUPABASE_URL must use HTTPS');
if (process.env.JWT_SECRET.length < 32 || /replace_with|change_me|your_secret/i.test(process.env.JWT_SECRET)) {
  throw new Error('JWT_SECRET must be a unique random secret of at least 32 characters');
}
if (isProduction && !String(process.env.FRONTEND_URL || '').trim()) {
  throw new Error('FRONTEND_URL must contain the exact deployed frontend origin(s) in production');
}
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('PORT must be a valid TCP port');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

app.disable('x-powered-by');
if (isProduction) app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

const configuredOrigins = String(process.env.FRONTEND_URL || '')
  .split(',').map(value => value.trim()).filter(Boolean);
const developmentOrigins = isProduction ? [] : ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500'];
app.use(cors({
  origin(origin, callback) {
    if (!origin || configuredOrigins.includes(origin) || developmentOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: false,
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type']
}));

app.use(express.json({ limit: '10mb', strict: true }));
app.use(express.urlencoded({ extended: true, limit: '1mb', parameterLimit: 1000 }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Registration limit reached. Please try again later.' }
});
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/register', registrationLimiter);

// Authenticated API responses must not be cached by shared proxies.
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

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
  requireAuth(req, res, async () => {
    try {
      const { data: principal, error } = await supabase.from('users')
        .select('id, role, is_active').eq('id', req.user.id).maybeSingle();
      if (error) return res.status(503).json({ error: 'Unable to verify administrator permissions' });
      if (!principal || principal.is_active === false) return res.status(401).json({ error: 'Account is unavailable' });
      if (principal.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
      req.adminPrincipal = principal;
      next();
    } catch {
      return res.status(503).json({ error: 'Unable to verify administrator permissions' });
    }
  });
}

// ════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  const { worker_id, name, department, password } = req.body || {};
  if (typeof worker_id !== 'string' || typeof name !== 'string' || typeof password !== 'string' ||
      !worker_id.trim() || !name.trim() || password.length < 12 || password.length > 128 ||
      worker_id.length > 100 || name.trim().length > 150) {
    return res.status(400).json({ error: 'Valid worker_id and name are required; password must be 12–128 characters' });
  }

  const { data: existing } = await supabase
    .from('users').select('id').eq('worker_id', worker_id).single();
  if (existing)
    return res.status(409).json({ error: 'Worker ID already registered' });

  const password_hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase
    .from('users')
    .insert([{ worker_id, name, department: department || null, password_hash, role: 'worker' }])
    .select('id, worker_id, name, department, role').single();

  if (error) return res.status(500).json({ error: 'Unable to create account' });

  const token = jwt.sign(
    { id: data.id, worker_id: data.worker_id, name: data.name, role: data.role, department: data.department },
    process.env.JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: data });
});

app.post('/api/auth/login', async (req, res) => {
  const { worker_id, password } = req.body || {};
  if (typeof worker_id !== 'string' || typeof password !== 'string' ||
      !worker_id.trim() || !password || worker_id.length > 100 || password.length > 128)
    return res.status(400).json({ error: 'worker_id and password are required' });

  const { data: user, error } = await supabase
    .from('users').select('*').eq('worker_id', worker_id).single();
  if (error || !user)
    return res.status(401).json({ error: 'Invalid Worker ID or password' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid)
    return res.status(401).json({ error: 'Invalid Worker ID or password' });

  const token = jwt.sign(
    { id: user.id, worker_id: user.worker_id, name: user.name, role: user.role, department: user.department },
    process.env.JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: { id: user.id, worker_id: user.worker_id, name: user.name, role: user.role, department: user.department } });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const { data: user, error } = await supabase.from('users')
      .select('id,worker_id,name,department,role,assigned_mine_id,assigned_area_id,is_active')
      .eq('id', req.user.id).maybeSingle();
    if (error) return res.status(503).json({ error: 'Unable to verify account' });
    if (!user || user.is_active === false) return res.status(401).json({ error: 'Account is unavailable' });
    res.set('Cache-Control', 'no-store');
    return res.json({ user });
  } catch {
    return res.status(503).json({ error: 'Unable to verify account' });
  }
});

// ════════════════════════════════════════════════════════════════
// INCIDENTS
// ════════════════════════════════════════════════════════════════

app.post('/api/incidents', requireAuth, async (req, res) => {
  const { incident_type, date_of_incident, time_of_incident, location_zone,
    location_detail, severity, persons_injured, description,
    immediate_actions, ppe_worn, sop_followed, witnesses, photos } = req.body;

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
    photos: photos || null,
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
    .is('mine_id', null) // legacy admin view must not bypass new organizational RBAC
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
    .update(updates).eq('id', req.params.id).is('mine_id', null).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ incident: data });
});

app.delete('/api/admin/incidents/:id', requireAdmin, async (req, res) => {
  return res.status(409).json({ error: 'Incident deletion is disabled to preserve safety records and auditability. Use an approved status workflow instead.' });
});

// ════════════════════════════════════════════════════════════════
// ADMIN STATS
// ════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const { data: recent } = await supabase.from('incidents')
    .select('severity, location_zone, created_at')
    .is('mine_id', null)
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
    .select('id', { count: 'exact', head: true }).eq('status', 'open').is('mine_id', null);

  const { data: lastSerious } = await supabase.from('incidents')
    .select('date_of_incident')
    .in('severity', ['serious', 'critical', 'fatality']).is('mine_id', null)
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

// Deployment identity used by the frontend to detect an old API deployment.
app.get('/api/version', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ service: 'mineguard-api', api_version: 'secl-safety-v1', commit: process.env.RENDER_GIT_COMMIT || null });
});

// ── HEALTH / READINESS ─────────────────────────────────────────
app.get('/health', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Deployment smoke check: verifies the database connection and that the
// SECL safety migration has been applied. It never returns schema/data details.
app.get('/ready', async (req, res) => {
  try {
    const checks = await Promise.all([
      supabase.from('areas').select('id', { head: true, count: 'exact' }).limit(1),
      supabase.from('mines').select('id,area_id', { head: true, count: 'exact' }).limit(1),
      supabase.from('users').select('id,assigned_mine_id,assigned_area_id,is_active', { head: true, count: 'exact' }).limit(1),
      supabase.from('incident_comments').select('id', { head: true, count: 'exact' }).limit(1),
      supabase.from('incident_forwarding_history').select('id', { head: true, count: 'exact' }).limit(1)
    ]);
    if (checks.some(result => result.error)) {
      return res.status(503).json({ status: 'not_ready', error: 'Database or safety schema is unavailable' });
    }
    // A missing incident must return P0002; this confirms the atomic RPC exists without writing data.
    const rpc = await supabase.rpc('mineguard_forward_incident_atomic', {
      p_incident_id: '00000000-0000-0000-0000-000000000000',
      p_expected_version: 1,
      p_new_status: 'open',
      p_assignee_id: null,
      p_actor_id: null,
      p_from_role: 'healthcheck',
      p_to_role: 'healthcheck',
      p_action: 'FORWARD',
      p_comments: null,
      p_context: { healthcheck: true }
    });
    if (!rpc.error || rpc.error.code !== 'P0002') {
      return res.status(503).json({ status: 'not_ready', error: 'Required atomic workflow database function is unavailable' });
    }
    return res.json({ status: 'ready' });
  } catch {
    return res.status(503).json({ status: 'not_ready', error: 'Database or safety schema is unavailable' });
  }
});


// ════════════════════════════════════════════════════════════════
// SECL SAFETY MANAGEMENT API (new role-scoped endpoints)
// These endpoints always reload the principal from the database;
// client-supplied role/scope fields are never used for authorization.
// ════════════════════════════════════════════════════════════════
async function safetyPrincipal(req, res, next) {
  try {
    const { data, error } = await supabase.from('users')
      .select('id,worker_id,name,department,role,assigned_mine_id,assigned_area_id,is_active')
      .eq('id', req.user.id).maybeSingle();
    if (error || !data || data.is_active === false) return res.status(401).json({error:'Account is unavailable'});
    if (!SAFETY_ROLES.has(data.role)) return res.status(403).json({error:'Safety-management role required'});
    req.principal = data;
    next();
  } catch {
    return res.status(500).json({error:'Unable to authenticate request'});
  }
}
async function getMine(id) {
  const {data,error}=await supabase.from('mines').select('id,name,area_id,normalized_name').eq('id',id).maybeSingle();
  if(error) throw new Error('MINE_LOOKUP_FAILED');
  return data;
}
async function getIncidentForPrincipal(id, principal) {
  const {data,error}=await supabase.from('incidents').select('*').eq('id',id).maybeSingle();
  if(error) throw new Error('INCIDENT_LOOKUP_FAILED');
  if(!data) return null;
  if(!data.mine_id || !data.area_id) return null;
  const mine=await getMine(data.mine_id);
  if(!mine || mine.area_id!==data.area_id || !canReadMine(principal,mine)) return null;
  return {...data, _mine:mine};
}
function cleanIncident(row) {
  if(!row) return row;
  const {_mine,...incident}=row;
  return incident;
}
function parsePeriod(query) {
  const from=query.from ? new Date(query.from) : new Date(Date.now()-30*86400000);
  const to=query.to ? new Date(query.to) : new Date();
  if(Number.isNaN(from.getTime())||Number.isNaN(to.getTime())||from>to) return null;
  return {from:from.toISOString(),to:to.toISOString()};
}

app.get('/api/org/areas', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal;
  if(p.role!=='HQ_SAFETY_HEAD' && p.role!=='AREA_SAFETY_OFFICER') return res.status(403).json({error:'Area list access denied'});
  let q=supabase.from('areas').select('id,name,normalized_name').order('name');
  if(p.role==='AREA_SAFETY_OFFICER') q=q.eq('id',p.assigned_area_id);
  const {data,error}=await q;
  if(error) return res.status(500).json({error:'Unable to load Areas'});
  res.json({areas:data||[]});
});

app.get('/api/org/mines', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal;
  let q=supabase.from('mines').select('id,area_id,name,normalized_name').order('name');
  if(p.role==='AREA_SAFETY_OFFICER') q=q.eq('area_id',p.assigned_area_id);
  else if(p.role!=='HQ_SAFETY_HEAD') q=q.eq('id',p.assigned_mine_id);
  const {data,error}=await q;
  if(error) return res.status(500).json({error:'Unable to load Mine/Project list'});
  res.json({mines:data||[]});
});

app.post('/api/safety/incidents', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal;
  if(!['MINE_SO_MINING','MINE_SO_EM'].includes(p.role)) return res.status(403).json({error:'Only assigned Safety Officers can create field observations'});
  const category=req.body.category, discipline=disciplineForRole(p.role);
  if(!CATEGORIES.has(category)||!String(req.body.description||'').trim()||String(req.body.description).length>10000)
    return res.status(400).json({error:'A valid category and description are required'});
  if(req.body.discipline && req.body.discipline!==discipline) return res.status(403).json({error:'Discipline is determined by the authenticated role'});
  try {
    const mine=await getMine(p.assigned_mine_id);
    if(!mine) return res.status(403).json({error:'No valid Mine/Project assignment'});
    const now=new Date();
    const severity=category==='Near Miss'?'nearMiss':'minor';
    const {data,error}=await supabase.from('incidents').insert([{
      reporter_id:p.id, reporter_worker_id:p.worker_id, reporter_name:p.name,
      incident_type:category, category, discipline, area_id:mine.area_id, mine_id:mine.id,
      date_of_incident:req.body.date_of_incident||now.toISOString().slice(0,10),
      time_of_incident:req.body.time_of_incident||null,
      location_zone:String(req.body.location_zone||mine.name).slice(0,200),
      location_detail:req.body.location_detail?String(req.body.location_detail).slice(0,500):null,
      severity, persons_injured:0, description:String(req.body.description).trim(),
      immediate_actions:req.body.immediate_actions?String(req.body.immediate_actions).slice(0,5000):null,
      ppe_worn:'unknown',sop_followed:'unknown',status:'open'
    }]).select('id,incident_ref,area_id,mine_id,category,discipline,status,created_at').single();
    if(error) return res.status(500).json({error:'Unable to save incident'});
    res.status(201).json({incident:data});
  } catch { res.status(500).json({error:'Unable to resolve assigned Mine/Project'}); }
});

app.get('/api/safety/incidents', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal, period=parsePeriod(req.query);
  if(!period) return res.status(400).json({error:'Invalid reporting period'});
  const limit=Math.max(1,Math.min(100,Number.parseInt(req.query.limit,10)||50));
  const offset=Math.max(0,Number.parseInt(req.query.offset,10)||0);
  let q=supabase.from('incidents').select('*',{count:'exact'}).not('mine_id','is',null)
    .gte('created_at',period.from).lte('created_at',period.to).order('created_at',{ascending:false}).range(offset,offset+limit-1);
  if(p.role==='AREA_SAFETY_OFFICER') q=q.eq('area_id',p.assigned_area_id);
  else if(p.role!=='HQ_SAFETY_HEAD') q=q.eq('mine_id',p.assigned_mine_id);
  if(req.query.status) {
    if(!STATUS_VALUES.has(req.query.status)) return res.status(400).json({error:'Invalid status filter'});
    q=q.eq('status',req.query.status);
  }
  if(req.query.category) {
    if(!CATEGORIES.has(req.query.category)) return res.status(400).json({error:'Invalid category filter'});
    q=q.eq('category',req.query.category);
  }
  if(req.query.mine_id) q=q.eq('mine_id',req.query.mine_id);
  if(req.query.area_id) {
    if(!['HQ_SAFETY_HEAD','AREA_SAFETY_OFFICER'].includes(p.role)) return res.status(403).json({error:'Area filter is not permitted for this role'});
    if(p.role==='AREA_SAFETY_OFFICER' && req.query.area_id!==p.assigned_area_id) return res.status(404).json({error:'Area not found'});
    q=q.eq('area_id',req.query.area_id);
  }
  const {data,error,count}=await q;
  if(error) return res.status(500).json({error:'Unable to load incidents'});
  res.json({incidents:data||[],total:count||0,limit,offset,from:period.from,to:period.to});
});

app.get('/api/safety/incidents/:id', requireAuth, safetyPrincipal, async (req,res) => {
  try {
    const incident=await getIncidentForPrincipal(req.params.id,req.principal);
    if(!incident) return res.status(404).json({error:'Incident not found'});
    const [{data:comments,error:ce},{data:history,error:he}]=await Promise.all([
      supabase.from('incident_comments').select('id,author_id,comment_text,context,created_at').eq('incident_id',incident.id).order('created_at'),
      supabase.from('incident_forwarding_history').select('id,actor_id,from_user_id,to_user_id,from_role,to_role,action,comments,context,created_at').eq('incident_id',incident.id).order('created_at')
    ]);
    if(ce||he) return res.status(500).json({error:'Unable to load incident history'});
    res.json({incident:cleanIncident(incident),comments:comments||[],forwarding_history:history||[]});
  } catch {res.status(500).json({error:'Unable to load incident'});}
});

app.post('/api/safety/incidents/:id/comments', requireAuth, safetyPrincipal, async (req,res) => {
  const text=String(req.body.comment_text||'').trim();
  if(!text||text.length>10000) return res.status(400).json({error:'Comment must contain 1–10000 characters'});
  try {
    const incident=await getIncidentForPrincipal(req.params.id,req.principal);
    if(!incident) return res.status(404).json({error:'Incident not found'});
    const {data,error}=await supabase.from('incident_comments').insert({incident_id:incident.id,author_id:req.principal.id,comment_text:text,context:{role:req.principal.role,status:incident.status}}).select('id,incident_id,author_id,comment_text,context,created_at').single();
    if(error) return res.status(500).json({error:'Unable to save comment'});
    res.status(201).json({comment:data});
  } catch {res.status(500).json({error:'Unable to save comment'});}
});

app.patch('/api/safety/incidents/:id/status', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal, nextStatus=req.body.status;
  if(!['MINE_MANAGER','AREA_SAFETY_OFFICER'].includes(p.role)) return res.status(403).json({error:'Status changes are not permitted for this role'});
  if(!STATUS_VALUES.has(nextStatus)) return res.status(400).json({error:'Invalid status'});
  if(nextStatus==='escalated') return res.status(400).json({error:'Use the authorized forwarding workflow to escalate an incident'});
  try {
    const incident=await getIncidentForPrincipal(req.params.id,p);
    if(!incident) return res.status(404).json({error:'Incident not found'});
    const allowed=STATUS_TRANSITIONS[incident.status]||new Set();
    if(!allowed.has(nextStatus)) return res.status(409).json({error:'Status transition is not permitted'});
    if(nextStatus==='closed' && incident.status!=='resolved') return res.status(409).json({error:'Only resolved incidents can be closed'});
    if(nextStatus==='action_assigned' && !incident.assignee_id) return res.status(409).json({error:'Assign an authorized recipient before marking action assigned'});
    const updates={status:nextStatus,updated_at:new Date().toISOString(),version:(incident.version||1)+1};
    if(nextStatus==='resolved'&&!incident.resolved_at) updates.resolved_at=new Date().toISOString();
    if(nextStatus==='closed') updates.closed_at=new Date().toISOString();
    const {data,error}=await supabase.from('incidents').update(updates).eq('id',incident.id).eq('version',incident.version||1).select('id,status,updated_at,resolved_at,closed_at,version').maybeSingle();
    if(error) return res.status(500).json({error:'Unable to update incident'});
    if(!data) return res.status(409).json({error:'Incident changed concurrently; reload and retry'});
    res.json({incident:data});
  } catch {res.status(500).json({error:'Unable to update incident'});}
});

app.post('/api/safety/incidents/:id/forward', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal, targetId=req.body.to_user_id, action=req.body.action;
  if(!['MINE_MANAGER','AREA_SAFETY_OFFICER'].includes(p.role)) return res.status(403).json({error:'Forwarding is not permitted for this role'});
  if(!targetId || !['FORWARD','ESCALATE','ASSIGN','REASSIGN'].includes(action)) return res.status(400).json({error:'Destination and valid action are required'});
  const comment=String(req.body.comments||'').trim();
  if(action==='ESCALATE'&&!comment) return res.status(400).json({error:'Escalation comments are required'});
  try {
    const incident=await getIncidentForPrincipal(req.params.id,p);
    if(!incident) return res.status(404).json({error:'Incident not found'});
    if(p.role==='MINE_MANAGER' && action==='ESCALATE' && incident._mine.area_id!==p.assigned_area_id && p.assigned_area_id)
      return res.status(403).json({error:'Incident Area does not match assignment'});
    const {data:target,error:te}=await supabase.from('users').select('id,role,assigned_mine_id,assigned_area_id,is_active').eq('id',targetId).maybeSingle();
    if(te||!target||target.is_active===false) return res.status(400).json({error:'Invalid destination assignment'});
    if(action==='ESCALATE'){
      if(p.role!=='MINE_MANAGER'||target.role!=='AREA_SAFETY_OFFICER'||target.assigned_area_id!==incident._mine.area_id)
        return res.status(403).json({error:'Escalation must target the assigned Area Safety Officer'});
    } else {
      if(p.role==='MINE_MANAGER' && !(['LOCAL_SUPERVISOR','LOCAL_ENGINEER'].includes(target.role)&&target.assigned_mine_id===incident._mine.id))
        return res.status(403).json({error:'Destination must be an authorized local supervisor or engineer in the same Mine/Project'});
      if(p.role==='AREA_SAFETY_OFFICER' && target.assigned_area_id!==p.assigned_area_id && target.assigned_mine_id===null)
        return res.status(403).json({error:'Destination is outside the assigned Area'});
    }
    if(action==='ESCALATE' && !(STATUS_TRANSITIONS[incident.status]||new Set()).has('escalated'))
      return res.status(409).json({error:'Incident cannot be escalated from its current status'});
    if(action==='ASSIGN' && incident.status!=='under_review' && incident.status!=='action_assigned')
      return res.status(409).json({error:'Corrective actions can be assigned only after review'});
    if(action==='REASSIGN' && incident.status!=='action_assigned')
      return res.status(409).json({error:'Only an action-assigned incident can be reassigned'});
    if(action==='ASSIGN' && !(STATUS_TRANSITIONS[incident.status]||new Set()).has('action_assigned') && incident.status!=='action_assigned')
      return res.status(409).json({error:'Incident cannot enter Action Assigned from its current status'});
    if(p.role==='AREA_SAFETY_OFFICER') {
      if(!['LOCAL_SUPERVISOR','LOCAL_ENGINEER','MINE_MANAGER'].includes(target.role))
        return res.status(403).json({error:'Area forwarding destination role is not permitted'});
      if(target.assigned_mine_id) {
        const targetMine=await getMine(target.assigned_mine_id);
        if(!targetMine || targetMine.area_id!==p.assigned_area_id)
          return res.status(403).json({error:'Destination Mine/Project is outside the assigned Area'});
      } else if(target.assigned_area_id!==p.assigned_area_id) {
        return res.status(403).json({error:'Destination is outside the assigned Area'});
      }
    }
    const newStatus=action==='ESCALATE'?'escalated':(action==='ASSIGN'?'action_assigned':incident.status);
    const {data:result,error:rpcError}=await supabase.rpc('mineguard_forward_incident_atomic',{
      p_incident_id:incident.id,
      p_expected_version:incident.version||1,
      p_new_status:newStatus,
      p_assignee_id:target.id,
      p_actor_id:p.id,
      p_from_role:p.role,
      p_to_role:target.role,
      p_action:action,
      p_comments:comment||null,
      p_context:{mine_id:incident._mine.id,area_id:incident._mine.area_id}
    });
    if(rpcError) {
      if(rpcError.code==='40001') return res.status(409).json({error:'Incident changed concurrently; reload and retry'});
      if(rpcError.code==='P0002') return res.status(404).json({error:'Incident not found'});
      return res.status(409).json({error:'Forwarding could not be committed atomically'});
    }
    res.json({incident:result.incident,forwarding_event:result.forwarding_event});
  } catch {res.status(500).json({error:'Unable to forward incident'});}
});


app.get('/api/safety/recipients', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal;
  if(!['MINE_MANAGER','AREA_SAFETY_OFFICER'].includes(p.role)) return res.status(403).json({error:'Recipient lookup is not permitted for this role'});
  if(!req.query.incident_id) return res.status(400).json({error:'incident_id is required'});
  try {
    const incident=await getIncidentForPrincipal(req.query.incident_id,p);
    if(!incident) return res.status(404).json({error:'Incident not found'});
    const roles=p.role==='MINE_MANAGER'?['LOCAL_SUPERVISOR','LOCAL_ENGINEER','AREA_SAFETY_OFFICER']:['MINE_MANAGER','LOCAL_SUPERVISOR','LOCAL_ENGINEER'];
    const {data:users,error}=await supabase.from('users').select('id,worker_id,name,role,assigned_mine_id,assigned_area_id,is_active').in('role',roles).eq('is_active',true);
    if(error) return res.status(500).json({error:'Unable to load authorized recipients'});
    const recipients=[];
    for(const u of users||[]) {
      if(p.role==='MINE_MANAGER') {
        if(['LOCAL_SUPERVISOR','LOCAL_ENGINEER'].includes(u.role)&&u.assigned_mine_id===incident._mine.id) recipients.push(u);
        if(u.role==='AREA_SAFETY_OFFICER'&&u.assigned_area_id===incident._mine.area_id) recipients.push(u);
      } else {
        if(u.role==='MINE_MANAGER'&&u.assigned_mine_id) {
          const targetMine=await getMine(u.assigned_mine_id);
          if(targetMine&&targetMine.area_id===p.assigned_area_id) recipients.push(u);
        }
        if(['LOCAL_SUPERVISOR','LOCAL_ENGINEER'].includes(u.role)&&u.assigned_mine_id) {
          const targetMine=await getMine(u.assigned_mine_id);
          if(targetMine&&targetMine.area_id===p.assigned_area_id) recipients.push(u);
        }
      }
    }
    res.json({recipients:recipients.map(u=>({id:u.id,worker_id:u.worker_id,name:u.name,role:u.role}))});
  } catch {res.status(500).json({error:'Unable to load authorized recipients'});}
});

app.get('/api/safety/analytics/hq', requireAuth, safetyPrincipal, async (req,res) => {
  if(req.principal.role!=='HQ_SAFETY_HEAD') return res.status(403).json({error:'HQ Safety Head access required'});
  const period=parsePeriod(req.query);
  if(!period) return res.status(400).json({error:'Invalid reporting period'});
  const {data:areas,error:ae}=await supabase.from('areas').select('id,name,normalized_name').order('name');
  if(ae) return res.status(500).json({error:'Unable to load analytics'});
  const {data:incidents,error:ie,count:incidentCount}=await supabase.from('incidents').select('id,area_id,mine_id,category,discipline,status,created_at,resolved_at,closed_at',{count:'exact'})
    .not('mine_id','is',null).gte('created_at',period.from).lte('created_at',period.to).limit(10000);
  if(ie) return res.status(500).json({error:'Unable to load analytics'});
  if((incidentCount||0)>10000) return res.status(422).json({error:'Reporting period exceeds the 10,000-record analytics processing limit; narrow the reporting period or deploy database-side aggregate analytics.'});
  const {data:mines,error:mineError}=await supabase.from('mines').select('id,name,area_id');
  if(mineError) return res.status(500).json({error:'Unable to load Mine/Project analytics'});
  const mineMap=new Map((mines||[]).map(m=>[m.id,m]));
  const rows=incidents||[];
  const byArea=(areas||[]).map(a=>{
    const list=rows.filter(i=>i.area_id===a.id), resolved=list.filter(i=>['resolved','closed'].includes(i.status));
    const durations=resolved.map(i=>i.resolved_at?((new Date(i.resolved_at)-new Date(i.created_at))/3600000):null).filter(n=>Number.isFinite(n)&&n>=0);
    return {area_id:a.id,area_name:a.name,total_incidents:list.length,open_incidents:list.filter(i=>!['resolved','closed'].includes(i.status)).length,
      unresolved_incidents:list.filter(i=>!['resolved','closed'].includes(i.status)).length,escalated_incidents:list.filter(i=>i.status==='escalated').length,
      resolved_or_closed:resolved.length,resolution_rate_percent:list.length?Math.round(resolved.length/list.length*10000)/100:null,
      average_resolution_hours:durations.length?Math.round(durations.reduce((x,y)=>x+y,0)/durations.length*100)/100:null};
  });
  const countBy=key=>rows.reduce((acc,i)=>{const k=i[key]||'Unclassified';acc[k]=(acc[k]||0)+1;return acc;},{});
  res.json({period,definitions:{resolution_rate:'Resolved or closed incidents divided by all incidents created in the selected period; null when denominator is zero.',average_resolution_hours:'Mean elapsed hours from incident creation to first recorded resolved_at; unresolved incidents and missing/invalid durations are excluded.'},
    totals:{incidents:rows.length,open:rows.filter(i=>!['resolved','closed'].includes(i.status)).length,escalated:rows.filter(i=>i.status==='escalated').length},
    area_ranking:byArea.sort((a,b)=>(b.resolution_rate_percent??-1)-(a.resolution_rate_percent??-1)),
    hazard_frequency:{category:countBy('category'),discipline:countBy('discipline'),status:countBy('status')},mine_frequency:Object.values(rows.reduce((acc,i)=>{const mine=mineMap.get(i.mine_id);const k=i.mine_id||'Unassigned';if(!acc[k])acc[k]={mine_id:i.mine_id||null,mine_name:mine?.name||'Unassigned',area_id:mine?.area_id||i.area_id,total_incidents:0};acc[k].total_incidents++;return acc;},{}))});
});

app.get('/api/safety/analytics/area/:id', requireAuth, safetyPrincipal, async (req,res) => {
  const p=req.principal, period=parsePeriod(req.query);
  if(!period) return res.status(400).json({error:'Invalid reporting period'});
  if(p.role!=='HQ_SAFETY_HEAD' && !(p.role==='AREA_SAFETY_OFFICER'&&p.assigned_area_id===req.params.id))
    return res.status(404).json({error:'Area not found'});
  const {data:area,error:ae}=await supabase.from('areas').select('id,name').eq('id',req.params.id).maybeSingle();
  if(ae||!area) return res.status(404).json({error:'Area not found'});
  const {data:mines,error:me}=await supabase.from('mines').select('id,name,area_id').eq('area_id',area.id).order('name');
  if(me) return res.status(500).json({error:'Unable to load Area'});
  const {data:incidents,error:ie,count:incidentCount}=await supabase.from('incidents').select('id,mine_id,category,discipline,status,created_at,resolved_at',{count:'exact'})
    .eq('area_id',area.id).not('mine_id','is',null).gte('created_at',period.from).lte('created_at',period.to).limit(10000);
  if(ie) return res.status(500).json({error:'Unable to load Area analytics'});
  if((incidentCount||0)>10000) return res.status(422).json({error:'Area reporting period exceeds the 10,000-record processing limit; narrow the reporting period or deploy database-side aggregate analytics.'});
  const rows=incidents||[], resolved=rows.filter(i=>['resolved','closed'].includes(i.status));
  const durations=resolved.map(i=>i.resolved_at?((new Date(i.resolved_at)-new Date(i.created_at))/3600000):null).filter(n=>Number.isFinite(n)&&n>=0);
  res.json({area,period,definitions:{resolution_rate:'Resolved or closed incidents divided by all incidents created in the selected period; null when denominator is zero.',average_resolution_hours:'Mean elapsed hours from creation to first recorded resolution; unresolved or invalid durations excluded.'},
    total_incidents:rows.length,unresolved_incidents:rows.filter(i=>!['resolved','closed'].includes(i.status)).length,
    escalated_incidents:rows.filter(i=>i.status==='escalated').length,
    resolution_rate_percent:rows.length?Math.round(resolved.length/rows.length*10000)/100:null,
    average_resolution_hours:durations.length?Math.round(durations.reduce((x,y)=>x+y,0)/durations.length*100)/100:null,
    mine_counts:(mines||[]).map(m=>({mine_id:m.id,mine_name:m.name,total_incidents:rows.filter(i=>i.mine_id===m.id).length}))});
});

app.use((req, res) => res.status(404).json({ error: 'Route not found' }));
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.message === 'Origin not allowed by CORS') return res.status(403).json({ error: 'Origin not allowed' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
  if (err instanceof SyntaxError && err.status === 400 && Object.prototype.hasOwnProperty.call(err, 'body')) {
    return res.status(400).json({ error: 'Invalid JSON request body' });
  }
  console.error('Unhandled MineGuard API error:', err && err.name ? err.name : 'Error');
  return res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => console.log(`MineGuard API listening on port ${PORT}; environment=${isProduction ? 'production' : 'non-production'}`));

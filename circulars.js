'use strict';
/* Circulars, Guidelines & Notifications API.
   Every route reloads the principal from the database (safetyPrincipal). Publication scope is derived from that record,
   reads are restricted by scope filters built from it, and the database independently enforces publication scope (see the
   20261116000000_circulars_module.sql migration: RLS + triggers). Nothing here trusts client-supplied scope. */
const P = require('./circular-policy');

const LIST_COLS = 'id,ref_no,scope_type,area_id,mine_id,issuer_id,issuer_role,issuer_name,category,priority,title,subject,issue_date,effective_date,requires_ack,status,version,created_at,updated_at,archived_at';
const chunk = (a, n) => { const o = []; for (let i = 0; i < a.length; i += n) o.push(a.slice(i, i + n)); return o; };
const clean = s => String(s || '').replace(/[,()*%\\:"']/g, ' ').trim().slice(0, 80);
const isUuid = s => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s));

module.exports = function mountCirculars(app, { supabase, requireAuth, safetyPrincipal }) {
  const auth = [requireAuth, safetyPrincipal];
  async function ownMine(p) {
    if (!p.assigned_mine_id) return null;
    const { data } = await supabase.from('mines').select('id,area_id,name,reporting_code').eq('id', p.assigned_mine_id).maybeSingle();
    return data || null;
  }
  const ctxFor = async p => { const mine = await ownMine(p); return { mine, mineAreaOf: id => (mine && mine.id === id ? mine.area_id : null), areaId: p.assigned_area_id || (mine && mine.area_id) || null }; };
  const audit = (circular_id, p, event, detail) => supabase.from('circular_audit').insert({ circular_id, actor_id: p.id, actor_role: p.role, event, detail: detail || {} }).then(() => null, () => null);

  async function readable(p, ctx, id) {
    if (!isUuid(id)) return null;
    const { data, error } = await supabase.from('circulars').select('*').eq('id', id).maybeSingle();
    if (error || !data) return null;
    return P.canRead(p, data, ctx.mineAreaOf) ? data : null;
  }
  const myRow = async (p, id) => (await supabase.from('circular_recipients').select('*').eq('circular_id', id).eq('user_id', p.id).maybeSingle()).data || null;

  /* Ensure a delivery row exists for every circular this user is a recipient of (covers users who joined after publication). */
  async function syncDeliveries(p, ctx) {
    const f = ['scope_type.eq.ALL'];
    if (p.assigned_area_id) f.push('and(scope_type.eq.AREA,area_id.eq.' + p.assigned_area_id + ')');
    if (ctx.mine) { f.push('and(scope_type.eq.MINE,mine_id.eq.' + ctx.mine.id + ')'); f.push('and(scope_type.eq.AREA,area_id.eq.' + ctx.mine.area_id + ')'); }
    const { data: cs } = await supabase.from('circulars').select('id').neq('issuer_id', p.id).or(f.join(',')).order('created_at', { ascending: false }).limit(1000);
    if (!cs || !cs.length) return;
    const { data: have } = await supabase.from('circular_recipients').select('circular_id').eq('user_id', p.id).limit(5000);
    const hs = new Set((have || []).map(r => r.circular_id)), missing = cs.filter(c => !hs.has(c.id));
    for (const part of chunk(missing, 200)) await supabase.from('circular_recipients').upsert(part.map(c => ({ circular_id: c.id, user_id: p.id })), { onConflict: 'circular_id,user_id', ignoreDuplicates: true });
  }
  const decorate = (p, ctx, c, r) => ({ ...c, is_issuer: c.issuer_id === p.id, is_recipient: P.isRecipient(p, c, ctx.mineAreaOf), unread: P.isRecipient(p, c, ctx.mineAreaOf) && P.isUnread(c, r), pending_ack: P.isRecipient(p, c, ctx.mineAreaOf) && P.isPending(c, r), viewed_at: r && r.viewed_at || null, acknowledged_at: r && r.ack_version >= c.version ? r.acknowledged_at : null });
  const mineRows = async (p, ids) => {
    const m = new Map();
    for (const part of chunk(ids, 100)) { const { data } = await supabase.from('circular_recipients').select('*').eq('user_id', p.id).in('circular_id', part); (data || []).forEach(r => m.set(r.circular_id, r)); }
    return m;
  };
  function scopedQuery(p, ctx, select, opts) {
    let q = supabase.from('circulars').select(select, opts);
    const f = P.readFilter(p, ctx.mine && ctx.mine.area_id);
    return { q, f };
  }
  const withAnd = (q, scopeF, searchF) => {
    if (scopeF && searchF) q.url.searchParams.append('and', '(or(' + scopeF + '),or(' + searchF + '))');
    else if (scopeF) q = q.or(scopeF);
    else if (searchF) q = q.or(searchF);
    return q;
  };

  /* ───────── list ───────── */
  app.get('/api/safety/circulars', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p); await syncDeliveries(p, ctx);
      const v = String(req.query.view || 'inbox'), limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25)), offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
      const flag = ['unread', 'pending'].includes(req.query.flag) ? req.query.flag : '';
      let { q, f } = scopedQuery(p, ctx, LIST_COLS, { count: 'exact' });
      const qs = clean(req.query.q), search = qs ? ['title', 'subject', 'ref_no', 'issuer_name'].map(c => c + '.ilike.*' + qs + '*').join(',') : '';
      q = withAnd(q, f, search);
      if (v === 'archive') q = q.eq('status', 'archived'); else if (v === 'issued') q = q.eq('issuer_id', p.id); else q = q.eq('status', 'published');
      if (req.query.priority && P.PRIORITIES.includes(req.query.priority)) q = q.eq('priority', req.query.priority);
      if (req.query.category && P.CATEGORIES.includes(req.query.category)) q = q.eq('category', req.query.category);
      if (req.query.issuer_role && P.ROLE_LABEL[req.query.issuer_role]) q = q.eq('issuer_role', req.query.issuer_role);
      if (req.query.ref) q = q.ilike('ref_no', '%' + clean(req.query.ref) + '%');
      if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.from || '')) q = q.gte('issue_date', req.query.from);
      if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.to || '')) q = q.lte('issue_date', req.query.to);
      q = q.order('created_at', { ascending: false });
      q = flag ? q.limit(500) : q.range(offset, offset + limit - 1);
      const { data, error, count } = await q;
      if (error) return res.status(500).json({ error: 'Unable to load communications' });
      const rows = await mineRows(p, (data || []).map(c => c.id));
      let items = (data || []).map(c => decorate(p, ctx, c, rows.get(c.id)));
      let total = count || 0;
      if (flag) { items = items.filter(i => flag === 'unread' ? i.unread : i.pending_ack); total = items.length; items = items.slice(offset, offset + limit); }
      res.json({ items, total, limit, offset });
    } catch { res.status(500).json({ error: 'Unable to load communications' }); }
  });

  /* ───────── summary (dashboard section + badge) ───────── */
  app.get('/api/safety/circulars/summary', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p); await syncDeliveries(p, ctx);
      let { q, f } = scopedQuery(p, ctx, LIST_COLS, {});
      q = withAnd(q, f, '').eq('status', 'published').order('created_at', { ascending: false }).limit(200);
      const { data, error } = await q; if (error) return res.status(500).json({ error: 'Unable to load communications' });
      const rows = await mineRows(p, (data || []).map(c => c.id));
      const items = (data || []).map(c => decorate(p, ctx, c, rows.get(c.id))), week = Date.now() - 7 * 864e5;
      const rank = { critical: 0, urgent: 1, important: 2, normal: 3 };
      res.json({
        counts: { unread: items.filter(i => i.unread).length, pending_ack: items.filter(i => i.pending_ack).length, urgent_open: items.filter(i => ['urgent', 'critical'].includes(i.priority) && (i.unread || i.pending_ack)).length, published: items.length },
        latest: items.slice(0, 5),
        urgent: items.filter(i => ['urgent', 'critical'].includes(i.priority) && (i.unread || i.pending_ack)).sort((a, b) => rank[a.priority] - rank[b.priority]).slice(0, 5),
        unread: items.filter(i => i.unread).slice(0, 5), pending: items.filter(i => i.pending_ack).slice(0, 5),
        recent: items.filter(i => Date.parse(i.created_at) >= week).slice(0, 5)
      });
    } catch { res.status(500).json({ error: 'Unable to load communications' }); }
  });

  /* ───────── publish ───────── */
  app.post('/api/safety/circulars', ...auth, async (req, res) => {
    try {
      const p = req.principal, b = req.body || {}, ctx = await ctxFor(p);
      const sc = P.publishScope(p, ctx.mine); if (!sc.ok) return res.status(sc.code).json({ error: sc.error });
      const val = P.validatePublish(b, p.role); if (!val.ok) return res.status(val.code || 400).json({ error: val.error });
      const atts = Array.isArray(b.attachments) ? b.attachments : [];
      if (atts.length > P.MAX_ATTACHMENTS) return res.status(400).json({ error: 'At most ' + P.MAX_ATTACHMENTS + ' attachments are allowed' });
      const files = []; for (const a of atts) { const r = P.validateAttachment(a); if (!r.ok) return res.status(400).json({ error: r.error }); files.push(r.value); }
      const year = new Date().getFullYear();
      const prefix = sc.scope_type === 'ALL' ? 'HQ' : sc.scope_type === 'AREA' ? 'ASO/' + String((await supabase.from('areas').select('name').eq('id', sc.area_id).maybeSingle()).data?.name || 'AREA').replace(/[^A-Za-z0-9]/g, '').slice(0, 4).toUpperCase() : String(ctx.mine.reporting_code || ctx.mine.name).replace(/[^A-Za-z0-9]/g, '').slice(0, 6).toUpperCase();
      let row = null, lastErr = null;
      for (let attempt = 0; attempt < 4 && !row; attempt++) {
        let ref = val.value.ref_no;
        if (!ref) { const { count } = await supabase.from('circulars').select('id', { count: 'exact', head: true }).ilike('ref_no', prefix + '/' + year + '/%'); ref = prefix + '/' + year + '/' + String((count || 0) + 1 + attempt).padStart(3, '0'); }
        const { data, error } = await supabase.from('circulars').insert({ ref_no: ref, scope_type: sc.scope_type, area_id: sc.area_id, mine_id: sc.mine_id, issuer_id: p.id, issuer_role: p.role, issuer_name: p.name, category: val.value.category, priority: val.value.priority, title: val.value.title, subject: val.value.subject, body_html: val.value.body_html, issue_date: val.value.issue_date || undefined, effective_date: val.value.effective_date, requires_ack: val.value.requires_ack }).select('*').single();
        if (!error) row = data; else { lastErr = error; if (error.code !== '23505' || val.value.ref_no) break; }
      }
      if (!row) return res.status(lastErr && lastErr.code === '23505' ? 409 : lastErr && /scope|Only HQ|ASO may|Mine-level/i.test(lastErr.message || '') ? 403 : 500).json({ error: lastErr && lastErr.code === '23505' ? 'A communication with this reference number already exists' : lastErr && /scope|Only HQ|ASO may|Mine-level/i.test(lastErr.message || '') ? 'You are not authorised to publish to this audience' : 'Unable to publish the communication' });
      if (files.length) await supabase.from('circular_attachments').insert(files.map(f => ({ ...f, circular_id: row.id })));
      const [{ data: users }, { data: mines }] = await Promise.all([supabase.from('users').select('id,role,is_active,assigned_area_id,assigned_mine_id').eq('is_active', true).limit(20000), supabase.from('mines').select('id,area_id').limit(5000)]);
      const ids = P.recipientIds(users || [], mines || [], row);
      for (const part of chunk(ids, 500)) await supabase.from('circular_recipients').upsert(part.map(uid => ({ circular_id: row.id, user_id: uid })), { onConflict: 'circular_id,user_id', ignoreDuplicates: true });
      await audit(row.id, p, 'published', { ref_no: row.ref_no, scope_type: row.scope_type, recipients: ids.length, attachments: files.length });
      res.status(201).json({ circular: { id: row.id, ref_no: row.ref_no, scope_type: row.scope_type, priority: row.priority, version: 1 }, recipients: ids.length });
    } catch { res.status(500).json({ error: 'Unable to publish the communication' }); }
  });

  /* ───────── detail (records a view) ───────── */
  app.get('/api/safety/circulars/:id', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p), c = await readable(p, ctx, req.params.id);
      if (!c) return res.status(404).json({ error: 'Communication not found' });
      await syncDeliveries(p, ctx);
      let r = await myRow(p, c.id);
      if (r && (r.viewed_version == null || r.viewed_version < c.version)) {
        const now = new Date().toISOString(); await supabase.from('circular_recipients').update({ viewed_at: now, viewed_version: c.version }).eq('circular_id', c.id).eq('user_id', p.id);
        await audit(c.id, p, 'viewed', { version: c.version }); r = { ...r, viewed_at: now, viewed_version: c.version };
      }
      const [{ data: atts }, { data: vers }] = await Promise.all([
        supabase.from('circular_attachments').select('id,file_name,mime_type,size_bytes,added_in_version,created_at').eq('circular_id', c.id).order('created_at'),
        supabase.from('circular_versions').select('version,title,subject,body_html,priority,effective_date,amendment_note,created_at,edited_by').eq('circular_id', c.id).order('version', { ascending: false })
      ]);
      const d = decorate(p, ctx, c, r), area = await supabase.from('areas').select('name').eq('id', c.area_id || '00000000-0000-0000-0000-000000000000').maybeSingle(), mine = await supabase.from('mines').select('name').eq('id', c.mine_id || '00000000-0000-0000-0000-000000000000').maybeSingle();
      const canTrack = c.issuer_id === p.id || p.role === 'HQ_SAFETY_HEAD' || (p.role === 'AREA_SAFETY_OFFICER' && p.assigned_area_id && (c.scope_type === 'ALL' || c.area_id === p.assigned_area_id));
      res.json({ circular: { ...d, body_html: P.sanitizeHtml(c.body_html), area_name: area.data && area.data.name || null, mine_name: mine.data && mine.data.name || null }, attachments: atts || [], versions: (vers || []).map(x => ({ ...x, body_html: P.sanitizeHtml(x.body_html) })), can_amend: c.issuer_id === p.id && c.status === 'published', can_archive: c.status === 'published' && (c.issuer_id === p.id || p.role === 'HQ_SAFETY_HEAD'), can_track: canTrack });
    } catch { res.status(500).json({ error: 'Unable to load the communication' }); }
  });

  app.get('/api/safety/circulars/:id/attachments/:aid', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p), c = await readable(p, ctx, req.params.id);
      if (!c || !isUuid(req.params.aid)) return res.status(404).json({ error: 'Attachment not found' });
      const { data } = await supabase.from('circular_attachments').select('file_name,mime_type,size_bytes,data_base64').eq('id', req.params.aid).eq('circular_id', c.id).maybeSingle();
      if (!data) return res.status(404).json({ error: 'Attachment not found' });
      res.json({ file_name: data.file_name, mime_type: data.mime_type, size_bytes: data.size_bytes, data_base64: data.data_base64 });
    } catch { res.status(500).json({ error: 'Unable to load the attachment' }); }
  });

  /* ───────── acknowledge / mark read ───────── */
  app.post('/api/safety/circulars/:id/acknowledge', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p), c = await readable(p, ctx, req.params.id);
      if (!c) return res.status(404).json({ error: 'Communication not found' });
      if (!P.isRecipient(p, c, ctx.mineAreaOf)) return res.status(403).json({ error: 'This communication was not addressed to you' });
      if (c.status !== 'published') return res.status(409).json({ error: 'This communication has been archived' });
      const now = new Date().toISOString();
      await supabase.from('circular_recipients').upsert({ circular_id: c.id, user_id: p.id, viewed_at: now, viewed_version: c.version, acknowledged_at: now, ack_version: c.version }, { onConflict: 'circular_id,user_id' });
      await audit(c.id, p, 'acknowledged', { version: c.version });
      res.json({ ok: true, acknowledged_at: now, version: c.version });
    } catch { res.status(500).json({ error: 'Unable to record acknowledgement' }); }
  });

  /* ───────── amend (new version, history kept) ───────── */
  app.post('/api/safety/circulars/:id/amend', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p), c = await readable(p, ctx, req.params.id), b = req.body || {};
      if (!c) return res.status(404).json({ error: 'Communication not found' });
      if (c.issuer_id !== p.id) return res.status(403).json({ error: 'Only the issuing authority can amend this communication' });
      if (c.status !== 'published') return res.status(409).json({ error: 'Archived communications cannot be amended' });
      const note = String(b.amendment_note || '').trim(); if (note.length < 3 || note.length > 1000) return res.status(400).json({ error: 'Describe what was amended (3–1000 characters)' });
      const val = P.validatePublish({ ...b, category: c.category, ref_no: '', issue_date: c.issue_date }, p.role); if (!val.ok) return res.status(val.code || 400).json({ error: val.error });
      const files = []; for (const a of (Array.isArray(b.attachments) ? b.attachments : [])) { const r = P.validateAttachment(a); if (!r.ok) return res.status(400).json({ error: r.error }); files.push(r.value); }
      const { count } = await supabase.from('circular_attachments').select('id', { count: 'exact', head: true }).eq('circular_id', c.id);
      if ((count || 0) + files.length > P.MAX_ATTACHMENTS) return res.status(400).json({ error: 'At most ' + P.MAX_ATTACHMENTS + ' attachments are allowed' });
      const snap = await supabase.from('circular_versions').insert({ circular_id: c.id, version: c.version, title: c.title, subject: c.subject, body_html: c.body_html, priority: c.priority, effective_date: c.effective_date, edited_by: p.id, amendment_note: note });
      if (snap.error) return res.status(409).json({ error: 'This communication was just changed. Reload and try again.' });
      const { data: upd, error } = await supabase.from('circulars').update({ title: val.value.title, subject: val.value.subject, body_html: val.value.body_html, priority: val.value.priority, effective_date: val.value.effective_date, requires_ack: val.value.requires_ack, version: c.version + 1, updated_at: new Date().toISOString() }).eq('id', c.id).eq('version', c.version).select('id,version').maybeSingle();
      if (error || !upd) { await supabase.from('circular_versions').delete().eq('circular_id', c.id).eq('version', c.version); return res.status(409).json({ error: 'This communication was just changed. Reload and try again.' }); }
      if (files.length) await supabase.from('circular_attachments').insert(files.map(f => ({ ...f, circular_id: c.id, added_in_version: upd.version })));
      await audit(c.id, p, 'amended', { from_version: c.version, to_version: upd.version, note });
      res.json({ ok: true, version: upd.version });
    } catch { res.status(500).json({ error: 'Unable to amend the communication' }); }
  });

  /* ───────── archive (kept permanently) ───────── */
  app.post('/api/safety/circulars/:id/archive', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p), c = await readable(p, ctx, req.params.id);
      if (!c) return res.status(404).json({ error: 'Communication not found' });
      if (!(c.issuer_id === p.id || p.role === 'HQ_SAFETY_HEAD')) return res.status(403).json({ error: 'Only the issuing authority or HQ can archive a communication' });
      if (c.status === 'archived') return res.json({ ok: true });
      const { error } = await supabase.from('circulars').update({ status: 'archived', archived_at: new Date().toISOString() }).eq('id', c.id);
      if (error) return res.status(500).json({ error: 'Unable to archive' });
      await audit(c.id, p, 'archived', {}); res.json({ ok: true });
    } catch { res.status(500).json({ error: 'Unable to archive' }); }
  });

  /* ───────── tracking + audit (issuer, HQ, ASO within own Area) ───────── */
  async function trackingAllowed(p, c) { return c.issuer_id === p.id || p.role === 'HQ_SAFETY_HEAD' || (p.role === 'AREA_SAFETY_OFFICER' && p.assigned_area_id && (c.scope_type === 'ALL' || c.area_id === p.assigned_area_id)); }
  app.get('/api/safety/circulars/:id/tracking', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p), c = await readable(p, ctx, req.params.id);
      if (!c || !(await trackingAllowed(p, c))) return res.status(404).json({ error: 'Communication not found' });
      const { data: recs } = await supabase.from('circular_recipients').select('*').eq('circular_id', c.id).limit(20000);
      const uids = (recs || []).map(r => r.user_id), users = new Map();
      for (const part of chunk(uids, 100)) { const { data } = await supabase.from('users').select('id,name,role,assigned_area_id,assigned_mine_id').in('id', part); (data || []).forEach(u => users.set(u.id, u)); }
      const { data: mines } = await supabase.from('mines').select('id,name,area_id');
      const mineMap = new Map((mines || []).map(m => [m.id, m]));
      const areaOfUser = u => u.assigned_area_id || (u.assigned_mine_id && mineMap.get(u.assigned_mine_id)?.area_id) || null;
      let rows = recs || [];
      const restrict = p.role === 'AREA_SAFETY_OFFICER' && c.issuer_id !== p.id && c.scope_type === 'ALL';
      if (restrict) rows = rows.filter(r => { const u = users.get(r.user_id); return u && areaOfUser(u) === p.assigned_area_id; });
      const by = new Map();
      rows.forEach(r => { const u = users.get(r.user_id) || {}, key = u.assigned_mine_id || (u.assigned_area_id ? 'area:' + u.assigned_area_id : 'hq'), m = mineMap.get(u.assigned_mine_id);
        const g = by.get(key) || { mine_id: u.assigned_mine_id || null, name: m ? m.name : u.assigned_area_id ? 'Area office' : 'HQ', total: 0, viewed: 0, acknowledged: 0 };
        g.total++; if (r.viewed_version >= c.version) g.viewed++; if (r.ack_version >= c.version) g.acknowledged++; by.set(key, g); });
      const pending = rows.filter(r => c.requires_ack ? !(r.ack_version >= c.version) : !(r.viewed_version >= c.version)).slice(0, 300).map(r => { const u = users.get(r.user_id) || {}; return { user_id: r.user_id, name: u.name || '—', role: u.role || null, mine: mineMap.get(u.assigned_mine_id)?.name || null, viewed: r.viewed_version >= c.version }; });
      res.json({ stats: P.trackingStats(c, rows), by_mine: [...by.values()].sort((a, b) => a.name.localeCompare(b.name)), pending, area_restricted: restrict });
    } catch { res.status(500).json({ error: 'Unable to load tracking' }); }
  });
  app.get('/api/safety/circulars/:id/audit', ...auth, async (req, res) => {
    try {
      const p = req.principal, ctx = await ctxFor(p), c = await readable(p, ctx, req.params.id);
      if (!c || !(c.issuer_id === p.id || p.role === 'HQ_SAFETY_HEAD')) return res.status(404).json({ error: 'Communication not found' });
      const { data } = await supabase.from('circular_audit').select('id,actor_id,actor_role,event,detail,created_at').eq('circular_id', c.id).order('created_at', { ascending: false }).limit(300);
      const ids = [...new Set((data || []).map(e => e.actor_id).filter(Boolean))], names = new Map();
      for (const part of chunk(ids, 100)) { const { data: us } = await supabase.from('users').select('id,name').in('id', part); (us || []).forEach(u => names.set(u.id, u.name)); }
      res.json({ events: (data || []).map(e => ({ ...e, actor_name: names.get(e.actor_id) || '—' })) });
    } catch { res.status(500).json({ error: 'Unable to load the audit trail' }); }
  });
};

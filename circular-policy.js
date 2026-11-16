'use strict';
/* Pure rules for the Circulars module (no I/O) so they can be unit-tested.
   Scope is ALWAYS derived from the publisher's database record, never from the request body. */
const CATEGORIES = ['Circular','Guideline','Instruction','Advisory','Safety Alert','Notification'];
const PRIORITIES = ['normal','important','urgent','critical'];
const ATTACH_MIME = {
  'application/pdf': [0x25,0x50,0x44,0x46],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [0x50,0x4b],
  'image/png': [0x89,0x50,0x4e,0x47],
  'image/jpeg': [0xff,0xd8,0xff],
  'image/webp': [0x52,0x49,0x46,0x46]
};
const MAX_ATTACH_BYTES = 3 * 1024 * 1024, MAX_ATTACHMENTS = 5;
const MINE_ROLES = new Set(['MINE_MANAGER','MINE_SO_MINING','MINE_SO_EM']);
const ROLE_LABEL = { HQ_SAFETY_HEAD:'HQ', AREA_SAFETY_OFFICER:'ASO', MINE_MANAGER:'Mine Manager', MINE_SO_MINING:'Mine Safety Officer', MINE_SO_EM:'Mine Safety Officer' };

/* Who may publish, and to what. Mine Safety Officers may only issue Normal/Important mine-level notes. */
function publishScope(p, mine) {
  if (!p) return { ok:false, code:403, error:'Not permitted' };
  if (p.role === 'HQ_SAFETY_HEAD') return { ok:true, scope_type:'ALL', area_id:null, mine_id:null };
  if (p.role === 'AREA_SAFETY_OFFICER') {
    if (!p.assigned_area_id) return { ok:false, code:403, error:'Your account has no Area assignment' };
    return { ok:true, scope_type:'AREA', area_id:p.assigned_area_id, mine_id:null };
  }
  if (MINE_ROLES.has(p.role)) {
    if (!p.assigned_mine_id || !mine || mine.id !== p.assigned_mine_id) return { ok:false, code:403, error:'Your account has no Mine/Project assignment' };
    return { ok:true, scope_type:'MINE', area_id:mine.area_id, mine_id:mine.id };
  }
  return { ok:false, code:403, error:'Your role is not permitted to publish communications' };
}
const maxPriority = role => (role === 'MINE_SO_MINING' || role === 'MINE_SO_EM') ? 'important' : 'critical';
const priorityAllowed = (role, pr) => PRIORITIES.includes(pr) && PRIORITIES.indexOf(pr) <= PRIORITIES.indexOf(maxPriority(role));

/* Is the user a recipient (delivery + acknowledgement expected)? */
function isRecipient(u, c, mineAreaOf) {
  if (!u || !c || u.is_active === false || u.id === c.issuer_id) return false;
  if (c.scope_type === 'ALL') return true;
  if (c.scope_type === 'AREA') return (!!u.assigned_area_id && u.assigned_area_id === c.area_id) || (!!u.assigned_mine_id && mineAreaOf(u.assigned_mine_id) === c.area_id);
  return !!u.assigned_mine_id && u.assigned_mine_id === c.mine_id;
}
/* May the user read it? Recipients, plus oversight: HQ reads everything, an ASO reads everything inside their Area. */
function canRead(u, c, mineAreaOf) {
  if (!u || !c) return false;
  if (u.role === 'HQ_SAFETY_HEAD') return true;
  if (c.issuer_id === u.id) return true;
  if (u.role === 'AREA_SAFETY_OFFICER' && c.scope_type !== 'ALL' && c.area_id === u.assigned_area_id) return true;
  return isRecipient(u, c, mineAreaOf);
}
/* PostgREST .or() filter that restricts a circulars query to what this user may read. null = no restriction (HQ). */
function readFilter(u, ownMineAreaId) {
  if (u.role === 'HQ_SAFETY_HEAD') return null;
  const f = ['scope_type.eq.ALL', 'issuer_id.eq.' + u.id];
  if (u.role === 'AREA_SAFETY_OFFICER' && u.assigned_area_id) f.push('area_id.eq.' + u.assigned_area_id);
  if (u.assigned_area_id) f.push('and(scope_type.eq.AREA,area_id.eq.' + u.assigned_area_id + ')');
  if (u.assigned_mine_id) {
    f.push('and(scope_type.eq.MINE,mine_id.eq.' + u.assigned_mine_id + ')');
    if (ownMineAreaId) f.push('and(scope_type.eq.AREA,area_id.eq.' + ownMineAreaId + ')');
  }
  return f.join(',');
}
/* Recipient ids for a circular, from user + mine lists. */
function recipientIds(users, mines, circ) {
  const area = new Map(mines.map(m => [m.id, m.area_id]));
  return users.filter(u => isRecipient(u, circ, id => area.get(id))).map(u => u.id);
}
const isPending = (c, r) => !!c.requires_ack && c.status === 'published' && !(r && r.ack_version != null && r.ack_version >= c.version);
const isUnread = (c, r) => c.status === 'published' && !(r && r.viewed_version != null && r.viewed_version >= c.version);

/* Strip everything except a small formatting allow-list. Defence in depth: the browser sanitises again before rendering. */
const ALLOWED = new Set(['p','br','b','strong','i','em','u','ul','ol','li','h3','h4','blockquote','a','span','hr']);
function sanitizeHtml(html) {
  let s = String(html || '').slice(0, 60000);
  s = s.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style|iframe|object|embed|svg|math)[\s\S]*?<\/\1\s*>/gi, '');
  return s.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/g, (m, tag, attrs) => {
    tag = tag.toLowerCase();
    if (!ALLOWED.has(tag)) return '';
    if (m[1] === '/') return '</' + tag + '>';
    if (tag === 'a') {
      const h = /href\s*=\s*("([^"]*)"|'([^']*)')/i.exec(attrs), url = h ? (h[2] || h[3] || '').trim() : '';
      return /^(https?:\/\/|mailto:)/i.test(url) ? '<a href="' + url.replace(/"/g, '&quot;') + '" target="_blank" rel="noopener noreferrer">' : '<a>';
    }
    return '<' + tag + '>';
  });
}
const textOf = h => String(h || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

function validatePublish(b, role) {
  const t = s => String(s == null ? '' : s).trim();
  const out = { title:t(b.title), subject:t(b.subject), category:t(b.category) || 'Circular', priority:t(b.priority) || 'normal', body_html:sanitizeHtml(b.body_html), ref_no:t(b.ref_no), requires_ack:b.requires_ack !== false, effective_date:t(b.effective_date) || null, issue_date:t(b.issue_date) || null };
  const date = d => !d || /^\d{4}-\d{2}-\d{2}$/.test(d) && !isNaN(Date.parse(d));
  if (out.title.length < 3 || out.title.length > 200) return { ok:false, error:'Title must be 3–200 characters' };
  if (out.subject.length < 3 || out.subject.length > 300) return { ok:false, error:'Subject must be 3–300 characters' };
  if (!CATEGORIES.includes(out.category)) return { ok:false, error:'Invalid category' };
  if (!PRIORITIES.includes(out.priority)) return { ok:false, error:'Invalid priority' };
  if (!priorityAllowed(role, out.priority)) return { ok:false, code:403, error:'Your role may issue communications only up to "Important" priority' };
  if (textOf(out.body_html).length < 3) return { ok:false, error:'Description is required' };
  if (out.ref_no.length > 60 || /[^\w\-\/. ]/.test(out.ref_no)) return { ok:false, error:'Reference number may contain letters, digits, space and - / . _ only' };
  if (!date(out.issue_date) || !date(out.effective_date)) return { ok:false, error:'Dates must be YYYY-MM-DD' };
  if (out.issue_date && out.effective_date && out.effective_date < out.issue_date) return { ok:false, error:'Effective date cannot be before the issue date' };
  return { ok:true, value:out };
}
/* Parses a data URL / base64 attachment; verifies type allow-list, size and magic bytes. */
function validateAttachment(a) {
  const name = String(a && a.name || '').replace(/[\\/\r\n]/g, '_').trim().slice(0, 200), mime = String(a && a.type || '');
  const m = /^data:([^;]+);base64,(.+)$/s.exec(String(a && a.data || ''));
  if (!name || !m) return { ok:false, error:'Invalid attachment' };
  const sig = ATTACH_MIME[mime];
  if (!sig || m[1] !== mime) return { ok:false, error:'Only PDF, DOCX, PNG, JPEG and WEBP files are allowed' };
  const buf = Buffer.from(m[2], 'base64');
  if (!buf.length || buf.length > MAX_ATTACH_BYTES) return { ok:false, error:'Each attachment must be under 3 MB' };
  if (!sig.every((b, i) => buf[i] === b)) return { ok:false, error:'File content does not match its type' };
  return { ok:true, value:{ file_name:name, mime_type:mime, size_bytes:buf.length, data_base64:m[2] } };
}
function summarize(items) {
  return { total: items.length, unread: items.filter(i => i.unread).length, pending_ack: items.filter(i => i.pending_ack).length };
}
/* Delivery statistics from recipient rows (version-aware). */
function trackingStats(c, rows) {
  const total = rows.length, viewed = rows.filter(r => r.viewed_version != null && r.viewed_version >= c.version).length;
  const ack = rows.filter(r => r.ack_version != null && r.ack_version >= c.version).length;
  return { total_recipients: total, delivered: rows.filter(r => r.delivered_at).length, viewed, acknowledged: ack, pending_ack: c.requires_ack ? total - ack : 0, not_viewed: total - viewed };
}

module.exports = { CATEGORIES, PRIORITIES, ATTACH_MIME, MAX_ATTACHMENTS, MAX_ATTACH_BYTES, ROLE_LABEL, publishScope, maxPriority, priorityAllowed, isRecipient, canRead, readFilter, recipientIds, isPending, isUnread, sanitizeHtml, validatePublish, validateAttachment, summarize, trackingStats };

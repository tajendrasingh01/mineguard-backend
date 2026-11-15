const SAFETY_ROLES = new Set([
  'MINE_SO_MINING','MINE_SO_EM','MINE_MANAGER','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD',
  'LOCAL_SUPERVISOR','LOCAL_ENGINEER'
]);
const STATUS_TRANSITIONS = Object.freeze({
  open: new Set(['under_review','escalated']),
  under_review: new Set(['action_assigned','escalated']),
  action_assigned: new Set(['under_review','resolved','escalated']),
  escalated: new Set(['under_review','action_assigned','resolved']),
  resolved: new Set(['closed','under_review']),
  closed: new Set()
});
const STATUS_VALUES = new Set(Object.keys(STATUS_TRANSITIONS));
const DISCIPLINES = new Set(['Mining','Electrical & Mechanical']);
const CATEGORIES = new Set(['Unsafe Practice','Near Miss','Unsafe Acts','Unsafe Act','Unsafe Condition','Incident Reporting']);
function canReadMine(principal, mine) {
  if (!principal || !mine) return false;
  if (principal.role === 'HQ_SAFETY_HEAD') return true;
  if (principal.role === 'AREA_SAFETY_OFFICER') return Boolean(principal.assigned_area_id) && mine.area_id === principal.assigned_area_id;
  return ['MINE_SO_MINING','MINE_SO_EM','MINE_MANAGER','LOCAL_SUPERVISOR','LOCAL_ENGINEER'].includes(principal.role)
    && Boolean(principal.assigned_mine_id) && principal.assigned_mine_id === mine.id;
}
function disciplineForRole(role) {
  if (role === 'MINE_SO_MINING') return 'Mining';
  if (role === 'MINE_SO_EM') return 'Electrical & Mechanical';
  return null;
}
/* ---------------------------------------------------------------------------
   Incident workflow (single source of truth, enforced by the API).
   1. A Mine Safety Officer (SO) reports -> it lands with the Mine Manager (MM).
   2. MM reviews, records remarks + recommendations and sends it back to the SO (REVIEW).
   3. SO either records the action taken and returns it to the MM for closure (ACTION_TAKEN),
      or asks the MM to escalate to the Area Safety Officer or HQ (REQUEST_ESCALATION).
   4. Only the MM can escalate (ESCALATE -> ASO or HQ). ASO / HQ give recommendations and hand it
      back to the MM (RECOMMEND). They can neither escalate onwards nor close.
   5. Only the MM can close (CLOSE), always from "resolved".
   --------------------------------------------------------------------------- */
const SO_ROLES = ['MINE_SO_MINING','MINE_SO_EM'];
const WORKFLOW = Object.freeze({
  REVIEW:             { roles:['MINE_MANAGER'], from:['open','under_review','resolved'], status:'action_assigned', to:'MINE_SO', action:'ASSIGN',  kind:'review_to_so',       stage:'with_so',              required:['remarks','recommendations'] },
  ACTION_TAKEN:       { roles:SO_ROLES, from:['action_assigned'], assignee:true, status:'resolved',     to:'MINE_MANAGER', action:'FORWARD', kind:'action_taken',        stage:'awaiting_closure',     required:['actions'] },
  REQUEST_ESCALATION: { roles:SO_ROLES, from:['action_assigned'], assignee:true, status:'under_review', to:'MINE_MANAGER', action:'FORWARD', kind:'escalation_request',  stage:'escalation_requested', required:['justification'], level:true },
  ESCALATE:           { roles:['MINE_MANAGER'], from:['open','under_review'], status:'escalated', to:'LEVEL', action:'ESCALATE', kind:'escalation', stage:'LEVEL', required:['remarks'], level:true },
  RECOMMEND:          { roles:['AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD'], from:['escalated'], assignee:true, status:'under_review', to:'MINE_MANAGER', action:'FORWARD', kind:'recommendation', stage:'recommended', required:['recommendations'] },
  CLOSE:              { roles:['MINE_MANAGER'], from:['resolved'], status:'closed', to:'SELF', action:'FORWARD', kind:'closure', stage:'closed', required:['remarks'] }
});
const LEVELS = Object.freeze({ ASO:{role:'AREA_SAFETY_OFFICER',stage:'with_aso'}, HQ:{role:'HQ_SAFETY_HEAD',stage:'with_hq'} });
const FIELD_MAX = 4000;
/* Pure decision: may this principal perform `step` on an incident in `status`? Returns the resulting
   status / destination role, or an HTTP-style error. No I/O, so it is unit-tested exhaustively. */
function decideWorkflow({ role, status, step, level, isAssignee, fields }) {
  const w = WORKFLOW[step];
  if (!w) return { ok:false, code:400, error:'Unknown workflow step' };
  if (!w.roles.includes(role)) return { ok:false, code:403, error:'Your role is not permitted to perform this step' };
  if (!w.from.includes(status)) return { ok:false, code:409, error:'This step is not available at the incident\'s current stage' };
  if (w.assignee && !isAssignee) return { ok:false, code:403, error:'This incident is not currently assigned to you' };
  let to = w.to, stage = w.stage;
  if (w.level) {
    const l = LEVELS[level];
    if (!l) return { ok:false, code:400, error:'Choose the escalation level: Area Safety Officer (ASO) or HQ' };
    if (to === 'LEVEL') { to = l.role; stage = l.stage; }
  }
  for (const f of w.required) {
    const v = String((fields && fields[f]) || '').trim();
    if (!v) return { ok:false, code:400, error:'Required: ' + f };
    if (v.length > FIELD_MAX) return { ok:false, code:400, error:f + ' is too long' };
  }
  return { ok:true, status:w.status, to, action:w.action, kind:w.kind, stage, level: w.level ? level : null };
}
/* Only the Mine Safety Officers (Mining and Electrical & Mechanical) may report incidents. */
const REPORTER_ROLES = new Set(['MINE_SO_MINING','MINE_SO_EM']);
function canReportIncident(role) { return REPORTER_ROLES.has(role); }
module.exports={canReportIncident,SAFETY_ROLES,STATUS_TRANSITIONS,STATUS_VALUES,DISCIPLINES,CATEGORIES,canReadMine,disciplineForRole,WORKFLOW,LEVELS,decideWorkflow};

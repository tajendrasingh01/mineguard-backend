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
/* Escalation chain: Mine Safety Officer reports -> Mine Manager (review + closure) -> Area Safety Officer -> HQ.
   Each level may escalate only to the next one; HQ is the top and may only return an incident downwards. */
const ESCALATION_NEXT = Object.freeze({ MINE_MANAGER: 'AREA_SAFETY_OFFICER', AREA_SAFETY_OFFICER: 'HQ_SAFETY_HEAD' });
const ASO_ESCALATABLE = new Set(['open','under_review','action_assigned','escalated']);
function escalationTargetRole(role) { return ESCALATION_NEXT[role] || null; }
function canEscalateFromStatus(role, status) {
  if (role === 'MINE_MANAGER') return Boolean(STATUS_TRANSITIONS[status] && STATUS_TRANSITIONS[status].has('escalated'));
  // An incident already escalated to the ASO must still be escalatable onwards to HQ (status stays 'escalated').
  if (role === 'AREA_SAFETY_OFFICER') return ASO_ESCALATABLE.has(status);
  return false;
}
/* Who HQ may hand an incident back to: the Area's ASO or the incident Mine's Manager. */
function hqReturnTargetAllowed(target, mine) {
  if (!target || !mine) return false;
  if (target.role === 'AREA_SAFETY_OFFICER') return Boolean(target.assigned_area_id) && target.assigned_area_id === mine.area_id;
  if (target.role === 'MINE_MANAGER') return Boolean(target.assigned_mine_id) && target.assigned_mine_id === mine.id;
  return false;
}
/* Only the Mine Safety Officers (Mining and Electrical & Mechanical) may report incidents. */
const REPORTER_ROLES = new Set(['MINE_SO_MINING','MINE_SO_EM']);
function canReportIncident(role) { return REPORTER_ROLES.has(role); }
module.exports={canReportIncident,SAFETY_ROLES,STATUS_TRANSITIONS,STATUS_VALUES,DISCIPLINES,CATEGORIES,canReadMine,disciplineForRole,ESCALATION_NEXT,escalationTargetRole,canEscalateFromStatus,hqReturnTargetAllowed};

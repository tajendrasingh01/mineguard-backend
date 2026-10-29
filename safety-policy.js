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
const CATEGORIES = new Set(['Near Miss','Unsafe Act','Unsafe Condition']);
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
module.exports={SAFETY_ROLES,STATUS_TRANSITIONS,STATUS_VALUES,DISCIPLINES,CATEGORIES,canReadMine,disciplineForRole};

const test=require('node:test');
const assert=require('node:assert/strict');
const {SAFETY_ROLES,STATUS_TRANSITIONS,STATUS_VALUES,DISCIPLINES,CATEGORIES,canReadMine,disciplineForRole,canReportIncident,escalationTargetRole,canEscalateFromStatus,hqReturnTargetAllowed}=require('../safety-policy');
test('safety roles are explicit and public worker/admin are not safety roles',()=>{
 for(const role of ['MINE_SO_MINING','MINE_SO_EM','MINE_MANAGER','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD','LOCAL_SUPERVISOR','LOCAL_ENGINEER'])assert.ok(SAFETY_ROLES.has(role));
 assert.equal(SAFETY_ROLES.has('worker'),false);assert.equal(SAFETY_ROLES.has('admin'),false);
});
test('Mine and Area scope checks reject cross-scope reads',()=>{
 const mineA={id:'mine-a',area_id:'area-a'},mineB={id:'mine-b',area_id:'area-b'};
 assert.equal(canReadMine({role:'MINE_MANAGER',assigned_mine_id:'mine-a'},mineA),true);
 assert.equal(canReadMine({role:'MINE_MANAGER',assigned_mine_id:'mine-a'},mineB),false);
 assert.equal(canReadMine({role:'AREA_SAFETY_OFFICER',assigned_area_id:'area-a'},mineA),true);
 assert.equal(canReadMine({role:'AREA_SAFETY_OFFICER',assigned_area_id:'area-a'},mineB),false);
 assert.equal(canReadMine({role:'HQ_SAFETY_HEAD'},mineB),true);
 assert.equal(canReadMine({role:'worker',assigned_mine_id:'mine-a'},mineA),false);
 assert.equal(canReadMine({role:'AREA_SAFETY_OFFICER'},mineA),false);
});
test('Safety Officer discipline is derived from authenticated role',()=>{
 assert.equal(disciplineForRole('MINE_SO_MINING'),'Mining');
 assert.equal(disciplineForRole('MINE_SO_EM'),'Electrical & Mechanical');
 assert.equal(disciplineForRole('MINE_MANAGER'),null);
 assert.deepEqual([...DISCIPLINES],['Mining','Electrical & Mechanical']);
});
test('workflow transitions are constrained and terminal closed state cannot transition',()=>{
 assert.deepEqual([...STATUS_VALUES].sort(),['action_assigned','closed','escalated','open','resolved','under_review'].sort());
 assert.ok(STATUS_TRANSITIONS.open.has('under_review'));
 assert.ok(STATUS_TRANSITIONS.under_review.has('action_assigned'));
 assert.ok(STATUS_TRANSITIONS.action_assigned.has('resolved'));
 assert.ok(STATUS_TRANSITIONS.resolved.has('closed'));
 assert.equal(STATUS_TRANSITIONS.closed.size,0);
 assert.equal(STATUS_TRANSITIONS.resolved.has('escalated'),false);
});
test('incident categories are limited to canonical values',()=>{
 assert.deepEqual([...CATEGORIES].sort(),['Unsafe Practice','Near Miss','Unsafe Acts','Unsafe Act','Unsafe Condition','Incident Reporting'].sort());
});

test('escalation chain is Mine Manager -> Area Safety Officer -> HQ, and nobody can skip a level',()=>{
 assert.equal(escalationTargetRole('MINE_MANAGER'),'AREA_SAFETY_OFFICER');
 assert.equal(escalationTargetRole('AREA_SAFETY_OFFICER'),'HQ_SAFETY_HEAD');
 for(const r of ['MINE_SO_MINING','MINE_SO_EM','HQ_SAFETY_HEAD','LOCAL_SUPERVISOR','LOCAL_ENGINEER','worker'])assert.equal(escalationTargetRole(r),null);
});
test('Mine Manager keeps the original status rules; ASO may escalate an already-escalated incident to HQ',()=>{
 assert.equal(canEscalateFromStatus('MINE_MANAGER','under_review'),true);
 assert.equal(canEscalateFromStatus('MINE_MANAGER','escalated'),false);
 assert.equal(canEscalateFromStatus('MINE_MANAGER','resolved'),false);
 assert.equal(canEscalateFromStatus('AREA_SAFETY_OFFICER','escalated'),true);
 assert.equal(canEscalateFromStatus('AREA_SAFETY_OFFICER','action_assigned'),true);
 assert.equal(canEscalateFromStatus('AREA_SAFETY_OFFICER','resolved'),false);
 assert.equal(canEscalateFromStatus('AREA_SAFETY_OFFICER','closed'),false);
 assert.equal(canEscalateFromStatus('HQ_SAFETY_HEAD','escalated'),false);
});
test('HQ may return an incident only to its own Area ASO or its own Mine Manager',()=>{
 const mine={id:'m1',area_id:'a1'};
 assert.equal(hqReturnTargetAllowed({role:'AREA_SAFETY_OFFICER',assigned_area_id:'a1'},mine),true);
 assert.equal(hqReturnTargetAllowed({role:'AREA_SAFETY_OFFICER',assigned_area_id:'a2'},mine),false);
 assert.equal(hqReturnTargetAllowed({role:'MINE_MANAGER',assigned_mine_id:'m1'},mine),true);
 assert.equal(hqReturnTargetAllowed({role:'MINE_MANAGER',assigned_mine_id:'m2'},mine),false);
 assert.equal(hqReturnTargetAllowed({role:'LOCAL_SUPERVISOR',assigned_mine_id:'m1'},mine),false);
 assert.equal(hqReturnTargetAllowed({role:'AREA_SAFETY_OFFICER'},mine),false);
});
test('only Mine Safety Officers (Mining and E&M) can report incidents',()=>{
 assert.equal(canReportIncident('MINE_SO_MINING'),true);
 assert.equal(canReportIncident('MINE_SO_EM'),true);
 for(const r of ['HQ_SAFETY_HEAD','AREA_SAFETY_OFFICER','MINE_MANAGER','LOCAL_SUPERVISOR','LOCAL_ENGINEER','worker','admin',undefined])assert.equal(canReportIncident(r),false);
});

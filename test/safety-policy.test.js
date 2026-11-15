const test=require('node:test');
const assert=require('node:assert/strict');
const {SAFETY_ROLES,STATUS_TRANSITIONS,STATUS_VALUES,DISCIPLINES,CATEGORIES,canReadMine,disciplineForRole,canReportIncident,decideWorkflow}=require('../safety-policy');
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

const D=(o)=>decideWorkflow({isAssignee:true,fields:{remarks:'r',recommendations:'rec',actions:'a',justification:'j'},...o});
test('MM review sends the incident back to the SO with remarks and recommendations',()=>{
 for(const st of ['open','under_review','resolved']){const r=D({role:'MINE_MANAGER',status:st,step:'REVIEW'});assert.equal(r.ok,true);assert.equal(r.status,'action_assigned');assert.equal(r.to,'MINE_SO');assert.equal(r.action,'ASSIGN')}
 assert.equal(D({role:'MINE_MANAGER',status:'open',step:'REVIEW',fields:{remarks:'r'}}).code,400);
 assert.equal(D({role:'MINE_MANAGER',status:'closed',step:'REVIEW'}).code,409);
 assert.equal(D({role:'MINE_MANAGER',status:'escalated',step:'REVIEW'}).code,409);
 for(const r of ['MINE_SO_MINING','MINE_SO_EM','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD'])assert.equal(D({role:r,status:'open',step:'REVIEW'}).code,403);
});
test('SO can record action taken (returns to MM as resolved) or request escalation (returns to MM under review)',()=>{
 for(const role of ['MINE_SO_MINING','MINE_SO_EM']){
  const a=D({role,status:'action_assigned',step:'ACTION_TAKEN'});assert.equal(a.ok,true);assert.equal(a.status,'resolved');assert.equal(a.to,'MINE_MANAGER');
  const e=D({role,status:'action_assigned',step:'REQUEST_ESCALATION',level:'HQ'});assert.equal(e.ok,true);assert.equal(e.status,'under_review');assert.equal(e.to,'MINE_MANAGER');assert.equal(e.stage,'escalation_requested');
 }
 assert.equal(D({role:'MINE_SO_MINING',status:'action_assigned',step:'REQUEST_ESCALATION'}).code,400);
 assert.equal(D({role:'MINE_SO_MINING',status:'action_assigned',step:'ACTION_TAKEN',isAssignee:false}).code,403);
 assert.equal(D({role:'MINE_SO_MINING',status:'open',step:'ACTION_TAKEN'}).code,409);
 assert.equal(D({role:'MINE_SO_MINING',status:'action_assigned',step:'ACTION_TAKEN',fields:{}}).code,400);
});
test('only the Mine Manager can escalate, to ASO or HQ, and not once it is with the SO or already escalated',()=>{
 assert.equal(D({role:'MINE_MANAGER',status:'under_review',step:'ESCALATE',level:'ASO'}).to,'AREA_SAFETY_OFFICER');
 const hq=D({role:'MINE_MANAGER',status:'open',step:'ESCALATE',level:'HQ'});assert.equal(hq.to,'HQ_SAFETY_HEAD');assert.equal(hq.stage,'with_hq');assert.equal(hq.status,'escalated');
 assert.equal(D({role:'MINE_MANAGER',status:'under_review',step:'ESCALATE'}).code,400);
 for(const st of ['action_assigned','escalated','resolved','closed'])assert.equal(D({role:'MINE_MANAGER',status:st,step:'ESCALATE',level:'ASO'}).code,409);
 for(const r of ['MINE_SO_MINING','MINE_SO_EM','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD','LOCAL_SUPERVISOR','LOCAL_ENGINEER'])assert.equal(D({role:r,status:'under_review',step:'ESCALATE',level:'ASO'}).code,403);
});
test('ASO and HQ can only recommend back to the Mine Manager',()=>{
 for(const role of ['AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD']){const r=D({role,status:'escalated',step:'RECOMMEND'});assert.equal(r.ok,true);assert.equal(r.status,'under_review');assert.equal(r.to,'MINE_MANAGER')}
 assert.equal(D({role:'AREA_SAFETY_OFFICER',status:'escalated',step:'RECOMMEND',isAssignee:false}).code,403);
 assert.equal(D({role:'AREA_SAFETY_OFFICER',status:'escalated',step:'RECOMMEND',fields:{}}).code,400);
 assert.equal(D({role:'MINE_MANAGER',status:'escalated',step:'RECOMMEND'}).code,403);
});
test('closure belongs exclusively to the Mine Manager and only from resolved',()=>{
 const c=D({role:'MINE_MANAGER',status:'resolved',step:'CLOSE'});assert.equal(c.ok,true);assert.equal(c.status,'closed');assert.equal(c.to,'SELF');
 for(const st of ['open','under_review','action_assigned','escalated','closed'])assert.equal(D({role:'MINE_MANAGER',status:st,step:'CLOSE'}).code,409);
 for(const r of ['MINE_SO_MINING','MINE_SO_EM','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD','LOCAL_SUPERVISOR','LOCAL_ENGINEER','worker','admin'])assert.equal(D({role:r,status:'resolved',step:'CLOSE'}).code,403);
 assert.equal(D({role:'MINE_MANAGER',status:'resolved',step:'CLOSE',fields:{}}).code,400);
});
test('no role other than the Mine Manager can ever produce a closed status, and unknown steps are rejected',()=>{
 for(const role of ['MINE_SO_MINING','MINE_SO_EM','AREA_SAFETY_OFFICER','HQ_SAFETY_HEAD'])for(const step of Object.keys(require('../safety-policy').WORKFLOW))for(const st of ['open','under_review','action_assigned','escalated','resolved']){const r=D({role,status:st,step,level:'ASO'});assert.ok(!(r.ok&&r.status==='closed'))}
 assert.equal(D({role:'MINE_MANAGER',status:'open',step:'NOPE'}).code,400);
});

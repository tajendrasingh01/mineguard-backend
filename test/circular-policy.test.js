const test=require('node:test'),assert=require('node:assert/strict'),P=require('../circular-policy');
const A1='a1',A2='a2',M1={id:'m1',area_id:A1},M2={id:'m2',area_id:A1},M3={id:'m3',area_id:A2};
const mines=[M1,M2,M3];
const U=(id,role,x={})=>({id,role,is_active:true,...x});
const users=[U('hq','HQ_SAFETY_HEAD'),U('aso1','AREA_SAFETY_OFFICER',{assigned_area_id:A1}),U('aso2','AREA_SAFETY_OFFICER',{assigned_area_id:A2}),
 U('mm1','MINE_MANAGER',{assigned_mine_id:'m1'}),U('so1','MINE_SO_MINING',{assigned_mine_id:'m1'}),U('mm2','MINE_MANAGER',{assigned_mine_id:'m2'}),U('mm3','MINE_MANAGER',{assigned_mine_id:'m3'}),{...U('gone','MINE_SO_EM',{assigned_mine_id:'m1'}),is_active:false}];
const ids=c=>P.recipientIds(users,mines,c).sort();
test('HQ publishes to everyone active except the issuer',()=>{
  const s=P.publishScope(users[0]);assert.equal(s.scope_type,'ALL');
  assert.deepEqual(ids({scope_type:'ALL',issuer_id:'hq'}),['aso1','aso2','mm1','mm2','mm3','so1']);
});
test('ASO reaches only their Area (ASO + mines in Area), never other Areas',()=>{
  const s=P.publishScope(users[1]);assert.deepEqual([s.scope_type,s.area_id],['AREA',A1]);
  assert.deepEqual(ids({scope_type:'AREA',area_id:A1,issuer_id:'aso1'}),['mm1','mm2','so1']);
});
test('Mine-level publication reaches only that mine',()=>{
  const s=P.publishScope(users[3],M1);assert.deepEqual([s.scope_type,s.mine_id,s.area_id],['MINE','m1',A1]);
  assert.deepEqual(ids({scope_type:'MINE',area_id:A1,mine_id:'m1',issuer_id:'mm1'}),['so1']);
});
test('mine users cannot publish for another mine or without assignment; unknown roles refused',()=>{
  assert.equal(P.publishScope(users[3],M2).ok,false);assert.equal(P.publishScope(U('x','MINE_MANAGER'),M1).ok,false);
  assert.equal(P.publishScope(U('y','LOCAL_SUPERVISOR',{assigned_mine_id:'m1'}),M1).ok,false);
});
test('ASO of Area 2 cannot read Area 1 circulars; ASO of Area 1 can oversee mine-level ones',()=>{
  const area1={scope_type:'AREA',area_id:A1,issuer_id:'aso1'},mine1={scope_type:'MINE',area_id:A1,mine_id:'m1',issuer_id:'mm1'};
  const ma=id=>mines.find(m=>m.id===id)?.area_id;
  assert.equal(P.canRead(users[2],area1,ma),false);assert.equal(P.canRead(users[2],mine1,ma),false);
  assert.equal(P.canRead(users[1],mine1,ma),true);assert.equal(P.canRead(users[6],area1,ma),false);assert.equal(P.canRead(users[5],mine1,ma),false);
  assert.equal(P.canRead(users[0],mine1,ma),true);
});
test('read filter never lets a mine user see other scopes',()=>{
  const f=P.readFilter(users[3],A1);assert.match(f,/mine_id\.eq\.m1/);assert.doesNotMatch(f,/m2|m3/);assert.equal(P.readFilter(users[0]),null);
  assert.match(P.readFilter(users[2],null),/area_id\.eq\.a2/);assert.doesNotMatch(P.readFilter(users[2],null),/a1/);
});
test('priority ceilings by role',()=>{
  assert.equal(P.priorityAllowed('HQ_SAFETY_HEAD','critical'),true);assert.equal(P.priorityAllowed('MINE_SO_MINING','urgent'),false);assert.equal(P.priorityAllowed('MINE_SO_EM','important'),true);
  assert.equal(P.validatePublish({title:'Valid title',subject:'Valid subject',body_html:'<p>Body text</p>',priority:'critical'},'MINE_SO_MINING').code,403);
});
test('validation of fields and dates',()=>{
  const ok={title:'Valid title',subject:'Valid subject',body_html:'<p>Body text</p>'};
  assert.equal(P.validatePublish(ok,'HQ_SAFETY_HEAD').ok,true);
  assert.equal(P.validatePublish({...ok,title:'x'},'HQ_SAFETY_HEAD').ok,false);
  assert.equal(P.validatePublish({...ok,issue_date:'2026-02-01',effective_date:'2026-01-01'},'HQ_SAFETY_HEAD').ok,false);
  assert.equal(P.validatePublish({...ok,ref_no:'bad;ref'},'HQ_SAFETY_HEAD').ok,false);
  assert.equal(P.validatePublish({...ok,category:'Gossip'},'HQ_SAFETY_HEAD').ok,false);
});
test('sanitizer strips scripts, handlers and unsafe links',()=>{
  const s=P.sanitizeHtml('<p onclick="x()">Hi<script>alert(1)</script><img src=x onerror=y><a href="javascript:alert(1)">l</a><a href="https://e.com/a" onclick="z">ok</a></p>');
  assert.doesNotMatch(s,/script|onclick|onerror|javascript:|<img/i);assert.match(s,/href="https:\/\/e.com\/a"/);
});
test('attachment checks type, size and magic bytes',()=>{
  const pdf='data:application/pdf;base64,'+Buffer.from('%PDF-1.4 hello').toString('base64');
  assert.equal(P.validateAttachment({name:'a.pdf',type:'application/pdf',data:pdf}).ok,true);
  assert.equal(P.validateAttachment({name:'a.pdf',type:'application/pdf',data:'data:application/pdf;base64,'+Buffer.from('MZ evil').toString('base64')}).ok,false);
  assert.equal(P.validateAttachment({name:'a.exe',type:'application/x-msdownload',data:'data:application/x-msdownload;base64,TVo='}).ok,false);
  assert.equal(P.validateAttachment({name:'big.pdf',type:'application/pdf',data:'data:application/pdf;base64,'+Buffer.concat([Buffer.from('%PDF'),Buffer.alloc(3.2*1024*1024)]).toString('base64')}).ok,false);
});
test('versions reset unread/pending after an amendment; tracking counts',()=>{
  const c={status:'published',requires_ack:true,version:2},r1={viewed_version:1,ack_version:1},r2={viewed_version:2,ack_version:2};
  assert.equal(P.isUnread(c,r1),true);assert.equal(P.isPending(c,r1),true);assert.equal(P.isPending(c,r2),false);
  const t=P.trackingStats(c,[{delivered_at:'x',...r1},{delivered_at:'x',...r2},{delivered_at:'x'}]);
  assert.deepEqual([t.total_recipients,t.viewed,t.acknowledged,t.pending_ack],[3,1,1,2]);
});

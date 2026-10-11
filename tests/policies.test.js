import test from 'node:test';
import assert from 'node:assert/strict';
import {emptyDatabase,generateId,hashPassword,verifyPassword} from '../data.js';
import {hostelIds,canView,scoped,beginCycle,cycleFor,reopen,processDue,validActionTransition,canStudentReopen,parseCsv} from '../rules.js';
const H=3600_000;
const hours=(n)=>new Date(Date.now()-n*H);
function fixture(){
 const db=emptyDatabase();
 const u=(id,role)=>{const x={id,role,active:true};db.users.set(id,x);return x;};
 const student=u('s','STUDENT'),student2=u('s2','STUDENT'),rector=u('r','RECTOR'),rector2=u('r2','RECTOR'),staff=u('w','MAINTENANCE_STAFF'),dean=u('d','DEAN'),dean2=u('d2','DEAN'),admin=u('a','SYSTEM_ADMIN');
 db.hostels.set('h1',{id:'h1'});db.hostels.set('h2',{id:'h2'});
 for(const [i,user_id,hostel_id] of [['sc1','r','h1'],['sc2','r2','h2'],['sc3','d','h1'],['sc4','d2','h2'],['sc5','w','h1']])db.scopes.set(i,{id:i,user_id,hostel_id});
 const c={id:'c1',number:'HC-01',student_id:student.id,hostel_id:'h1',status:'SUBMITTED',cycle_number:1,effective_priority:'NORMAL',created_at:hours(52),work_started_at:null,work_completed_at:null};
 db.complaints.set(c.id,c);beginCycle(db,c,c.created_at);
 return {db,c,student,student2,rector,rector2,staff,dean,dean2,admin};
}
test('scrypt uses distinct random salts and verifies safely',()=>{
 const a=hashPassword('TestingStrong12345'),b=hashPassword('TestingStrong12345');
 assert.notEqual(a,b);assert.ok(verifyPassword('TestingStrong12345',a));assert.equal(verifyPassword('wrong',a),false);
});
test('each role and hostel scope are enforced; dean views escalated complaints only',()=>{
 const f=fixture();
 assert.deepEqual(hostelIds(f.db,f.rector),['h1']);
 assert.ok(canView(f.db,f.student,f.c));assert.ok(!canView(f.db,f.student2,f.c));
 assert.ok(canView(f.db,f.rector,f.c));assert.ok(!canView(f.db,f.rector2,f.c));
 assert.ok(!canView(f.db,f.dean,f.c));assert.ok(!canView(f.db,f.dean2,f.c));
 assert.ok(!canView(f.db,f.staff,f.c));
 const a={id:'as1',complaint_id:f.c.id,staff_id:f.staff.id};f.db.assignments.set(a.id,a);f.c.current_staff_id=f.staff.id;
 assert.ok(canView(f.db,f.staff,f.c));
 processDue(f.db,new Date());
 assert.ok(canView(f.db,f.dean,f.c));assert.ok(!canView(f.db,f.dean2,f.c));
 assert.ok(canView(f.db,f.admin,f.c));
});
test('48h escalation is once per cycle and late start still escalates',()=>{
 const f=fixture();const now=new Date();
 const cy=cycleFor(f.db,f.c);cy.work_started_at=hours(1);f.c.status='IN_PROGRESS';
 assert.equal(processDue(f.db,now).escalated,1);
 assert.equal(processDue(f.db,now).escalated,0);
 assert.equal(f.db.escalations.size,1);
 assert.ok([...f.db.notifications.values()].some(n=>n.recipient_id==='d'));
});
test('timely started work avoids escalation, even when complaint old',()=>{
 const f=fixture();cycleFor(f.db,f.c).work_started_at=hours(51);
 assert.equal(processDue(f.db,new Date()).escalated,0);
});
test('24h student reminder, ordinary 48h auto-close and seven-day reopen',()=>{
 const f=fixture();cycleFor(f.db,f.c).work_started_at=hours(51);
 f.c.status='AWAITING_CONFIRMATION';f.c.work_completed_at=hours(25);
 assert.equal(processDue(f.db,new Date()).reminded,1);
 assert.equal(processDue(f.db,new Date()).reminded,0);
 f.c.work_completed_at=hours(49);
 assert.equal(processDue(f.db,new Date()).auto_closed,1);
 assert.equal(f.c.status,'AUTO_CLOSED');
 const prevCycles=f.db.workCycles.size;
 reopen(f.db,f.c,f.student,'Still broken',new Date());
 assert.equal(f.c.cycle_number,2);assert.equal(f.c.current_staff_id,null);
 assert.equal(f.db.workCycles.size,prevCycles+1);assert.equal(f.c.status,'REOPENED');
 assert.equal(processDue(f.db,new Date()).escalated,0);
});
test('emergency and escalated repairs cannot be automatically closed',()=>{
 for(const risk of ['EMERGENCY','ESCALATED']){
  const f=fixture();cycleFor(f.db,f.c).work_started_at=hours(51);
  f.c.status='AWAITING_CONFIRMATION';f.c.work_completed_at=hours(52);
  if(risk==='EMERGENCY') f.c.effective_priority='EMERGENCY';
  else f.db.escalations.set('esc',{id:'esc',complaint_id:f.c.id,cycle_number:1});
  assert.equal(processDue(f.db,new Date()).auto_closed,0);
  assert.equal(f.c.status,'AWAITING_CONFIRMATION');
  assert.ok([...f.db.notifications.values()].some(n=>n.recipient_id==='r'));
 }
});
test('reopen rejects bogus states and expired auto-closed cases',()=>{
 const f=fixture();assert.throws(()=>reopen(f.db,f.c,f.student,'broken again'),/cannot be reopened/);
 f.c.status='AUTO_CLOSED';f.c.closed_at=hours(9*24);
 assert.equal(canStudentReopen(f.c),false);
 assert.doesNotThrow(()=>reopen(f.db,f.c,f.rector,'Exceptional reopening by Rector')); 
});
test('staff and Rector state transition guards forbid skipping work-start',()=>{
 assert.equal(validActionTransition('MAINTENANCE_STAFF','complete','ASSIGNED'),false);
 assert.equal(validActionTransition('MAINTENANCE_STAFF','start','ACCEPTED'),true);
 assert.equal(validActionTransition('RECTOR','reject','IN_PROGRESS'),false);
 assert.equal(validActionTransition('RECTOR','assign','CLOSED'),false);
 assert.equal(validActionTransition('RECTOR','verify','AWAITING_CONFIRMATION'),true);
});

test('CSV parser handles quoted commas and reports broken quoting',()=>{
 assert.deepEqual(parseCsv('urn,name\n1024031068,"Anita, Sharma"\n'),[['urn','name'],['1024031068','Anita, Sharma']]);
 assert.throws(()=>parseCsv('urn,name\n1024,"Unclosed'),/unclosed/);
});

test('former technician loses access when assignment ends or hostel scope revoked',()=>{
 const f=fixture();f.c.current_staff_id=f.staff.id;
 const a={id:'work1',complaint_id:f.c.id,staff_id:f.staff.id,assigned_at:new Date()};f.db.assignments.set(a.id,a);
 assert.equal(canView(f.db,f.staff,f.c),true);
 a.ended_at=new Date();assert.equal(canView(f.db,f.staff,f.c),false);
 delete a.ended_at;f.db.scopes.delete('sc5');assert.equal(canView(f.db,f.staff,f.c),false);
});
test('reopened complaint terminates old assignments and begins an independent work clock',()=>{
 const f=fixture();f.c.status='AWAITING_CONFIRMATION';f.c.current_staff_id='w';cycleFor(f.db,f.c).work_started_at=hours(51);
 const a={id:'a1',staff_id:'w',complaint_id:f.c.id,cycle_number:1,assigned_at:hours(3)};f.db.assignments.set('a1',a);
 reopen(f.db,f.c,f.student,'Problem not fixed yet',new Date());
 assert.ok(a.ended_at);
 assert.equal(f.c.current_staff_id,null);
 assert.equal(cycleFor(f.db,f.c).number,2);
 assert.equal(processDue(f.db,new Date()).escalated,0);
});

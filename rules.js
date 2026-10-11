import {generateId,OPEN_STATES} from './data.js';
const HOUR=3600_000;
const CLOSED=new Set(['CLOSED','AUTO_CLOSED','REJECTED','DUPLICATE']);
export function hostelIds(db,user){
  if(user.role==='SYSTEM_ADMIN')return [...db.hostels.keys()];
  return [...db.scopes.values()].filter(s=>s.user_id===user.id).map(s=>s.hostel_id);
}
export function scoped(db,role,hid){return [...db.users.values()].filter(u=>u.active&&u.role===role&&hostelIds(db,u).includes(hid));}
export function canView(db,user,c){
  if(!user||!c)return false;
  if(user.role==='SYSTEM_ADMIN')return true;
  if(user.role==='STUDENT')return c.student_id===user.id;
  if(user.role==='RECTOR')return hostelIds(db,user).includes(c.hostel_id);
  if(user.role==='MAINTENANCE_STAFF')return hostelIds(db,user).includes(c.hostel_id)&&c.current_staff_id===user.id&&[...db.assignments.values()].some(a=>a.complaint_id===c.id&&a.staff_id===user.id&&!a.ended_at);
  if(user.role==='DEAN')return hostelIds(db,user).includes(c.hostel_id)&&[...db.escalations.values()].some(e=>e.complaint_id===c.id);
  return false;
}
export function event(db,c,actor,action,detail=''){
 const id=generateId();db.events.set(id,{id,complaint_id:c.id,actor_id:actor?.id||null,action,detail:String(detail).slice(0,2000),at:new Date()});
}
export function notify(db,users,c,title,body){
 const seen=new Set();for(const u of users){if(!u||!u.active||seen.has(u.id))continue;seen.add(u.id);
 const id=generateId();db.notifications.set(id,{id,recipient_id:u.id,complaint_id:c?.id||null,title,body,read_at:null,created_at:new Date(),email_state:'PENDING',email_attempts:0});}
}
export function beginCycle(db,c,now=new Date()){
  const id=generateId();db.workCycles.set(id,{id,complaint_id:c.id,number:c.cycle_number,started_at:now,work_started_at:null});
}
export function cycleFor(db,c){return [...db.workCycles.values()].find(w=>w.complaint_id===c.id&&w.number===c.cycle_number);}
export function reopen(db,c,actor,reason,now=new Date()){
 if(!reason||reason.trim().length<5)throw new Error('Please explain the unresolved problem (at least 5 characters).');
 if(!['AWAITING_CONFIRMATION','AUTO_CLOSED','CLOSED'].includes(c.status))throw new Error('This complaint cannot be reopened now.');
 // Student 7-day window is enforced by the student route; Rectors may reopen exceptional cases.
 for(const a of db.assignments.values())if(a.complaint_id===c.id&&!a.ended_at)a.ended_at=now;
 const previous=c.status;c.status='REOPENED';c.cycle_number+=1;c.current_staff_id=null;c.work_started_at=null;c.work_completed_at=null;c.confirmation_reminded_at=null;c.closed_at=null;c.closure_reason=null;c.updated_at=now;
 beginCycle(db,c,now);event(db,c,actor,'REOPENED',`Previous status: ${previous}; Reason: ${reason}`);
 notify(db,scoped(db,'RECTOR',c.hostel_id),c,'Complaint reopened',`${c.number}: ${reason}`);
}
export function hasEscalation(db,c){return [...db.escalations.values()].some(e=>e.complaint_id===c.id);}
export function processDue(db,now=new Date()){
 const stats={escalated:0,reminded:0,auto_closed:0};
 for(const cycle of db.workCycles.values()){
  const c=db.complaints.get(cycle.complaint_id);if(!c)continue;
  const due=new Date(cycle.started_at).getTime()+48*HOUR;
  if(now.getTime()<due)continue;
  if(cycle.work_started_at && new Date(cycle.work_started_at).getTime()<due)continue;
  if(c.cycle_number===cycle.number && ['REJECTED','DUPLICATE'].includes(c.status))continue;
  if([...db.escalations.values()].some(e=>e.complaint_id===c.id&&e.cycle_number===cycle.number&&e.reason==='NO_WORK_STARTED_48H'))continue;
  const id=generateId();db.escalations.set(id,{id,complaint_id:c.id,cycle_number:cycle.number,reason:'NO_WORK_STARTED_48H',escalated_at:now});
  event(db,c,null,'DEAN_ESCALATION',`Work cycle ${cycle.number}: no repair start before 48-hour deadline`);
  const deans=scoped(db,'DEAN',c.hostel_id);notify(db,[...deans,...scoped(db,'RECTOR',c.hostel_id)],c,'48-hour Dean escalation',`${c.number}: repair not started within 48 hours.`);
  if(!deans.length)notify(db,[...db.users.values()].filter(u=>u.active&&u.role==='SYSTEM_ADMIN'),c,'Dean scope missing',`${c.number} overdue; assign a Dean to this hostel.`);
  stats.escalated++;
 }
 for(const c of db.complaints.values()){
  if(c.status!=='AWAITING_CONFIRMATION'||!c.work_completed_at)continue;
  const age=now-new Date(c.work_completed_at);
  if(age>=48*HOUR){
   if(c.effective_priority==='EMERGENCY'||hasEscalation(db,c)){
    if(!c.confirmation_reminded_at){notify(db,scoped(db,'RECTOR',c.hostel_id),c,'Rector verification required',`${c.number} is an emergency or escalated case.`);c.confirmation_reminded_at=now;}
    continue;
   }
   c.status='AUTO_CLOSED';c.closed_at=now;c.closure_reason='NO_STUDENT_RESPONSE';c.updated_at=now;
   event(db,c,null,'AUTO_CLOSED','No student response after 48 hours; reopen within 7 days.');notify(db,[db.users.get(c.student_id)],c,'Complaint auto-closed',`${c.number} closed after 48 hours; reopen within 7 days.`);
   stats.auto_closed++;
  }else if(age>=24*HOUR&&!c.confirmation_reminded_at){
   c.confirmation_reminded_at=now;event(db,c,null,'CONFIRMATION_REMINDER','24-hour student reminder');notify(db,[db.users.get(c.student_id)],c,'Please verify repair',`${c.number}: confirm if repaired.`);stats.reminded++;
  }
 }
 db.loginAttempts=db.loginAttempts.filter(x=>now-new Date(x.created_at)<30*24*HOUR);
 return stats;
}
export function validActionTransition(role,action,status){
 const graph={
  STUDENT:{confirm:['AWAITING_CONFIRMATION'],reopen:['AWAITING_CONFIRMATION','CLOSED','AUTO_CLOSED']},
  RECTOR:{review:['SUBMITTED','REOPENED'],assign:['SUBMITTED','UNDER_REVIEW','ASSIGNED','ACCEPTED','REOPENED','ON_HOLD'],classify:OPEN_STATES,reject:['SUBMITTED','UNDER_REVIEW','REOPENED'],verify:['AWAITING_CONFIRMATION'],reopen:['CLOSED','AUTO_CLOSED']},
  MAINTENANCE_STAFF:{accept:['ASSIGNED'],start:['ACCEPTED'],progress:['IN_PROGRESS','ON_HOLD'],hold:['ACCEPTED','IN_PROGRESS'],resume:['ON_HOLD'],complete:['IN_PROGRESS']}
 };
 return Boolean(graph[role]?.[action]?.includes(status));
}
export function parseCsv(input){
 const rows=[];let row=[],val='',quoted=false;
 for(let i=0;i<input.length;i++){
  const ch=input[i];
  if(ch==='"'){
   if(quoted&&input[i+1]==='"'){val+='"';i++;}
   else if(!quoted&&val===''){quoted=true;}
   else if(quoted){quoted=false;}
   else throw new Error('Malformed CSV quoting');
  }else if(ch===','&&!quoted){row.push(val);val='';}
  else if((ch==='\n'||ch==='\r')&&!quoted){
   if(ch==='\r'&&input[i+1]==='\n')i++;
   row.push(val);if(row.some(x=>x.trim()))rows.push(row);
   row=[];val='';
  }else val+=ch;
 }
 if(quoted)throw new Error('CSV contains an unclosed quoted field');
 row.push(val);if(row.some(x=>x.trim()))rows.push(row);
 return rows;
}

export function canStudentReopen(c,now=new Date()){
 if(c?.status==='AWAITING_CONFIRMATION')return true;
 if(c?.status!=='AUTO_CLOSED'||!c.closed_at)return false;
 const age=now-new Date(c.closed_at);
 return age>=0&&age<=7*24*3600_000;
}

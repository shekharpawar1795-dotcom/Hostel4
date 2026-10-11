import crypto from 'node:crypto';
import {loadState,saveState} from '../store.js';
import {hashPassword,generateId} from '../data.js';
const {db,version}=await loadState();
if([...db.users.values()].some(u=>u.role==='SYSTEM_ADMIN')){
  console.log('An administrator already exists. No credentials changed.');process.exit(0);
}
const password='HC-'+crypto.randomBytes(18).toString('base64url')+'8a';
const id=generateId();
const login='HCMSADMIN';
db.users.set(id,{id,login_id:login,urn:null,name:'System Administrator',preferred_name:null,email:null,phone:null,role:'SYSTEM_ADMIN',password_hash:hashPassword(password),force_password_change:true,active:true,created_at:new Date()});
await saveState(version,db);
console.log('SYSTEM ADMIN LOGIN:',login);
console.log('ONE-TIME PASSWORD:',password);
console.log('Store these details privately. You must change this password at first login.');

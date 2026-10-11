import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {requestContext} from '../data.js';
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'hostelcare-sqlite-tests-'));
process.env.SQLITE_DB_FILE=path.join(directory,'pilot.sqlite3');
const {loadState,saveState,stageEvidence,readEvidence,WriteConflict,sqliteFile,closeStore}=await import('../store.js');

test('SQLite database is actually created with separate durable evidence storage',async()=>{
 const state=await loadState();
 assert.equal(state.db.users.size,0,'a fresh database must not include hard-coded demo users');
 state.db.hostels.set('h1',{id:'h1',name:'Fictional Hostel',active:true});
 await saveState(state.version,state.db);
 assert.ok(fs.existsSync(sqliteFile));
 const restored=await loadState();
 assert.equal(restored.version,1);
 assert.equal(restored.db.hostels.get('h1').name,'Fictional Hostel');
});

test('evidence and attachment metadata commit atomically, and binary bytes survive reload',async()=>{
 const current=await loadState();
 const bytes=Buffer.from([0,255,13,10,5,4,3,2,1]);
 await requestContext.run({version:current.version,db:current.db},async()=>{
  current.db.attachments.set('photo1',{id:'photo1',complaint_id:'fake-complaint',mime_type:'image/png',storage_key:'photo1'});
  stageEvidence('photo1',bytes);
  await saveState(current.version,current.db);
 });
 assert.deepEqual(readEvidence('photo1'),bytes);
 const persisted=await loadState();
 assert.equal(persisted.db.attachments.get('photo1').mime_type,'image/png');
 const snapshotText=JSON.stringify([...persisted.db.attachments.values()]);
 assert.ok(!snapshotText.includes(bytes.toString('base64')),'image data must not inflate state snapshots');
});

test('concurrent stale request is rejected, never overwriting another complaint',async()=>{
 const a=await loadState();const b=await loadState();
 a.db.complaints.set('c1',{id:'c1',status:'SUBMITTED'});
 await saveState(a.version,a.db);
 b.db.complaints.set('c2',{id:'c2',status:'SUBMITTED'});
 await assert.rejects(()=>saveState(b.version,b.db),WriteConflict);
 const after=await loadState();
 assert.ok(after.db.complaints.has('c1'));
 assert.ok(!after.db.complaints.has('c2'));
});

test('failed duplicate photo write rolls back both state and image transaction',async()=>{
 const state=await loadState();
 await requestContext.run({version:state.version,db:state.db},async()=>{
  state.db.complaints.set('unsafe',{id:'unsafe',status:'SUBMITTED'});
  stageEvidence('photo1',Buffer.from('different bytes'));
  await assert.rejects(()=>saveState(state.version,state.db),/UNIQUE|constraint/i);
 });
 const after=await loadState();
 assert.ok(!after.db.complaints.has('unsafe'));
 assert.deepEqual(readEvidence('photo1'),Buffer.from([0,255,13,10,5,4,3,2,1]));
});

test('read-only commits do not change revision and invalid evidence is rejected',async()=>{
 const state=await loadState();
 assert.equal(await saveState(state.version,state.db),state.version);
 await requestContext.run({version:state.version,db:state.db},async()=>{
  assert.throws(()=>stageEvidence('empty',Buffer.alloc(0)),/Invalid evidence/);
 });
});

test('persistent sqlite file can be reopened without losing complaint or evidence',async()=>{
 const before=await loadState();
 closeStore();
 const {DatabaseSync}=await import('node:sqlite');
 const reopened=new DatabaseSync(sqliteFile);
 const current=reopened.prepare('SELECT version,payload FROM app_state WHERE id=1').get();
 const photo=reopened.prepare('SELECT content FROM evidence WHERE id=?').get('photo1');
 assert.equal(current.version,before.version);
 assert.ok(JSON.parse(current.payload).complaints.some(([id])=>id==='c1'));
 assert.deepEqual(Buffer.from(photo.content),Buffer.from([0,255,13,10,5,4,3,2,1]));
 reopened.close();
 fs.rmSync(directory,{recursive:true,force:true});
});

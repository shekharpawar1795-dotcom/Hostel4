/** SQLite persistence for the Node / Express / EJS single-server testing edition.
 * A versioned application snapshot and private evidence BLOBs are committed in
 * ONE SQLite transaction. No memory, JSON-file or remote-service fallbacks.
 * Requires Node 22.13+ (Node 24 LTS recommended for native node:sqlite).
 */
import {DatabaseSync} from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import {emptyDatabase,requestContext} from './data.js';

const dbPath=path.resolve(process.env.SQLITE_DB_FILE || './data/hostelcare.sqlite3');
fs.mkdirSync(path.dirname(dbPath),{recursive:true,mode:0o700});
const sql=new DatabaseSync(dbPath);
sql.exec(`
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS app_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 version INTEGER NOT NULL DEFAULT 0,
 payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
 id TEXT PRIMARY KEY,
 content BLOB NOT NULL CHECK(length(content)>0),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const mapFields=Object.keys(emptyDatabase()).filter(k=>emptyDatabase()[k] instanceof Map);
export const sqliteFile=dbPath;
export function serialize(db){
 const s={};
 for(const [name,value] of Object.entries(db))s[name]=value instanceof Map?[...value.entries()]:value;
 return s;
}
export function deserialize(data={}){
 const db=emptyDatabase();
 for(const k of Object.keys(db)){
  if(mapFields.includes(k))db[k]=new Map(Array.isArray(data[k])?data[k]:[]);
  else db[k]=Array.isArray(data[k])?data[k]:[];
 }
 return db;
}
export async function loadState(){
 const row=sql.prepare('SELECT version,payload FROM app_state WHERE id=1').get();
 return row?{version:row.version,db:deserialize(JSON.parse(row.payload))}:{version:0,db:emptyDatabase()};
}
export class WriteConflict extends Error{
 constructor(){super('Another request updated HostelCare first. Refresh and retry.');this.status=409;}
}
export function stageEvidence(id,buffer){
 const context=requestContext.getStore();
 if(!context)throw new Error('Evidence upload requires a request transaction');
 if(!Buffer.isBuffer(buffer)||buffer.length===0)throw new Error('Invalid evidence bytes');
 if(!context.pendingEvidence)context.pendingEvidence=[];
 context.pendingEvidence.push({id,buffer:Buffer.from(buffer)});
}
export function readEvidence(id){
 const row=sql.prepare('SELECT content FROM evidence WHERE id=?').get(id);
 return row?Buffer.from(row.content):null;
}
export async function saveState(expectedVersion,db){
 const context=requestContext.getStore();
 const pending=context?.pendingEvidence||[];
 const nextPayload=JSON.stringify(serialize(db));
 let active=false;
 try{
  sql.exec('BEGIN IMMEDIATE'); active=true;
  const row=sql.prepare('SELECT version,payload FROM app_state WHERE id=1').get();
  const currentVersion=row?.version||0;
  if(currentVersion!==expectedVersion)throw new WriteConflict();
  // Read-only/invalid POSTs do not unnecessarily alter the state version.
  if(row?.payload===nextPayload && !pending.length){sql.exec('COMMIT');active=false;return currentVersion;}
  if(row){
   const result=sql.prepare('UPDATE app_state SET version=?,payload=? WHERE id=1 AND version=?')
    .run(currentVersion+1,nextPayload,currentVersion);
   if(result.changes!==1)throw new WriteConflict();
  }else{
   sql.prepare('INSERT INTO app_state(id,version,payload) VALUES(1,?,?)').run(1,nextPayload);
  }
  const insert=sql.prepare('INSERT INTO evidence(id,content) VALUES(?,?)');
  for(const {id,buffer} of pending)insert.run(id,buffer);
  sql.exec('COMMIT');active=false;
  if(context)context.pendingEvidence=[];
  return currentVersion+1;
 }catch(error){if(active){try{sql.exec('ROLLBACK');}catch{}}throw error;}
}
export function closeStore(){sql.close();}

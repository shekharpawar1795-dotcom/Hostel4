import {existsSync,mkdirSync} from 'node:fs';
import path from 'node:path';
import {DatabaseSync,backup} from 'node:sqlite';
const src=path.resolve(process.env.SQLITE_DB_FILE||'./data/hostelcare.sqlite3');
if(!existsSync(src)){console.error('No SQLite database yet. Start and initialize the project first.');process.exit(1)}
mkdirSync('./backups',{recursive:true,mode:0o700});
const dest=path.resolve('backups',`hostelcare-${new Date().toISOString().replace(/[:.]/g,'-')}.sqlite3`);
const database=new DatabaseSync(src);
try {await backup(database,dest);console.log('SQLite backup completed:',dest)}
finally {database.close()}

import {existsSync,writeFileSync,mkdirSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import path from 'node:path';
if(existsSync('.env')){
 console.log('Existing .env was not overwritten.');
}else{
 const session=randomBytes(48).toString('hex');
 const cron=randomBytes(32).toString('hex');
 writeFileSync('.env',`PORT=3000\nSESSION_SECRET=${session}\nSQLITE_DB_FILE=./data/hostelcare.sqlite3\nCRON_SECRET=${cron}\n`,{mode:0o600,flag:'wx'});
 console.log('Created private .env with strong random secrets.');
}
mkdirSync(path.resolve('data'),{recursive:true,mode:0o700});
console.log('Next: npm run admin:init   then   npm start');

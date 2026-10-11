import {loadState,saveState} from '../store.js';
import {processDue} from '../rules.js';
async function tick(){
 try{const {db,version}=await loadState();const stats=processDue(db);await saveState(version,db);console.log('Scheduled checks',new Date().toISOString(),stats);}
 catch(error){console.error('Scheduled check failed:',error.message);}
}
await tick();setInterval(tick,5*60*1000);

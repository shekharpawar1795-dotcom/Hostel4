/** Optional import from the previously shipped local .local-hcms-data.json.
 * Must run on an EMPTY new SQLite database, BEFORE bootstrapping admin.
 * Refuses to silently lose photos whose bytes are not available in the JSON.
 */
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {requestContext} from '../data.js';
import {deserialize,loadState,saveState,stageEvidence} from '../store.js';
import {looksLikeImage} from '../evidence.js';
const filename=process.argv[2];
if(!filename){console.error('Usage: node --env-file=.env scripts/import-legacy-json.js "C:\\path\\to\\.local-hcms-data.json"');process.exit(1)}
const state=await loadState();
if(state.version!==0 || state.db.users.size){console.error('Import refused: SQLite is not empty. Use a clean test database and import before initializing admin.');process.exit(1)}
const contents=JSON.parse(readFileSync(resolve(filename),'utf8'));
if(!contents.payload || typeof contents.payload!=='object')throw new Error('Invalid local JSON state file');
const imported=deserialize(contents.payload);
let photoCount=0;
await requestContext.run({version:state.version,db:imported},async()=>{
 for(const attachment of imported.attachments.values()){
  if(typeof attachment.buffer!=='string'||!attachment.buffer.length)throw new Error(`Cannot import attachment ${attachment.id}: the JSON does not contain its image bytes. Export/download photos from the original storage first.`);
  const bytes=Buffer.from(attachment.buffer,'base64');
  if(!looksLikeImage(bytes,attachment.mime_type))throw new Error(`Invalid or corrupted image bytes for ${attachment.id}`);
  stageEvidence(attachment.id,bytes);
  attachment.storage_key=attachment.id;
  attachment.byte_length=bytes.length;
  delete attachment.buffer;
  delete attachment.public_url;
  photoCount++;
 }
 await saveState(0,imported);
});
console.log(`Imported ${imported.users.size} users, ${imported.complaints.size} complaints and ${photoCount} private photos into SQLite.`);
console.log('If legacy demo accounts were included, RESET THEIR PASSWORDS before sharing the website.');

export function looksLikeImage(b,m){
 if(!Buffer.isBuffer(b))return false;
 if(m==='image/png')return b.length>=24&&b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))&&b.toString('ascii',12,16)==='IHDR'&&b.toString('ascii',b.length-8,b.length-4)==='IEND';
 if(m==='image/jpeg')return b.length>20&&b[0]===255&&b[1]===216&&b[2]===255&&b[b.length-2]===255&&b[b.length-1]===217;
 if(m==='image/webp')return b.length>=16&&b.toString('ascii',0,4)==='RIFF'&&b.toString('ascii',8,12)==='WEBP'&&b.readUInt32LE(4)===b.length-8;
 return false;
}

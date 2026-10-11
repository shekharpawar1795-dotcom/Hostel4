import test from 'node:test';
import assert from 'node:assert/strict';
import {looksLikeImage} from '../evidence.js';
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO5KDlkAAAAASUVORK5CYII=','base64');
test('PNG evidence requires full signature, IHDR and IEND',()=>{
 assert.equal(looksLikeImage(png,'image/png'),true);
 assert.equal(looksLikeImage(png.subarray(0,png.length-8),'image/png'),false);
 assert.equal(looksLikeImage(png,'image/jpeg'),false);
});
test('rejects non-images, empty files and MIME spoofing',()=>{
 assert.equal(looksLikeImage(Buffer.from('plain text'),'image/png'),false);
 assert.equal(looksLikeImage(Buffer.alloc(0),'image/webp'),false);
 assert.equal(looksLikeImage(png,'application/pdf'),false);
});
test('WebP evidence requires a consistent RIFF byte count',()=>{
 const webp=Buffer.alloc(20);
 webp.write('RIFF',0);webp.writeUInt32LE(12,4);webp.write('WEBP',8);
 assert.equal(looksLikeImage(webp,'image/webp'),true);
 webp.writeUInt32LE(4,4);
 assert.equal(looksLikeImage(webp,'image/webp'),false);
});

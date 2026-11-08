// Complete bounded read-only snapshot. No producer, subprocess, network or host query.
import assert from 'node:assert/strict';
import {open,lstat,readdir,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {outputName} from './output-contract.mjs';

export async function readOutputDirectory(directory) {
 const root=resolve(directory);assert.equal(await realpath(root),root,'Output root is an alias');
 const top=await lstat(root);assert(top.isDirectory()&&!top.isSymbolicLink(),'Output root is not a directory');
 const entries=[],contents=new Map(),aliases=new Set();let total=0;
 async function walk(prefix='') {
  for(const entry of (await readdir(join(root,prefix),{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))) {
   assert(entries.length<4096,'Output namespace budget exceeded');const path=outputName(prefix+entry.name),alias=path.normalize('NFC').toLowerCase();assert(!aliases.has(alias),'Output path alias');aliases.add(alias);
   const actual=join(root,path),st=await lstat(actual);assert(!st.isSymbolicLink(),'Output link is forbidden');
   if(st.isDirectory()){entries.push({path,type:'directory',mode:st.mode&0o7777});await walk(path+'/');continue;}
   assert(st.isFile()&&st.nlink===1,'Output must be an unlinked regular file');assert(st.size<=8*1024*1024,'Output file budget exceeded');
   const handle=await open(actual,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
   try {
    const before=await handle.stat();assert(before.isFile()&&before.nlink===1);assert.equal(before.dev,st.dev);assert.equal(before.ino,st.ino);
    const chunks=[],hash=createHash('sha256');let bytes=0;
    for await(const chunk of handle.createReadStream({autoClose:false})){bytes+=chunk.length;total+=chunk.length;assert(bytes<=8*1024*1024&&total<=32*1024*1024,'Output byte budget exceeded');chunks.push(chunk);hash.update(chunk);}
    const after=await handle.stat();for(const key of ['size','mode','dev','ino','mtimeMs','ctimeMs','nlink'])assert.equal(after[key],before[key],'Output changed during inspection');assert.equal(bytes,before.size);
    entries.push({path,type:'file',bytes,sha256:hash.digest('hex'),mode:before.mode&0o7777,nlink:before.nlink});contents.set(path,Buffer.concat(chunks));
   }finally{await handle.close();}
  }
 }
 await walk();assert(contents.size<=2048,'Output file count budget exceeded');return {entries:entries.sort((a,b)=>a.path.localeCompare(b.path)),contents};
}

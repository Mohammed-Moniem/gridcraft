import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,readdir,lstat,copyFile,chmod} from 'node:fs/promises';
import {constants,createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {join,dirname,relative,resolve,sep} from 'node:path';
import {spawn} from 'node:child_process';
import {connect} from 'node:net';
import {sha,safeRelative,assertPreparationSelection} from './core.mjs';

export const json=async path=>JSON.parse(await readFile(path,'utf8'));
export async function save(path,value) {await mkdir(dirname(path),{recursive:true});await writeFile(path,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o644});}
export async function hash(path) {const h=createHash('sha256');for await(const b of createReadStream(path))h.update(b);return h.digest('hex');}
export async function fileIdentity(path) {const st=await lstat(path);assert(st.isFile()&&!st.isSymbolicLink(),'Expected regular file');return {path,bytes:st.size,sha256:await hash(path),mode:st.mode&0o777};}
export async function checkIdentity(path,expected) {const actual=await fileIdentity(path);assert.equal(actual.bytes,expected.bytes);assert.equal(actual.sha256,expected.sha256);return actual;}
export function inside(root,path) {const result=resolve(path);assert(result.startsWith(resolve(root)+sep),'Path outside owned workspace');return result;}
export async function inventory(root,prefix='') {const rows=[];for(const entry of (await readdir(join(root,prefix),{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:1)){const path=safeRelative(prefix+entry.name),absolute=join(root,path);assert(!entry.isSymbolicLink(),'Symbolic link in inventory');if(entry.isDirectory())rows.push(...await inventory(root,path+'/'));else {assert(entry.isFile(),'Special file in inventory');const f=await fileIdentity(absolute);rows.push({path,bytes:f.bytes,sha256:f.sha256,mode:f.mode});}}return rows.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);}
export async function checkInventory(root,expected,{checkMode=process.platform!=='win32'}={}) {const actual=await inventory(root);assert.deepEqual(actual.map(f=>f.path),expected.map(f=>f.path).sort(),'Extra or absent files');const index=new Map(actual.map(f=>[f.path,f]));for(const row of expected){const got=index.get(row.path);assert.equal(got.bytes,row.bytes,row.path);assert.equal(got.sha256,row.sha256,row.path);if(checkMode)assert.equal(got.mode,typeof row.mode==='string'?parseInt(row.mode.slice(-3),8):row.mode,row.path);}return actual;}
export async function copyRegular(source,destination) {const st=await lstat(source);assert(!st.isSymbolicLink(),'Refuse link copy');if(st.isDirectory()){await mkdir(destination,{recursive:true});for(const entry of await readdir(source))await copyRegular(join(source,entry),join(destination,entry));}else {assert(st.isFile());await mkdir(dirname(destination),{recursive:true});await copyFile(source,destination,constants.COPYFILE_EXCL);await chmod(destination,st.mode&0o111?0o755:0o644);}}
export async function command(executable,args,{cwd,env,log,timeoutMs=120000,maxBytes=32*1024*1024,expected=0}={}) {
  assert.equal(typeof executable,'string');assert(Array.isArray(args)&&args.every(a=>typeof a==='string'));
  const startedAt=new Date().toISOString(),out=[],err=[];let total=0,timedOut=false,overflow=false,launchError=null;
  const child=spawn(executable,args,{cwd,env,stdio:['ignore','pipe','pipe'],windowsHide:true,detached:process.platform!=='win32',shell:false});let forceTimer;
  const terminate=()=>{try {if(process.platform==='win32')child.kill('SIGTERM');else process.kill(-child.pid,'SIGTERM');}catch{}if(!forceTimer)forceTimer=setTimeout(()=>{try{if(process.platform==='win32')child.kill('SIGKILL');else process.kill(-child.pid,'SIGKILL');}catch{}},5000);};
  const timer=setTimeout(()=>{timedOut=true;terminate();},timeoutMs);
  for(const [stream,chunks]of [[child.stdout,out],[child.stderr,err]])stream.on('data',b=>{total+=b.length;if(total>maxBytes){overflow=true;terminate();}else chunks.push(b);});
  const [code,signal]=await new Promise(yes=>{child.once('error',error=>{launchError=error.message;yes([null,null]);});child.once('close',(c,s)=>yes([c,s]));});clearTimeout(timer);clearTimeout(forceTimer);
  const result={executable,args,cwd,environment:env,startedAt,finishedAt:new Date().toISOString(),code,signal,timedOut,overflow,launchError,stdout:Buffer.concat(out).toString(),stderr:Buffer.concat(err).toString()};
  if(log)await save(log,result);
  assert.equal(launchError,null);assert.equal(timedOut,false,'Command timed out');assert.equal(overflow,false,'Log budget exceeded');assert.equal(signal,null);assert.equal(code,expected,result.stderr);
  assert(!/panicked at|stack backtrace:/.test(result.stderr),'Runtime panic');return result;
}
export async function externalDenied() {return new Promise((yes,no)=>{const socket=connect({host:'1.1.1.1',port:443});socket.setTimeout(3000);socket.once('connect',()=>{socket.destroy();no(Error('External TCP is available'));});socket.once('timeout',()=>{socket.destroy();no(Error('Timeout is not OS denial'));});socket.once('error',e=>{socket.destroy();if(['EPERM','EACCES'].includes(e.code))yes({target:'1.1.1.1:443',denied:true,code:e.code,scope:'This permission-denied probe; not a whole-network audit'});else no(e);});});}
export async function download(asset,path) {
  assert(asset.url&&Number.isSafeInteger(asset.bytes)&&asset.bytes>0&&asset.bytes<=2*1024**3);assert.match(asset.sha256,/^[a-f0-9]{64}$/);assert.match(asset.name,/^[a-zA-Z0-9._-]+$/);await mkdir(dirname(path),{recursive:true});
  const response=await fetch(asset.url,{signal:AbortSignal.timeout(300000),credentials:'omit',headers:{'Accept-Encoding':'identity'}});
  assert(response.ok&&response.body,'Anonymous download failed: '+response.status);
  const length=response.headers.get('content-length');if(length!==null)assert.equal(Number(length),asset.bytes,'Download length header differs');
  const handle=await import('node:fs/promises').then(fs=>fs.open(path+'.partial','wx',0o644));let count=0;const h=createHash('sha256');
  try {for await(const chunk of response.body){count+=chunk.length;assert(count<=asset.bytes,'Download exceeds pin');h.update(chunk);await handle.writeFile(chunk);}await handle.sync();}finally{await handle.close();}
  assert.equal(count,asset.bytes,'Truncated download');assert.equal(h.digest('hex'),asset.sha256,'Anonymous byte hash differs');
  await copyFile(path+'.partial',path,constants.COPYFILE_EXCL); // retain partial as failure/download evidence
  return {url:asset.url,finalUrl:response.url,bytes:count,sha256:asset.sha256,anonymous:true,credentialHeaders:false};
}
export async function receiptProof(root,spec) {assert(spec.path);const path=resolve(root,spec.path);await checkIdentity(path,spec);return json(path);}
export async function preparationProof(here,admission,pins,target,kitDigest) {
 const selection=await receiptProof(here,admission.independentSelection),critic=await receiptProof(here,selection.critic),replay=await receiptProof(here,selection.rootReplay);
 assertPreparationSelection(selection,critic,replay,pins,target,admission.stages,kitDigest,admission.discoveryBinding);return selection;
}
export async function verifyKit(here) {const raw=await readFile(join(here,'FREEZE.json')),freeze=JSON.parse(raw);for(const row of freeze.files)await checkIdentity(join(here,safeRelative(row.path)),row);return {sha256:sha(raw),freeze};}

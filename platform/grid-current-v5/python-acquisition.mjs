// ACTUAL shared read-only filesystem policy. No query, interpreter, child, network, write or host probe.
import assert from 'node:assert/strict';
import {open,lstat,opendir,realpath,readlink} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve,dirname,parse,sep,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {PYTHON_NAMESPACE_POLICY,PYTHON_NAMESPACE_LIMITS,assertPythonNamespaceDescription,assertPythonNamespaceCapture,assertPythonNamespaceObservation,pythonPathWithin} from './python-namespace-contract.mjs';
const order=(a,b)=>a<b?-1:a>b?1:0;
const statKeys=['dev','ino','size','mtimeNs','ctimeNs','mode','nlink'];
function stable(before,after){for(const key of statKeys)assert.equal(after[key],before[key],'Python namespace changed while acquiring '+key);}
const metadata=(st,link=false)=>({dev:String(st.dev),ino:String(st.ino),mode:Number(st.mode&0o777n),...(link?{size:String(st.size),mtimeNs:String(st.mtimeNs),ctimeNs:String(st.ctimeNs),nlink:String(st.nlink)}:{})});
export async function acquirePythonInputs(description,{allowedRoots,recordIdentity}={}){
 assertPythonNamespaceDescription(description);assert(Array.isArray(allowedRoots)&&allowedRoots.length>0&&allowedRoots.length<=32);allowedRoots=[...new Set(allowedRoots.map(path=>resolve(path)))].sort(order);
 const started=Date.now(),files=new Map(),directories=new Map(),links=new Map(),resolutions=new Map(),observations=new Map(),missing=new Set(),absent=new Set(),lookups=[];let bytes=0,entryCount=0,resolutionSteps=0;
 const budget=()=>assert(Date.now()-started<PYTHON_NAMESPACE_LIMITS.wallMs,'Python acquisition time budget');
 const bounded=path=>assert(allowedRoots.some(base=>pythonPathWithin(base,path)),'Python executable/search/alias target outside reviewed roots: '+path);
 async function observe(path){budget();const st=await lstat(path,{bigint:true});assert(!(st.mode&0o7000n),'Special Python namespace permissions');const prior=observations.get(path);if(prior)stable(prior,st);else observations.set(path,st);return st;}
 async function resolveLookup(locator){
  if(resolutions.has(locator))return resolutions.get(locator);assert(resolutions.size<PYTHON_NAMESPACE_LIMITS.resolutions);bounded(locator);
  let current=parse(locator).root,pending=locator.slice(current.length).split(sep==='\\'?/[\\/]/:/\//),kind='directory',hops=0;const steps=[],seen=new Set();
  const step=row=>{budget();assert(++resolutionSteps<=PYTHON_NAMESPACE_LIMITS.resolutionSteps&&steps.length<PYTHON_NAMESPACE_LIMITS.resolutionPathSteps,'Python resolution step budget');steps.push(row);};
  async function root(){const st=await observe(current);assert(st.isDirectory()&&!st.isSymbolicLink(),'Python resolution root changed');step({path:current,kind:'directory',identity:metadata(st)});}
  await root();let absence=null;
  while(pending.length){budget();const part=pending.shift();if(!part||part==='.')continue;if(part==='..'){current=dirname(current);kind='directory';continue;}assert(!/[\\/\x00-\x1f]/.test(part));const child=join(current,part);let st;
   try{st=await observe(child);}catch(error){if(error.code!=='ENOENT')throw error;bounded(child);step({path:child,kind:'absent'});missing.add(child);absence={missingPath:child,remaining:[...pending]};current=resolve(child,...pending);bounded(current);kind='absent';break;}
   if(st.isSymbolicLink()){
    bounded(child);assert(++hops<=PYTHON_NAMESPACE_LIMITS.resolutionHops,'Python alias hop budget');const state=child+'\0'+pending.join('\0');assert(!seen.has(state),'Unresolved Python alias cycle');seen.add(state);const link=await readlink(child);assert(link.length>0&&link.length<=4096&&!/[\x00-\x1f]/.test(link));stable(st,await lstat(child,{bigint:true}));step({path:child,kind:'symlink',link,identity:metadata(st,true)});
    if(isAbsolute(link)){current=parse(link).root;pending=link.slice(current.length).split(sep==='\\'?/[\\/]/:/\//).concat(pending);bounded(resolve(current,...pending));await root();}else{pending=link.split(sep==='\\'?/[\\/]/:/\//).concat(pending);bounded(resolve(current,...pending));}kind='directory';continue;
   }
   assert(st.isDirectory()||st.isFile(),'Special Python namespace resolution entry');kind=st.isDirectory()?'directory':'file';step({path:child,kind,identity:metadata(st)});current=child;if(kind==='file')assert.equal(pending.length,0,'Python lookup traverses a regular file');
  }
  bounded(current);const result={locator,kind,path:current,steps,...(absence??{})};resolutions.set(locator,result);return result;
 }
 async function file(path){if(files.has(path))return;budget();bounded(path);assert(files.size<PYTHON_NAMESPACE_LIMITS.files);const pathBefore=await observe(path);assert(pathBefore.isFile()&&!pathBefore.isSymbolicLink());assert.equal(await realpath(path),path);const handle=await open(path,constants.O_RDONLY|(constants.O_NOFOLLOW??0));let row;
  try{const before=await handle.stat({bigint:true});stable(pathBefore,before);assert(before.isFile()&&before.nlink>=1n&&before.size>=0n&&before.size<=BigInt(PYTHON_NAMESPACE_LIMITS.fileBytes));bytes+=Number(before.size);assert(bytes<=PYTHON_NAMESPACE_LIMITS.totalBytes);let count=0;const hash=createHash('sha256');for await(const chunk of handle.createReadStream({autoClose:false,highWaterMark:65536})){budget();count+=chunk.length;assert(count<=Number(before.size));hash.update(chunk);}stable(before,await handle.stat({bigint:true}));stable(before,await lstat(path,{bigint:true}));assert.equal(await realpath(path),path);assert.equal(count,Number(before.size));row={path,bytes:count,sha256:hash.digest('hex'),mode:Number(before.mode&0o777n)};}finally{await handle.close();}if(recordIdentity)await recordIdentity({...row});files.set(path,row);
 }
 async function visit(path,depth=0){budget();assert(depth<=PYTHON_NAMESPACE_LIMITS.depth);bounded(path);assert.equal(await realpath(path),path,'Python resolved namespace ancestor changed');const st=await observe(path);assert(!st.isSymbolicLink());if(st.isFile()){await file(path);return {kind:'file',path};}assert(st.isDirectory(),'Special Python namespace entry');if(directories.has(path))return {kind:'directory',path};assert(directories.size<PYTHON_NAMESPACE_LIMITS.directories);const record={path,mode:Number(st.mode&0o777n),entries:[]};directories.set(path,record);const names=new Set();
  const stream=await opendir(path,{bufferSize:32});for await(const entry of stream){budget();assert(++entryCount<=PYTHON_NAMESPACE_LIMITS.entries);assert(entry.name&&!/[\\/\x00-\x1f]/.test(entry.name));const alias=entry.name.normalize('NFC').toLowerCase();assert(!names.has(alias),'Python namespace case/Unicode alias');names.add(alias);const child=join(path,entry.name),before=await observe(child);const type=before.isSymbolicLink()?'symlink':before.isDirectory()?'directory':before.isFile()?'file':'special';assert.notEqual(type,'special');
   if(type==='symlink'){assert(links.size<PYTHON_NAMESPACE_LIMITS.links);const resolution=await resolveLookup(child),raw=resolution.steps.find(row=>row.path===child&&row.kind==='symlink');assert(raw,'Python alias raw body missing');if(resolution.kind!=='absent')await visit(resolution.path,depth+1);assert.equal(await readlink(child),raw.link);stable(before,await lstat(child,{bigint:true}));links.set(child,{path:child,link:raw.link,resolved:resolution.path,kind:resolution.kind});record.entries.push({name:entry.name,type,link:raw.link});}
   else{await visit(child,depth+1);stable(before,await lstat(child,{bigint:true}));record.entries.push({name:entry.name,type});}}
  stable(st,await lstat(path,{bigint:true}));record.entries.sort((a,b)=>order(a.name,b.name));return {kind:'directory',path};
 }
 for(const role of ['runtimeRoots','searchPaths','requiredFiles','optionalFiles'])for(const [index,locator]of description[role].entries()){
  const resolution=await resolveLookup(locator);let found;if(resolution.kind==='absent'){assert(['searchPaths','optionalFiles'].includes(role),'Required Python namespace is absent');absent.add(locator);found={kind:'absent'};}else found=await visit(resolution.path);
  if(role==='runtimeRoots')assert.equal(found.kind,'directory');if(role==='requiredFiles'||role==='optionalFiles'&&found.kind!=='absent')assert.equal(found.kind,'file');if(role==='searchPaths'&&found.kind==='file')assert(/\.zip$/i.test(locator));lookups.push({role,index,locator,...found});
 }
 // Recheck all ancestor, link and missing-component observations after complete body acquisition.
 // No persistent directory mtime is required: identity/shape and raw link resolution are retained,
 // while full metadata must be stable throughout each individual acquisition.
 for(const [path,before]of observations){budget();stable(before,await lstat(path,{bigint:true}));}
 for(const resolution of resolutions.values())for(const row of resolution.steps)if(row.kind==='symlink'){budget();assert.equal(await readlink(row.path),row.link,'Python raw alias changed during acquisition');}
 for(const path of missing){budget();try{await lstat(path,{bigint:true});assert.fail('Previously missing Python alias/lookup target appeared during acquisition');}catch(error){if(error.code!=='ENOENT')throw error;}}
 const result={policy:PYTHON_NAMESPACE_POLICY,complete:true,limits:{...PYTHON_NAMESPACE_LIMITS},description:structuredClone(description),allowedRoots,files:[...files.values()].sort((a,b)=>order(a.path,b.path)),directories:[...directories.values()].sort((a,b)=>order(a.path,b.path)),links:[...links.values()].sort((a,b)=>order(a.path,b.path)),resolutions:[...resolutions.values()].sort((a,b)=>order(a.locator,b.locator)),lookups,absentFiles:[...absent].sort(order)};assertPythonNamespaceCapture(result);return result;
}
export async function revalidatePythonInputs(expected,{recordIdentity}={}){assertPythonNamespaceCapture(expected);const observed=await acquirePythonInputs(expected.description,{allowedRoots:expected.allowedRoots,recordIdentity});assertPythonNamespaceObservation(expected,observed);return observed;}

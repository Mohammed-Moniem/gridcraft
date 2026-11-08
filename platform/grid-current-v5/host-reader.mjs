// Read-only actual consuming-host observation; no program, interpreter, query or network execution.
import assert from 'node:assert/strict';
import {open,lstat,realpath,readdir,readlink} from 'node:fs/promises';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {cpus,release} from 'node:os';
import {revalidatePythonInputs} from './python-acquisition.mjs';
export const CONTEXT_KEYS=['GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_ARCH','ImageOS','ImageVersion'];
export const hostContextEnvironment=()=>Object.fromEntries(CONTEXT_KEYS.filter(key=>process.env[key]!==undefined).map(key=>[key,process.env[key]]));
export function currentHost(){return {platform:process.platform,arch:process.arch,release:release(),cpuModels:[...new Set(cpus().map(cpu=>cpu.model))],imageOS:process.env.ImageOS??null,imageVersion:process.env.ImageVersion??null,runnerEnvironment:process.env.RUNNER_ENVIRONMENT??null,repository:process.env.GITHUB_REPOSITORY??null};}
export async function directoryEvidence(path){const st=await lstat(path);assert(st.isDirectory()&&!st.isSymbolicLink());assert.equal(await realpath(path),path);const entries=[];for(const entry of await readdir(path,{withFileTypes:true})){assert(entries.length<1024,'Python import namespace budget');const full=join(path,entry.name),s=await lstat(full);const type=s.isSymbolicLink()?'symlink':s.isDirectory()?'directory':s.isFile()?'file':'special';assert.notEqual(type,'special');entries.push({name:entry.name,type,...(type==='symlink'?{link:await readlink(full)}:{})});}return {path,entries:entries.sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)};}
export async function observeCapturedHost(capture) {
 const pythonNamespace=await revalidatePythonInputs(capture.tools.python.query.namespaceCapture);
 for(const row of [...capture.tools.python.query.loadedFiles,...capture.tools.python.query.cacheFiles,...capture.tools.python.query.supportFiles])if(row.locator)assert.equal(await realpath(row.locator),row.path,'Python executable input locator changed');
 const files=[];let total=0;const started=Date.now();
 for(const row of capture.inspection.files){assert(Date.now()-started<600000,'Host preflight time budget');assert.equal(await realpath(row.path),row.path,'Captured path alias changed');const handle=await open(row.path,constants.O_RDONLY|(constants.O_NOFOLLOW??0));try{const before=await handle.stat();assert(before.isFile()&&before.nlink>=1&&before.size<=512*1024*1024&&!(before.mode&0o7000));const hash=createHash('sha256');let bytes=0;for await(const chunk of handle.createReadStream({autoClose:false})){bytes+=chunk.length;total+=chunk.length;assert(total<=2*1024**3);hash.update(chunk);}const after=await handle.stat();for(const key of ['dev','ino','size','mtimeMs','ctimeMs','mode','nlink'])assert.equal(after[key],before[key]);files.push({path:row.path,bytes,sha256:hash.digest('hex'),mode:before.mode&0o777});}finally{await handle.close();}}
 // The shared revalidation above proves terminal target absence through the same raw
 // alias/ancestor chain; lstat of a stable dangling alias itself correctly succeeds.
 const absentFiles=pythonNamespace.lookups.filter(row=>row.role==='optionalFiles'&&row.kind==='absent').map(row=>row.locator);
 const searchDirectories=[];for(const directory of capture.tools.python.query.searchDirectories){if(directory.locator)assert.equal(await realpath(directory.locator),directory.path,'Python import namespace locator changed');searchDirectories.push({...await directoryEvidence(directory.path),...(directory.locator?{locator:directory.locator}:{})});}
 return {host:currentHost(),files,absentFiles:absentFiles.sort(),searchDirectories,pythonNamespace};
}

import assert from 'node:assert/strict';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {cpus,machine,release} from 'node:os';
import {sha,assertAdmission,assertPublicSource,assertRuntimeManifest,assertArtifactSelection} from './core.mjs';
import {json,save,hash,fileIdentity,checkIdentity,checkInventory,inventory,inside,command,externalDenied,receiptProof,verifyKit,preparationProof} from './io.mjs';
import {archiveArgs,assertArchiveInvocation} from './python-plan.mjs';
import {effectPreflight} from './effect-preflight.mjs';
import {hostContextEnvironment} from './host-reader.mjs';

export async function openQualification(stage) {
 const here=fileURLToPath(new URL('.',import.meta.url));
 const {values}=parseArgs({options:{workspace:{type:'string'},admission:{type:'string'},'admission-sha256':{type:'string'}}});
 const pins=await json(join(here,'inputs.json')),kit=await verifyKit(here),work=inside(join(here,'runs'),values.workspace);
 const raw=await readFile(resolve(values.admission));assert.equal(sha(raw),values['admission-sha256']);const admission=JSON.parse(raw),target=admission.target;
 assertAdmission(admission,pins,target,stage,kit.sha256);assert.equal(process.platform,pins.targets[target].platform);assert.equal(process.arch,pins.targets[target].arch);
 const cpuModels=[...new Set(cpus().map(cpu=>cpu.model))];if(target==='macos-x64')assert(cpuModels.some(model=>/Intel|AMD/i.test(model))&&!cpuModels.some(model=>/Apple/i.test(model)),'A real Intel host is required; translation on ARM is not Intel-host proof');
 await preparationProof(here,admission,pins,target,kit.sha256);assertPublicSource(await receiptProof(here,admission.publicSourceProof),pins);
 await checkIdentity(process.execPath,admission.tools.node);await checkIdentity(admission.tools.python.path,admission.tools.python);
 const effectGuard=await effectPreflight(here,admission,pins,target,stage,kit.sha256);
 const dir=join(work,'qualification',stage);await mkdir(dir,{recursive:true});
 const result={schemaVersion:1,kind:'CURRENT_GRID_'+stage.toUpperCase()+'_QUALIFICATION',target,passed:false,host:{platform:process.platform,arch:process.arch,machine:machine(),release:release(),cpuModels},sourceTree:pins.source.tree,sourceArchiveSha256:pins.source.sha256,kitSha256:kit.sha256,archiveOrigin:stage==='public'?'anonymous-public-download':'local-package',commands:[],startedAt:new Date().toISOString(),privateHostQualified:false,windows11Qualified:false,fullGoalComplete:false};
 await save(join(dir,'START.json'),result);
 const env={...admission.environment,...hostContextEnvironment(),PATH:join(work,'qualification','empty PATH Ω 日本語'),TMPDIR:dir,TMP:dir,TEMP:dir,LANG:'en_US.UTF-8'};await mkdir(env.PATH,{recursive:true});assert.deepEqual(await inventory(env.PATH),[]);
 let count=0;
 const run=async(label,executable,args,expected=0)=>{await effectGuard.revalidate();if(executable===admission.tools.python.path)assertArchiveInvocation(executable,args,env,admission.tools.python.path,join(here,'archive.py'));const log=join(dir,String(++count).padStart(2,'0')+'-'+label+'.json');try{return await command(executable,args,{cwd:dir,env,log,expected});}finally{try{const stored=await json(log);result.commands.push({label,log,sha256:await hash(log),code:stored.code});}catch(error){if(error.code!=='ENOENT')throw error;}}};
 const finish=async error=>{if(error){result.error=error.message;process.exitCode=1;}else result.passed=true;result.finishedAt=new Date().toISOString();await save(join(dir,'RESULT.json'),result);console.log(JSON.stringify({stage,target,passed:result.passed,error:result.error??null}));};
 return {here,pins,work,admission,target,dir,result,env,run,finish,effectGuard,kitSha256:kit.sha256};
}

export async function checkArtifactSelection(q,archive) {
 const descriptor=q.admission.artifactSelection;assert(descriptor,'Separate exact runtime artifact selection receipt is required');
 const selected=await receiptProof(q.here,descriptor),critic=await receiptProof(q.here,selected.critic),replay=await receiptProof(q.here,selected.rootReplay);
 assertArtifactSelection(selected,critic,replay,q.pins,q.target,archive,q.kitSha256);
 q.result.artifactSelection={selection:descriptor,critic:selected.critic,rootReplay:selected.rootReplay};return selected;
}

export async function extractRuntime(q,{publicDownload=false}={}) {
 const {work,here,admission,pins,target,dir,result}=q;
 const spec=publicDownload?admission.publicRuntime:await json(join(work,'ARCHIVE.json'));
 assert(spec&&spec.target===target,'Exact per-platform released runtime identity is required');assert.equal(spec.top,'gridcraft-current-'+target);
 if(publicDownload) {assert(spec.url.startsWith('https://github.com/Mohammed-Moniem/gridcraft/releases/download/'));await checkArtifactSelection(q,spec);}
 const archive=publicDownload?join(dir,spec.name):join(work,spec.name);
 if(publicDownload) {
  const receipt=await json(join(work,'qualification','public-download','RESULT.json'));assert.equal(receipt.passed,true);assert.equal(receipt.download.sha256,spec.sha256);assert.equal(receipt.download.bytes,spec.bytes);assert.equal(receipt.download.url,spec.url);assert.equal(receipt.download.anonymous,true);
  await checkIdentity(join(work,'qualification','public-download',spec.name),spec);
 } else await checkIdentity(archive,spec);
 const actualArchive=publicDownload?join(work,'qualification','public-download',spec.name):archive;
 const extracted=join(dir,'runtime with space Ω 日本語');
 await q.run('safe-extract-runtime',admission.tools.python.path,archiveArgs(join(here,'archive.py'),'extract',actualArchive,extracted,spec.sha256,String(spec.bytes)));
 const root=join(extracted,spec.top),manifest=await json(join(root,'MANIFEST.json'));assertRuntimeManifest(manifest,pins,target);
 if(spec.manifest)await checkIdentity(join(root,'MANIFEST.json'),spec.manifest);
 const f=await fileIdentity(join(root,'MANIFEST.json'));await checkInventory(root,[...manifest.files,{path:'MANIFEST.json',bytes:f.bytes,sha256:f.sha256,mode:f.mode}]);
 result.archive={name:spec.name,bytes:spec.bytes,sha256:spec.sha256};result.runtimeManifestSha256=await hash(join(root,'MANIFEST.json'));result.extractedFiles=manifest.files.length+1;
 return {root,manifest,spec};
}

export async function denyForRuntime(q) {
 assert.equal(q.admission.network.runtimeOsRestrictionRequired,true,'An OS restriction must be separately admitted');
 await checkIdentity(q.admission.network.profile.path,q.admission.network.profile);
 await q.effectGuard.revalidate();
 q.result.network=await externalDenied();
 q.result.network.profile=q.admission.network.profile;
 q.result.network.claim='External permission-denied probe under supplied OS restriction; loopback remains available';
 return q.result.network;
}

export function pngIdentity(bytes) {assert.equal(bytes.subarray(0,8).toString('hex'),'89504e470d0a1a0a');assert.equal(bytes.subarray(12,16).toString(),'IHDR');const width=bytes.readUInt32BE(16),height=bytes.readUInt32BE(20);assert(width>=400&&height>=300&&width<=10000&&height<=10000,'Unexpected capture dimensions');assert(bytes.length>2000,'Empty screenshot');return {bytes:bytes.length,sha256:sha(bytes),width,height,visualReview:'PENDING_INDEPENDENT_REVIEW'};}

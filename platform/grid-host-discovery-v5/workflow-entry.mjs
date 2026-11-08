// External payload delivery is data-only; inputs are never interpolated into shell commands.
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {TARGETS,KIT_SHA,sha,LIMITS,validateLaunch} from './model.mjs';
import {checkPacket,save} from './probe-support.mjs';
import {decodeDelivery,validateDelivery} from './delivery-contract.mjs';
const here=fileURLToPath(new URL('.',import.meta.url)),target=process.env.GRID_DISCOVERY_TARGET;let validated=false,wroteOutput=false,directory=null;
try {
 assert(TARGETS[target]);assert.equal(process.env.GITHUB_REPOSITORY,'Mohammed-Moniem/gridcraft');assert(/^[1-9][0-9]{0,5}$/.test(process.env.GRID_DELIVERY_BYTES??''));
 const spec={bytes:Number(process.env.GRID_DELIVERY_BYTES),sha256:process.env.GRID_DELIVERY_SHA256},raw=decodeDelivery(process.env.GRID_DELIVERY_BASE64,spec),packetSha256=await checkPacket(here),context={repository:process.env.GITHUB_REPOSITORY,head:process.env.GITHUB_SHA,kitSha256:KIT_SHA,packetSha256},payload=validateDelivery(raw,spec,context);
 for(const name of Object.keys(TARGETS))validateLaunch(payload.targets[name],name,packetSha256,{repository:context.repository,head:context.head});validated=true;
 // Only the fully validated external envelope can create this fresh owned namespace.
 directory=join(here,'runs',target,'delivery');await mkdir(join(here,'runs',target),{recursive:true});await mkdir(directory);wroteOutput=true;
 await writeFile(join(directory,'PAYLOAD.json'),raw,{flag:'wx',mode:0o644});const launch=payload.targets[target],body=Buffer.from(JSON.stringify(launch,null,2)+'\n'),admission=join(directory,'LAUNCH.json');await save(admission,launch);
 const entry={path:'LAUNCH.json',bytes:body.length,sha256:sha(body)};await save(join(directory,'INDEX.json'),{schemaVersion:1,kind:'GRID_DISCOVERY_MATERIALIZED_INDEX',externalPayload:spec,codeCommit:payload.codeCommit,kitSha256:KIT_SHA,packetSha256,targets:{[target]:entry},rootAdmissionIssued:false});await save(join(directory,'DELIVERY.json'),{kind:'GRID_EXTERNAL_DELIVERY_MATERIALIZATION',externalPayload:spec,codeCommit:payload.codeCommit,kitSha256:KIT_SHA,packetSha256,target,launch:entry,materialized:true,rootAdmissionIssued:false,fullGoalComplete:false});
 const args=[join(here,'probe.mjs'),'--target',target,'--output',join(here,'runs',target,'actual-host'),'--launch-admission',admission,'--launch-admission-sha256',entry.sha256,'--launch-admission-bytes',String(entry.bytes)],env=Object.fromEntries(['GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_ARCH','ImageOS','ImageVersion','SystemRoot'].filter(key=>process.env[key]!==undefined).map(key=>[key,process.env[key]]));env.PATH='';
 const child=spawn(process.execPath,args,{cwd:here,env,stdio:'inherit',shell:false,windowsHide:true}),timer=setTimeout(()=>child.kill('SIGKILL'),LIMITS.probeMs+30000);let outcome;try{outcome=await new Promise((yes,no)=>{child.once('error',no);child.once('close',(c,s)=>yes([c,s]));});}finally{clearTimeout(timer);}const [code,signal]=outcome;assert.equal(signal,null);assert.equal(code,0,'Discovery NOT_READY or failed; inspect retained actual-host journals');
}catch(error){const failure={kind:'GRID_DISCOVERY_DELIVERY_FAILURE',validated,wroteOutput,error:String(error.message).slice(0,1000),actualDiscoveryQualified:false,fullGoalComplete:false};if(wroteOutput)await save(join(directory,'FAILURE.json'),failure);console.error(JSON.stringify(failure));process.exitCode=1;}

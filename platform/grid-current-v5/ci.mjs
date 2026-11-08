// Staged workflow driver. Every effect still requires an exact independent admission file.
import assert from 'node:assert/strict';
import {readFile,mkdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {sha,assertAdmission,assertPublicSource} from './core.mjs';
import {json,checkIdentity,command,save,verifyKit,receiptProof,inside,preparationProof} from './io.mjs';
import {effectPreflight} from './effect-preflight.mjs';
import {hostContextEnvironment} from './host-reader.mjs';
const {values}=parseArgs({options:{target:{type:'string'},workspace:{type:'string'},admission:{type:'string'},'admission-sha256':{type:'string'},profile:{type:'string',default:'build'}}});
const here=fileURLToPath(new URL('.',import.meta.url)),work=inside(join(here,'runs'),values.workspace),raw=await readFile(resolve(values.admission));assert.equal(sha(raw),values['admission-sha256']);const admission=JSON.parse(raw),pins=await json(join(here,'inputs.json')),kit=await verifyKit(here);await checkIdentity(process.execPath,admission.tools.node);await preparationProof(here,admission,pins,values.target,kit.sha256);assertPublicSource(await receiptProof(here,admission.publicSourceProof),pins);
assert(['build','local-runtime','public-download','public-runtime'].includes(values.profile));
const stages={build:['restore','compile-native','compile-wasm','package'],'local-runtime':['native','gui','browser'],'public-download':['public-download'],'public-runtime':['public']}[values.profile];
for(const stage of stages)assertAdmission(admission,pins,values.target,stage,kit.sha256);
const effectGuard=await effectPreflight(here,admission,pins,values.target,stages[0],kit.sha256);
await mkdir(join(work,'ci'),{recursive:true});
for(const stage of stages) {
 assertAdmission(admission,pins,values.target,stage,kit.sha256);
 const args=[join(here,'pipeline.mjs'),'--stage',stage,'--target',values.target,'--workspace',work,'--admission',resolve(values.admission),'--admission-sha256',values['admission-sha256']];
 const restricted=['native','gui','browser','public'].includes(stage);let executable=process.execPath,fullArgs=args;
 if(restricted&&process.platform==='darwin'){assert(admission.tools.sandboxExec);await checkIdentity(admission.tools.sandboxExec.path,admission.tools.sandboxExec);await checkIdentity(join(here,'deny-external.sb'),admission.network.profile);executable=admission.tools.sandboxExec.path;fullArgs=['-f',join(here,'deny-external.sb'),process.execPath,...args];}
 else if(restricted){assert.equal(process.platform,'win32');assert(admission.tools.powershell);await checkIdentity(admission.tools.powershell.path,admission.tools.powershell);await checkIdentity(join(here,'restrict-windows.ps1'),admission.network.profile);executable=admission.tools.powershell.path;fullArgs=['-NoProfile','-File',join(here,'restrict-windows.ps1'),'-NodePath',process.execPath,'-KitPath',here,'-Workspace',work,'-AdmissionPath',resolve(values.admission),'-AdmissionSha256',values['admission-sha256'],'-Stage',stage];}
 const env={...admission.environment,...hostContextEnvironment(),PATH:admission.systemPath};
 await effectGuard.revalidate();
 await command(executable,fullArgs,{cwd:here,env,log:join(work,'ci',stage+'.json'),timeoutMs:restricted?15*60*1000:120*60*1000});
}
await save(join(work,'ci',values.profile+'-RESULT.json'),{profile:values.profile,target:values.target,stages,passed:true,published:false,fullGoalComplete:false});

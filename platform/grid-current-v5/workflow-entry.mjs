// Fixed workflow entry: inputs remain data, never interpolated into shell commands.
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {safeRelative,assertAdmission,assertPublicSource} from './core.mjs';
import {json,command,verifyKit,receiptProof,preparationProof,checkIdentity} from './io.mjs';
import {effectPreflight} from './effect-preflight.mjs';
import {hostContextEnvironment} from './host-reader.mjs';
const here=fileURLToPath(new URL('.',import.meta.url)),target=process.env.GRID_TARGET,profile=process.env.GRID_PROFILE;
assert(['macos-arm64','macos-x64','windows-x64'].includes(target));assert(['build','local-runtime','public-download','public-runtime'].includes(profile));
const index=await json(join(here,safeRelative(process.env.GRID_ADMISSION_INDEX)));
assert.equal(index.independentlySelected,true);const entry=index.targets[target];assert(entry);safeRelative(entry.path);assert.match(entry.sha256,/^[a-f0-9]{64}$/);assert(Number.isSafeInteger(entry.bytes)&&entry.bytes>0,'Exact admission index byte length required');
const admission=join(here,entry.path),work=join(here,'runs',target);
const profiles=profile==='local-runtime'?['build','local-runtime']:profile==='public-runtime'?['public-download','public-runtime']:[profile];
const pins=await json(join(here,'inputs.json')),kit=await verifyKit(here),admitted=await receiptProof(here,entry);
await preparationProof(here,admitted,pins,target,kit.sha256);assertPublicSource(await receiptProof(here,admitted.publicSourceProof),pins);await checkIdentity(process.execPath,admitted.tools.node);
for(const phase of profiles)for(const stage of {build:['restore','compile-native','compile-wasm','package'],'local-runtime':['native','gui','browser'],'public-download':['public-download'],'public-runtime':['public']}[phase])assertAdmission(admitted,pins,target,stage,kit.sha256);
const firstStage={build:'restore','local-runtime':'native','public-download':'public-download','public-runtime':'public'}[profiles[0]],effectGuard=await effectPreflight(here,admitted,pins,target,firstStage,kit.sha256);
for(const phase of profiles){await effectGuard.revalidate();await command(process.execPath,[join(here,'ci.mjs'),'--target',target,'--workspace',work,'--admission',admission,'--admission-sha256',entry.sha256,'--profile',phase],{cwd:here,env:{...hostContextEnvironment(),GRID_TARGET:target,GRID_PROFILE:phase,GRID_ADMISSION_INDEX:process.env.GRID_ADMISSION_INDEX,...(process.platform==='win32'?{SystemRoot:process.env.SystemRoot}:{}),PATH:''},timeoutMs:3*60*60*1000});}

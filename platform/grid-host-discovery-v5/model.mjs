// Pure data contracts. The preparation oracle imports this module, never the probe.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {assertPythonEnvironment} from '../grid-current-v5/python-plan.mjs';
import {PYTHON_MODULES} from './query-plan.mjs';
import {assertPythonExecutionClosure} from '../grid-current-v5/host-contract.mjs';
export const KIT_SHA='d943cd714d711cc3fadcc2862ebee266186eab9143e2c6d1c795e3eb2a096a5b';
export const SOURCE_TREE='c4544e89868075cca2570ede803540bdbf0afae9';
export const SOURCE_SHA='01b4d9d365d7265a26e0446a81f256e0c56094769a6f641a03ce7867bd47de27';
export const SOURCE_COMMIT='17c5aba04c33b107ec3a9264b0fa6f28966faf2c';
export const TARGETS={'macos-arm64':{platform:'darwin',arch:'arm64',runner:'macos-15'},'macos-x64':{platform:'darwin',arch:'x64',runner:'macos-15-intel'},'windows-x64':{platform:'win32',arch:'x64',runner:'windows-2022'}};
export const LIMITS={maxCommands:8,commandMs:15000,commandBytes:2*1024*1024,maxFileBytes:512*1024*1024,maxReadBytes:2*1024**3,maxFiles:33792,maxDirectoryEntries:128,maxApiSetEntries:16384,maxImportModules:256,maxImportDepth:12,probeMs:10*60*1000};
export const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function relativeName(path){assert.equal(typeof path,'string');assert(path.length>0&&path.length<1024&&!/[\\:\x00-\x1f]/.test(path));assert(path.split('/').every(p=>p&&p!=='.'&&p!=='..'&&!/[. ]$/.test(p)));return path;}
export function fileIdentity(row){assert(row&&typeof row.path==='string'&&row.path.length>0);assert(Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=LIMITS.maxFileBytes);assert.match(row.sha256,/^[a-f0-9]{64}$/);assert(Number.isInteger(row.mode)&&row.mode>=0&&row.mode<=0o777);return row;}
export function validateLaunch(value,target,packetSha,workflow){
 assert.equal(value.kind,'GRID_READ_ONLY_HOST_DISCOVERY_LAUNCH');assert.equal(value.selected,true,'Discovery launch is not selected');assert.equal(value.purpose,'READ_ONLY_HOST_DISCOVERY');assert.equal(value.packetSha256,packetSha);assert.equal(value.kitSha256,KIT_SHA);assert.equal(value.target,target);assert(TARGETS[target]);
 assert.equal(value.repository,'Mohammed-Moniem/gridcraft');assert.equal(workflow.repository,value.repository);assert.match(value.workflowHead,/^[a-f0-9]{40}$/);assert.equal(workflow.head,value.workflowHead,'Unreviewed workflow head');
 assert.deepEqual(value.allowedQueries,['python-isolated-stdlib','mac-developer-path','mac-os-version','windows-host-registry','vswhere-supported-installations']);assert.equal(value.nativeInput===null||typeof value.nativeInput==='object',true);
 assert.deepEqual(value.forbiddenEffects,['downloads','installs','builds','browser-launch','native-app-launch','firewall-changes','SDK-changes','publication','root-admission']);return true;
}
export function validateHost(capture){
 assert.equal(capture.schemaVersion,1);assert.equal(capture.kind,'ACTUAL_GRID_HOST_DISCOVERY');assert.equal(capture.selected,false);assert.equal(capture.kitSha256,KIT_SHA);assert.equal(capture.sourceTree,SOURCE_TREE);assert(TARGETS[capture.target]);
 const target=TARGETS[capture.target];assert.equal(capture.host.platform,target.platform);assert.equal(capture.host.arch,target.arch);assert.equal(capture.host.runner,target.runner);assert.equal(capture.host.runnerEnvironment,'github-hosted');assert(capture.host.imageOS&&capture.host.imageVersion,'Runner image identity missing');
 assert.equal(typeof capture.host.release,'string');assert(capture.host.release);assert.equal(capture.host.repository,'Mohammed-Moniem/gridcraft');assert.match(capture.host.workflowHead,/^[a-f0-9]{40}$/);
 assert(Array.isArray(capture.host.cpuModels)&&capture.host.cpuModels.length>0);if(capture.target==='macos-x64')assert(capture.host.cpuModels.some(m=>/Intel|AMD/i.test(m))&&!capture.host.cpuModels.some(m=>/Apple/i.test(m)),'Actual Intel CPU required');
 if(capture.target==='windows-x64'){assert.equal(capture.host.windows.productType,3,'Windows Server target required');assert.equal(capture.host.windows.buildNumber,'20348','Wrong Windows Server image');}
 for(const key of ['node','python','browser']){fileIdentity(capture.tools[key]);assert(capture.tools[key].bytes>0,'Empty executable');}assert(Number(capture.tools.node.version.split('.')[0])>=22);assert.equal(capture.tools.python.query.isolated,true);assert.equal(capture.tools.python.query.bytecodeWritesDisabled,true);assert.equal(capture.tools.python.query.pointerBits,64);assert(capture.tools.python.query.modules.includes('lzma'));
 assert(capture.sdk&&capture.sdk.platform===capture.target&&capture.sdk.files.length>=6);for(const row of capture.sdk.files)fileIdentity(row);assert.equal(capture.sdk.redistributed,false);assert.equal(capture.sdk.fullSdkClosureEstablished,false);
 assert(Array.isArray(capture.missing));assert.equal(capture.windows11Qualified,false);assert.equal(capture.runtimeQualified,false);assert.equal(capture.fullGoalComplete,false);return capture;
}
export function validateCapturedFileClosure(capture){
 assertPythonExecutionClosure(capture.tools.python,capture.inspection.files);
 assert.deepEqual(capture.tools.python.query.modules,PYTHON_MODULES,'Archive stdlib query module set differs');
 const rows=capture.inspection.files;assert(rows.length>0&&rows.length<=LIMITS.maxFiles);assert(Number.isSafeInteger(capture.inspection.commands)&&capture.inspection.commands>=0&&capture.inspection.commands<=LIMITS.maxCommands);assert(Number.isSafeInteger(capture.inspection.bytesRead)&&capture.inspection.bytesRead>=rows.reduce((n,row)=>n+row.bytes,0)&&capture.inspection.bytesRead<=LIMITS.maxReadBytes);const index=new Map();for(const row of rows){fileIdentity(row);const key=capture.target==='windows-x64'?row.path.toLowerCase():row.path;assert(!index.has(key),'Duplicate captured identity');index.set(key,row);}
 const referenced=[...Object.values(capture.tools).filter(t=>t?.path),...Object.values(capture.queryPrograms??{}),...capture.sdk.files,...capture.tools.python.query.loadedFiles,...capture.tools.python.query.cacheFiles,...capture.tools.python.query.supportFiles];for(const row of referenced){const got=index.get(capture.target==='windows-x64'?row.path.toLowerCase():row.path);assert(got,'Referenced file absent from capture inventory');assert.equal(got.bytes,row.bytes);assert.equal(got.sha256,row.sha256);assert.equal(got.mode,row.mode);}assert.equal(capture.tools.python.query.noSite,true,'Python site startup must be disabled');assertPythonEnvironment(capture.environment);return true;
}
export function candidateFromCapture(capture,receipt){
 validateHost(capture);fileIdentity(receipt);assert.deepEqual(capture.missing,[],'Missing or ambiguous host inputs');
 return {schemaVersion:1,selected:false,kind:'GRID_HOST_ADMISSION_CANDIDATE',purpose:'REQUIRES_SEPARATE_ROOT_REVIEW',kitSha256:KIT_SHA,sourceTree:SOURCE_TREE,sourceCommit:SOURCE_COMMIT,sourceArchiveSha256:SOURCE_SHA,target:capture.target,stages:[],discoveryEvidence:receipt,tools:capture.tools,sdkProof:capture.sdk,environment:capture.environment,systemPath:capture.systemPath,independentSelection:null,publicSourceProof:null,windowsDependencies:null,network:{buildIsolationClaim:false,runtimeOsRestrictionRequired:true,profile:null,programs:[]},artifactSelection:null,publicRuntime:null,proposedBuildStages:['restore','compile-native','compile-wasm','package'],runtimeStagesAuthorized:false,cloudBuildAuthorized:false,fullGoalComplete:false};
}
export function assertCandidate(candidate,capture,receipt){assert.equal(candidate.selected,false);assert.deepEqual(candidate.stages,[]);assert.equal(candidate.kitSha256,KIT_SHA);assert.equal(candidate.sourceTree,SOURCE_TREE);assert.equal(candidate.target,capture.target);assert.deepEqual(candidate.discoveryEvidence,receipt);assert.deepEqual(candidate.tools,capture.tools);assert.deepEqual(candidate.sdkProof,capture.sdk);for(const key of ['independentSelection','publicSourceProof','windowsDependencies','artifactSelection','publicRuntime'])assert.equal(candidate[key],null);assert.equal(candidate.cloudBuildAuthorized,false);assert.equal(candidate.runtimeStagesAuthorized,false);return true;}

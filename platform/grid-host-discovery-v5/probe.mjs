// FUTURE EFFECTFUL PROBE. Never imported by preparation CHECKs; requires separate launch review.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,lstat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {cpus,machine,release} from 'node:os';
import {parseArgs} from 'node:util';
import {TARGETS,LIMITS,KIT_SHA,SOURCE_TREE,sha,validateLaunch,validateHost,validateCapturedFileClosure,candidateFromCapture,assertCandidate} from './model.mjs';
import {json,save,startOutput,inspection,checkPacket,outputInventory} from './probe-support.mjs';
import {macCapture,windowsCapture} from './platforms.mjs';
import {windowsDependencies} from './windows-dependencies.mjs';
import {OUTPUT_MODE_MEANING} from './output-contract.mjs';
import {revalidatePythonInputs} from '../grid-current-v5/python-acquisition.mjs';

const here=fileURLToPath(new URL('.',import.meta.url));
const {values}=parseArgs({options:{target:{type:'string'},output:{type:'string'},'launch-admission':{type:'string'},'launch-admission-sha256':{type:'string'},'launch-admission-bytes':{type:'string'}}});
const target=values.target;assert(TARGETS[target]);assert.equal(process.platform,TARGETS[target].platform);assert.equal(process.arch,TARGETS[target].arch);
assert(/^[1-9][0-9]{0,5}$/.test(values['launch-admission-bytes']??''));const launchSize=Number(values['launch-admission-bytes']);assert(launchSize<=32768);const launchPath=resolve(values['launch-admission']),launchStat=await lstat(launchPath);assert(launchStat.isFile()&&!launchStat.isSymbolicLink());assert.equal(launchStat.size,launchSize);
const packetSha=await checkPacket(here),launchRaw=await readFile(launchPath);assert.equal(launchRaw.length,launchSize);assert.match(values['launch-admission-sha256']??'',/^[a-f0-9]{64}$/);assert.equal(sha(launchRaw),values['launch-admission-sha256']);const launch=JSON.parse(launchRaw);
const workflow={repository:process.env.GITHUB_REPOSITORY,head:process.env.GITHUB_SHA};validateLaunch(launch,target,packetSha,workflow);
const protectedKit=join(here,'..','grid-current-v5'),kitRaw=await readFile(join(protectedKit,'FREEZE.json'));assert.equal(sha(kitRaw),KIT_SHA);const frozenKit=JSON.parse(kitRaw);for(const row of frozenKit.files){const path=join(protectedKit,row.path),s=await lstat(path);assert(s.isFile()&&!s.isSymbolicLink());assert.equal(s.size,row.bytes);assert.equal(sha(await readFile(path)),row.sha256);}
const out=await startOutput(here,resolve(values.output)),p=inspection(out),host={platform:process.platform,arch:process.arch,machine:machine(),release:release(),cpuModels:[...new Set(cpus().map(cpu=>cpu.model))],runner:TARGETS[target].runner,runnerEnvironment:process.env.RUNNER_ENVIRONMENT??null,imageOS:process.env.ImageOS??null,imageVersion:process.env.ImageVersion??null,runnerOS:process.env.RUNNER_OS??null,runnerArch:process.env.RUNNER_ARCH??null,repository:workflow.repository,workflowHead:workflow.head,runId:process.env.GITHUB_RUN_ID??null,runAttempt:process.env.GITHUB_RUN_ATTEMPT??null};
const capture={schemaVersion:1,kind:'ACTUAL_GRID_HOST_DISCOVERY',selected:false,state:'IN_PROGRESS',target,kitSha256:KIT_SHA,sourceTree:SOURCE_TREE,packetSha256:packetSha,packetDirectory:here,outputDirectory:out,queryPrograms:{},host,tools:{},sdk:null,missing:[],environment:{},systemPath:'',windows11Qualified:false,runtimeQualified:false,fullGoalComplete:false,discoveryLaunchSha256:sha(launchRaw),startedAt:new Date().toISOString()};
await save(join(out,'START.json'),capture);await mkdir(join(out,'temp'));
const environment=process.platform==='win32'?{SystemRoot:process.env.SystemRoot??'C:\\Windows',PATH:'C:\\Windows\\System32;C:\\Windows',TEMP:join(out,'temp'),TMP:join(out,'temp'),LANG:'en_US.UTF-8',PSModuleAnalysisCachePath:join(out,'temp','PowerShell-ModuleAnalysisCache'),PSModulePath:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules;C:\\Program Files\\PowerShell\\7\\Modules',POWERSHELL_TELEMETRY_OPTOUT:'1',DOTNET_CLI_TELEMETRY_OPTOUT:'1',COMPlus_EnableDiagnostics:'0'}:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin',TMPDIR:join(out,'temp'),LANG:'en_US.UTF-8'};
if(process.platform==='win32')assert(/^[a-z]:\\Windows$/i.test(environment.SystemRoot),'Unsupported Windows root');
capture.queryEnvironment=environment;
const deadline=setTimeout(()=>{save(join(out,'TIMEOUT.json'),{state:'NOT_READY',reason:'Probe wall-time budget exhausted',limits:LIMITS,elapsed:p.summary(),selected:false,remainingQueriesRequireHostJobCleanup:true}).finally(()=>process.exit(1));},LIMITS.probeMs);
try {
 try{if(process.platform==='darwin')await macCapture(p,capture,environment);else await windowsCapture(p,capture,environment,here);}catch(error){capture.missing.push({code:'REQUIRED_PLATFORM_CAPTURE_INCOMPLETE',error:error.message,remainingFacts:'NOT_CAPTURED_AFTER_FIRST_REQUIRED_ERROR'});}
 if(process.platform==='win32'&&capture.sdk){try{await windowsDependencies(p,capture,launch,out);}catch(error){capture.missing.push({code:'WINDOWS_DEPENDENCY_CAPTURE_INCOMPLETE',error:error.message});}}
 try{validateHost(capture);}catch(error){capture.missing.push({code:'HOST_CONTRACT_NOT_READY',error:error.message});}
 capture.state=capture.missing.length?'NOT_READY':'CAPTURED_REQUIRES_REVIEW';capture.finishedAt=new Date().toISOString();capture.inspection=p.summary();capture.runtimeStagesAuthorized=false;capture.sdkRedistributed=false;
 await save(join(out,'DISCOVERY.json'),capture);const body=Buffer.from(JSON.stringify(capture,null,2)+'\n'),receipt={path:join(out,'DISCOVERY.json'),bytes:body.length,sha256:sha(body),mode:(await lstat(join(out,'DISCOVERY.json'))).mode&0o777};
 if(capture.state==='CAPTURED_REQUIRES_REVIEW'){validateCapturedFileClosure(capture);const candidate=candidateFromCapture(capture,receipt);assertCandidate(candidate,capture,receipt);await save(join(out,'ADMISSION-CANDIDATE.json'),candidate);}else await save(join(out,'ADMISSION-CANDIDATE.json'),{kind:'GRID_HOST_ADMISSION_CANDIDATE',selected:false,state:'NOT_READY',target,kitSha256:KIT_SHA,sourceTree:SOURCE_TREE,stages:[],discoveryEvidence:receipt,missing:capture.missing,cloudBuildAuthorized:false,runtimeStagesAuthorized:false});
 // Re-read every actual discovered regular file; changed inputs prevent even a captured-ready state.
 await p.recheck();
 if(capture.state==='CAPTURED_REQUIRES_REVIEW')await revalidatePythonInputs(capture.tools.python.query.namespaceCapture,{recordIdentity:p.recordCaptured});
 await save(join(out,'RESULT.json'),{state:capture.state,selected:false,discoveryEvidence:receipt,inputsStable:true,inspectionFinal:p.summary(),commands:p.summary().commands,packetSha256:packetSha,kitSha256:KIT_SHA,cloudBuildAuthorized:false,nativeApplicationExecuted:false,browserExecuted:false,compilerExecuted:false,downloads:false,installs:false,systemSettingMutationsRequested:false,fullGoalComplete:false});
 if(capture.state==='NOT_READY')process.exitCode=1;
}catch(error){await save(join(out,'FAILURE.json'),{state:'NOT_READY',selected:false,error:error.message,inspection:p.summary(),capturedPrefix:capture,fullGoalComplete:false});process.exitCode=1;}finally{clearTimeout(deadline);await save(join(out,'OUTPUT-MANIFEST.json'),{schemaVersion:1,kind:'GRID_DISCOVERY_OUTPUT_INVENTORY',selected:false,selfExcluded:'OUTPUT-MANIFEST.json',files:await outputInventory(out),modeSemantics:OUTPUT_MODE_MEANING});}

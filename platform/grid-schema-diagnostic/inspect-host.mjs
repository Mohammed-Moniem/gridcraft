// Future Windows workflow entrypoint. Prepared only; not run on a real host by local tests.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {diagnoseSchemaBytes,LIMITS} from './diagnose-schema.mjs';
assert.equal(process.argv.length,2);assert.equal(process.platform,'win32');assert.equal(process.arch,'x64');
assert.equal(process.env.GITHUB_REPOSITORY,'Mohammed-Moniem/gridcraft');assert.equal(process.env.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(process.env.GITHUB_RUN_ATTEMPT,'1');assert(/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA??''));assert(/^\d+$/.test(process.env.GITHUB_RUN_ID??''));
const workspace=fs.realpathSync(process.cwd());assert.equal(workspace.toLowerCase(),fs.realpathSync(process.env.GITHUB_WORKSPACE).toLowerCase());
const parent=path.join(workspace,'diagnostics'),out=path.join(parent,'grid-apiset');if(fs.existsSync(parent)){assert(fs.lstatSync(parent).isDirectory()&&!fs.lstatSync(parent).isSymbolicLink());assert.equal(fs.realpathSync(parent).toLowerCase(),parent.toLowerCase());}else fs.mkdirSync(parent);assert(!fs.existsSync(out));fs.mkdirSync(out);
const expected={bytes:144800,sha256:'fd45c0d71100c8d2bff924fc7650b1c2c869fbeea6f8d1f521315e6781de4aaa'},input='C:\\Windows\\System32\\apisetschema.dll',began=Date.now();
const ident=s=>({dev:String(s.dev),ino:String(s.ino),nlink:String(s.nlink),mode:String(s.mode),bytes:String(s.size),mtimeNs:String(s.mtimeNs),ctimeNs:String(s.ctimeNs)});
const metadata={repository:process.env.GITHUB_REPOSITORY,codeCommit:process.env.GITHUB_SHA,runId:process.env.GITHUB_RUN_ID,runAttempt:process.env.GITHUB_RUN_ATTEMPT,runnerOS:process.env.RUNNER_OS??null,runnerArch:process.env.RUNNER_ARCH??null,imageOS:process.env.ImageOS??null,imageVersion:process.env.ImageVersion??null,node:process.version};
let result={kind:'EXACT_WINDOWS_APISET_DIAGNOSTIC',state:'FAILED',metadata,expected,rawPeRetained:false,inputPeLoadedOrExecuted:false,sourceRepairSelected:false,hostSelected:false,runtimeQualified:false,fullGoalComplete:false};
try{
 const real=fs.realpathSync.native(input);assert.equal(real.toLowerCase(),input.toLowerCase());const before=fs.lstatSync(input,{bigint:true});assert(before.isFile()&&!before.isSymbolicLink());assert(before.size>0n&&before.size<=BigInt(LIMITS.fileBytes));const fd=fs.openSync(input,fs.constants.O_RDONLY);let raw;
 try{assert.deepEqual(ident(fs.fstatSync(fd,{bigint:true})),ident(before));raw=fs.readFileSync(fd);assert.equal(BigInt(raw.length),before.size);assert.deepEqual(ident(fs.fstatSync(fd,{bigint:true})),ident(before));assert.deepEqual(ident(fs.lstatSync(input,{bigint:true})),ident(before));assert.equal(fs.realpathSync.native(input).toLowerCase(),real.toLowerCase());}finally{fs.closeSync(fd);}
 const actual={bytes:raw.length,sha256:createHash('sha256').update(raw).digest('hex')};result={...result,input:real,fileIdentity:ident(before),actual,exactIdentityMatched:actual.bytes===expected.bytes&&actual.sha256===expected.sha256};
 if(result.exactIdentityMatched){const diagnostic=diagnoseSchemaBytes(raw);result={...result,state:'DATA_CAPTURED_REQUIRES_REVIEW',diagnostic,matchesPriorHostShapeFailure:diagnostic.firstRejected?.kind==='host_name_shape'};}else result.state='EXACT_SCHEMA_IDENTITY_MISMATCH';
}catch(error){result={...result,error:String(error.stack??error).slice(0,6000)};}
result.elapsedMs=Date.now()-began;const raw=Buffer.from(JSON.stringify(result,null,2)+'\n');assert(raw.length<=1024**2,'DIAG_OUTPUT_LIMIT');fs.writeFileSync(path.join(out,'DIAGNOSTIC.json'),raw,{flag:'wx'});if(result.state!=='DATA_CAPTURED_REQUIRES_REVIEW')process.exitCode=1;
console.log(JSON.stringify({state:result.state,bytes:raw.length,rawPeRetained:false,inputPeLoadedOrExecuted:false,hostSelected:false,fullGoalComplete:false}));

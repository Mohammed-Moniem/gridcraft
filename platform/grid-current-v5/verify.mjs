// Read-only preparation oracle. Never import the effectful pipeline or smoke modules.
import assert from 'node:assert/strict';
import {readFile,readdir,lstat} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sha,safeRelative,validateRows,gitTree,assertPins,commandPlan,assertAdmission,assertPublicSource,assertRuntimeManifest,assertArtifactSelection} from './core.mjs';
import {inspectPEBytes,assertStaticCRT,bindWindowsImports} from './pe.mjs';
import {runCorrectionControls} from './correction-controls.mjs';
import {runHostControls} from './host-controls.mjs';
import {runDeliveryControls} from './delivery-controls.mjs';

const here=fileURLToPath(new URL('.',import.meta.url)),root=fileURLToPath(new URL('../../../',import.meta.url));
const json=async path=>JSON.parse(await readFile(path,'utf8'));
const pins=await json(join(here,'inputs.json')),source=await json(join(here,'inventory/source.json')),vendor=await json(join(here,'inventory/vendor.json'));
const readiness=await json(join(here,'READINESS.json')),oracle=await json(join(here,'ORACLE.json'));
const mode=process.argv[2];assert(['preparation','controls'].includes(mode));
async function digest(path){const h=createHash('sha256');for await(const chunk of createReadStream(path))h.update(chunk);return h.digest('hex');}
async function identity(base,row,checkMode=true){const path=join(base,safeRelative(row.path)),st=await lstat(path);assert(st.isFile()&&!st.isSymbolicLink(),'Non-regular input: '+row.path);assert.equal(st.size,row.bytes,row.path);assert.equal(await digest(path),row.sha256,row.path);if(checkMode&&process.platform!=='win32'&&row.mode!==undefined)assert.equal(st.mode&0o777,row.mode,row.path);}
async function ownedFiles(directory,prefix=''){let files=[];for(const e of await readdir(join(directory,prefix),{withFileTypes:true})){assert(!e.isSymbolicLink());const path=prefix+e.name;if(e.isDirectory())files.push(...await ownedFiles(directory,path+'/'));else{assert(e.isFile());files.push(path);}}return files.sort();}
const freezeRaw=await readFile(join(here,'FREEZE.json')),freeze=JSON.parse(freezeRaw);
assert.equal(freeze.kind,'CURRENT_GRID_PLATFORM_PREPARATION_FREEZE');
for(const row of freeze.files)await identity(here,row);
assert.deepEqual((await ownedFiles(here)).filter(p=>p!=='FREEZE.json'),freeze.files.map(f=>f.path).sort(),'Unfrozen authored file or unexpected execution output');
assert.equal(readiness.status,'PREPARED_NOT_EXECUTED');assert.equal(readiness.runtimeSelected,false);assert.equal(readiness.fullGoalComplete,false);
assert.deepEqual(readiness.stages,Object.fromEntries(pins.stages.map(stage=>[stage,'NOT_RUN'])));
assertPins(pins,source,vendor);
for(const row of [...pins.inventoryCaptures,...Object.values(pins.toolDefinitions).flatMap(x=>Object.values(x)),...pins.source.publicProof])await identity(here,row);
assertPublicSource(await json(join(here,'inventory/PUBLIC-ASSETS.json')),pins);
const remote=await json(join(here,'inventory/REMOTE-SOURCE.json'));assert.equal(remote.tree,pins.source.tree);assert.equal(remote.commit,pins.source.commit);assert.equal(remote.mainChangedThroughPullRequest,true);assert.equal(remote.publishedSource,true);assert.equal(remote.filesVerified,source.files);

let negativeControls=0;
const rejects=(fn,pattern)=>{assert.throws(fn,pattern);negativeControls++;};
const cloned=value=>structuredClone(value);

{
 assert.equal(source.members.length,790);assert.equal(vendor.files.length,33243);assert.equal((await json(join(here,'inventory/support.json'))).files.length,303);
 const lock=await readFile(join(here,'inventory/CURRENT-CARGO.lock'),'utf8');assert.equal(sha(lock),pins.sourceLockSha256);assert.match(lock,/\[\[package\]\]\nname = "wasm-bindgen"\nversion = "0\.2\.129"/);
 assert.match(await readFile(join(here,'inventory/GRID-FONT-PROVENANCE.json'),'utf8'),new RegExp(pins.fonts.commit));assert((await readFile(join(here,'inventory/GRID-CHINESE-FONTS.txt'),'utf8')).trim().length>0);
 for(const [target,platform]of Object.entries(pins.targets)){
  const plan=commandPlan(pins,target,'/owned/work');assert.deepEqual(plan.native,['build','--frozen','--offline','--release','--target',platform.triple,'-p','gridcraft-cli','-p','gridcraft']);assert(plan.wasm.includes('--public-url')&&plan.wasm.includes('./'));assert.equal(plan.wasmRustflags,null);assert.equal(plan.staticNativeRustflags,target==='windows-x64'?'-C target-feature=+crt-static':null);
  const manifest=await json(join(here,'inventory/tools-'+target+'.json'));assert.equal(manifest.platform,target);assert.equal(manifest.rust,'1.95.0');assert.equal(manifest.trunk,'0.22.1');assert.equal(manifest.wasmBindgen,'0.2.129');assert.equal(manifest.binaryen,'131');
  const rust=await json(join(here,pins.toolDefinitions[target]['toolchain-'+target+'-manifest.json'].path));assert.equal(rust.components.length,4);assert(rust.components.some(c=>c.name==='rust-std-1.95.0-wasm32-unknown-unknown'));assert.equal(rust.host,platform.triple);
 }
 const workflow=await readFile(join(here,'workflow/grid-current-platform.yml'),'utf8');for(const runner of ['macos-15','macos-15-intel','windows-2022'])assert(workflow.includes('runner: '+runner));assert(workflow.includes('if: always()'));assert(workflow.includes('contents: read'));assert(!workflow.includes('contents: write'));assert(!workflow.includes('npm '));
 const imports=await readFile(join(here,'pipeline.mjs'),'utf8');assert(imports.includes("from './core.mjs'"));assert(imports.includes("from './io.mjs'"));assert(!/import\s*\([^)]*source|from\s+['"][^'"]*(?:progress|embedded-office-suite)/.test(imports));
 rejects(()=>assertPins({...pins,source:{...pins.source,tree:'0'.repeat(40)}},source,vendor),/strictly equal|Source/);
 rejects(()=>assertPins({...pins,sourceLockSha256:'0'.repeat(64)},source,vendor),/strictly equal|lock/);
 rejects(()=>assertPins(pins,source,{...vendor,engineLockSha256:'0'.repeat(64)}),/Vendor\/source lock mismatch/);
 rejects(()=>commandPlan(pins,'linux-x64','/owned/work'),/Unknown target/);
}
{
 const template=await json(join(here,'admission-template.json'));assert.equal(template.selected,false);assert.equal(template.kitSha256,null);assert.equal(template.publicRuntime,null);assert.deepEqual(template.network.programs,[]);
 const item=(path,mode=0o644)=>({path,bytes:1,sha256:'a'.repeat(64),mode});
 const runtime={kind:'CURRENT_GRID_RUNTIME_CANDIDATE',target:'windows-x64',sourceTree:pins.source.tree,sourceArchiveSha256:pins.source.sha256,files:['bin/gridcraft-cli.exe','bin/gridcraft.exe','web/index.html','web/host.html','web/host.mjs','web/gridcraft.js','web/gridcraft_bg.wasm','launch.mjs','BUILD.json','legal/source/LICENSE-MIT','legal/source/LICENSE-APACHE','legal/source/NOTICE','legal/source/ATTRIBUTION.md','legal/fonts/OFL.txt','legal/vendor/license'].map(p=>item(p)),nativeQualified:false,guiQualified:false,browserQualified:false,publicQualified:false,windows11Qualified:false,privateHostQualified:false,signed:false,notarized:false,fullGoalComplete:false};
 runtime.integrationLicense={path:pins.integrationLicense.runtimePath,bytes:pins.integrationLicense.bytes,sha256:pins.integrationLicense.sha256};runtime.files.push({...runtime.integrationLicense,mode:0o644});assertRuntimeManifest(runtime,pins,'windows-x64');
 for(const missing of ['bin/gridcraft.exe','web/gridcraft.js','web/gridcraft_bg.wasm','legal/fonts/OFL.txt','legal/vendor/license'])rejects(()=>assertRuntimeManifest({...runtime,files:runtime.files.filter(f=>f.path!==missing)},pins,'windows-x64'),/absent|Incomplete/);
 rejects(()=>assertRuntimeManifest({...runtime,sourceTree:'0'.repeat(40)},pins,'windows-x64'));
 rejects(()=>assertRuntimeManifest({...runtime,guiQualified:true},pins,'windows-x64'),/cannot qualify/);
 const admission={...template,selected:true,target:'macos-arm64',kitSha256:sha(freezeRaw),sourceTree:pins.source.tree,sourceArchiveSha256:pins.source.sha256,sourceCommit:pins.source.commit,stages:pins.stages,independentSelection:{path:'selection.json',sha256:'a'.repeat(64),bytes:1},publicSourceProof:{path:'public.json',sha256:'b'.repeat(64),bytes:1},environment:{LANG:'en_US.UTF-8'},systemPath:'/usr/bin',tools:{node:{path:'/node',bytes:1,sha256:'c'.repeat(64)},python:{path:'/python',bytes:1,sha256:'d'.repeat(64)}}};
 admission.discoveryEvidence={path:'/synthetic/DISCOVERY.json',bytes:1,sha256:'a'.repeat(64)};admission.discoveryBundle={directory:'/synthetic/output',manifest:{bytes:1,sha256:'b'.repeat(64)}};admission.hostSelection={path:'synthetic-host.json',bytes:1,sha256:'c'.repeat(64)};admission.discoveryBinding={scope:'ACTUAL_GRID_CONSUMING_HOST',pythonPolicy:'COMPLETE_ISOLATED_RUNTIME_AND_SEARCH_NAMESPACES_V2',packetFreezeSha256:'d'.repeat(64),manifestSha256:'b'.repeat(64),discoverySha256:'a'.repeat(64)};admission.sdkProof={platform:'macos-arm64',files:Array.from({length:6},(_,index)=>item('synthetic-sdk-'+index))};assertAdmission(admission,pins,'macos-arm64','restore',sha(freezeRaw));
 rejects(()=>assertAdmission({...admission,selected:false},pins,'macos-arm64','restore',sha(freezeRaw)),/Independent selection/);
 rejects(()=>assertAdmission({...admission,kitSha256:'0'.repeat(64)},pins,'macos-arm64','restore',sha(freezeRaw)),/Reviewed kit changed/);
 rejects(()=>assertAdmission({...admission,publicSourceProof:null},pins,'macos-arm64','restore',sha(freezeRaw)),/Missing publicSourceProof/);
 rejects(()=>assertAdmission({...admission,stages:['package']},pins,'macos-arm64','restore',sha(freezeRaw)),/Stage not admitted/);
 rejects(()=>assertAdmission({...admission,environment:{NODE_OPTIONS:'--require /unreviewed.js'}},pins,'macos-arm64','restore',sha(freezeRaw)),/Unreviewed tool override/);
 const publicProof=await json(join(here,'inventory/PUBLIC-ASSETS.json')),bad=cloned(publicProof);bad.downloads[0].sha256='0'.repeat(64);rejects(()=>assertPublicSource(bad,pins));
 const syntheticArchive={name:'synthetic-control.tar.gz',bytes:1,sha256:'a'.repeat(64),manifest:{bytes:1,sha256:'b'.repeat(64)}};
 const syntheticBinding={scope:'CURRENT_GRID_RUNTIME_ARCHIVE',target:'macos-arm64',sourceTree:pins.source.tree,archive:syntheticArchive};
 const syntheticSelection={...syntheticBinding,kind:'CURRENT_GRID_PLATFORM_ARTIFACT_SELECTION',kitSha256:sha(freezeRaw),critic:{path:'synthetic-critic.json',bytes:1,sha256:'c'.repeat(64)},rootReplay:{path:'synthetic-replay.json',bytes:1,sha256:'d'.repeat(64)},blockingHandoffs:[]};
 const syntheticCritic={...syntheticBinding,independent:true,kitSha256:sha(freezeRaw),reviewer:{identity:'synthetic-independent-reviewer',implementationAuthor:false},evidenceAdequate:'YES',objectiveGates:'PASS',thresholdResult:'PASS',materialFindings:[],blockingHandoffs:[]};const syntheticReplay={...syntheticBinding,kind:'EXACT_SELECTED_GRID_ARTIFACT_REPLAY',passed:true,exactArchiveAndManifestVerified:true,kitSha256:sha(freezeRaw),criticReceiptSha256:'c'.repeat(64),reviewerIdentity:'synthetic-independent-reviewer'};
 syntheticSelection.selected=true;assertArtifactSelection(syntheticSelection,syntheticCritic,syntheticReplay,pins,'macos-arm64',syntheticArchive,sha(freezeRaw));
 rejects(()=>assertArtifactSelection(syntheticSelection,{...syntheticCritic,target:'windows-x64'},syntheticReplay,pins,'macos-arm64',syntheticArchive,sha(freezeRaw)),/target differs/);
 rejects(()=>assertArtifactSelection(syntheticSelection,syntheticCritic,{...syntheticReplay,passed:false},pins,'macos-arm64',syntheticArchive,sha(freezeRaw)));
 rejects(()=>assertArtifactSelection(syntheticSelection,{...syntheticCritic,thresholdResult:'FAIL'},syntheticReplay,pins,'macos-arm64',syntheticArchive,sha(freezeRaw)));
 rejects(()=>assertArtifactSelection(syntheticSelection,syntheticCritic,syntheticReplay,pins,'macos-arm64',{...syntheticArchive,sha256:'e'.repeat(64)},sha(freezeRaw)),/archive or manifest differs/);
 rejects(()=>assertArtifactSelection(syntheticSelection,syntheticCritic,syntheticReplay,pins,'macos-arm64',{...syntheticArchive,manifest:{...syntheticArchive.manifest,sha256:'e'.repeat(64)}},sha(freezeRaw)),/archive or manifest differs/);
 rejects(()=>assertArtifactSelection(syntheticSelection,syntheticCritic,{...syntheticReplay,criticReceiptSha256:'e'.repeat(64)},pins,'macos-arm64',syntheticArchive,sha(freezeRaw)),/different critic/);
 for(const script of ['native-smoke.mjs','gui-smoke.mjs','browser-smoke.mjs','public-smoke.mjs']){const text=await readFile(join(here,script),'utf8');assert(text.includes('denyForRuntime'));}
 const browser=await readFile(join(here,'browser-smoke.mjs'),'utf8');for(const text of ['Fetch.failRequest','requestStage','endsWith(\'.wasm\')','browser-export-native-reopen','Page.captureScreenshot'])assert(browser.includes(text));
 const host=await readFile(join(here,'host.mjs'),'utf8');for(const text of ["transaction.oncomplete=yes","storage-failure-retains-dirty-owner","durable-save-byte-roundtrip","malformed-open-preserves-current-workbook","second-edit-save-reopen"])assert(host.includes(text));
}
{
 assert.deepEqual(oracle.localModules,['verify.mjs','core.mjs','python-plan.mjs','pe.mjs','correction-controls.mjs','control-fixtures.mjs','host-contract.mjs','host-controls.mjs','archive-policy.mjs','delivery-controls.mjs','python-namespace-contract.mjs']);
 for(const name of oracle.localModules){const text=await readFile(join(here,name),'utf8');const imports=[...text.matchAll(/^import\b[^;]*?from\s+['"]([^'"]+)['"];?/gm)].map(m=>m[1]).sort();assert.deepEqual(imports,[...oracle.imports[name]].sort(),'Unexpected oracle import');}
 const preservation=await json(join(here,'PRESERVATION.json'));assert(preservation.files.length>=790);for(const row of preservation.files)await identity(root,row);
 for(const packet of preservation.frozenPackets){const packetRoot=join(root,packet.root);assert.equal(await digest(join(packetRoot,'FREEZE.json')),packet.freezeSha256);assert.deepEqual(await ownedFiles(packetRoot),packet.files,'Rejected packet namespace changed');}
 for(const namespace of preservation.frozenNamespaces??[])assert.deepEqual(await ownedFiles(join(root,namespace.root)),namespace.files,'Preserved parser/review namespace changed');
 assert.equal(gitTree(source.members),pins.source.tree);
 rejects(()=>safeRelative('../escape'),/Unsafe/);rejects(()=>safeRelative('C:/absolute'),/Unsafe/);rejects(()=>safeRelative('safe/CON.txt'),/Unsafe/);rejects(()=>safeRelative('name /part'),/Unsafe/);
 rejects(()=>validateRows([{path:'safe.txt',bytes:1,sha256:'a'.repeat(64),mode:0o644},{path:'SAFE.txt',bytes:1,sha256:'a'.repeat(64),mode:0o644}]),/case alias/);
 rejects(()=>validateRows([{path:'safe.txt',bytes:1,sha256:'a'.repeat(64),mode:0o666}]),/Unsafe member mode/);
 const fixture=Buffer.alloc(1024);fixture.write('MZ');fixture.writeUInt32LE(0x80,0x3c);fixture.write('PE\0\0',0x80);fixture.writeUInt16LE(0x8664,0x84);fixture.writeUInt16LE(1,0x86);fixture.writeUInt16LE(240,0x94);fixture.writeUInt16LE(0x20b,0x98);fixture.writeBigUInt64LE(0x140000000n,0x98+24);fixture.writeUInt32LE(0x200,0x98+60);fixture.writeUInt32LE(16,0x98+108);fixture.writeUInt32LE(0x1000,0x98+112+8);fixture.writeUInt32LE(40,0x98+112+12);const section=0x98+240;fixture.writeUInt32LE(0x1000,section+12);fixture.writeUInt32LE(0x200,section+16);fixture.writeUInt32LE(0x200,section+20);fixture.writeUInt32LE(0x1050,0x200+12);fixture.write('KERNEL32.dll\0',0x250);
 assertStaticCRT(inspectPEBytes(fixture));const wrong=Buffer.from(fixture);wrong.fill(0,0x250,0x270);wrong.write('VCRUNTIME140.dll\0',0x250);rejects(()=>assertStaticCRT(inspectPEBytes(wrong)),/VC runtime dependency/);rejects(()=>inspectPEBytes(fixture.subarray(0,80)),/outside file|Missing PE signature/);
 const moduleContract={kind:'WINDOWS_TARGET_SYSTEM_MODULE_CONTRACT',selected:true,osRelease:'fixture-os',entries:[{name:'kernel32.dll',kind:'system-file',file:{path:'C:\\Windows\\System32\\kernel32.dll',bytes:1,sha256:'a'.repeat(64)}}]};const pe=inspectPEBytes(fixture);assert.equal(bindWindowsImports(pe,[],moduleContract,'fixture-os').length,1);rejects(()=>bindWindowsImports({...pe,delayImports:['unreviewed-optional.dll']},[],moduleContract,'fixture-os'),/Unbound Windows import/);rejects(()=>bindWindowsImports(pe,[],{...moduleContract,selected:false},'fixture-os'),/selected/);rejects(()=>bindWindowsImports(pe,[],moduleContract,'different-os'),/OS/);
 const mutated=cloned(source.members);mutated[0].gitBlob='0'.repeat(40);assert.notEqual(gitTree(mutated),pins.source.tree);negativeControls++;
}
for(const row of oracle.externalPureModules)await identity(root,row);
for(const row of oracle.localModuleRecords)await identity(here,row);
const discoveryFreeze=await readFile(join(here,'..','grid-host-discovery-v5','FREEZE.json'));
const corrections=runCorrectionControls(pins,sha(freezeRaw),sha(discoveryFreeze),await readFile(join(here,'LICENSE-SUITE-TOOLS')));
const hostCorrections=runHostControls(pins,sha(freezeRaw),sha(discoveryFreeze));
const deliveryCorrections=runDeliveryControls(await json(join(here,'..','grid-host-discovery-v5','launch-admission-template.json')),sha(freezeRaw),sha(discoveryFreeze),await json(join(here,'archive-budget.json')));
assert(negativeControls>=4,'No meaningful wrong-data controls ran');console.log(mode==='preparation'?'Grid supported Python namespace preparation verified':'Grid selected delivery and namespace controls verified');console.log(JSON.stringify({mode,negativeControls,corrections,hostCorrections,deliveryCorrections,preparationOnly:true,executedBuilds:0,executedNative:0,executedBrowser:0,downloads:0,publication:false,fullGoalComplete:false}));

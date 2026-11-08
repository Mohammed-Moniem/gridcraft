// The positive and wrong-data cases call the same pure validators used at the future effect boundary.
import assert from 'node:assert/strict';
import {sha,assertPreparationSelection,assertArtifactSelection,assertRuntimeManifest} from './core.mjs';
import {archiveArgs,assertArchivePlan,assertArchiveInvocation,assertPythonEnvironment} from './python-plan.mjs';
import {validateOutputBundle} from '../grid-host-discovery-v5/output-contract.mjs';
import {discoveryFixture} from './control-fixtures.mjs';
import {PYTHON_NAMESPACE_POLICY} from './python-namespace-contract.mjs';
export function runCorrectionControls(pins,kitDigest,packetDigest,integrationBytes) {
 let rejected=0,positive=0;const no=fn=>{assert.throws(fn);rejected++;},yes=fn=>{fn();positive++;};
 const script='/reviewed/archive.py',python='/reviewed/python',args=archiveArgs(script,'extract','/archive','/destination','a'.repeat(64),'1');
 yes(()=>assertArchiveInvocation(python,args,{LANG:'C'},python,script));for(const operation of [['install-tools','/inputs','/tools','macos-arm64'],['pack','/runtime','/runtime.tar.gz']])yes(()=>assertArchivePlan(archiveArgs(script,...operation),script));
 for(const unsafe of [[script,...args.slice(4)],['-B','-I',script,...args.slice(4)],['-B','-I','-s',script,...args.slice(4)],['-B','-I','-S','-c','import sitecustomize'],['-B','-I','-S','/unreviewed/archive.py',...args.slice(4)],[...args,'-c','import sitecustomize']])no(()=>assertArchiveInvocation(python,unsafe,{},python,script));
 for(const key of ['PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','PYTHONUSERBASE','PYTHONINSPECT','__PYVENV_LAUNCHER__','VIRTUAL_ENV','pythonpath'])no(()=>assertPythonEnvironment({[key]:'/unreviewed/sitecustomize.py'}));
 no(()=>assertArchiveInvocation('/unreviewed/python',args,{},python,script));
 const ref=name=>({path:name,bytes:Buffer.byteLength(name),sha256:sha(Buffer.from(name))}),stages=['restore','compile-native','compile-wasm','package'];
 const discoveryBinding={scope:'ACTUAL_GRID_CONSUMING_HOST',pythonPolicy:PYTHON_NAMESPACE_POLICY,packetFreezeSha256:packetDigest,manifestSha256:sha(Buffer.from('synthetic manifest')),discoverySha256:sha(Buffer.from('synthetic discovery'))};const binding={scope:'PREPARATION_CODE_ONLY',kitSha256:kitDigest,target:'macos-arm64',stages,repository:pins.repository,sourceTree:pins.source.tree,sourceCommit:pins.source.commit,sourceArchiveSha256:pins.source.sha256,discoveryBinding};
 const selected={...binding,schemaVersion:1,kind:'CURRENT_GRID_PLATFORM_PREPARATION_SELECTION',selected:true,independent:true,critic:ref('synthetic-critic.json'),rootReplay:ref('synthetic-replay.json'),blockingHandoffs:[]},critic={...binding,kind:'INDEPENDENT_GRID_PLATFORM_PREPARATION_REVIEW',independent:true,evidenceAdequate:'YES',objectiveGates:'PASS',thresholdResult:'PASS',materialFindings:[],blockingHandoffs:[],reviewer:{identity:'synthetic-independent-reviewer',implementationAuthor:false}},replay={...binding,kind:'EXACT_GRID_PREPARATION_REPLAY',passed:true,exactKitVerified:true,criticReceiptSha256:selected.critic.sha256,reviewerIdentity:critic.reviewer.identity};
 const check=(a=selected,b=critic,c=replay)=>assertPreparationSelection(a,b,c,pins,'macos-arm64',stages,kitDigest,discoveryBinding);yes(()=>check());
 for(const field of [{kitSha256:'0'.repeat(64)},{target:'windows-x64'},{scope:'CURRENT_GRID_RUNTIME_ARCHIVE'},{stages:['package']},{independent:false},{selected:false},{blockingHandoffs:['MISSING']}])no(()=>check({...selected,...field}));
 for(const field of [{independent:false},{kitSha256:'0'.repeat(64)},{evidenceAdequate:'NO'},{objectiveGates:'FAIL'},{thresholdResult:'REJECT'},{materialFindings:['MATERIAL']},{blockingHandoffs:['MISSING']},{reviewer:{identity:'author',implementationAuthor:true}}])no(()=>check(selected,{...critic,...field}));
 for(const field of [{passed:false},{exactKitVerified:false},{criticReceiptSha256:'0'.repeat(64)},{reviewerIdentity:'another-reviewer'}])no(()=>check(selected,critic,{...replay,...field}));
 const archive={name:'synthetic.tar.gz',bytes:1,sha256:sha(Buffer.from('archive')),manifest:{bytes:1,sha256:sha(Buffer.from('manifest'))}},artifactBinding={scope:'CURRENT_GRID_RUNTIME_ARCHIVE',target:'macos-arm64',sourceTree:pins.source.tree,archive},artifactSelection={...artifactBinding,kind:'CURRENT_GRID_PLATFORM_ARTIFACT_SELECTION',kitSha256:kitDigest,critic:ref('synthetic-artifact-critic.json'),rootReplay:ref('synthetic-artifact-replay.json'),blockingHandoffs:[]},artifactCritic={...artifactBinding,kitSha256:kitDigest,independent:true,evidenceAdequate:'YES',objectiveGates:'PASS',thresholdResult:'PASS',materialFindings:[],blockingHandoffs:[],reviewer:critic.reviewer},artifactReplay={...artifactBinding,kind:'EXACT_SELECTED_GRID_ARTIFACT_REPLAY',passed:true,exactArchiveAndManifestVerified:true,kitSha256:kitDigest,criticReceiptSha256:artifactSelection.critic.sha256,reviewerIdentity:critic.reviewer.identity};
 artifactSelection.selected=true;const artifact=(b=artifactCritic,c=artifactReplay)=>assertArtifactSelection(artifactSelection,b,c,pins,'macos-arm64',archive,kitDigest);yes(()=>artifact());for(const field of [{independent:false},{independent:undefined},{kitSha256:'0'.repeat(64)},{kitSha256:undefined},{reviewer:{identity:'author',implementationAuthor:true}}])no(()=>artifact({...artifactCritic,...field}));no(()=>artifact(artifactCritic,{...artifactReplay,reviewerIdentity:'another-reviewer'}));
 assert.equal(sha(integrationBytes),pins.integrationLicense.sha256);assert.equal(integrationBytes.length,pins.integrationLicense.bytes);
 const integration={path:pins.integrationLicense.runtimePath,bytes:integrationBytes.length,sha256:sha(integrationBytes),mode:0o644},member=path=>({path,bytes:1,sha256:sha(Buffer.from(path)),mode:0o644});
 for(const target of Object.keys(pins.targets)){
  const exe=target==='windows-x64'?'.exe':'',runtime={kind:'CURRENT_GRID_RUNTIME_CANDIDATE',target,sourceTree:pins.source.tree,sourceArchiveSha256:pins.source.sha256,integrationLicense:{path:integration.path,bytes:integration.bytes,sha256:integration.sha256},files:['bin/gridcraft-cli'+exe,target==='windows-x64'?'bin/gridcraft.exe':'GridCraft.app/Contents/MacOS/GridCraft','web/index.html','web/host.html','web/host.mjs','web/glue.js','web/grid.wasm','launch.mjs','BUILD.json','legal/source/LICENSE-MIT','legal/source/LICENSE-APACHE','legal/source/NOTICE','legal/source/ATTRIBUTION.md','legal/fonts/OFL.txt','legal/vendor/LICENSE'].map(member).concat(integration),nativeQualified:false,guiQualified:false,browserQualified:false,publicQualified:false,windows11Qualified:false,privateHostQualified:false,signed:false,notarized:false,fullGoalComplete:false};
  yes(()=>assertRuntimeManifest(runtime,pins,target));no(()=>assertRuntimeManifest({...runtime,files:runtime.files.filter(row=>row.path!==integration.path)},pins,target));no(()=>assertRuntimeManifest({...runtime,files:runtime.files.map(row=>row.path===integration.path?{...row,sha256:sha(Buffer.concat([integrationBytes,Buffer.from('changed')]))}:row)},pins,target));no(()=>assertRuntimeManifest({...runtime,integrationLicense:undefined},pins,target));
 }
 const expected={kitSha256:kitDigest,packetSha256:packetDigest,sourceTree:pins.source.tree};
 for(const target of Object.keys(pins.targets)){
  const fresh=()=>discoveryFixture(target,expected);yes(()=>validateOutputBundle(fresh().seal(),expected));
  const fail=mutate=>{const fixture=fresh();fixture.seal();const bundle=mutate(fixture)??fixture.seal();no(()=>validateOutputBundle(bundle,expected));};
  fail(f=>{const manifest=f.read('OUTPUT-MANIFEST.json');manifest.files.pop();f.put('OUTPUT-MANIFEST.json',manifest);return f.snapshot();});
  fail(f=>{f.remove('queries/01-python-isolated-stdlib.json');});
  for(const name of ['FAILURE.json','TIMEOUT.json'])fail(f=>{f.put(name,{state:'NOT_READY'});return f.snapshot();});
  fail(f=>{f.put('unlisted.json',{});return f.snapshot();});fail(f=>{f.put('listed-extra.json',{});});
  fail(f=>{f.put('queries/01-python-isolated-stdlib.json',Buffer.from('changed'));return f.snapshot();});
  fail(f=>{const query=f.read('queries/01-python-isolated-stdlib.json');query.args=[query.args.at(-1)];f.put('queries/01-python-isolated-stdlib.json',query);});
  for(const field of [{code:1},{timedOut:true},{overflow:true},{error:'launch failed'},{signal:'SIGKILL'}])fail(f=>{f.put('queries/01-python-isolated-stdlib.json',{...f.read('queries/01-python-isolated-stdlib.json'),...field});});
  fail(f=>{const bundle=f.snapshot();bundle.entries[0].type='symlink';return bundle;});fail(f=>{const bundle=f.snapshot();bundle.entries.find(row=>row.type==='file').nlink=2;return bundle;});
  fail(f=>{const bundle=f.snapshot();bundle.entries.push({...bundle.entries.find(row=>row.path==='START.json'),path:'start.json'});return bundle;});
  fail(f=>{const bundle=f.snapshot();bundle.entries.find(row=>row.type==='file').path='../escape';return bundle;});
  fail(f=>{const bundle=f.snapshot();bundle.entries.find(row=>row.type==='file').mode=0o777;return bundle;});
  if(target==='windows-x64'){fail(f=>{f.remove('WINDOWS-SYSTEM-MODULES-CANDIDATE.json');});fail(f=>{f.remove('mappings/api-ms-win-core-synthetic-l1-1-0.dll.json');});}
 }
 assert(positive>=10&&rejected>=100);return {positive,rejected,correctedFindingIds:['GCP-001','GCP-002','GCP-003','GCP-004','GCP-005'],pythonProcessesExecuted:0,syntheticEvidenceOnly:true};
}

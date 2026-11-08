// Pure contract functions: no filesystem, process, network, or acquired-code execution.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {assertPythonEnvironment} from './python-plan.mjs';
import {PYTHON_NAMESPACE_POLICY} from './python-namespace-contract.mjs';

export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function safeRelative(path) {
  assert.equal(typeof path,'string');
  assert(path.length>0 && path.length<2048 && !/[\\:\x00-\x1f]/.test(path),'Unsafe member path');
  const parts=path.split('/');
  assert(parts.every(p=>p && p!=='.' && p!=='..' && !/[. ]$/.test(p) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)),'Unsafe portable member name');
  return path;
}
export function validateRows(rows) {
  assert(Array.isArray(rows) && rows.length>0 && rows.length<=100000,'Invalid file inventory');
  const seen=new Set();
  for(const row of rows) {
    safeRelative(row.path);
    const alias=row.path.normalize('NFC').toLowerCase();
    assert(!seen.has(alias),'Duplicate or case alias'); seen.add(alias);
    assert(Number.isSafeInteger(row.bytes) && row.bytes>=0 && row.bytes<=1024**3,'Invalid member size');
    assert.match(row.sha256,/^[a-f0-9]{64}$/,'Invalid member digest');
    const mode=typeof row.mode==='string'?parseInt(row.mode.slice(-3),8):row.mode;
    assert(Number.isInteger(mode) && mode>=0 && mode<=0o777 && !(mode&0o022),'Unsafe member mode');
  }
  return rows;
}
export function gitTree(rows) {
  const tree={};
  for(const row of rows) {
    const bits=safeRelative(row.path).split('/'); let node=tree;
    for(const part of bits.slice(0,-1)) {assert(!node[part]?.blob,'File/directory conflict');node=node[part]??={};}
    assert(!Object.hasOwn(node,bits.at(-1)),'Duplicate Git path');
    node[bits.at(-1)]={blob:row.gitBlob,mode:row.mode};
  }
  function hashNode(node) {
    const parts=[];
    const entries=Object.entries(node).sort(([a,av],[b,bv])=>Buffer.compare(Buffer.from(a+(av.blob?'':'/')),Buffer.from(b+(bv.blob?'':'/'))));
    for(const [name,value]of entries) {const digest=value.blob??hashNode(value);assert.match(digest,/^[a-f0-9]{40}$/);parts.push(Buffer.from((value.blob?value.mode:'40000')+' '+name+'\0'),Buffer.from(digest,'hex'));}
    const content=Buffer.concat(parts);return createHash('sha1').update('tree '+content.length+'\0').update(content).digest('hex');
  }
  return hashNode(tree);
}
export function assertPins(pins,source,vendor) {
  assert.equal(pins.kind,'CURRENT_GRID_PLATFORM_PREPARATION');
  assert.equal(pins.source.tree,'c4544e89868075cca2570ede803540bdbf0afae9');
  assert.equal(pins.source.sha256,'01b4d9d365d7265a26e0446a81f256e0c56094769a6f641a03ce7867bd47de27');
  assert.equal(pins.source.bytes,5616695);
  validateRows(source.members); assert.equal(source.members.length,source.files);
  assert.equal(gitTree(source.members),pins.source.tree,'Source Git tree mismatch');
  assert.equal(source.sha256,pins.source.sha256);assert.equal(source.bytes,pins.source.bytes);assert.equal(source.top,pins.source.top);
  assert.equal(source.members.find(f=>f.path==='Cargo.lock').sha256,pins.sourceLockSha256);
  assert.equal(vendor.kind,'captured-vendor-build-inputs');assert.equal(vendor.app,'gridcraft');
  assert.equal(vendor.engineLockSha256,pins.sourceLockSha256,'Vendor/source lock mismatch');
  assert.equal(vendor.files.find(f=>f.path==='Cargo.lock').sha256,pins.sourceLockSha256);
  assert.deepEqual(pins.versions,{nodeMinimum:22,rust:'1.95.0',trunk:'0.22.1',wasmBindgen:'0.2.129',binaryen:'131'});
  for(const asset of pins.assets) {assert.equal(new URL(asset.url).hostname,'github.com');assert(asset.url.startsWith('https://github.com/Mohammed-Moniem/embedded-office-suite/releases/download/'));assert.match(asset.sha256,/^[a-f0-9]{64}$/);assert(Number.isSafeInteger(asset.bytes)&&asset.bytes>0);}
  return true;
}
export function commandPlan(pins,target,workspace) {
  const t=pins.targets[target];assert(t,'Unknown target');
  const exe=target==='windows-x64'?'.exe':'';
  const native=['build','--frozen','--offline','--release','--target',t.triple,'-p','gridcraft-cli','-p','gridcraft'];
  const wasm=['build','--offline=true','--frozen=true','--skip-version-check','--release=true','--public-url','./','--dist',workspace+'/web-build'];
  return {native,wasm,staticNativeRustflags:target==='windows-x64'?'-C target-feature=+crt-static':null,wasmRustflags:null,cli:'target/'+t.triple+'/release/gridcraft-cli'+exe,app:'target/'+t.triple+'/release/gridcraft'+exe,sourceUnchangedRequired:true};
}
export function assertAdmission(admission,pins,target,stage,kitDigest) {
  assert(admission.discoveryEvidence?.path&&Number.isSafeInteger(admission.discoveryEvidence.bytes)&&admission.discoveryEvidence.bytes>0,'Exact discovery evidence required');assert.match(admission.discoveryEvidence.sha256??'',/^[a-f0-9]{64}$/);
  assert(admission.discoveryBundle&&typeof admission.discoveryBundle.directory==='string'&&admission.discoveryBundle.directory,'Complete discovery bundle required');assert(admission.discoveryBundle.manifest&&Number.isSafeInteger(admission.discoveryBundle.manifest.bytes)&&admission.discoveryBundle.manifest.bytes>0);assert.match(admission.discoveryBundle.manifest.sha256??'',/^[a-f0-9]{64}$/);
  assert(admission.hostSelection?.path&&Number.isSafeInteger(admission.hostSelection.bytes)&&admission.hostSelection.bytes>0,'Selected consuming-host receipt required');assert.match(admission.hostSelection.sha256??'',/^[a-f0-9]{64}$/);
  assert.equal(admission.discoveryBinding?.scope,'ACTUAL_GRID_CONSUMING_HOST');assert.equal(admission.discoveryBinding.pythonPolicy,PYTHON_NAMESPACE_POLICY);for(const key of ['packetFreezeSha256','manifestSha256','discoverySha256'])assert.match(admission.discoveryBinding[key]??'',/^[a-f0-9]{64}$/);
  assert(admission.sdkProof&&admission.sdkProof.platform===target&&Array.isArray(admission.sdkProof.files)&&admission.sdkProof.files.length>=6,'Selected SDK evidence required');
  assert.equal(admission.schemaVersion,1);assert.equal(admission.selected,true,'Independent selection is required');
  assert.equal(admission.kitSha256,kitDigest,'Reviewed kit changed');
  assert.equal(admission.target,target);assertStages(admission.stages,pins);assert(admission.stages.includes(stage),'Stage not admitted');
  assert.equal(admission.sourceTree,pins.source.tree);assert.equal(admission.sourceArchiveSha256,pins.source.sha256);
  assert.equal(admission.sourceCommit,pins.source.commit);
  for(const name of ['independentSelection','publicSourceProof']) {
    const proof=admission[name];assert(proof && proof.path,'Missing '+name);assert.match(proof.sha256,/^[a-f0-9]{64}$/);assert(Number.isSafeInteger(proof.bytes)&&proof.bytes>0);
  }
  assert.equal(admission.network.buildIsolationClaim,false,'Build offline flags are not OS isolation');
  assert.equal(typeof admission.environment,'object');assert.equal(typeof admission.systemPath,'string');
  assert(!Object.keys(admission.environment).some(k=>/TOKEN|PASSWORD|SECRET|AUTH|CREDENTIAL/i.test(k)),'Secrets are not build environment inputs');
  assert(!Object.keys(admission.environment).some(k=>/^(CARGO|RUST|TRUNK|CRAFT|NODE_OPTIONS|LD_|DYLD_)/i.test(k)),'Unreviewed tool override');
  assertPythonEnvironment(admission.environment);
  assert(admission.tools.python && admission.tools.node,'Explicit Python and Node tool identities required');
  return true;
}
export function assertStages(stages,pins) {
  assert(Array.isArray(stages)&&stages.length>0,'Empty permitted stage set');
  assert(stages.every(stage=>pins.stages.includes(stage)),'Unknown permitted stage');
  assert.equal(new Set(stages).size,stages.length,'Duplicate permitted stage');
  assert.deepEqual(stages,pins.stages.filter(stage=>stages.includes(stage)),'Noncanonical stage set');
  return stages;
}
export function assertPreparationSelection(selection,critic,replay,pins,target,stages,kitDigest,discoveryBinding) {
  assert(discoveryBinding&&discoveryBinding.scope==='ACTUAL_GRID_CONSUMING_HOST','Preparation must bind discovery host evidence');
  assertStages(stages,pins);assert(pins.targets[target],'Unknown selection target');
  assert.equal(selection.schemaVersion,1);assert.equal(selection.kind,'CURRENT_GRID_PLATFORM_PREPARATION_SELECTION');assert.equal(selection.selected,true);
  for(const proof of [selection,critic,replay]) {
    assert.deepEqual(proof.discoveryBinding,discoveryBinding,'Preparation discovery evidence differs');
    assert.equal(proof.scope,'PREPARATION_CODE_ONLY','Selection scope differs');assert.equal(proof.kitSha256,kitDigest,'Selection kit differs');
    assert.equal(proof.repository,pins.repository);assert.equal(proof.target,target,'Selection target differs');assert.deepEqual(proof.stages,stages,'Selection stages differ');
    assert.equal(proof.sourceTree,pins.source.tree);assert.equal(proof.sourceCommit,pins.source.commit);assert.equal(proof.sourceArchiveSha256,pins.source.sha256);
  }
  assert.equal(selection.independent,true,'Preparation selection is not independent');
  assert.equal(critic.kind,'INDEPENDENT_GRID_PLATFORM_PREPARATION_REVIEW');assert.equal(critic.independent,true,'Preparation critic is not independent');
  assert.equal(critic.evidenceAdequate,'YES');assert.equal(critic.objectiveGates,'PASS');assert.equal(critic.thresholdResult,'PASS');
  assert.deepEqual(critic.materialFindings,[]);assert.deepEqual(critic.blockingHandoffs,[]);assert.deepEqual(selection.blockingHandoffs,[]);
  assert(critic.reviewer&&typeof critic.reviewer.identity==='string'&&critic.reviewer.identity.trim(),'Reviewer provenance missing');assert.equal(critic.reviewer.implementationAuthor,false);
  for(const row of [selection.critic,selection.rootReplay]){assert(row&&typeof row.path==='string'&&row.path);assert(Number.isSafeInteger(row.bytes)&&row.bytes>0);assert.match(row.sha256,/^[a-f0-9]{64}$/);}
  assert.equal(replay.kind,'EXACT_GRID_PREPARATION_REPLAY');assert.equal(replay.passed,true);assert.equal(replay.exactKitVerified,true);
  assert.equal(replay.criticReceiptSha256,selection.critic.sha256,'Preparation replay used a different critic');assert.equal(replay.reviewerIdentity,critic.reviewer.identity,'Preparation reviewer differs');
  return true;
}
export function assertPublicSource(proof,pins) {
  assert.equal(proof.repository,pins.repository);assert.equal(proof.commit,pins.source.commit);assert.equal(proof.tree,pins.source.tree);assert.equal(proof.anonymous,true);
  const download=proof.downloads.find(d=>d.name===pins.source.name);assert(download,'Source download absent');
  assert.equal(download.bytes,pins.source.bytes);assert.equal(download.sha256,pins.source.sha256);assert.equal(download.url,pins.source.url);assert.equal(download.anonymous,true);assert.equal(download.status,200);
  return true;
}
export function assertArtifactSelection(selection,critic,replay,pins,target,archive,kitDigest) {
  assert.equal(selection.selected,true,'Runtime artifact is not explicitly selected');
  const identity=value=>({name:value.name,bytes:value.bytes,sha256:value.sha256,manifest:{bytes:value.manifest?.bytes,sha256:value.manifest?.sha256}});
  assert.match(archive.name,/^[a-zA-Z0-9._-]+$/);assert(Number.isSafeInteger(archive.bytes)&&archive.bytes>0);assert.match(archive.sha256,/^[a-f0-9]{64}$/);assert(archive.manifest&&Number.isSafeInteger(archive.manifest.bytes)&&archive.manifest.bytes>0);assert.match(archive.manifest.sha256,/^[a-f0-9]{64}$/);
  assert.equal(selection.kind,'CURRENT_GRID_PLATFORM_ARTIFACT_SELECTION');assert.equal(selection.scope,'CURRENT_GRID_RUNTIME_ARCHIVE');assert.equal(selection.kitSha256,kitDigest,'Artifact kit differs');
  for(const proof of [selection,critic,replay]){assert.equal(proof.scope,'CURRENT_GRID_RUNTIME_ARCHIVE');assert.equal(proof.target,target,'Artifact target differs');assert.equal(proof.sourceTree,pins.source.tree,'Artifact source differs');assert.deepEqual(identity(proof.archive),identity(archive),'Artifact archive or manifest differs');}
  assert.equal(critic.evidenceAdequate,'YES');assert.equal(critic.objectiveGates,'PASS');assert.equal(critic.thresholdResult,'PASS');assert.deepEqual(critic.materialFindings,[]);assert.deepEqual(critic.blockingHandoffs,[]);
  assert.equal(critic.independent,true,'Artifact critic is not independent');assert.equal(critic.kitSha256,kitDigest,'Artifact critic kit differs');
  assert(critic.reviewer&&typeof critic.reviewer.identity==='string'&&critic.reviewer.identity.trim(),'Artifact reviewer provenance missing');assert.equal(critic.reviewer.implementationAuthor,false);
  assert.equal(replay.kind,'EXACT_SELECTED_GRID_ARTIFACT_REPLAY');assert.equal(replay.passed,true);assert.equal(replay.exactArchiveAndManifestVerified,true);assert.equal(replay.kitSha256,kitDigest);assert.equal(replay.criticReceiptSha256,selection.critic.sha256,'Root replay used a different critic');
  assert.equal(replay.reviewerIdentity,critic.reviewer.identity,'Artifact reviewer differs');
  for(const row of [selection.critic,selection.rootReplay]){assert(row.path);assert(Number.isSafeInteger(row.bytes)&&row.bytes>0);assert.match(row.sha256,/^[a-f0-9]{64}$/);}
  assert.deepEqual(selection.blockingHandoffs,[]);return true;
}
export function assertRuntimeManifest(manifest,pins,target) {
  assert.equal(manifest.kind,'CURRENT_GRID_RUNTIME_CANDIDATE');assert.equal(manifest.target,target);
  assert.equal(manifest.sourceTree,pins.source.tree);assert.equal(manifest.sourceArchiveSha256,pins.source.sha256);
  validateRows(manifest.files);
  const legal=pins.integrationLicense;assert(legal,'Captured integration license identity missing');
  assert.deepEqual(manifest.integrationLicense,{path:legal.runtimePath,bytes:legal.bytes,sha256:legal.sha256},'Runtime integration license identity differs');
  const notice=manifest.files.filter(row=>row.path===legal.runtimePath);assert.equal(notice.length,1,'Integration license absent');
  assert.equal(notice[0].bytes,legal.bytes);assert.equal(notice[0].sha256,legal.sha256,'Integration license bytes changed');assert.equal(notice[0].mode,0o644);
  const paths=manifest.files.map(f=>f.path),exe=target==='windows-x64'?'.exe':'';
  for(const name of ['bin/gridcraft-cli'+exe,'web/index.html','web/host.html','web/host.mjs','launch.mjs','BUILD.json','legal/source/LICENSE-MIT','legal/source/LICENSE-APACHE','legal/source/NOTICE','legal/source/ATTRIBUTION.md'])assert(paths.includes(name),'Incomplete runtime: '+name);
  assert(paths.some(p=>p.startsWith('web/')&&p.endsWith('.wasm')),'WASM absent');
  assert(paths.some(p=>p.startsWith('web/')&&p.endsWith('.js')),'WASM JavaScript glue absent');
  assert(paths.some(p=>p.startsWith('legal/fonts/')),'Font licences absent');
  assert(paths.some(p=>p.startsWith('legal/vendor/')),'Vendor licences absent');
  assert(paths.includes(target==='windows-x64'?'bin/gridcraft.exe':'GridCraft.app/Contents/MacOS/GridCraft'),'Native application absent');
  for(const value of ['nativeQualified','guiQualified','browserQualified','publicQualified','windows11Qualified','privateHostQualified','signed','notarized','fullGoalComplete'])assert.equal(manifest[value],false,'Package preparation cannot qualify runtime');
  return true;
}

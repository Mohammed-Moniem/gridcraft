// Shared pure mandatory preflight contracts. No I/O or host query is performed by this module.
import assert from 'node:assert/strict';
import {assertStages} from './core.mjs';
import {PYTHON_NAMESPACE_POLICY,assertPythonNamespaceCapture,assertPythonNamespaceObservation} from './python-namespace-contract.mjs';
export const PYTHON_EXECUTION_POLICY=PYTHON_NAMESPACE_POLICY;
const id=row=>({path:row.path,bytes:row.bytes,sha256:row.sha256,mode:row.mode});
const lookup=(rows,path)=>rows.find(row=>row.path===path||row.locator===path);
export function assertPythonExecutionClosure(python,inventory) {
 const q=python.query;assert.equal(q.executionPolicy,PYTHON_EXECUTION_POLICY);assert.equal(q.bytecodeWritesDisabled,true,'-B suppresses writes only');
 assert.equal(q.pycachePrefix,null,'Custom Python cache-prefix namespaces are outside the supported isolated policy');
 assertPythonNamespaceCapture(q.namespaceCapture,inventory);
 assert.deepEqual(q.namespaceCapture.description,{runtimeRoots:q.runtimeRootCandidates,searchPaths:q.importSearchCandidates,requiredFiles:[...new Set([python.path,...q.loadedFiles.map(row=>row.locator??row.path)])],optionalFiles:[...new Set([...q.cacheCandidates,...q.supportCandidates])]},'Complete namespace acquisition differs from actual isolated query');
 assert(Array.isArray(q.moduleLoaders)&&q.moduleLoaders.length>0&&q.moduleLoaders.length<=256);
 assert(Array.isArray(q.cacheFiles)&&Array.isArray(q.supportFiles)&&Array.isArray(q.absentFiles));
 for(const key of ['cacheCandidates','supportCandidates']){assert(Array.isArray(q[key])&&q[key].length<=512);assert.equal(new Set(q[key]).size,q[key].length);}
 assert.deepEqual([...q.absentFiles].sort(),q.namespaceCapture.lookups.filter(row=>row.role==='optionalFiles'&&row.kind==='absent').map(row=>row.locator).sort(),'Cache/config absences differ from resolved namespace evidence');
 assert(Array.isArray(q.searchDirectories)&&q.searchDirectories.length>0&&q.searchDirectories.length<=64);
 const present=[...q.loadedFiles,...q.cacheFiles,...q.supportFiles],absent=new Set(q.absentFiles);assert.equal(absent.size,q.absentFiles.length);
 for(const path of [...q.cacheCandidates,...q.supportCandidates])assert(lookup(present,path)||absent.has(path),'Python cache/support candidate omitted');
 for(const locator of q.searchDirectoryCandidates)assert(q.searchDirectories.some(row=>(row.locator??row.path)===locator),'Python import/cache namespace omitted');
 for(const row of present){const found=lookup(inventory,row.path);assert(found,'Python executable input absent from inventory');assert.deepEqual(id(found),id(row));}
 let caches=0;for(const module of q.moduleLoaders){assert.equal(typeof module.name,'string');assert(['BuiltinImporter','FrozenImporter','SourceFileLoader','SourcelessFileLoader','ExtensionFileLoader','zipimporter'].includes(module.loader),'Unsupported Python loader');
  for(const path of [module.file,module.loaderFile,module.archive].filter(Boolean))assert(lookup(present,path),'Python loader/support input omitted');
  for(const field of ['cached','specCached'])assert(module[field]==null||typeof module[field]==='string'&&module[field].length>0,'Invalid Python loader cache path');
  if(module.loader==='SourceFileLoader')assert(module.cached||module.specCached,'Source-backed loader module/spec cache candidates both omitted');
  for(const path of [module.cached,module.specCached].filter(Boolean)){caches++;assert(q.cacheCandidates.includes(path),'Loader module/spec cache candidate omitted from query candidates');assert(lookup(present,path)||absent.has(path),'Python bytecode cache neither captured nor proven absent');}
 }
 assert(caches>0,'No bytecode cache candidates recorded');
 for(const path of absent){assert.equal(typeof path,'string');assert(path&&!lookup(present,path),'Contradictory Python absence');}
 for(const directory of q.searchDirectories){assert.equal(typeof directory.path,'string');assert(Array.isArray(directory.entries)&&directory.entries.length<=1024);assert.equal(new Set(directory.entries.map(row=>row.name)).size,directory.entries.length);for(const entry of directory.entries){assert(entry.name&&!/[\\/\x00-\x1f]/.test(entry.name));assert(['file','directory','symlink'].includes(entry.type));if(entry.type==='symlink')assert.equal(typeof entry.link,'string');}}
 return true;
}
export function assertHostObservation(capture,observed) {
 const host=capture.host;for(const key of ['platform','arch','release','imageOS','imageVersion','runnerEnvironment','repository'])assert.equal(observed.host[key],host[key],'Consuming host '+key+' differs');
 assert.deepEqual([...observed.host.cpuModels].sort(),[...host.cpuModels].sort(),'Consuming CPU differs');
 assert.deepEqual(observed.files.map(id),capture.inspection.files.map(id),'Consuming executable/stdlib/cache/SDK/module bytes differ');
 assert.deepEqual(observed.absentFiles,[...capture.tools.python.query.absentFiles].sort(),'Python cache/config absence changed');
 assert.deepEqual(observed.searchDirectories,capture.tools.python.query.searchDirectories,'Python import/cache namespace changed');
 assertPythonNamespaceObservation(capture.tools.python.query.namespaceCapture,observed.pythonNamespace);
 assertPythonExecutionClosure(capture.tools.python,capture.inspection.files);return true;
}
export function assertDiscoveryBinding(value) {
 assert(value&&typeof value==='object'&&!Array.isArray(value),'Selected discovery binding required');
 for(const key of ['packetFreezeSha256','manifestSha256','discoverySha256'])assert.match(value[key]??'',/^[a-f0-9]{64}$/,'Exact discovery identity required');
 assert.equal(value.scope,'ACTUAL_GRID_CONSUMING_HOST');assert.equal(value.pythonPolicy,PYTHON_EXECUTION_POLICY);return value;
}
export function assertSelectedHost(admission,selection,critic,replay,capture,pins,target,stage,kitDigest,binding) {
 assertDiscoveryBinding(binding);assertStages(admission.stages,pins);assert(admission.stages.includes(stage));
 for(const proof of [selection,critic,replay]){assert.equal(proof.scope,'ACTUAL_GRID_CONSUMING_HOST');assert.equal(proof.kitSha256,kitDigest);assert.equal(proof.target,target);assert.equal(proof.sourceTree,pins.source.tree);assert.equal(proof.sourceCommit,pins.source.commit);assert.equal(proof.sourceArchiveSha256,pins.source.sha256);assert.deepEqual(proof.stages,admission.stages);assert.deepEqual(proof.discoveryBinding,binding,'Selected discovery bundle differs');assert.deepEqual(proof.host,capture.host,'Selected host identity differs');}
 assert.equal(selection.kind,'SELECTED_GRID_CONSUMING_HOST');assert.equal(selection.selected,true,'Consuming host is not selected');assert.equal(selection.independent,true);
 assert.equal(critic.kind,'INDEPENDENT_GRID_DISCOVERY_HOST_REVIEW');assert.equal(critic.independent,true);assert.equal(critic.evidenceAdequate,'YES');assert.equal(critic.objectiveGates,'PASS');assert.equal(critic.thresholdResult,'PASS');assert.deepEqual(critic.materialFindings,[]);assert.deepEqual(critic.blockingHandoffs,[]);assert.deepEqual(selection.blockingHandoffs,[]);
 assert(critic.reviewer?.identity);assert.equal(critic.reviewer.implementationAuthor,false);assert.equal(replay.kind,'EXACT_SELECTED_GRID_HOST_REPLAY');assert.equal(replay.passed,true);assert.equal(replay.completeDiscoveryBundleVerified,true);assert.equal(replay.criticReceiptSha256,selection.critic.sha256);assert.equal(replay.reviewerIdentity,critic.reviewer.identity);
 assert.deepEqual(admission.discoveryBinding,binding);assert.deepEqual(admission.tools,capture.tools,'Admitted tools differ from selected discovery');assert.deepEqual(admission.sdkProof,capture.sdk,'Admitted SDK differs from selected discovery');assert.deepEqual(admission.environment,capture.environment);assert.equal(admission.systemPath,capture.systemPath);assert.deepEqual(admission.discoveryEvidence,{...admission.discoveryEvidence,bytes:selection.discoveryEvidence.bytes,sha256:selection.discoveryEvidence.sha256});
 assertPythonExecutionClosure(capture.tools.python,capture.inspection.files);return true;
}

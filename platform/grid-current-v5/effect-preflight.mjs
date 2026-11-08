// Mandatory read-only effect preflight. Every relevant entrypoint calls this before its first effect.
import assert from 'node:assert/strict';
import {readFile,lstat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {sha,safeRelative,assertAdmission,assertPreparationSelection,assertPublicSource} from './core.mjs';
import {assertDiscoveryBinding,assertSelectedHost,assertHostObservation} from './host-contract.mjs';
import {observeCapturedHost} from './host-reader.mjs';
import {assertArchivePolicy} from './archive-policy.mjs';
import {readOutputDirectory} from '../grid-host-discovery-v5/evidence-reader.mjs';
import {validateOutputBundle} from '../grid-host-discovery-v5/output-contract.mjs';
import {validateHost,validateCapturedFileClosure,candidateFromCapture} from '../grid-host-discovery-v5/model.mjs';
export async function effectPreflight(here,admission,pins,target,stage,kitDigest) {
 assertAdmission(admission,pins,target,stage,kitDigest);
 assertArchivePolicy(JSON.parse(await readFile(join(here,'archive-budget.json'))));
 async function exact(path,row){const st=await lstat(path);assert(st.isFile()&&!st.isSymbolicLink());const raw=await readFile(path);assert.equal(raw.length,row.bytes);assert.equal(sha(raw),row.sha256);return raw;}
 const receipt=async row=>{assert(row?.path);return JSON.parse(await exact(resolve(here,row.path),row));};
 const preparation=await receipt(admission.independentSelection),preparationCritic=await receipt(preparation.critic),preparationReplay=await receipt(preparation.rootReplay);assertPreparationSelection(preparation,preparationCritic,preparationReplay,pins,target,admission.stages,kitDigest,admission.discoveryBinding);assertPublicSource(await receipt(admission.publicSourceProof),pins);
 const discovery=join(here,'..','grid-host-discovery-v5'),raw=await readFile(join(discovery,'FREEZE.json')),packetSha256=sha(raw);assert.equal(packetSha256,admission.discoveryBinding.packetFreezeSha256,'Unreviewed discovery packet');for(const row of JSON.parse(raw).files)await exact(join(discovery,safeRelative(row.path)),row);
 const bundle=await readOutputDirectory(admission.discoveryBundle.directory),validated=validateOutputBundle(bundle,{kitSha256:kitDigest,packetSha256,sourceTree:pins.source.tree}),capture=validated.capture;validateHost(capture);validateCapturedFileClosure(capture);assert.deepEqual(validated.admission,candidateFromCapture(capture,validated.receipt));
 const manifest=bundle.entries.find(row=>row.path==='OUTPUT-MANIFEST.json'),binding={scope:'ACTUAL_GRID_CONSUMING_HOST',pythonPolicy:capture.tools.python.query.executionPolicy,packetFreezeSha256:packetSha256,manifestSha256:manifest.sha256,discoverySha256:validated.receipt.sha256};assertDiscoveryBinding(binding);assert.deepEqual(binding,admission.discoveryBinding);assert.equal(manifest.bytes,admission.discoveryBundle.manifest.bytes);assert.equal(manifest.sha256,admission.discoveryBundle.manifest.sha256);assert.equal(admission.discoveryEvidence.bytes,validated.receipt.bytes);assert.equal(admission.discoveryEvidence.sha256,validated.receipt.sha256);
 const selected=await receipt(admission.hostSelection),critic=await receipt(selected.critic),replay=await receipt(selected.rootReplay);assertSelectedHost(admission,selected,critic,replay,capture,pins,target,stage,kitDigest,binding);
 assert.equal(resolve(admission.tools.node.path),resolve(process.execPath),'Current Node differs from selected host');
 const revalidate=async()=>{assertHostObservation(capture,await observeCapturedHost(capture));};await revalidate();
 return {capture,binding,revalidate,scope:'Read-only same-host and exact captured input preflight; no build/runtime/platform acceptance'};
}

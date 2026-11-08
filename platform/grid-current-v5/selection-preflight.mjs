// Read-only preflight used before the Windows wrapper makes any network change.
import assert from 'node:assert/strict';
import {readFile,lstat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {sha,safeRelative,assertAdmission,assertPreparationSelection,assertPublicSource} from './core.mjs';
import {effectPreflight} from './effect-preflight.mjs';
const {values}=parseArgs({options:{admission:{type:'string'},sha256:{type:'string'},target:{type:'string'},stage:{type:'string'}}}),here=fileURLToPath(new URL('.',import.meta.url));
async function exact(path,row){const st=await lstat(path);assert(st.isFile()&&!st.isSymbolicLink());const raw=await readFile(path);assert.equal(raw.length,row.bytes);assert.equal(sha(raw),row.sha256);return raw;}
const raw=await readFile(resolve(values.admission));assert.match(values.sha256??'',/^[a-f0-9]{64}$/);assert.equal(sha(raw),values.sha256);
const admission=JSON.parse(raw),pins=JSON.parse(await readFile(join(here,'inputs.json'))),freezeRaw=await readFile(join(here,'FREEZE.json')),kitDigest=sha(freezeRaw);
for(const row of JSON.parse(freezeRaw).files)await exact(join(here,safeRelative(row.path)),row);
assertAdmission(admission,pins,values.target,values.stage,kitDigest);await exact(process.execPath,admission.tools.node);assert.equal(resolve(process.execPath),resolve(admission.tools.node.path));
const proof=async row=>JSON.parse(await exact(resolve(here,row.path),row)),selection=await proof(admission.independentSelection),critic=await proof(selection.critic),replay=await proof(selection.rootReplay);
assertPreparationSelection(selection,critic,replay,pins,values.target,admission.stages,kitDigest,admission.discoveryBinding);assertPublicSource(await proof(admission.publicSourceProof),pins);
await effectPreflight(here,admission,pins,values.target,values.stage,kitDigest);
console.log('Exact Grid preparation selection permits this stage; no runtime or network effect performed');

// Future read-only consumer: enumerate the complete namespace before accepting a ready claim.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {sha,KIT_SHA,SOURCE_TREE,validateHost,validateCapturedFileClosure,candidateFromCapture,assertCandidate} from './model.mjs';
import {validateOutputBundle} from './output-contract.mjs';
import {readOutputDirectory} from './evidence-reader.mjs';
const {values}=parseArgs({options:{directory:{type:'string'}}}),here=fileURLToPath(new URL('.',import.meta.url));
const packetSha256=sha(await readFile(join(here,'FREEZE.json'))),bundle=await readOutputDirectory(values.directory);
const {capture,admission,receipt}=validateOutputBundle(bundle,{kitSha256:KIT_SHA,packetSha256,sourceTree:SOURCE_TREE});
validateHost(capture);validateCapturedFileClosure(capture);assertCandidate(admission,capture,receipt);assert.deepEqual(admission,candidateFromCapture(capture,receipt));
console.log('Complete actual captured host evidence is consistent; root selection remains required');

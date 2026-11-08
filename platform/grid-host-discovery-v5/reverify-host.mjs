// Optional read-only standalone view of the same mandatory consuming-host preflight contract.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {parseArgs} from 'node:util';
import {sha,validateHost,validateCapturedFileClosure} from './model.mjs';
import {assertHostObservation} from '../grid-current-v5/host-contract.mjs';
import {observeCapturedHost} from '../grid-current-v5/host-reader.mjs';
const {values}=parseArgs({options:{evidence:{type:'string'},sha256:{type:'string'}}}),raw=await readFile(values.evidence);assert.match(values.sha256??'',/^[a-f0-9]{64}$/);assert.equal(sha(raw),values.sha256);const capture=JSON.parse(raw);validateHost(capture);validateCapturedFileClosure(capture);assert.deepEqual(capture.missing,[]);assert.equal(capture.state,'CAPTURED_REQUIRES_REVIEW');assertHostObservation(capture,await observeCapturedHost(capture));
console.log('Actual selected host and every captured loader/cache/support/SDK/module input remain exact; no execution admission is granted');

// Shared pure acyclic delivery contract. Payload bytes are supplied outside the reviewed code commit.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
export const DELIVERY_LIMITS=Object.freeze({payloadBytes:32768,base64Chars:43692});
export const DELIVERY_TARGETS=Object.freeze(['macos-arm64','macos-x64','windows-x64']);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function decodeDelivery(base64,spec){
 assert.equal(typeof base64,'string');assert(base64.length>0&&base64.length<=DELIVERY_LIMITS.base64Chars&&base64.length%4===0&&/^[A-Za-z0-9+/]*={0,2}$/.test(base64),'Bounded canonical payload base64 required');
 assert(spec&&Number.isSafeInteger(spec.bytes)&&spec.bytes>0&&spec.bytes<=DELIVERY_LIMITS.payloadBytes);assert.match(spec.sha256??'',/^[a-f0-9]{64}$/);
 const raw=Buffer.from(base64,'base64');assert.equal(raw.toString('base64'),base64,'Noncanonical payload encoding');assert.equal(raw.length,spec.bytes,'Payload length differs');assert.equal(sha(raw),spec.sha256,'Payload digest differs');assert(Buffer.from(raw.toString('utf8')).equals(raw),'Invalid payload UTF-8');return raw;
}
export function validateDelivery(raw,spec,context){
 assert(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=DELIVERY_LIMITS.payloadBytes);assert.equal(raw.length,spec.bytes);assert.equal(sha(raw),spec.sha256);const value=JSON.parse(raw);
 assert.deepEqual(Object.keys(value).sort(),['schemaVersion','kind','selected','repository','codeCommit','kitSha256','packetSha256','targets','review','rootReplay'].sort(),'Unknown delivery fields');
 assert.equal(value.schemaVersion,1);assert.equal(value.kind,'EXTERNAL_GRID_DISCOVERY_DELIVERY');assert.equal(value.selected,true,'External delivery is not selected');
 assert.equal(value.repository,'Mohammed-Moniem/gridcraft');assert.equal(value.repository,context.repository);assert.match(value.codeCommit,/^[a-f0-9]{40}$/);assert.equal(value.codeCommit,context.head,'Reviewed code/head differs');assert.equal(value.kitSha256,context.kitSha256);assert.equal(value.packetSha256,context.packetSha256);
 assert.deepEqual(Object.keys(value.targets).sort(),[...DELIVERY_TARGETS].sort(),'Exact three target receipts required');const launchDigests={};for(const target of DELIVERY_TARGETS){const launch=value.targets[target];assert(launch&&typeof launch==='object'&&!Array.isArray(launch));assert.equal(launch.selected,true);assert.equal(launch.workflowHead,value.codeCommit);assert.equal(launch.repository,value.repository);assert.equal(launch.target,target);assert.equal(launch.packetSha256,value.packetSha256);assert.equal(launch.kitSha256,value.kitSha256);launchDigests[target]=sha(Buffer.from(JSON.stringify(launch)));}
 for(const proof of [value.review,value.rootReplay]){assert.equal(proof.scope,'READ_ONLY_GRID_DISCOVERY_DELIVERY');assert.equal(proof.repository,value.repository);assert.equal(proof.codeCommit,value.codeCommit);assert.equal(proof.kitSha256,value.kitSha256);assert.equal(proof.packetSha256,value.packetSha256);assert.deepEqual(proof.targets,DELIVERY_TARGETS);assert.deepEqual(proof.launchDigests,launchDigests,'Reviewed target receipt bytes differ');}
 const review=value.review;assert.equal(review.independent,true);assert.equal(review.evidenceAdequate,'YES');assert.equal(review.objectiveGates,'PASS');assert.equal(review.thresholdResult,'PASS');assert.deepEqual(review.materialFindings,[]);assert.deepEqual(review.blockingHandoffs,[]);assert(review.reviewer?.identity);assert.equal(review.reviewer.implementationAuthor,false);
 assert.equal(value.rootReplay.passed,true);assert.equal(value.rootReplay.exactCodeAndFreezeVerified,true);assert.equal(value.rootReplay.reviewSha256,sha(Buffer.from(JSON.stringify(review))));assert.equal(value.rootReplay.reviewerIdentity,review.reviewer.identity);return value;
}

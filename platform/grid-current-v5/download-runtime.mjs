// Separate online acquisition stage; public runtime execution runs in a later OS-restricted process.
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {download} from './io.mjs';
import {openQualification,checkArtifactSelection} from './qualification.mjs';
const q=await openQualification('public-download');
try {const spec=q.admission.publicRuntime;assert(spec&&spec.target===q.target);assert(spec.url.startsWith('https://github.com/Mohammed-Moniem/gridcraft/releases/download/'));assert.equal(spec.top,'gridcraft-current-'+q.target);await checkArtifactSelection(q,spec);await q.effectGuard.revalidate();q.result.download=await download(spec,join(q.dir,spec.name));await q.finish();}catch(error){await q.finish(error);}

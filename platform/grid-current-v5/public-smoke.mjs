import {openQualification,extractRuntime,denyForRuntime} from './qualification.mjs';
import {exerciseCli} from './native-smoke.mjs';
import {exerciseGui} from './gui-smoke.mjs';
import {exerciseBrowser} from './browser-smoke.mjs';
const q=await openQualification('public');
try {await denyForRuntime(q);const {root}=await extractRuntime(q,{publicDownload:true});await exerciseCli(q,root);await exerciseGui(q,root);await exerciseBrowser(q,root);q.result.publicArchiveActuallyExecuted=true;q.result.guiVisualReview='PENDING_INDEPENDENT_IMAGE_REVIEW';await q.finish();}catch(error){await q.finish(error);}

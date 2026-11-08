// Shared pure consumer contract. The actual validator and negative controls call these functions.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {win32,posix} from 'node:path';
import {queryLabels,queryArgs,PYTHON_MODULES} from './query-plan.mjs';
import {assertPythonEnvironment} from '../grid-current-v5/python-plan.mjs';
import {assertPythonExecutionClosure} from '../grid-current-v5/host-contract.mjs';
export const OUTPUT_MODE_MEANING='Node file-mode metadata only; Windows read-only bits do not establish Windows ACL permissions. Exact recorded modes are required; extraction normalization requires separate reviewed recapture.';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function outputName(path) {
 assert.equal(typeof path,'string');assert(path.length>0&&path.length<1024&&!/[\\:\x00-\x1f]/.test(path),'Unsafe output path');
 assert(path.split('/').every(part=>part&&part!=='.'&&part!=='..'&&!/[. ]$/.test(part)&&!/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)),'Unsafe output component');return path;
}
const identity=row=>({path:row.path,bytes:row.bytes,sha256:row.sha256,mode:row.mode});
const same=(actual,expected,message)=>assert.deepEqual(identity(actual),identity(expected),message);
export function validateOutputBundle(bundle,expected) {
 const {entries,contents}=bundle;assert(Array.isArray(entries)&&entries.length>0&&entries.length<=4096);assert(contents instanceof Map);
 const files=new Map(),aliases=new Set();let total=0;
 for(const entry of entries){outputName(entry.path);const alias=entry.path.normalize('NFC').toLowerCase();assert(!aliases.has(alias),'Output alias');aliases.add(alias);assert(['file','directory'].includes(entry.type),'Nonregular output');assert(Number.isInteger(entry.mode)&&entry.mode>=0&&entry.mode<=0o777,'Invalid output mode');
  if(entry.type==='directory'){assert(['queries','mappings','temp'].includes(entry.path)||entry.path.startsWith('temp/'),'Unexpected output directory');continue;}
  assert.equal(entry.nlink,1,'Output hard link');assert(Number.isSafeInteger(entry.bytes)&&entry.bytes>=0&&entry.bytes<=8*1024*1024);assert.match(entry.sha256,/^[a-f0-9]{64}$/);total+=entry.bytes;assert(total<=32*1024*1024);
  const raw=contents.get(entry.path);assert(Buffer.isBuffer(raw),'Output bytes missing');assert.equal(raw.length,entry.bytes);assert.equal(sha(raw),entry.sha256,'Output bytes changed');files.set(entry.path,entry);
 }
 assert(files.size<=2048);assert.deepEqual([...contents.keys()].sort(),[...files.keys()].sort(),'Unlisted output byte body');
 const doc=name=>{assert(files.has(name),'Mandatory output absent: '+name);return JSON.parse(contents.get(name).toString('utf8'));};
 const capture=doc('DISCOVERY.json'),result=doc('RESULT.json'),start=doc('START.json'),admission=doc('ADMISSION-CANDIDATE.json'),manifest=doc('OUTPUT-MANIFEST.json');
 const windows=capture.target==='windows-x64',paths=windows?win32:posix;
 for(const entry of entries.filter(row=>row.type==='directory'))assert((windows?[0o555,0o755,0o777]:[0o555,0o755]).includes(entry.mode),'Output directory mode violation');
 assert.equal(capture.kitSha256,expected.kitSha256,'Discovery kit differs');assert.equal(capture.packetSha256,expected.packetSha256,'Discovery packet differs');assert.equal(capture.sourceTree,expected.sourceTree);assert.equal(capture.selected,false);assert.equal(capture.state,'CAPTURED_REQUIRES_REVIEW');assert.deepEqual(capture.missing,[]);
 assert.equal(capture.runtimeStagesAuthorized,false);assert.equal(capture.sdkRedistributed,false);
 assert(paths.isAbsolute(capture.outputDirectory)&&paths.isAbsolute(capture.packetDirectory),'Captured absolute context missing');assert.equal(paths.basename(capture.packetDirectory),'grid-host-discovery-v5','Wrong captured packet directory');
 for(const entry of files.values()){assert(!/(?:^|\/)(?:failure|timeout)\.json$/i.test(entry.path),'Failure or timeout evidence prevents ready state');assert((windows?[0o444,0o644,0o666]:[0o444,0o644]).includes(entry.mode),'Output data mode violation');}
 for(const proof of [start,result]){assert.equal(proof.kitSha256,capture.kitSha256);assert.equal(proof.packetSha256,capture.packetSha256);assert.equal(proof.selected,false);}
 assert.equal(start.target,capture.target);assert.equal(start.sourceTree,capture.sourceTree);assert.equal(start.state,'IN_PROGRESS');assert.equal(result.state,capture.state);assert.equal(result.inputsStable,true);
 for(const key of ['cloudBuildAuthorized','nativeApplicationExecuted','browserExecuted','compilerExecuted','downloads','installs','systemSettingMutationsRequested','fullGoalComplete'])assert.equal(result[key],false,'Discovery result overclaim');
 const receipt=result.discoveryEvidence,discoveryFile=files.get('DISCOVERY.json');same(receipt,{...discoveryFile,path:paths.join(capture.outputDirectory,'DISCOVERY.json')},'Discovery receipt differs');
 assert.equal(admission.selected,false);assert.deepEqual(admission.stages,[]);assert.equal(admission.kitSha256,capture.kitSha256);assert.equal(admission.target,capture.target);assert.deepEqual(admission.discoveryEvidence,receipt);assert.equal(admission.cloudBuildAuthorized,false);assert.equal(admission.runtimeStagesAuthorized,false);
 assert.equal(manifest.schemaVersion,1);assert.equal(manifest.kind,'GRID_DISCOVERY_OUTPUT_INVENTORY');assert.equal(manifest.selected,false);assert.equal(manifest.selfExcluded,'OUTPUT-MANIFEST.json');assert.equal(manifest.modeSemantics,OUTPUT_MODE_MEANING);
 assert(Array.isArray(manifest.files)&&manifest.files.length>0&&manifest.files.length<=2048);const listed=new Map();for(const row of manifest.files){outputName(row.path);assert(!listed.has(row.path),'Duplicate manifest row');assert.notEqual(row.path,'OUTPUT-MANIFEST.json','Self-inclusive output manifest');listed.set(row.path,row);}
 assert.deepEqual([...listed.keys()].sort(),[...files.keys()].filter(path=>path!=='OUTPUT-MANIFEST.json').sort(),'Incomplete or extra output manifest');for(const row of listed.values())same(row,files.get(row.path),'Output manifest identity differs');
 const capturedFiles=new Map();for(const row of capture.inspection.files){const key=windows?row.path.toLowerCase():row.path;assert(!capturedFiles.has(key));capturedFiles.set(key,row);}
 const captured=row=>{assert(row&&row.path);same(row,capturedFiles.get(windows?row.path.toLowerCase():row.path),'Referenced actual input is missing or changed');};
 const labels=queryLabels(capture.target),required=new Set(['START.json','DISCOVERY.json','RESULT.json','ADMISSION-CANDIDATE.json','OUTPUT-MANIFEST.json']);
 assert.deepEqual(capture.tools.python.query.modules,PYTHON_MODULES,'Archive stdlib query module set differs');
 assertPythonExecutionClosure(capture.tools.python,capture.inspection.files);
 assert.deepEqual(Object.keys(capture.queryPrograms).sort(),[...labels].sort(),'Query program identity set differs');assertPythonEnvironment(capture.queryEnvironment);
 assert.equal(capture.inspection.commands,labels.length,'Captured query count differs');assert.equal(result.commands,labels.length,'Final query count differs');assert.equal(result.inspectionFinal.commands,labels.length);assert.deepEqual(result.inspectionFinal.files,capture.inspection.files,'Final input set differs');
 assert(Number.isSafeInteger(result.inspectionFinal.bytesRead)&&result.inspectionFinal.bytesRead>=capture.inspection.bytesRead&&result.inspectionFinal.bytesRead<=2*1024**3,'Final input read budget differs');
 for(const [index,label]of labels.entries()){
  const name='queries/'+String(index+1).padStart(2,'0')+'-'+label+'.json';required.add(name);const query=doc(name);assert.equal(query.label,label);same(query.program,capture.queryPrograms[label],'Query program differs');captured(query.program);assert.deepEqual(query.args,queryArgs(capture.target,label,capture.packetDirectory),'Query arguments differ');assert.equal(query.cwd,capture.outputDirectory);assert.deepEqual(query.environment,capture.queryEnvironment,'Query environment differs');assert.equal(query.code,0,'Failed query');assert.equal(query.signal,null);assert.equal(query.error,null);assert.equal(query.timedOut,false,'Timed out query');assert.equal(query.overflow,false);assert.equal(typeof query.stdout,'string');assert.equal(typeof query.stderr,'string');assert(Buffer.byteLength(query.stdout)+Buffer.byteLength(query.stderr)<=2*1024*1024);
  if(label==='python-isolated-stdlib'){const data=JSON.parse(query.stdout);assert.equal(data.pycachePrefix,null);assert.equal(capture.tools.python.query.pycachePrefix,data.pycachePrefix);for(const key of ['moduleLoaders','cacheCandidates','supportCandidates','searchDirectoryCandidates','runtimeRootCandidates','importSearchCandidates'])assert.deepEqual(data[key],capture.tools.python.query[key],'Python loader/cache/complete namespace query differs');}
  if(label==='python-isolated-stdlib'){same(query.program,capture.tools.python);const data=JSON.parse(query.stdout);assert.equal(data.executable,capture.tools.python.path);assert.equal(data.version,capture.tools.python.version);assert.deepEqual(data.modules,capture.tools.python.query.modules);for(const key of ['isolated','noSite','bytecodeWritesDisabled']){assert.equal(data[key],true);assert.equal(capture.tools.python.query[key],data[key]);}assert.equal(data.pointerBits,64);assert.deepEqual([...data.loadedFiles].sort(),capture.tools.python.query.loadedFiles.map(row=>row.locator??row.path).sort(),'Python loaded-file evidence differs');}
  if(label==='mac-developer-path'){assert.equal(query.program.path,'/usr/bin/xcode-select');assert.equal(query.stdout.trim(),capture.sdk.developerDirectory);}
  if(label==='mac-os-version'){assert.equal(query.program.path,'/usr/bin/sw_vers');assert.equal(query.stdout,capture.host.apple.raw);}
  if(label==='windows-host-registry'){same(query.program,capture.tools.powershell);const data=JSON.parse(query.stdout.replace(/^\uFEFF/,''));assert.equal(data.schemaVersion,1);assert.equal(data.settingsChanged,false);assert.equal(data.windows11Qualified,false);assert.deepEqual(data.errors,[]);assert.deepEqual(data.os,capture.host.windows);assert.equal(paths.normalize(data.kitsRoot10).toLowerCase(),paths.normalize(capture.sdk.sdkRoot).toLowerCase());}
  if(label==='vswhere-supported-installations'){const rows=JSON.parse(query.stdout).filter(row=>row.isComplete===true&&row.isLaunchable===true&&/^17\./.test(row.installationVersion));assert.equal(rows.length,1);for(const key of ['installationPath','installationVersion','instanceId'])assert.equal(rows[0][key],capture.sdk.visualStudio[key]);}
 }
 if(windows){
  const descriptor=capture.windowsDependencyCapture.candidate,name='WINDOWS-SYSTEM-MODULES-CANDIDATE.json';required.add(name);same(descriptor,{...files.get(name),path:paths.join(capture.outputDirectory,name)},'Windows candidate receipt differs');const candidate=doc(name);
  assert.equal(candidate.kind,'WINDOWS_TARGET_SYSTEM_MODULE_CONTRACT');assert.equal(candidate.selected,false);assert.equal(candidate.osRelease,capture.host.release);assert.deepEqual(candidate.missing,[]);assert.deepEqual(capture.windowsDependencyCapture.missing,[]);assert.deepEqual(candidate.nativeCoverage,capture.windowsDependencyCapture.nativeCoverage);
  assert.equal(candidate.capturedInputsNormalAndDelayImportsParsed,true);for(const key of ['exportForwarderAndDynamicModuleClosureQualified','optionalRuntimeLoadedModulesQualified','windows11Qualified'])assert.equal(candidate[key],false);
  assert(['UNAVAILABLE_UNTIL_EXACT_CURRENT_ARTIFACT_EXISTS','ACTUAL_BYTES_CAPTURED_NOT_SELECTED'].includes(candidate.nativeCoverage.state));for(const file of candidate.nativeCoverage.files)captured(file);
  assert(candidate.inputs.length>0&&candidate.inputs.length<=256);const inputNames=new Set();for(const input of candidate.inputs){captured(input.file);assert(!inputNames.has(input.file.path.toLowerCase()));inputNames.add(input.file.path.toLowerCase());for(const names of [input.imports,input.delayImports])assert(Array.isArray(names)&&names.length<=256&&names.every(name=>/^[a-z0-9_.-]+\.(?:dll|drv)$/i.test(name)));}
  for(const tool of Object.values(capture.tools).filter(tool=>tool?.path))assert(inputNames.has(tool.path.toLowerCase()),'Windows captured tool import evidence missing');
  for(const file of [...capture.tools.python.query.loadedFiles,...capture.tools.python.query.supportFiles])if(/\.(?:exe|dll|pyd)$/i.test(file.path))assert(inputNames.has(file.path.toLowerCase()),'Python executable loader/support PE evidence missing');
  const modules=new Map();assert(candidate.entries.length<=256);for(const entry of candidate.entries){assert.match(entry.name,/^[a-z0-9_.-]+\.(?:dll|drv)$/);assert(!modules.has(entry.name));modules.set(entry.name,entry);
   if(entry.kind==='system-file'){captured(entry.file);assert.equal(paths.basename(entry.file.path).toLowerCase(),entry.name);}
   else {assert.equal(entry.kind,'api-set');assert.equal(entry.mappingIndependentlyReviewed,false);captured(entry.schema);assert(entry.hostFiles.length>0);for(const file of entry.hostFiles)captured(file);const mappingName='mappings/'+entry.name+'.json';required.add(mappingName);same(entry.mappingEvidence,{...files.get(mappingName),path:paths.join(capture.outputDirectory,...mappingName.split('/'))},'API-set mapping receipt differs');const mapping=doc(mappingName);assert.equal(mapping.name,entry.name);assert.equal(mapping.schemaSha256,entry.schema.sha256);assert.equal(mapping.namespaceVersion,6);assert.equal(mapping.selection,'UNSELECTED_ALL_CAPTURED_HOSTS');assert.equal(mapping.optionalCapabilityAvailable,'NOT_PROVEN');assert.deepEqual([...mapping.hostNames].sort(),entry.hostFiles.map(file=>paths.basename(file.path).toLowerCase()).sort());assert(mapping.rawValues.length>0&&mapping.rawValues.every(row=>typeof row.alias==='string'&&row.host));assert.deepEqual([...new Set(mapping.rawValues.map(row=>row.host))].sort(),[...mapping.hostNames].sort());}
  }
  for(const input of candidate.inputs)for(const name of [...input.imports,...input.delayImports].map(name=>name.toLowerCase()))assert(modules.has(name)||candidate.inputs.some(other=>paths.dirname(other.file.path).toLowerCase()===paths.dirname(input.file.path).toLowerCase()&&paths.basename(other.file.path).toLowerCase()===name),'Unbound normal or delay import');
 }else assert.equal(capture.windowsDependencyCapture,undefined);
 for(const name of files.keys())assert(required.has(name)||name.startsWith('temp/'),'Unexpected discovery output file: '+name);
 return {capture,result,admission,receipt,queryCount:labels.length,files:files.size};
}

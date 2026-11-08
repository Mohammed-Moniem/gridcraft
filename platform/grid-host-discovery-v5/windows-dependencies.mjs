// Read actual PE bytes and the actual OS schema; never load a DLL or execute a PE input.
import assert from 'node:assert/strict';
import {lstat} from 'node:fs/promises';
import {join,dirname,basename} from 'node:path';
import {inspectPEBytes,parseApiSetSchemaPE} from './pe.mjs';
import {LIMITS,SOURCE_TREE,SOURCE_SHA,sha} from './model.mjs';
import {save,within} from './probe-support.mjs';

export async function windowsDependencies(p,capture,launch,out) {
 const system32=join(capture.environment.SystemRoot,'System32'),schema=await p.identity(join(system32,'apisetschema.dll'),[system32]),namespace=parseApiSetSchemaPE(await p.readBytes(schema.path,[system32]));
 const seeds=Object.entries(capture.tools).filter(([,tool])=>tool?.path).map(([role,tool])=>({role,path:tool.path,roots:[dirname(tool.path),system32],depth:0}));for(const file of [...capture.tools.python.query.loadedFiles,...capture.tools.python.query.supportFiles])if(/\.(?:exe|dll|pyd)$/i.test(file.path))seeds.push({role:'python-executable-loader-support',path:file.path,roots:[dirname(file.path),system32],depth:0});
 let nativeCoverage={state:'UNAVAILABLE_UNTIL_EXACT_CURRENT_ARTIFACT_EXISTS',files:[]};
 if(launch.nativeInput){const input=launch.nativeInput;assert(input.target==='windows-x64');const raw=await p.readBytes(input.manifest.path,[input.root]);assert.equal(raw.length,input.manifest.bytes);assert.equal(sha(raw),input.manifest.sha256);const manifest=JSON.parse(raw);assert.equal(manifest.kind,'CURRENT_GRID_RUNTIME_CANDIDATE');assert.equal(manifest.target,'windows-x64');assert.equal(manifest.sourceTree,SOURCE_TREE);assert.equal(manifest.sourceArchiveSha256,SOURCE_SHA);const current=[];for(const name of ['gridcraft-cli.exe','gridcraft.exe']){const member=manifest.files.filter(row=>row.path==='bin/'+name);assert.equal(member.length,1);const file=await p.identity(join(input.root,'bin',name),[input.root]);assert.equal(file.bytes,member[0].bytes);assert.equal(file.sha256,member[0].sha256);current.push(file);seeds.push({role:name,path:file.path,roots:[dirname(file.path),system32],depth:0});}nativeCoverage={state:'ACTUAL_BYTES_CAPTURED_NOT_SELECTED',manifest:input.manifest,files:current};}
 const queue=[...seeds],visited=new Set(),entries=new Map(),inputs=[],missing=[];
 while(queue.length){p.budget();const next=queue.shift();assert(next.depth<=LIMITS.maxImportDepth,'Import depth limit reached');const id=await p.identity(next.path,next.roots);if(visited.has(id.path.toLowerCase()))continue;assert(visited.size<LIMITS.maxImportModules,'Import module count limit reached');visited.add(id.path.toLowerCase());const pe=inspectPEBytes(await p.readBytes(id.path,next.roots));assert.equal(pe.machine,'x64','Wrong PE architecture');inputs.push({role:next.role,file:id,imports:pe.imports,delayImports:pe.delayImports});
  for(const name of [...new Set([...pe.imports,...pe.delayImports].map(s=>s.toLowerCase()))]){
   if(/^(api|ext)-/.test(name)){
    const mapping=namespace.get(name);if(!mapping){missing.push({code:'API_SET_NOT_IN_ACTUAL_SCHEMA',module:name,importer:id.path});continue;}
    const hosts=[...new Set(mapping.values.map(value=>value.host).filter(Boolean))];if(!hosts.length||mapping.values.some(value=>!value.host)){missing.push({code:'API_SET_STUB_OR_EMPTY_HOST',module:name,importer:id.path});continue;}
    const hostFiles=[];for(const host of hosts){try{const file=await p.identity(join(system32,host),[system32]);hostFiles.push(file);queue.push({role:'system-api-host',path:file.path,roots:[system32],depth:next.depth+1});}catch(error){if(error.code!=='ENOENT')throw error;missing.push({code:'API_SET_HOST_FILE_MISSING',module:name,host});}}
    const path=join(out,'mappings',name+'.json');const evidence={name,schemaSha256:schema.sha256,hostNames:hosts,namespaceVersion:6,rawValues:mapping.values,selection:'UNSELECTED_ALL_CAPTURED_HOSTS',optionalCapabilityAvailable:'NOT_PROVEN'};
    if(!entries.has(name)){await save(path,evidence);const raw=Buffer.from(JSON.stringify(evidence,null,2)+'\n');entries.set(name,{name,kind:'api-set',schema,hostFiles,mappingEvidence:{path,bytes:raw.length,sha256:sha(raw),mode:(await lstat(path)).mode&0o777},mappingIndependentlyReviewed:false});}
   }else{
    let dependency;try{dependency=await p.identity(join(dirname(id.path),name),next.roots);}catch(error){if(error.code!=='ENOENT')throw error;try{dependency=await p.identity(join(system32,name),[system32]);}catch(e){if(e.code!=='ENOENT')throw e;missing.push({code:'UNRESOLVED_NORMAL_OR_DELAY_IMPORT',module:name,importer:id.path});continue;}}
    if(within(system32,dependency.path)){if(!entries.has(name))entries.set(name,{name,kind:'system-file',file:dependency});}
    queue.push({role:'actual-normal-or-delay-dependency',path:dependency.path,roots:next.roots.includes(system32)?[dirname(dependency.path),system32]:next.roots,depth:next.depth+1});
   }
  }
 }
 const candidate={kind:'WINDOWS_TARGET_SYSTEM_MODULE_CONTRACT',selected:false,osRelease:capture.host.release,entries:[...entries.values()].sort((a,b)=>a.name<b.name?-1:1),nativeCoverage,inputs,missing,capturedInputsNormalAndDelayImportsParsed:true,exportForwarderAndDynamicModuleClosureQualified:false,optionalRuntimeLoadedModulesQualified:false,windows11Qualified:false};const candidatePath=join(out,'WINDOWS-SYSTEM-MODULES-CANDIDATE.json');await save(candidatePath,candidate);capture.windowsDependencyCapture={candidate:{path:candidatePath,bytes:Buffer.byteLength(JSON.stringify(candidate,null,2)+'\n'),sha256:sha(JSON.stringify(candidate,null,2)+'\n'),mode:(await lstat(candidatePath)).mode&0o777},nativeCoverage,missing};capture.missing.push(...missing);return candidate;
}

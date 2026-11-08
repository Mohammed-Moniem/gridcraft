// Pure schema/replay for the shared bounded acquisition. No filesystem or host effects.
import assert from 'node:assert/strict';
import {posix,win32} from 'node:path';
export const PYTHON_NAMESPACE_POLICY='COMPLETE_ISOLATED_RUNTIME_AND_SEARCH_NAMESPACES_V3';
export const PYTHON_NAMESPACE_LIMITS=Object.freeze({files:32768,directories:8192,entries:65536,links:2048,depth:40,fileBytes:256*1024**2,totalBytes:1024**3,wallMs:120000,resolutions:4096,resolutionSteps:1048576,resolutionPathSteps:256,resolutionHops:40});
export const pythonPaths=value=>/^[a-z]:[\\/]/i.test(value)?win32:posix;
const order=(a,b)=>a<b?-1:a>b?1:0;
const exactKeys=(value,keys)=>assert.deepEqual(Object.keys(value).sort(),keys.sort());
export function assertPythonAbsolutePath(value,{normalized=true}={}){
 assert.equal(typeof value,'string');assert(value.length>0&&value.length<=4096&&!/[\x00-\x1f]/.test(value));
 const paths=pythonPaths(value);assert(paths.isAbsolute(value),'Relative Python lookup rejected');
 if(normalized)assert.equal(paths.resolve(value),value,'Noncanonical Python lookup rejected');return paths;
}
export function pythonPathWithin(base,value){const paths=pythonPaths(base),fold=text=>paths===win32?text.toLowerCase():text;return pythonPaths(value)===paths&&(fold(value)===fold(base)||fold(value).startsWith(fold(base)+paths.sep));}
export function assertPythonNamespaceDescription(value){
 assert(value&&typeof value==='object'&&!Array.isArray(value));exactKeys(value,['optionalFiles','requiredFiles','runtimeRoots','searchPaths']);
 for(const key of Object.keys(value)){assert(Array.isArray(value[key])&&value[key].length<=512);assert.equal(new Set(value[key]).size,value[key].length);for(const path of value[key])assertPythonAbsolutePath(path);}
 assert(value.runtimeRoots.length>0&&value.runtimeRoots.length<=8);assert(value.searchPaths.length>0&&value.searchPaths.length<=32);assert(value.requiredFiles.length>0);
 for(const path of value.runtimeRoots)assert.notEqual(path,pythonPaths(path).parse(path).root,'Filesystem-root runtime prefix rejected');return value;
}
function stepIdentity(value,link=false){
 assert(value&&typeof value==='object');exactKeys(value,link?['dev','ino','mode','size','mtimeNs','ctimeNs','nlink']:['dev','ino','mode']);
 for(const key of link?['dev','ino','size','mtimeNs','ctimeNs','nlink']:['dev','ino'])assert.match(value[key]??'',/^[0-9]+$/);
 assert(Number.isInteger(value.mode)&&value.mode>=0&&value.mode<=0o777);
}
// Reconstruct every followed ancestor and raw link expansion from the evidence itself.
// A missing component is a terminal lookup failure even if later raw components contain '..'.
export function assertPythonResolution(value,allowedRoots){
 const paths=assertPythonAbsolutePath(value?.locator),bounded=path=>assert(allowedRoots.some(base=>pythonPathWithin(base,path)),'Python resolution outside reviewed roots');
 assert(['file','directory','absent'].includes(value.kind));assertPythonAbsolutePath(value.path);bounded(value.locator);bounded(value.path);
 exactKeys(value,value.kind==='absent'?['locator','kind','path','steps','missingPath','remaining']:['locator','kind','path','steps']);
 assert(Array.isArray(value.steps)&&value.steps.length>0&&value.steps.length<=PYTHON_NAMESPACE_LIMITS.resolutionPathSteps);
 let current=paths.parse(value.locator).root,pending=value.locator.slice(current.length).split(paths===win32?/[\\/]/:/\//),index=0,hops=0,kind='directory',missing=null;
 const take=(path,root=false)=>{const row=value.steps[index++];assert(row&&row.path===path,'Unreplayed Python resolution step');assertPythonAbsolutePath(row.path);assert(['directory','file','symlink','absent'].includes(row.kind));if(root)assert.equal(row.kind,'directory');if(row.kind==='absent')exactKeys(row,['path','kind']);else if(row.kind==='symlink'){exactKeys(row,['path','kind','identity','link']);assert(typeof row.link==='string'&&row.link.length>0&&row.link.length<=4096&&!/[\x00-\x1f]/.test(row.link));stepIdentity(row.identity,true);}else{exactKeys(row,['path','kind','identity']);stepIdentity(row.identity);}return row;};
 take(current,true);
 while(pending.length){const part=pending.shift();if(!part||part==='.')continue;if(part==='..'){current=paths.dirname(current);kind='directory';continue;}
  assert(!/[\\/\x00-\x1f]/.test(part));const child=paths.join(current,part),row=take(child);
  if(row.kind==='symlink'){
   bounded(child);assert(++hops<=PYTHON_NAMESPACE_LIMITS.resolutionHops,'Python alias hop budget');const link=row.link;
   if(paths.isAbsolute(link)){assert.equal(pythonPaths(link),paths,'Unsupported cross-style Python alias');current=paths.parse(link).root;pending=link.slice(current.length).split(paths===win32?/[\\/]/:/\//).concat(pending);take(current,true);}
   else pending=link.split(paths===win32?/[\\/]/:/\//).concat(pending);
   bounded(paths.resolve(current,...pending));kind='directory';continue;
  }
  if(row.kind==='absent'){bounded(child);missing={path:child,remaining:[...pending]};current=paths.resolve(child,...pending);kind='absent';break;}
  current=child;kind=row.kind;if(kind==='file')assert.equal(pending.length,0,'Python lookup traverses a regular file');
 }
 assert.equal(index,value.steps.length,'Unused Python resolution evidence');assert.equal(value.kind,kind);assert.equal(value.path,current);
 if(missing){assert.equal(value.missingPath,missing.path);assert.deepEqual(value.remaining,missing.remaining);}else assert.notEqual(value.kind,'absent');return value;
}
const identity=row=>{assert(row&&typeof row.path==='string');assertPythonAbsolutePath(row.path);assert(Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=PYTHON_NAMESPACE_LIMITS.fileBytes);assert.match(row.sha256??'',/^[a-f0-9]{64}$/);assert(Number.isInteger(row.mode)&&row.mode>=0&&row.mode<=0o777);};
export function assertPythonNamespaceCapture(value,inventory){
 assert.equal(value?.policy,PYTHON_NAMESPACE_POLICY);assert.equal(value.complete,true);assert.deepEqual(value.limits,PYTHON_NAMESPACE_LIMITS);assertPythonNamespaceDescription(value.description);
 assert(Array.isArray(value.allowedRoots)&&value.allowedRoots.length>0&&value.allowedRoots.length<=32);for(const path of value.allowedRoots)assertPythonAbsolutePath(path);
 assert.equal(new Set(value.allowedRoots.map(path=>pythonPaths(path)===win32?path.toLowerCase():path)).size,value.allowedRoots.length);
 const bounded=path=>assert(value.allowedRoots.some(base=>pythonPathWithin(base,path)),'Captured Python target outside reviewed roots');
 for(const [key,max]of [['files',PYTHON_NAMESPACE_LIMITS.files],['directories',PYTHON_NAMESPACE_LIMITS.directories],['links',PYTHON_NAMESPACE_LIMITS.links],['resolutions',PYTHON_NAMESPACE_LIMITS.resolutions],['lookups',2048],['absentFiles',1024]])assert(Array.isArray(value[key])&&value[key].length<=max);
 const files=new Map(),directories=new Map(),links=new Map(),resolutions=new Map();let bytes=0,entries=0,steps=0;
 for(const row of value.files){identity(row);bounded(row.path);assert(!files.has(row.path));files.set(row.path,row);bytes+=row.bytes;}assert(bytes<=PYTHON_NAMESPACE_LIMITS.totalBytes);
 for(const row of value.directories){assertPythonAbsolutePath(row.path);bounded(row.path);assert(!directories.has(row.path));assert(Number.isInteger(row.mode)&&row.mode>=0&&row.mode<=0o777);assert(Array.isArray(row.entries));entries+=row.entries.length;assert(entries<=PYTHON_NAMESPACE_LIMITS.entries);const names=new Set();for(const entry of row.entries){assert(entry.name&&!/[\\/\x00-\x1f]/.test(entry.name));const alias=entry.name.normalize('NFC').toLowerCase();assert(!names.has(alias),'Namespace case/Unicode alias');names.add(alias);assert(['file','directory','symlink'].includes(entry.type));}directories.set(row.path,row);}
 for(const row of value.resolutions){assertPythonResolution(row,value.allowedRoots);assert(!resolutions.has(row.locator));resolutions.set(row.locator,row);steps+=row.steps.length;assert(steps<=PYTHON_NAMESPACE_LIMITS.resolutionSteps);if(row.kind!=='absent')assert((row.kind==='file'?files:directories).has(row.path),'Resolved namespace body omitted');}
 for(const row of value.links){assertPythonAbsolutePath(row.path);bounded(row.path);assert(!links.has(row.path));assert(typeof row.link==='string'&&row.link.length>0&&row.link.length<=4096);assert(['file','directory','absent'].includes(row.kind));const resolution=resolutions.get(row.path);assert(resolution,'Alias resolution evidence omitted');assert.equal(resolution.kind,row.kind);assert.equal(resolution.path,row.resolved);assert(resolution.steps.some(step=>step.path===row.path&&step.kind==='symlink'&&step.link===row.link),'Raw alias evidence omitted');if(row.kind!=='absent')assert((row.kind==='file'?files:directories).has(row.resolved),'Alias target not captured');links.set(row.path,row);}
 for(const directory of value.directories)for(const entry of directory.entries){const path=pythonPaths(directory.path).join(directory.path,entry.name);assert((entry.type==='file'?files:entry.type==='directory'?directories:links).has(path),'Recursive namespace member body omitted');if(entry.type==='symlink')assert.equal(links.get(path).link,entry.link);}
 assert.equal(new Set(value.absentFiles).size,value.absentFiles.length);const expected=[];for(const role of ['runtimeRoots','searchPaths','requiredFiles','optionalFiles'])value.description[role].forEach((locator,index)=>expected.push({role,index,locator}));assert.equal(value.lookups.length,expected.length);
 for(let index=0;index<expected.length;index++){const row=value.lookups[index];for(const key of ['role','index','locator'])assert.equal(row[key],expected[index][key]);assert(['file','directory','absent'].includes(row.kind));const resolution=resolutions.get(row.locator);assert(resolution,'Lookup resolution evidence omitted');assert.equal(resolution.kind,row.kind);if(row.kind==='absent'){assert(['searchPaths','optionalFiles'].includes(row.role));assert(value.absentFiles.includes(row.locator));}else{assert.equal(resolution.path,row.path);assert((row.kind==='file'?files:directories).has(row.path),'Lookup target omitted');if(row.role==='runtimeRoots')assert.equal(row.kind,'directory');if(row.role==='requiredFiles'||row.role==='optionalFiles')assert.equal(row.kind,'file');if(row.role==='searchPaths'&&row.kind==='file')assert(/\.zip$/i.test(row.locator),'Unsupported non-directory Python search input');}}
 assert.deepEqual([...value.absentFiles].sort(order),value.lookups.filter(row=>row.kind==='absent').map(row=>row.locator).filter((path,index,all)=>all.indexOf(path)===index).sort(order));
 assert.deepEqual([...resolutions.keys()].sort(order),[...new Set([...value.lookups.map(row=>row.locator),...links.keys()])].sort(order),'Unreferenced or missing Python resolution');
 if(inventory){const recorded=new Map(inventory.map(row=>[row.path,row]));for(const row of value.files){const found=recorded.get(row.path);assert(found,'Complete Python namespace body absent from capture inventory');for(const key of ['path','bytes','sha256','mode'])assert.equal(found[key],row[key]);}}
 return value;
}
export function assertPythonNamespaceObservation(expected,observed){assertPythonNamespaceCapture(expected);assertPythonNamespaceCapture(observed);assert.deepEqual(observed,expected,'Python runtime/search namespace, executable/cache/support body, alias, ancestor resolution or absence changed');return true;}

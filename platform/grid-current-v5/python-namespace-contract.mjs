// Pure schema for the actual shared bounded filesystem acquisition; no filesystem or host effects.
import assert from 'node:assert/strict';
import {posix,win32} from 'node:path';
export const PYTHON_NAMESPACE_POLICY='COMPLETE_ISOLATED_RUNTIME_AND_SEARCH_NAMESPACES_V2';
export const PYTHON_NAMESPACE_LIMITS=Object.freeze({files:32768,directories:8192,entries:65536,links:2048,depth:40,fileBytes:256*1024**2,totalBytes:1024**3,wallMs:120000});
export const pythonPaths=value=>/^[a-z]:[\\/]/i.test(value)?win32:posix;
export function assertPythonNamespaceDescription(value){
 assert(value&&typeof value==='object'&&!Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),['optionalFiles','requiredFiles','runtimeRoots','searchPaths'].sort());
 for(const key of Object.keys(value)){assert(Array.isArray(value[key])&&value[key].length<=512);assert.equal(new Set(value[key]).size,value[key].length);for(const path of value[key]){assert.equal(typeof path,'string');assert(path.length>0&&path.length<=4096&&!/[\x00-\x1f]/.test(path));assert(pythonPaths(path).isAbsolute(path),'Relative Python lookup rejected');}}
 assert(value.runtimeRoots.length>0&&value.runtimeRoots.length<=8);assert(value.searchPaths.length>0&&value.searchPaths.length<=32);assert(value.requiredFiles.length>0);
 for(const path of value.runtimeRoots)assert.notEqual(pythonPaths(path).normalize(path),pythonPaths(path).parse(path).root,'Filesystem-root runtime prefix rejected');return value;
}
const identity=row=>{assert(row&&typeof row.path==='string');assert(pythonPaths(row.path).isAbsolute(row.path));assert(Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=PYTHON_NAMESPACE_LIMITS.fileBytes);assert.match(row.sha256??'',/^[a-f0-9]{64}$/);assert(Number.isInteger(row.mode)&&row.mode>=0&&row.mode<=0o777);};
export function assertPythonNamespaceCapture(value,inventory){
 assert.equal(value?.policy,PYTHON_NAMESPACE_POLICY);assert.equal(value.complete,true);assert.deepEqual(value.limits,PYTHON_NAMESPACE_LIMITS);assertPythonNamespaceDescription(value.description);
 assert(Array.isArray(value.allowedRoots)&&value.allowedRoots.length>0&&value.allowedRoots.length<=32);for(const path of value.allowedRoots)assert(pythonPaths(path).isAbsolute(path));
 const bounded=path=>assert(value.allowedRoots.some(base=>{const paths=pythonPaths(base),fold=text=>paths===win32?text.toLowerCase():text;return fold(path)===fold(base)||fold(path).startsWith(fold(base)+paths.sep); }),'Captured Python target outside reviewed roots');
 for(const [key,max]of [['files',PYTHON_NAMESPACE_LIMITS.files],['directories',PYTHON_NAMESPACE_LIMITS.directories],['links',PYTHON_NAMESPACE_LIMITS.links],['lookups',2048],['absentFiles',1024]])assert(Array.isArray(value[key])&&value[key].length<=max);
 const files=new Map(),directories=new Map(),links=new Map();let bytes=0,entries=0;
 for(const row of value.files){identity(row);bounded(row.path);assert(!files.has(row.path));files.set(row.path,row);bytes+=row.bytes;}assert(bytes<=PYTHON_NAMESPACE_LIMITS.totalBytes);
 for(const row of value.directories){assert(pythonPaths(row.path).isAbsolute(row.path));bounded(row.path);assert(!directories.has(row.path));assert(Number.isInteger(row.mode)&&row.mode>=0&&row.mode<=0o777);assert(Array.isArray(row.entries));entries+=row.entries.length;assert(entries<=PYTHON_NAMESPACE_LIMITS.entries);const names=new Set();for(const entry of row.entries){assert(entry.name&&!/[\\/\x00-\x1f]/.test(entry.name));const alias=entry.name.normalize('NFC').toLowerCase();assert(!names.has(alias),'Namespace case/Unicode alias');names.add(alias);assert(['file','directory','symlink'].includes(entry.type));}directories.set(row.path,row);}
 for(const row of value.links){assert(!links.has(row.path));assert(typeof row.link==='string'&&row.link);assert(['file','directory'].includes(row.kind));assert((row.kind==='file'?files:directories).has(row.resolved),'Alias target not captured');links.set(row.path,row);}
 for(const directory of value.directories)for(const entry of directory.entries){const path=pythonPaths(directory.path).join(directory.path,entry.name);assert((entry.type==='file'?files:entry.type==='directory'?directories:links).has(path),'Recursive namespace member body omitted');if(entry.type==='symlink')assert.equal(links.get(path).link,entry.link);}
 assert.equal(new Set(value.absentFiles).size,value.absentFiles.length);const expected=[];for(const role of ['runtimeRoots','searchPaths','requiredFiles','optionalFiles'])value.description[role].forEach((locator,index)=>expected.push({role,index,locator}));assert.equal(value.lookups.length,expected.length);
 for(let index=0;index<expected.length;index++){const row=value.lookups[index];for(const key of ['role','index','locator'])assert.equal(row[key],expected[index][key]);assert(['file','directory','absent'].includes(row.kind));if(row.kind==='absent'){assert(['searchPaths','optionalFiles'].includes(row.role));assert(value.absentFiles.includes(row.locator));}else{assert((row.kind==='file'?files:directories).has(row.path),'Lookup target omitted');if(row.role==='runtimeRoots')assert.equal(row.kind,'directory');if(row.role==='requiredFiles'||row.role==='optionalFiles')assert.equal(row.kind,'file');if(row.role==='searchPaths'&&row.kind==='file')assert(/\.zip$/i.test(row.locator),'Unsupported non-directory Python search input');}}
 assert.deepEqual([...value.absentFiles].sort(),value.lookups.filter(row=>row.kind==='absent').map(row=>row.locator).filter((path,index,all)=>all.indexOf(path)===index).sort());
 if(inventory){const recorded=new Map(inventory.map(row=>[row.path,row]));for(const row of value.files){const found=recorded.get(row.path);assert(found,'Complete Python namespace body absent from capture inventory');for(const key of ['path','bytes','sha256','mode'])assert.equal(found[key],row[key]);}}
 return value;
}
export function assertPythonNamespaceObservation(expected,observed){assertPythonNamespaceCapture(expected);assertPythonNamespaceCapture(observed);assert.deepEqual(observed,expected,'Python runtime/search namespace, executable/cache/support body, alias or absence changed');return true;}

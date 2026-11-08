// Derived from the selected current CLI smoke; no historical module is imported.
import assert from 'node:assert/strict';
import {readFile,writeFile,lstat,readlink,symlink,unlink,chmod} from 'node:fs/promises';
import {join,resolve,basename,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {sha} from './core.mjs';
import {checkIdentity,json,receiptProof} from './io.mjs';
import {inspectPEBytes,assertStaticCRT,bindWindowsImports} from './pe.mjs';
import {openQualification,extractRuntime,denyForRuntime} from './qualification.mjs';

export async function exerciseCli(q,root) {
 const {dir,target,result,run,admission}=q,exe=target==='windows-x64'?'.exe':'',binary=join(root,'bin','gridcraft-cli'+exe),app=target==='windows-x64'?join(root,'bin','gridcraft.exe'):join(root,'GridCraft.app','Contents','MacOS','GridCraft');
 result.dependencies=[];
 let systemContract;
 if(target==='windows-x64'){assert(admission.windowsDependencies,'Missing independently selected Windows target-system module contract');systemContract=await receiptProof(q.here,admission.windowsDependencies);}
 for(const path of [binary,app]) {
  const raw=await readFile(path);
  if(target==='windows-x64') {
   const pe=inspectPEBytes(raw);assertStaticCRT(pe);const manifest=await json(join(root,'MANIFEST.json')),bindings=bindWindowsImports(pe,manifest.files,systemContract,result.host.release);
   const systemRoot=resolve(envSystemRoot(q),'System32')+sep;
   for(const binding of bindings){if(binding.source==='shipped-sibling')await checkIdentity(join(root,binding.file.path),binding.file);else {const entry=binding.entry,files=entry.kind==='system-file'?[entry.file]:[entry.schema,...entry.hostFiles];for(const file of files){assert(resolve(file.path).toLowerCase().startsWith(systemRoot.toLowerCase()),'Module outside scoped system directory');await checkIdentity(file.path,file);}if(entry.kind==='system-file')assert.equal(basename(entry.file.path).toLowerCase(),binding.name);else {const mapping=await receiptProof(q.here,entry.mappingEvidence);assert.equal(mapping.name,binding.name);assert.equal(mapping.schemaSha256,entry.schema.sha256);assert.deepEqual(mapping.hostNames.map(s=>s.toLowerCase()).sort(),entry.hostFiles.map(f=>basename(f.path).toLowerCase()).sort());}}}
   result.dependencies.push({path,...pe,bindings,scope:'All normal/delay imports bound to shipped siblings or this exact independently selected OS module/API-set contract; optional runtime-loaded modules remain outside this static closure'});
  }
  else {assert.equal(raw.readUInt32LE(0),0xfeedfacf);assert.equal(raw.readUInt32LE(4),target==='macos-arm64'?0x0100000c:0x01000007);assert(admission.tools.otool,'Pinned system otool required');await checkIdentity(admission.tools.otool.path,admission.tools.otool);const links=await run('dynamic-links-'+(path===binary?'cli':'app'),admission.tools.otool.path,['-L',path]);const libraries=links.stdout.split('\n').slice(1).filter(l=>l.trim()).map(l=>l.trim().split(' (')[0]);assert(libraries.length>0);for(const p of libraries)assert(p.startsWith('/System/Library/')||p.startsWith('/usr/lib/'),'Unbundled dynamic dependency '+p);result.dependencies.push({path,libraries});}
 }
 const cell=(address,input)=>'cell.set='+JSON.stringify({cell:address,input});
 const book=join(dir,'original Ω 日本語.xlsx'),edited=join(dir,'edited Ω 日本語.xlsx');
 const version=await run('01-version',binary,['--version']);assert.match(version.stdout,/^gridcraft-cli \d+\.\d+\.\d+/);
 await run('02-create-xlsx',binary,['run','--cmd',cell('A1','Label Ω'),'--cmd',cell('B1','Value'),'--cmd',cell('A2','مرحبا 日本語'),'--cmd',cell('B2','7'),'--cmd',cell('C2','=B2*3'),'--out',book,'--quiet']);assert.equal((await readFile(book)).subarray(0,2).toString(),'PK');
 const info=JSON.parse((await run('03-reopen-info',binary,['info',book,'--json'])).stdout);assert.equal(info.sheets.length,1);assert.equal(info.sheets[0].cells,5);
 const first=await run('04-reopen-values',binary,['cat',book,'--range','A1:C2','--csv']);assert.equal(first.stdout,'Label Ω,Value,\nمرحبا 日本語,7,21\n');
 assert.equal((await run('05-reopen-formulas',binary,['cat',book,'--range','A1:C2','--csv','--formulas'])).stdout,'Label Ω,Value,\nمرحبا 日本語,7,=B2*3\n');
 assert.equal((await run('06-evaluate',binary,['eval','=SUM(B2:C2)','--in',book])).stdout,'28\n');
 await run('07-open-edit-save',binary,['run','--in',book,'--cmd',cell('B2','9'),'--out',edited,'--quiet']);
 assert.equal((await run('08-reopen-edited-values',binary,['cat',edited,'--range','A1:C2','--csv'])).stdout,'Label Ω,Value,\nمرحبا 日本語,9,27\n');
 assert.equal((await run('09-reopen-edited-formulas',binary,['cat',edited,'--range','A1:C2','--csv','--formulas'])).stdout,'Label Ω,Value,\nمرحبا 日本語,9,=B2*3\n');
 const protectedBefore=await readFile(edited),bad=join(dir,'invalid Ω.json');await writeFile(join(dir,'destination-before.xlsx'),protectedBefore,{flag:'wx'});await writeFile(bad,'{"sheets":',{flag:'wx'});
 await run('10-invalid-input-refusal',binary,['run','--in',bad,'--out',edited,'--quiet'],1);assert.deepEqual(await readFile(edited),protectedBefore);assert.equal(await readFile(bad,'utf8'),'{"sheets":');
 const temp=edited+'.sctmp',unowned=Buffer.from("another writer's pending data Ω\n");await writeFile(temp,unowned,{flag:'wx',mode:0o600});const before=await lstat(temp);
 await run('11-occupied-regular-refusal',binary,['run','--in',book,'--cmd',cell('B2','11'),'--out',edited,'--quiet'],1);assert.deepEqual(await readFile(edited),protectedBefore);assert.deepEqual(await readFile(temp),unowned);const after=await lstat(temp);assert.equal(after.ino,before.ino);assert.equal(after.dev,before.dev);if(target!=='windows-x64')assert.equal(after.mode&0o777,0o600);await unlink(temp);
 const linkTarget=join(dir,'another writer target Ω.txt');await writeFile(linkTarget,unowned,{flag:'wx'});
 // A Windows host without symlink authority cannot silently pass this requirement.
 await symlink(linkTarget,temp,'file');const linkBefore=await lstat(temp),text=await readlink(temp);
 await run('12-occupied-symlink-refusal',binary,['run','--in',book,'--cmd',cell('B2','11'),'--out',edited,'--quiet'],1);assert.deepEqual(await readFile(edited),protectedBefore);assert.deepEqual(await readFile(linkTarget),unowned);assert.equal(await readlink(temp),text);const linkAfter=await lstat(temp);assert(linkAfter.isSymbolicLink());assert.equal(linkAfter.ino,linkBefore.ino);assert.equal(linkAfter.dev,linkBefore.dev);await unlink(temp);
 if(target!=='windows-x64')await chmod(edited,0o600);
 await run('13-retry-save',binary,['run','--in',book,'--cmd',cell('B2','11'),'--out',edited,'--quiet']);if(target!=='windows-x64')assert.equal((await lstat(edited)).mode&0o777,0o600);await assert.rejects(lstat(temp),{code:'ENOENT'});
 assert.equal((await run('14-reopen-retry',binary,['cat',edited,'--range','A1:C2','--csv'])).stdout,'Label Ω,Value,\nمرحبا 日本語,11,33\n');assert.equal((await run('15-original-input-preserved',binary,['cat',book,'--range','A1:C2','--csv'])).stdout,first.stdout);
 result.cli={passed:true,commands:15,binarySha256:sha(await readFile(binary)),syntheticXlsxCreateReopenEditSave:true,formulaPreserved:true,malformedInputPreservedDestination:true,regularTemporaryPreserved:true,symlinkTemporaryPreserved:true,symlinkTargetPreserved:true,retryRemovedOwnedTemporary:true,originalInputPreserved:true,posixModePreserved:target!=='windows-x64'?'PASSED':'NOT_APPLICABLE_WINDOWS'};
 return {book,edited,binary};
}
function envSystemRoot(q){assert(q.env.SystemRoot,'Explicit Windows SystemRoot is required');return q.env.SystemRoot;}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const q=await openQualification('native');try{await denyForRuntime(q);const {root}=await extractRuntime(q);await exerciseCli(q,root);await q.finish();}catch(error){await q.finish(error);}}

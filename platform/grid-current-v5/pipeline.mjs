// Effectful runner. Preparation gates never import this module.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,readdir,chmod,lstat} from 'node:fs/promises';
import {join,resolve,delimiter} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {sha,assertPins,commandPlan,assertAdmission,assertRuntimeManifest,assertPublicSource} from './core.mjs';
import {json,save,hash,fileIdentity,checkIdentity,inside,inventory,checkInventory,copyRegular,command,download,receiptProof,verifyKit,preparationProof} from './io.mjs';
import {archiveArgs,assertArchiveInvocation} from './python-plan.mjs';
import {effectPreflight} from './effect-preflight.mjs';
import {hostContextEnvironment} from './host-reader.mjs';

const here=fileURLToPath(new URL('.',import.meta.url));
const {values}=parseArgs({options:{stage:{type:'string'},target:{type:'string'},workspace:{type:'string'},admission:{type:'string'},'admission-sha256':{type:'string'}}});
const pins=await json(join(here,'inputs.json')),sourceManifest=await json(join(here,pins.source.manifest.path)),vendorManifest=await json(join(here,'inventory/vendor.json'));
assertPins(pins,sourceManifest,vendorManifest);
assert(pins.stages.includes(values.stage),'Choose one exact stage');assert(pins.targets[values.target],'Choose a declared platform');
const target=values.target,stage=values.stage,t=pins.targets[target];
assert.equal(process.platform,t.platform);assert.equal(process.arch,t.arch,'The claimed CPU must actually execute this driver');
assert(Number(process.versions.node.split('.')[0])>=22);
const work=inside(join(here,'runs'),values.workspace),kit=await verifyKit(here);
const admissionRaw=await readFile(resolve(values.admission));assert.match(values['admission-sha256']??'',/^[a-f0-9]{64}$/);assert.equal(sha(admissionRaw),values['admission-sha256'],'Admission bytes changed');
const admitted=JSON.parse(admissionRaw);assertAdmission(admitted,pins,target,stage,kit.sha256);
await preparationProof(here,admitted,pins,target,kit.sha256);const publicProof=await receiptProof(here,admitted.publicSourceProof);
assertPublicSource(publicProof,pins);
await checkIdentity(process.execPath,admitted.tools.node);assert.equal(resolve(admitted.tools.node.path),resolve(process.execPath));
await checkIdentity(admitted.tools.python.path,admitted.tools.python);
const source=join(work,'source',pins.source.top),input=join(work,'inputs'),tools=join(work,'prepared-tools'),exe=target==='windows-x64'?'.exe':'';
const effectGuard=await effectPreflight(here,admitted,pins,target,stage,kit.sha256);
const runtimeName='gridcraft-current-'+target,runtime=join(work,runtimeName),plan=commandPlan(pins,target,work),journal=join(work,'evidence',stage);
await mkdir(journal,{recursive:true});
const previous={};for(const name of pins.stages){try{previous[name]=(await json(join(work,'evidence',name,'RESULT.json'))).state;}catch(error){if(error.code!=='ENOENT')throw error;previous[name]='NOT_RUN';}}
assert.equal(previous[stage],'NOT_RUN','A stage journal already exists; use a new workspace after a failed stage');
const record={schemaVersion:1,stage,target,state:'IN_PROGRESS',sourceTree:pins.source.tree,sourceArchiveSha256:pins.source.sha256,kitSha256:kit.sha256,admissionSha256:sha(admissionRaw),startedAt:new Date().toISOString(),previous,commands:[],sourcePreserved:null,runtimeQualified:false,published:false,fullGoalComplete:false};
await save(join(journal,'START.json'),record);
let serial=0;
const systemEnv={...admitted.environment,...hostContextEnvironment(),PATH:admitted.systemPath,TMPDIR:join(work,'temp'),TMP:join(work,'temp'),TEMP:join(work,'temp'),LANG:'en_US.UTF-8'};
await mkdir(join(work,'temp'),{recursive:true});
const run=async(label,program,args,env=systemEnv,cwd=work,timeoutMs=120000)=>{await effectGuard.revalidate();if(program===admitted.tools.python.path)assertArchiveInvocation(program,args,env,admitted.tools.python.path,join(here,'archive.py'));const log=join(journal,String(++serial).padStart(2,'0')+'-'+label+'.json');try{return await command(program,args,{cwd,env,log,timeoutMs});}finally{try{record.commands.push({label,log,sha256:await hash(log)});}catch(error){if(error.code!=='ENOENT')throw error;}}};
async function prior(name){assert.equal(previous[name],'PASSED','Required earlier stage '+name+' is not PASSED');return json(join(work,'evidence',name,'RESULT.json'));}
async function sourceIntact(){return checkInventory(source,sourceManifest.members);}
async function verifyInput(folder,expected){const id=folder.split(/[\\/]/).at(-1).replace('vendor-gridcraft','vendor'),capture=pins.inventoryCaptures.find(row=>row.id===id);assert(capture,'Unpinned input manifest');await checkIdentity(join(folder,'MANIFEST.json'),capture);return checkInventory(folder,[...expected.files,{path:'MANIFEST.json',bytes:capture.bytes,sha256:capture.sha256,mode:0o644}],{checkMode:false});}
async function restored(){await prior('restore');await sourceIntact();await verifyInput(join(input,'vendor-gridcraft'),vendorManifest);for(const id of ['support','tools-'+target])await verifyInput(join(input,id),await json(join(here,'inventory/'+id+'.json')));}
const cargo=join(tools,'rust','bin','cargo'+exe),rustc=join(tools,'rust','bin','rustc'+exe),trunk=join(tools,'bin','trunk'+exe);
const buildEnv={...systemEnv,PATH:[join(tools,'rust','bin'),join(tools,'bin'),join(tools,'lib'),admitted.systemPath].join(delimiter),RUSTC:rustc,CARGO_HOME:join(work,'cargo-home'),CARGO_TARGET_DIR:join(work,'target'),CARGO_NET_OFFLINE:'true',CARGO_BUILD_JOBS:'2',TRUNK_OFFLINE:'true',TRUNK_SKIP_VERSION_CHECK:'true',CRAFT_FONTS_DIR:join(input,'support',pins.fonts.directory),CRAFT_FONTS_REQUIRED:'1',GRIDCRAFT_BUILD_SHA:pins.source.commit,...(target==='windows-x64'?{GRIDCRAFT_REQUIRE_WINRES:'1'}:{MACOSX_DEPLOYMENT_TARGET:'11.0'})};

try {
 if(stage==='restore') {
  for(const name of ['downloads','source','inputs'])await mkdir(join(work,name),{recursive:false});
  const assets=[pins.source,...pins.assets.filter(a=>a.role!=='tools'||a.platform===target)];record.downloads=[];
  for(const asset of assets){await effectGuard.revalidate();const path=join(work,'downloads',asset.name);record.downloads.push(await download(asset,path));const dest=asset===pins.source?join(work,'source','archive'):join(input,asset.id);await run('extract-'+(asset.id??'source'),admitted.tools.python.path,archiveArgs(join(here,'archive.py'),'extract',path,dest,asset.sha256,String(asset.bytes)));}
  // The source archive has one exact top directory. Move-free source path keeps extraction evidence intact.
  const archiveSource=join(work,'source','archive',pins.source.top);await checkInventory(archiveSource,sourceManifest.members);await copyRegular(archiveSource,source);
  await sourceIntact();await verifyInput(join(input,'vendor-gridcraft'),vendorManifest);
  for(const id of ['support','tools-'+target])await verifyInput(join(input,id),await json(join(here,'inventory/'+id+'.json')));
  await run('install-tools-without-installer-scripts',admitted.tools.python.path,archiveArgs(join(here,'archive.py'),'install-tools',join(input,'tools-'+target,'.toolchains'),tools,target));
  const font=join(input,'support',pins.fonts.directory),provenance=await json(join(font,'office-input-provenance.json'));assert.equal(provenance.commit,pins.fonts.commit);await lstat(join(font,'fonts','simplified-chinese-manifest.txt'));
  await mkdir(join(work,'cargo-home'));await mkdir(join(work,'target'));assert.deepEqual(await readdir(join(work,'target')),[]);assert.deepEqual(await readdir(join(work,'cargo-home')),[]);
  const original=await readFile(join(input,'vendor-gridcraft','offline-config.toml'),'utf8'),vendorPath=join(input,'vendor-gridcraft','vendor');
  const config=original.replace(/(\[source\.vendored-sources\]\s*\ndirectory\s*=\s*)"[^"]+"/,'$1'+JSON.stringify(vendorPath));assert(config.includes(JSON.stringify(vendorPath)));await writeFile(join(work,'cargo-home','config.toml'),config,{flag:'wx'});
  record.targetInitiallyEmpty=true;record.cargoHomeInitiallyEmpty=true;record.toolInventory=await inventory(tools);record.config=await fileIdentity(join(work,'cargo-home','config.toml'));record.restoreOnly=true;
 } else if(stage==='compile-native'||stage==='compile-wasm') {
  await restored();const restore=await prior('restore');await checkInventory(tools,restore.toolInventory);await checkIdentity(join(work,'cargo-home','config.toml'),restore.config);
  record.targetInitiallyEmpty=(await readdir(join(work,'target'))).length===0;record.ownedTargetReused=!record.targetInitiallyEmpty;record.externalTargetReused=false;
  for(const [label,path,version]of [['cargo',cargo,'1.95.0'],['rustc',rustc,'1.95.0'],['trunk',trunk,'0.22.1'],['wasm-bindgen',join(tools,'bin','wasm-bindgen'+exe),'0.2.129'],['wasm-opt',join(tools,'bin','wasm-opt'+exe),'131']]){const result=await run('version-'+label,path,['--version'],buildEnv);assert(result.stdout.includes(version));}
  if(stage==='compile-native') {
   assert(admitted.sdkProof&&admitted.sdkProof.platform===target,'A matching supported SDK identity is required');for(const row of admitted.sdkProof.files)await checkIdentity(row.path,row);
   assert(admitted.sdkProof.files.length>0,'Empty SDK identity');record.sdk=admitted.sdkProof;
   const env={...buildEnv,...(plan.staticNativeRustflags?{RUSTFLAGS:plan.staticNativeRustflags}:{})};await run('cargo-native-cli-and-application',cargo,plan.native,env,source,90*60*1000);
   record.outputs={cli:await fileIdentity(join(work,plan.cli)),application:await fileIdentity(join(work,plan.app))};record.crtProfile=plan.staticNativeRustflags;
  } else {
   assert(!Object.hasOwn(buildEnv,'RUSTFLAGS'),'Native CRT flags leaked into WASM');await run('trunk-complete-browser-distribution',trunk,plan.wasm,buildEnv,join(source,'apps','gridcraft-web'),90*60*1000);
   const files=await inventory(join(work,'web-build'));assert(files.some(f=>f.path==='index.html')&&files.some(f=>f.path.endsWith('.wasm'))&&files.some(f=>f.path.endsWith('.js')));record.distribution=files;record.loadedInBrowser=false;
  }
 } else if(stage==='package') {
  await restored();const native=await prior('compile-native'),web=await prior('compile-wasm');for(const row of Object.values(native.outputs))await checkIdentity(row.path,row);await checkInventory(join(work,'web-build'),web.distribution);
  await mkdir(runtime);await copyRegular(native.outputs.cli.path,join(runtime,'bin','gridcraft-cli'+exe));
  if(target==='windows-x64')await copyRegular(native.outputs.application.path,join(runtime,'bin','gridcraft.exe'));
  else {await copyRegular(native.outputs.application.path,join(runtime,'GridCraft.app','Contents','MacOS','GridCraft'));await copyRegular(join(source,'assets','app-icon','gridcraft.icns'),join(runtime,'GridCraft.app','Contents','Resources','GridCraft.icns'));let plist=await readFile(join(source,'packaging','macos','Info.plist.in'),'utf8');plist=plist.replaceAll('@VERSION@','0.17.0').replaceAll('@SHORT_VERSION@','0.17.0').replaceAll('@BUILD_SHA@',pins.source.commit);await writeFile(join(runtime,'GridCraft.app','Contents','Info.plist'),plist,{flag:'wx'});}
  await copyRegular(join(work,'web-build'),join(runtime,'web'));for(const name of ['host.html','host.mjs'])await copyRegular(join(here,name),join(runtime,'web',name));await copyRegular(join(here,'launch.mjs'),join(runtime,'launch.mjs'));
  await checkIdentity(join(here,pins.integrationLicense.path),pins.integrationLicense);await copyRegular(join(here,pins.integrationLicense.path),join(runtime,pins.integrationLicense.runtimePath));
  for(const name of ['LICENSE-MIT','LICENSE-APACHE','NOTICE','ATTRIBUTION.md'])await copyRegular(join(source,name),join(runtime,'legal','source',name));
  let vendorLegal=0,fontLegal=0;for(const row of vendorManifest.files){if(row.path.startsWith('vendor/')&&/(^|\/)(licen[cs]e[^/]*|copying[^/]*|notice[^/]*|copyright[^/]*)$/i.test(row.path)){await copyRegular(join(input,'vendor-gridcraft',row.path),join(runtime,'legal','vendor',row.path.slice(7)));vendorLegal++;}}
  const support=await json(join(here,'inventory/support.json'));for(const row of support.files){if(row.path.startsWith(pins.fonts.directory+'/')&&/(ofl|licen[cs]e|copying|notice|copyright)/i.test(row.path.split('/').at(-1))){await copyRegular(join(input,'support',row.path),join(runtime,'legal','fonts',row.path.slice(pins.fonts.directory.length+1)));fontLegal++;}}assert(vendorLegal>0&&fontLegal>0);
  await save(join(runtime,'BUILD.json'),{sourceTree:pins.source.tree,sourceCommit:pins.source.commit,sourceArchiveSha256:pins.source.sha256,native,web,legalScope:'Exact integration license plus engine, captured vendor and Grid font legal reference superset; not a linked-crate SBOM',nodeLauncherRequires:'Node >=22; native CLI and app do not require Node',compilerRequiredAtRuntime:false,registryRequiredAtRuntime:false,signed:false,notarized:false});
  const manifest={schemaVersion:1,kind:'CURRENT_GRID_RUNTIME_CANDIDATE',target,sourceTree:pins.source.tree,sourceArchiveSha256:pins.source.sha256,integrationLicense:{path:pins.integrationLicense.runtimePath,bytes:pins.integrationLicense.bytes,sha256:pins.integrationLicense.sha256},files:(await inventory(runtime)).map(row=>({...row,mode:row.mode&0o111?0o755:0o644})),nativeQualified:false,guiQualified:false,browserQualified:false,publicQualified:false,windows11Qualified:false,privateHostQualified:false,signed:false,notarized:false,fullGoalComplete:false};assertRuntimeManifest(manifest,pins,target);await save(join(runtime,'MANIFEST.json'),manifest);
  const archive=join(work,runtimeName+'.tar.gz');const packed=await run('package-runtime',admitted.tools.python.path,archiveArgs(join(here,'archive.py'),'pack',runtime,archive));record.archive=JSON.parse(packed.stdout);record.manifest=await fileIdentity(join(runtime,'MANIFEST.json'));await save(join(work,'ARCHIVE.json'),{...record.archive,target,top:runtimeName,manifest:record.manifest});
 } else {
  if(!['public-download','public'].includes(stage))await prior('package');
  const module={native:'native-smoke.mjs',gui:'gui-smoke.mjs',browser:'browser-smoke.mjs','public-download':'download-runtime.mjs',public:'public-smoke.mjs'}[stage];assert(module);
  await run(stage+'-qualification',process.execPath,[join(here,module),'--workspace',work,'--admission',resolve(values.admission),'--admission-sha256',values['admission-sha256']],systemEnv,work,10*60*1000);
  record.qualification=await json(join(work,'qualification',stage,'RESULT.json'));assert.equal(record.qualification.passed,true);
 }
 if(['public-download','public'].includes(stage))record.sourcePreserved='NOT_APPLICABLE_PUBLIC_RUNTIME_CONSUMER';else {await sourceIntact();record.sourcePreserved=true;}record.state='PASSED';
} catch(error){record.state='FAILED';record.error=error.message;try{if(!['public-download','public'].includes(stage))await sourceIntact();record.sourcePreserved=true;}catch(e){record.sourcePreserved=false;record.preservationError=e.message;}process.exitCode=1;}
record.finishedAt=new Date().toISOString();await save(join(journal,'RESULT.json'),record);console.log(JSON.stringify({stage,target,state:record.state,error:record.error??null}));

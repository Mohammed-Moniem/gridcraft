import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {createServer,connect} from 'node:net';
import {pathToFileURL} from 'node:url';
import {save,hash} from './io.mjs';
import {openQualification,extractRuntime,denyForRuntime,pngIdentity} from './qualification.mjs';

async function unusedPort(){const server=createServer();await new Promise((yes,no)=>{server.once('error',no);server.listen(0,'127.0.0.1',yes);});const port=server.address().port;await new Promise(yes=>server.close(yes));return port;}
const delay=ms=>new Promise(yes=>setTimeout(yes,ms));
async function request(port,token,method,params,id=1){return new Promise((yes,no)=>{const socket=connect({host:'127.0.0.1',port});let buffer='',authenticated=false;const timer=setTimeout(()=>{socket.destroy();no(Error('GUI control request timeout'));},12000);const finish=(fn,value)=>{clearTimeout(timer);socket.destroy();fn(value);};socket.once('error',e=>finish(no,e));socket.once('connect',()=>socket.write(JSON.stringify({id:0,method:'auth',params:{token}})+'\n'));socket.on('data',b=>{buffer+=b.toString();if(buffer.length>2*1024*1024)return finish(no,Error('Oversized control response'));while(buffer.includes('\n')){const index=buffer.indexOf('\n'),line=buffer.slice(0,index);buffer=buffer.slice(index+1);try{const reply=JSON.parse(line);if(!authenticated){if(reply.ok!==true)return finish(no,Error('Control authentication refused'));authenticated=true;socket.write(JSON.stringify({id,method,params})+'\n');}else {assert.equal(reply.id,id);finish(yes,reply);}}catch(e){finish(no,e);}}});});}

export async function exerciseGui(q,root) {
 const {dir,target,env,result,run}=q,exe=target==='windows-x64'?'.exe':'',cli=join(root,'bin','gridcraft-cli'+exe),app=target==='windows-x64'?join(root,'bin','gridcraft.exe'):join(root,'GridCraft.app','Contents','MacOS','GridCraft');
 const input=join(dir,'gui-input Ω.xlsx'),saved=join(dir,'gui-saved Ω.xlsx'),bad=join(dir,'gui-malformed.json');
 await run('gui-create-synthetic-input',cli,['run','--cmd','cell.set={"cell":"A1","input":"7"}','--cmd','cell.set={"cell":"A2","input":"=A1*3"}','--out',input,'--quiet']);await writeFile(bad,'{"sheets":',{flag:'wx'});
 const port=await unusedPort(),token=randomBytes(32).toString('hex');
 const appEnv={...env,GRIDCRAFT_CONTROL_TOKEN:token,XDG_CONFIG_HOME:join(dir,'preferences'),XDG_CACHE_HOME:join(dir,'cache'),XDG_RUNTIME_DIR:dir};
 await q.effectGuard.revalidate();const args=['--control',String(port),input],child=spawn(app,args,{cwd:dir,env:appEnv,stdio:['ignore','pipe','pipe'],windowsHide:false,shell:false});
 let output=[],errorOutput=[],size=0,launchError=null;
 child.once('error',e=>{launchError=e.message;});for(const [stream,chunks]of [[child.stdout,output],[child.stderr,errorOutput]])stream.on('data',b=>{size+=b.length;if(size<=4*1024*1024)chunks.push(b);else child.kill();});
 const calls=[];
 const rpc=async(method,params={},expected=true)=>{const response=await request(port,token,method,params);calls.push({method,params,response});assert.equal(response.ok,expected,JSON.stringify(response));return response.result;};
 try {
  let ready=false,lastError='';for(let n=0;n<100;n++){if(launchError)throw Error(launchError);if(child.exitCode!==null)throw Error('Native app exited before control was ready');try{await request(port,token,'document.inspect',{});ready=true;break;}catch(e){lastError=e.message;await delay(250);}}assert(ready,'Native GUI/control unavailable: '+lastError);
  await assert.rejects(request(port,'incorrect-test-token-000000000000','document.inspect',{}),/authentication refused/);result.guiAuthenticationRefusal=true;
  await rpc('ui.set',{animations:false});
  const before=await rpc('cell.get',{cell:'A2'});assert.equal(before.value,21);assert.equal(before.formula,'=A1*3');
  await rpc('ui.cell.click',{cell:'A1'});await rpc('ui.edit.begin',{text:'9'});await rpc('ui.edit.commit',{move:'none'});
  let updated;for(let n=0;n<40;n++){updated=await rpc('cell.get',{cell:'A2'});if(updated.value===27)break;await delay(100);}assert.equal(updated.value,27);assert.equal(updated.formula,'=A1*3');
  const shot=join(dir,'native-gui.png');await rpc('ui.screenshot',{path:shot});const screenshot=pngIdentity(await readFile(shot));
  await rpc('app.save',{path:saved});assert.equal((await run('gui-save-reopen-cli',cli,['cat',saved,'--range','A1:A2','--csv'])).stdout,'9\n27\n');
  await rpc('app.open',{path:bad},false);const preserved=await rpc('cell.get',{cell:'A2'});assert.equal(preserved.value,27);assert.equal(preserved.formula,'=A1*3');
  await rpc('app.open',{path:saved});const reopened=await rpc('cell.get',{cell:'A2'});assert.equal(reopened.value,27);assert.equal(reopened.formula,'=A1*3');
  await rpc('app.quit',{});await save(join(dir,'GUI-CONTROL.json'),{calls,secretAuthRequestsOmitted:true});
  result.gui={controlAndScreenshotPassed:true,actualApplicationSha256:await hash(app),syntheticUiEdit:true,formulaRecalculated:true,saveReopenedInCliAndGui:true,malformedInputPreservedWorkbook:true,screenshot:{path:shot,...screenshot},visualAcceptance:'PENDING_INDEPENDENT_IMAGE_REVIEW',interactiveDesktopRequired:true};
 } finally {
  if(child.exitCode===null&&!child.killed)child.kill('SIGTERM');
  await save(join(dir,'GUI-PROCESS.json'),{executable:app,args,environment:{...env,XDG_CONFIG_HOME:appEnv.XDG_CONFIG_HOME,XDG_CACHE_HOME:appEnv.XDG_CACHE_HOME,XDG_RUNTIME_DIR:dir,GRIDCRAFT_CONTROL_TOKEN:'EPHEMERAL_VALUE_NOT_RECORDED'},launchError,exitCode:child.exitCode,stdout:Buffer.concat(output).toString(),stderr:Buffer.concat(errorOutput).toString(),callsCompleted:calls.length});
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const q=await openQualification('gui');try{await denyForRuntime(q);const {root}=await extractRuntime(q);await exerciseGui(q,root);await q.finish();}catch(error){await q.finish(error);}}

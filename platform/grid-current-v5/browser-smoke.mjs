// Installed Chrome/Edge and native Node CDP. No browser or npm install is performed.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {checkIdentity,save,hash} from './io.mjs';
import {serveDistribution} from './launch.mjs';
import {openQualification,extractRuntime,denyForRuntime,pngIdentity} from './qualification.mjs';

const delay=ms=>new Promise(yes=>setTimeout(yes,ms));
async function cdp(url) {
 const socket=new WebSocket(url),pending=new Map(),events=[];let sequence=0,handler=()=>{},fatal=null;
 await new Promise((yes,no)=>{socket.addEventListener('open',yes,{once:true});socket.addEventListener('error',no,{once:true});});
 socket.addEventListener('message',event=>{try{const message=JSON.parse(event.data);if(message.id){const request=pending.get(message.id);if(!request)return;pending.delete(message.id);clearTimeout(request.timer);if(message.error)request.reject(Error(message.error.message));else request.resolve(message.result);}else {events.push(message);Promise.resolve(handler(message)).catch(error=>{fatal=error;});}}catch(error){fatal=error;}});
 const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method));},180000);pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params}));});
 return {send,events,onEvent:fn=>{handler=fn;},assertHealthy:()=>{if(fatal)throw fatal;},close:()=>{for(const request of pending.values()){clearTimeout(request.timer);request.reject(Error('CDP closed'));}pending.clear();socket.close();}};
}

export async function exerciseBrowser(q,root) {
 await q.effectGuard.revalidate();
 const {admission,dir,result,target,run}=q;assert(admission.tools.browser,'A reviewed installed Chrome or Edge is required');await checkIdentity(admission.tools.browser.path,admission.tools.browser);
 const site=await serveDistribution(join(root,'web')),profile=join(dir,'browser-profile');await mkdir(profile);
 const browserArgs=['--headless=new','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'--use-angle=swiftshader','--enable-unsafe-swiftshader','about:blank'];
 await q.effectGuard.revalidate();const child=spawn(admission.tools.browser.path,browserArgs,{cwd:dir,env:q.env,stdio:['ignore','pipe','pipe'],windowsHide:true,shell:false});let out=[],err=[],length=0,launchError=null,client=null;
 child.once('error',e=>{launchError=e.message;});for(const [stream,chunks]of [[child.stdout,out],[child.stderr,err]])stream.on('data',b=>{length+=b.length;if(length<=4*1024*1024)chunks.push(b);else child.kill();});
 try {
  let port;for(let n=0;n<120;n++){if(launchError)throw Error(launchError);if(child.exitCode!==null)throw Error('Installed browser exited');try{port=Number((await readFile(join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]);if(port>0)break;}catch(error){if(error.code!=='ENOENT')throw error;}await delay(250);}assert(port>0,'Browser debugging endpoint absent');
  const response=await fetch('http://127.0.0.1:'+port+'/json/new?about:blank',{method:'PUT'});assert(response.ok);const page=await response.json();assert(page.webSocketDebuggerUrl.startsWith('ws://127.0.0.1:'+port+'/'));
  client=await cdp(page.webSocketDebuggerUrl);const blocked=[],allowed=[],consoleErrors=[];
  client.onEvent(async message=>{if(message.method==='Fetch.requestPaused'){const {requestId,request}=message.params;const url=new URL(request.url);if(url.origin===site.url){allowed.push(request.url);await client.send('Fetch.continueRequest',{requestId});}else {blocked.push(request.url);await client.send('Fetch.failRequest',{requestId,errorReason:'BlockedByClient'});}}else if(message.method==='Runtime.exceptionThrown')consoleErrors.push(message.params.exceptionDetails);});
  await client.send('Page.enable');await client.send('Runtime.enable');await client.send('Network.enable');await client.send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});await client.send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
  await client.send('Page.navigate',{url:site.url+'/host.html?qualify=1'});
  let browserResult;
  for(let n=0;n<120;n++){client.assertHealthy();const state=await client.send('Runtime.evaluate',{expression:'window.gridKit && window.gridKit.qualification',awaitPromise:true,returnByValue:true});assert(!state.exceptionDetails,JSON.stringify(state.exceptionDetails));if(state.result?.value){browserResult=state.result.value;break;}await delay(250);}
  assert.equal(browserResult?.passed,true,'Actual WASM interactions did not pass');assert.equal(browserResult.tests.length,5);
  const negative=await client.send('Runtime.evaluate',{expression:"fetch('https://example.invalid/grid-network-denial-control').then(()=>false,()=>true)",awaitPromise:true,returnByValue:true});assert.equal(negative.result.value,true);assert(blocked.some(url=>url.includes('example.invalid/grid-network-denial-control')),'Positive remote-asset blocker control did not run');
  assert(allowed.some(url=>new URL(url).pathname.endsWith('.wasm')),'The extracted WASM was not requested');assert(allowed.some(url=>new URL(url).pathname.endsWith('.js')),'The extracted JavaScript glue was not requested');
  assert.deepEqual(consoleErrors,[],'Browser exception');assert(site.requests.length>0&&site.requests.every(row=>row.status===200),'Missing or failed local assets');
  const exported=Buffer.from(browserResult.exportBase64,'base64');assert(exported.length>0&&exported.length<=32*1024*1024);const exportPath=join(dir,'browser-export Ω.xlsx');await writeFile(exportPath,exported,{flag:'wx'});
  const cli=join(root,'bin','gridcraft-cli'+(target==='windows-x64'?'.exe':''));assert.equal((await run('browser-export-native-reopen',cli,['cat',exportPath,'--range','A1:A2','--csv'])).stdout,'9\n27\n');assert.equal((await run('browser-export-formula-reopen',cli,['cat',exportPath,'--range','A1:A2','--csv','--formulas'])).stdout,'9\n=A1*3\n');
  const capture=await client.send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});const png=Buffer.from(capture.data,'base64');const path=join(dir,'browser.png');await writeFile(path,png,{flag:'wx'});
  const screenshot=pngIdentity(png);delete browserResult.exportBase64;
  await save(join(dir,'BROWSER-NETWORK.json'),{allowed,blocked,requests:site.requests,consoleErrors});
  result.browser={...browserResult,installedBrowser:admission.tools.browser,actualWasmRequested:true,allRequestsServedFromExtractedDistribution:true,remoteAssetBlockerControl:true,networkLogSha256:await hash(join(dir,'BROWSER-NETWORK.json')),exportReopenedByNativeCli:true,screenshot:{path,...screenshot},privateHostIntegrated:false};
 } finally {
  client?.close();if(child.exitCode===null&&!child.killed)child.kill('SIGTERM');await site.close();
  await save(join(dir,'BROWSER-PROCESS.json'),{executable:admission.tools.browser.path,args:browserArgs,environment:q.env,launchError,exitCode:child.exitCode,stdout:Buffer.concat(out).toString(),stderr:Buffer.concat(err).toString()});
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const q=await openQualification('browser');try{await denyForRuntime(q);const {root}=await extractRuntime(q);await exerciseBrowser(q,root);await q.finish();}catch(error){await q.finish(error);}}

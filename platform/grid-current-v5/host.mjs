// Same-origin adapter for the current Rust office bridge. No private desktop host is used.
const frame=document.querySelector('#grid'),status=document.querySelector('#status');
const sessionId='grid-kit-'+crypto.randomUUID(),pending=new Map(),records=[];
let sequence=0,ready=false,saveMode='durable',saved=null,readyResolve,readyReject;
const readyPromise=new Promise((yes,no)=>{readyResolve=yes;readyReject=no;});
const envelope=kind=>({type:'gridcraft:office',protocol:'office',version:1,sessionId,kind});
const send=message=>frame.contentWindow.postMessage(message,location.origin);
const check=(condition,message)=>{if(!condition)throw Error(message);};
const store=await new Promise((yes,no)=>{const request=indexedDB.open('grid-current-kit',1);request.onupgradeneeded=()=>request.result.createObjectStore('workbooks');request.onsuccess=()=>yes(request.result);request.onerror=()=>no(request.error);});
async function durableWrite(message){
 check(message.bytes instanceof ArrayBuffer&&message.bytes.byteLength>0&&message.bytes.byteLength<=32*1024*1024,'Invalid saved bytes');
 await new Promise((yes,no)=>{const transaction=store.transaction('workbooks','readwrite');transaction.objectStore('workbooks').put({name:message.name,bytes:message.bytes,revision:message.revision},'current');transaction.oncomplete=yes;transaction.onerror=()=>no(transaction.error);transaction.onabort=()=>no(transaction.error??Error('Storage aborted'));});
 const actual=await new Promise((yes,no)=>{const request=store.transaction('workbooks','readonly').objectStore('workbooks').get('current');request.onsuccess=()=>yes(request.result);request.onerror=()=>no(request.error);});
 const expected=new Uint8Array(message.bytes),got=new Uint8Array(actual.bytes);check(expected.length===got.length&&expected.every((v,i)=>v===got[i]),'Stored bytes differ');saved=actual;
}
const hello=setInterval(()=>{if(!ready)send(envelope('hello'));},250);
const timeout=setTimeout(()=>{if(!ready)readyReject(Error('Spreadsheet bridge did not become ready'));},60000);
window.addEventListener('message',async event=>{
 if(event.origin!==location.origin||event.source!==frame.contentWindow)return;
 const message=event.data;
 if(message?.type==='gridcraft:failed'){status.textContent='Spreadsheet failed to open';readyReject(Error('WASM application failed'));return;}
 if(message?.type!=='gridcraft:office'||message.protocol!=='office'||message.version!==1||message.sessionId!==sessionId)return;
 if(message.kind==='ready'){ready=true;clearInterval(hello);clearTimeout(timeout);status.textContent='Local spreadsheet ready';readyResolve(message);}
 else if(message.kind==='save'){
  try{check(saveMode!=='fail','Intentional storage refusal');await durableWrite(message);send({...envelope('saved'),id:message.id,revision:message.revision});status.textContent='Saved in this browser';}
  catch(error){send({...envelope('save-failed'),id:message.id,revision:message.revision});status.textContent='Save failed; workbook remains open';}
 }else if(message.kind==='response'){
  const request=pending.get(message.id);if(!request)return;pending.delete(message.id);clearTimeout(request.timer);if(message.ok===true)request.resolve(message.result);else request.reject(Error(message.error?.code??'Operation failed'));
 }
});
async function request(method,params={}){await readyPromise;check(pending.size<32,'Request limit');const id='request-'+(++sequence);return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending.delete(id);reject(Error('Bridge request timeout'));},45000);pending.set(id,{resolve,reject,timer});send({...envelope('request'),id,method,params});});}
async function runQualification(){
 const passed=[];const test=async(name,fn)=>{await fn();passed.push(name);};
 await readyPromise;
 const execute=(command,params)=>request('office.execute',{command,params});
 await test('visible-workbook-edit-and-formula',async()=>{await execute('cell.set',{cell:'A1',input:'7'});await execute('cell.set',{cell:'A2',input:'=A1*3'});const cell=await execute('cell.get',{cell:'A2'});check(cell.value===21&&cell.formula==='=A1*3','Formula calculation differs');});
 await test('storage-failure-retains-dirty-owner',async()=>{saveMode='fail';let refused=false;try{await request('office.save');}catch(error){refused=error.message==='SAVE_FAILED';}check(refused,'Storage refusal did not propagate');const state=await request('office.inspect',{range:'A1:A2'});check(state.dirty===true,'Failed save lost dirty ownership');saveMode='durable';});
 await test('durable-save-byte-roundtrip',async()=>{const ack=await request('office.save');check(ack.saved===true&&ack.dirty===false,'Save was not acknowledged');check(saved?.bytes instanceof ArrayBuffer,'Saved bytes absent');const expected=saved.bytes.slice(0);await request('office.close');await request('office.open',{name:'browser-synthetic Ω.xlsx',bytes:expected});const cell=await execute('cell.get',{cell:'A2'});check(cell.value===21&&cell.formula==='=A1*3','Reopened save differs');});
 await test('malformed-open-preserves-current-workbook',async()=>{let refused=false;try{await request('office.open',{name:'invalid.xlsx',bytes:new TextEncoder().encode('not a workbook').buffer});}catch{refused=true;}check(refused,'Malformed input accepted');const cell=await execute('cell.get',{cell:'A2'});check(cell.value===21&&cell.formula==='=A1*3','Malformed open replaced workbook');});
 await test('second-edit-save-reopen',async()=>{await execute('cell.set',{cell:'A1',input:'9'});const cell=await execute('cell.get',{cell:'A2'});check(cell.value===27,'Edited formula differs');await request('office.save');const bytes=saved.bytes.slice(0);await request('office.close');await request('office.open',{name:'edited-browser.xlsx',bytes});const reopened=await execute('cell.get',{cell:'A2'});check(reopened.value===27&&reopened.formula==='=A1*3','Edited save differs');});
 const exported=await request('office.export',{format:'xlsx'});check(exported.bytes instanceof ArrayBuffer&&new Uint8Array(exported.bytes)[0]===0x50,'XLSX export absent');
 const exportArray=new Uint8Array(exported.bytes);let binary='';for(let offset=0;offset<exportArray.length;offset+=16384)binary+=String.fromCharCode(...exportArray.subarray(offset,offset+16384));
 return {passed:true,tests:passed,exportBase64:btoa(binary),saveDurability:'IndexedDB write transaction completed and exact bytes read back before matching revision ACK',privateHostIntegrated:false};
}
document.querySelector('#save').onclick=()=>request('office.save').catch(()=>{});
window.gridKit={request,ready:readyPromise,records};
if(new URLSearchParams(location.search).get('qualify')==='1')window.gridKit.qualification=runQualification();

// Optional local web launcher/adapter; native CLI/application need no Node runtime.
import {createServer} from 'node:http';
import {readFile,lstat} from 'node:fs/promises';
import {resolve,join,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

export async function serveDistribution(directory,{port=0}={}) {
 const base=resolve(directory),requests=[];
 const types={'.wasm':'application/wasm','.js':'text/javascript','.mjs':'text/javascript','.html':'text/html; charset=utf-8','.css':'text/css','.png':'image/png','.ico':'image/x-icon','.json':'application/json','.ttf':'font/ttf','.woff2':'font/woff2'};
 const server=createServer(async(req,res)=>{
  try {
   if(!['GET','HEAD'].includes(req.method))throw Error('Read-only server');
   const url=new URL(req.url,'http://127.0.0.1');const name=decodeURIComponent(url.pathname==='/'?'/host.html':url.pathname);const path=resolve(base,'.'+name);
   if(!path.startsWith(base+sep))throw Error('Path outside distribution');
   const pieces=path.slice(base.length+1).split(sep);let current=base;
   for(const piece of pieces){current=join(current,piece);if((await lstat(current)).isSymbolicLink())throw Error('Symbolic links not served');}
   if(!(await lstat(path)).isFile())throw Error('Not a file');
   const bytes=await readFile(path),extension=path.slice(path.lastIndexOf('.'));
   requests.push({method:req.method,path:name,status:200,bytes:bytes.length});
   res.writeHead(200,{'Content-Type':types[extension]??'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Cross-Origin-Opener-Policy':'same-origin','Cross-Origin-Embedder-Policy':'require-corp'});res.end(req.method==='HEAD'?undefined:bytes);
  }catch(error){requests.push({method:req.method,path:req.url,status:404});res.writeHead(404,{'Content-Type':'text/plain'});res.end('Local asset unavailable');}
 });
 await new Promise((yes,no)=>{server.once('error',no);server.listen(port,'127.0.0.1',yes);});
 return {server,url:'http://127.0.0.1:'+server.address().port,requests,close:()=>new Promise(yes=>{server.closeAllConnections();server.close(yes);})};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const here=fileURLToPath(new URL('.',import.meta.url));const served=await serveDistribution(join(here,'web'));console.log('Grid local web: '+served.url+'/host.html');}

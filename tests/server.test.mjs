import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {networkInterfaces} from 'node:os';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
const cwd=fileURLToPath(new URL('..',import.meta.url));
async function startServer(lan,t){
  const child=spawn(process.execPath,['serve.mjs',...(lan?['--lan']:[])],{cwd,env:{...process.env,PACKET_LENS_PORT:'0'},stdio:['ignore','pipe','pipe'],windowsHide:true});
  t.after(async()=>{if(child.exitCode===null){const ended=once(child,'exit');child.kill();await ended;}});
  return await new Promise((resolve,reject)=>{let text='';const timeout=setTimeout(()=>reject(Error('Server did not become ready.')),10000);child.stdout.on('data',chunk=>{text+=chunk;const match=text.match(/ready at http:\/\/127\.0\.0\.1:(\d+)/);if(match){clearTimeout(timeout);resolve({port:Number(match[1]),child});}});child.once('error',e=>{clearTimeout(timeout);reject(e);});child.once('exit',code=>{clearTimeout(timeout);reject(Error(`Server exited early: ${code}`));});});
}
function request(port,pathname,method='GET'){return new Promise((resolve,reject)=>{const r=http.request({hostname:'127.0.0.1',port,path:pathname,method},res=>{const data=[];res.on('data',b=>data.push(b));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(data).toString()}));});r.on('error',reject);r.end();});}
test('Local server serves app assets and rejects access outside dist or uploads',async t=>{
  const {port}=await startServer(false,t);const index=await request(port,'/');assert.equal(index.status,200);assert.match(index.body,/Packet Lens/);
  const worker=await request(port,'/worker.js');assert.equal(worker.status,200);assert.equal(worker.headers['content-type'],'text/javascript');
  assert.equal((await request(port,'/demo.pcap')).status,200);
  assert.equal((await request(port,'/serve.mjs')).status,404);
  assert.equal((await request(port,'/%2e%2e%2fserve.mjs')).status,403);
  assert.equal((await request(port,'/%2e%2e%5cREADME.md')).status,403);
  assert.equal((await request(port,'/','POST')).status,405);
  const head=await request(port,'/','HEAD');assert.equal(head.status,200);assert.equal(head.body,'');
});
test('Network mode accepts requests using a non-loopback IPv4 address',async t=>{
  const address=Object.values(networkInterfaces()).flat().find(a=>a&&a.family==='IPv4'&&!a.internal&&!a.address.startsWith('169.254.'));
  if(!address){t.skip('No network IPv4 address available.');return;}
  const {port}=await startServer(true,t);const res=await fetch(`http://${address.address}:${port}/`,{signal:AbortSignal.timeout(5000)});assert.equal(res.status,200);assert.match(await res.text(),/Packet Lens/);
});

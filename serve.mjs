import http from 'node:http';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {networkInterfaces} from 'node:os';
const root=path.join(path.dirname(fileURLToPath(import.meta.url)),'dist');
const host=process.argv.includes('--lan')?'0.0.0.0':'127.0.0.1';
const port=Number(process.env.PACKET_LENS_PORT||8876);
if(!Number.isInteger(port)||port<0||port>65535)throw Error('PACKET_LENS_PORT must be an integer from 0 to 65535.');
const types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.pcap':'application/octet-stream'};
const server=http.createServer(async(req,res)=>{try{if(!['GET','HEAD'].includes(req.method)){res.writeHead(405,{'Allow':'GET, HEAD'});res.end('Method not allowed');return;}const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);const target=path.resolve(root,'.'+(pathname==='/'?'/index.html':pathname));if(!target.startsWith(root+path.sep)){res.writeHead(403);res.end();return;}const data=await readFile(target);res.writeHead(200,{'Content-Type':types[path.extname(target)]||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(req.method==='HEAD'?undefined:data);}catch{res.writeHead(404);res.end('Not found');}});
server.listen(port,host,()=>{
  const activePort=server.address().port;
  console.log(`Packet Lens ready at http://127.0.0.1:${activePort}`);
  if(host==='0.0.0.0'){
    console.log('Network hosting enabled. Share one of these links with people on that network:');
    for(const [name,addresses] of Object.entries(networkInterfaces()))for(const address of addresses||[]){if(address.family==='IPv4'&&!address.internal&&!address.address.startsWith('169.254.'))console.log(`  ${name}: http://${address.address}:${activePort}`);}
  }
  console.log('Keep this server running. Press Ctrl+C to stop.');
});
server.on('error',e=>{console.error(e.message);process.exitCode=1;});

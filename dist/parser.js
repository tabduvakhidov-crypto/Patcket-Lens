// Bounds-checked capture reader. No network access or payload persistence.
export const LIMITS = { bytes: 150 * 1024 * 1024, packets: 750000, flows: 50000, hosts: 20000, domains: 20000 };
const decoder = new TextDecoder();
const serviceNames = {20:'FTP data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',68:'DHCP',80:'HTTP',110:'POP3',123:'NTP',135:'RPC',139:'NetBIOS',143:'IMAP',161:'SNMP',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTP over TLS',514:'Syslog',587:'SMTP submission',636:'LDAP over TLS',853:'DNS over TLS',993:'IMAP over TLS',995:'POP3 over TLS',1433:'SQL Server',1900:'SSDP',3306:'MySQL',3389:'Remote Desktop',5353:'mDNS',5355:'LLMNR',5432:'PostgreSQL',5900:'VNC',8080:'HTTP alternate'};
export const explanations = {TCP:'Connections that deliver data reliably and in order.',UDP:'Messages sent without a delivery handshake, often used for DNS, streaming, and calls.',DNS:'Looks up a domain name to find its IP address.',mDNS:'Helps devices find names and services on the local network.',HTTPS:'Port 443 traffic, usually encrypted web traffic. The contents are not readable here.',TLS:'An observed TLS handshake indicates an encrypted connection; contents are not decrypted.',QUIC:'UDP port 443 traffic, commonly used for encrypted HTTP/3; inferred from the port.',HTTP:'Unencrypted web traffic; content may be visible to anyone with the capture.',ARP:'Local devices asking which network adapter owns an IPv4 address.',ICMP:'Network control messages such as ping replies and unreachable destinations.',ICMPv6:'IPv6 network control messages, including neighbor discovery.',Other:'A protocol or link type that this reader cannot fully decode.'};
export function addressKind(ip) {
  if(ip.includes(':')) { const x=ip.toLowerCase(); return x.startsWith('ff')?'Multicast':x==='0:0:0:0:0:0:0:1'?'Loopback':x==='0:0:0:0:0:0:0:0'?'Unspecified': /^(fc|fd|fe[89ab])/.test(x)?'Local':'Public / other'; }
  const a=ip.split('.').map(Number); return a[0]===10 || (a[0]===172&&a[1]>=16&&a[1]<=31) || (a[0]===192&&a[1]===168)?'Private':a[0]===127?'Loopback':a[0]===169&&a[1]===254?'Link-local':a[0]>=224&&a[0]<=239?'Multicast':ip==='255.255.255.255'?'Broadcast':a[0]===0?'Unspecified':'Public / other';
}
function dnsMessage(b) {
  if(b.length<12)return null;
  const v=new DataView(b.buffer,b.byteOffset,b.byteLength), names=[];
  function name(at) {
    let out=[],next=null,steps=0; const seen=new Set();
    while(at<b.length && steps++<128) {
      if(seen.has(at))throw Error('DNS pointer loop'); seen.add(at);
      const n=b[at++]; if(!n)return {value:out.join('.'),next:next??at};
      if((n&192)===192) {if(at>=b.length)throw Error('DNS pointer'); next??=at+1;at=((n&63)<<8)|b[at];continue;}
      if(n>63||at+n>b.length)throw Error('DNS label');out.push(decoder.decode(b.subarray(at,at+n)));at+=n;
    } throw Error('DNS name');
  }
  let pos=12; const q=v.getUint16(4),an=v.getUint16(6),answers=[];
  if(q>128||an>256)return null;
  for(let i=0;i<q;i++) {const n=name(pos);pos=n.next;if(pos+4>b.length)throw Error('DNS question');names.push(n.value);pos+=4;}
  for(let i=0;i<an;i++) {const n=name(pos);pos=n.next;if(pos+10>b.length)throw Error('DNS answer');const type=v.getUint16(pos),len=v.getUint16(pos+8);pos+=10;if(pos+len>b.length)throw Error('DNS data');if(type===1&&len===4)answers.push({name:n.value,ip:Array.from(b.subarray(pos,pos+4)).join('.')});if(type===28&&len===16)answers.push({name:n.value,ip:Array.from({length:8},(_,j)=>v.getUint16(pos+j*2).toString(16)).join(':')});pos+=len;}
  return {names,answers,response:!!(b[2]&128),rcode:b[3]&15};
}
function tlsName(b) {
  if(b.length<9||b[0]!==22||b[5]!==1)return null;
  const v=new DataView(b.buffer,b.byteOffset,b.byteLength); let p=43;
  if(p>=b.length)return null;p+=1+b[p];if(p+2>b.length)return null;p+=2+v.getUint16(p);if(p>=b.length)return null;p+=1+b[p];if(p+2>b.length)return null;
  const end=Math.min(b.length,p+2+v.getUint16(p));p+=2;
  while(p+4<=end) {const type=v.getUint16(p),len=v.getUint16(p+2);p+=4;if(p+len>end)return null;if(type===0&&len>=5){let q=p+2;while(q+3<=p+len){const kind=b[q],n=v.getUint16(q+1);q+=3;if(q+n>p+len)return null;if(kind===0)return decoder.decode(b.subarray(q,q+n));q+=n;}}p+=len;}
  return null;
}
function decodePacket(b,link) {
  const v=new DataView(b.buffer,b.byteOffset,b.byteLength); const need=(p,n)=>{if(p+n>b.length)throw Error('Short frame');};
  let p=0,eth=0,mac=null;
  if(link===1) {need(0,14);mac=Array.from(b.subarray(6,12),n=>n.toString(16).padStart(2,'0')).join(':');eth=v.getUint16(12);p=14;let depth=0;while([0x8100,0x88a8,0x9100].includes(eth)&&depth++<4){need(p,4);eth=v.getUint16(p+2);p+=4;}}
  else if(link===113){need(0,16);eth=v.getUint16(14);p=16;}
  else if(link===276){need(0,20);eth=v.getUint16(0);p=20;}
  else if([101,228,229].includes(link)){need(0,1);eth=(b[0]>>4)===4?0x800:(b[0]>>4)===6?0x86dd:0;}
  else if(link===0||link===108){need(0,5);p=4;eth=(b[p]>>4)===4?0x800:(b[p]>>4)===6?0x86dd:0;}
  else return {protocol:'Other',info:`Unsupported link type ${link}`,unsupported:true};
  const ip4=at=>Array.from(b.subarray(at,at+4)).join('.');const ip6=at=>Array.from({length:8},(_,i)=>v.getUint16(at+2*i).toString(16)).join(':');
  if(eth===0x806){need(p,8);if(b[p+4]!==6||b[p+5]!==4)return {protocol:'ARP',info:'ARP with an unsupported address format'};need(p,28);const src=ip4(p+14),dst=ip4(p+24);return {src,dst,mac,protocol:'ARP',info:v.getUint16(p+6)===1?`Who has ${dst}? Tell ${src}.`:`${src} is announcing its hardware address.`};}
  let src,dst,proto,fragmented=false;
  if(eth===0x800){need(p,20);const n=(b[p]&15)*4,total=v.getUint16(p+2);if((b[p]>>4)!==4||n<20||total<n)throw Error('Invalid IPv4');need(p,n);src=ip4(p+12);dst=ip4(p+16);proto=b[p+9];fragmented=!!(v.getUint16(p+6)&0x3fff);const nonfirst=!!(v.getUint16(p+6)&0x1fff);b=b.subarray(0,Math.min(b.length,p+total));p+=n;if(nonfirst)return {src,dst,mac,protocol:proto===6?'TCP':proto===17?'UDP':'Other',fragmented,info:'IP fragment; transport details unavailable.'};}
  else if(eth===0x86dd){need(p,40);if((b[p]>>4)!==6)throw Error('Invalid IPv6');src=ip6(p+8);dst=ip6(p+24);proto=b[p+6];const len=v.getUint16(p+4);if(len)b=b.subarray(0,Math.min(b.length,p+40+len));p+=40;let depth=0;while([0,43,44,51,60].includes(proto)&&depth++<12){need(p,2);const next=b[p];if(proto===44){need(p,8);fragmented=true;if(v.getUint16(p+2)&0xfff8)return {src,dst,mac,protocol:next===6?'TCP':next===17?'UDP':'Other',fragmented,info:'IPv6 fragment; transport details unavailable.'};p+=8;}else {const len=proto===51?(b[p+1]+2)*4:(b[p+1]+1)*8;need(p,len);p+=len;}proto=next;}}
  else return {protocol:'Other',info:`Ethernet type 0x${eth.toString(16)}`};
  // Rebuild view after trimming padding outside the IP length.
  const w=new DataView(b.buffer,b.byteOffset,b.byteLength);const check=n=>{if(p+n>b.length)throw Error('Short transport');};
  const pkt={src,dst,mac,fragmented,protocol:'Other',transport:null,info:`IP protocol ${proto}`};
  if(proto===6||proto===17) {
    check(proto===6?20:8);pkt.transport=proto===6?'TCP':'UDP';pkt.sport=w.getUint16(p);pkt.dport=w.getUint16(p+2);let header=8;
    if(proto===6){header=(b[p+12]>>4)*4;if(header<20)throw Error('TCP header');check(header);pkt.flags=b[p+13];pkt.seq=w.getUint32(p+4);pkt.window=w.getUint16(p+14);pkt.syn=!!(pkt.flags&2)&&!(pkt.flags&16);pkt.rst=!!(pkt.flags&4);}
    else {const len=w.getUint16(p+4);if(len<8)throw Error('UDP length');b=b.subarray(0,Math.min(b.length,p+len));}
    const ports=[pkt.sport,pkt.dport];let service=ports.map(n=>serviceNames[n]).find(Boolean);pkt.service=service||'Unrecognized port';pkt.protocol=service||pkt.transport;if(!['DNS','mDNS','HTTPS','HTTP','ICMP','ARP'].includes(pkt.protocol))pkt.protocol=pkt.transport;
    if(proto===17&&ports.includes(443))pkt.protocol='QUIC';const payload=b.subarray(p+header);pkt.payloadLength=payload.length;
    pkt.info=`${pkt.transport} ${pkt.sport} → ${pkt.dport}${service?` · ${service} (port based)`:''}`;
    if(proto===6){const flags=[];for(const [bit,name] of [[2,'SYN'],[16,'ACK'],[1,'FIN'],[4,'RST'],[8,'PSH']])if(pkt.flags&bit)flags.push(name);pkt.info+=` · ${flags.join(', ')||'no flags'}`;}
    if(!fragmented&&(ports.includes(53)||ports.includes(5353)))try{let d=payload;if(proto===6){if(d.length<2)return pkt;const n=(d[0]<<8)|d[1];if(n>d.length-2)return pkt;d=d.subarray(2,n+2);}pkt.dns=dnsMessage(d);if(pkt.dns){pkt.protocol=ports.includes(5353)?'mDNS':'DNS';pkt.info=`${pkt.dns.response?'DNS answer':'DNS lookup'}: ${pkt.dns.names.join(', ')||'(no question)'}${pkt.dns.rcode?` · error ${pkt.dns.rcode}`:''}`;}}catch{/* Packet still contributes to transport totals. */}
    if(proto===6&&!fragmented){if(payload.length>=6&&payload[0]===22&&payload[1]===3){pkt.protocol='TLS';pkt.hostname=tlsName(payload);if(pkt.hostname)pkt.info=`TLS handshake for ${pkt.hostname}`;}
      const txt=decoder.decode(payload.subarray(0,8192));if(/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|CONNECT)\s\S+\sHTTP\/1\.[01]\r\n|^HTTP\/1\.[01] \d{3}/.test(txt)){pkt.protocol='HTTP';pkt.cleartext=true;pkt.hostname=txt.match(/\r\nHost:\s*([^\r\n]+)/i)?.[1]?.split(':')[0];pkt.info=txt.split('\r\n')[0].slice(0,180);}}
    return pkt;
  }
  if(proto===1||proto===58){check(4);pkt.protocol=proto===1?'ICMP':'ICMPv6';pkt.icmpType=b[p];pkt.icmpError=proto===1?[3,11,12].includes(b[p]):b[p]<128;pkt.info=proto===1?({0:'Ping reply',8:'Ping request',3:'Destination unreachable',11:'TTL expired'}[b[p]]||`ICMP type ${b[p]}`):({128:'IPv6 ping request',129:'IPv6 ping reply',135:'IPv6 neighbor solicitation',136:'IPv6 neighbor advertisement',1:'IPv6 destination unreachable',2:'Packet too big',3:'Hop limit expired'}[b[p]]||`ICMPv6 type ${b[p]}`);}
  return pkt;
}
export function analyzeCapture(buffer,progress=()=>{}) {
  if(buffer.byteLength>LIMITS.bytes)throw Error('This version accepts files up to 150 MiB. Split a larger capture in Wireshark first.');
  const v=new DataView(buffer),u=new Uint8Array(buffer);if(u.length<4)throw Error('This file is too short to be a packet capture.');
  const hosts=new Map(),flows=new Map(),domains=new Map(),protocols=new Map(),timeline=new Map(),samples=[],warnings=new Set(),links=new Set();
  const stats={packets:0,bytes:0,capturedBytes:0,truncated:0,undecoded:0,malformed:0,fragments:0,resets:0,dnsFailures:0,cleartext:0,icmpErrors:0,missingTime:0,start:null,end:null};
  function host(ip){if(!hosts.has(ip)){if(hosts.size>=LIMITS.hosts){warnings.add('Device list limited to 20,000 addresses.');return null;}hosts.set(ip,{ip,kind:addressKind(ip),sent:0,received:0,packets:0,macs:new Set(),names:new Set(),peers:new Set()});}return hosts.get(ip);}
  function domain(name,source,response=false,failed=false){if(!name||name.length>253)return;name=name.toLowerCase();if(!domains.has(name)){if(domains.size>=LIMITS.domains){warnings.add('Domain list limited to 20,000 names.');return;}domains.set(name,{name,observations:0,queries:0,responses:0,failures:0,sources:new Set(),ips:new Set()});}const d=domains.get(name);d.observations++;d.sources.add(source);if(source==='DNS'||source==='mDNS'){response?d.responses++:d.queries++;if(failed)d.failures++;}}
  function consume(at,cap,orig,time,link){
    if(stats.packets>=LIMITS.packets)throw Error('Capture exceeds 750,000 packets. Split it in Wireshark to analyze every packet.');
    stats.packets++;stats.bytes+=orig;stats.capturedBytes+=cap;if(cap<orig)stats.truncated++;links.add(link);
    if(time!==null&&Number.isFinite(time)){stats.start=stats.start===null?time:Math.min(stats.start,time);stats.end=stats.end===null?time:Math.max(stats.end,time);}else stats.missingTime++;
    let pkt;try{pkt=decodePacket(u.subarray(at,at+cap),link);}catch{stats.malformed++;pkt={protocol:'Other',info:'Incomplete or malformed frame; transport details unavailable.'};}
    if(pkt.protocol==='Other')stats.undecoded++;if(pkt.fragmented)stats.fragments++;if(pkt.rst)stats.resets++;if(pkt.dns?.rcode)stats.dnsFailures++;if(pkt.cleartext)stats.cleartext++;if(pkt.icmpError)stats.icmpErrors++;
    const protocol=protocols.get(pkt.protocol)||{name:pkt.protocol,packets:0,bytes:0};protocol.packets++;protocol.bytes+=orig;protocols.set(pkt.protocol,protocol);
    if(time!==null){const bucket=Math.floor(time);timeline.set(bucket,(timeline.get(bucket)||0)+orig);}
    if(pkt.src&&pkt.dst){const a=host(pkt.src),b=host(pkt.dst);if(a){a.sent+=orig;a.packets++;if(a.peers.size<1000)a.peers.add(pkt.dst);if(pkt.mac)a.macs.add(pkt.mac);}if(b){b.received+=orig;b.packets++;if(b.peers.size<1000)b.peers.add(pkt.src);}
      if(pkt.transport){const x=`${pkt.src}|${pkt.sport}`,y=`${pkt.dst}|${pkt.dport}`,key=[x,y].sort().join('~')+'~'+pkt.transport;let f=flows.get(key);if(!f&&flows.size<LIMITS.flows){f={src:pkt.src,dst:pkt.dst,sport:pkt.sport,dport:pkt.dport,transport:pkt.transport,service:pkt.service,protocol:pkt.protocol,packets:0,bytes:0,resets:0,syn:0,responsePackets:0,start:time,end:time};flows.set(key,f);}else if(!f)warnings.add('Connection list limited to 50,000 endpoint pairs.');if(f){f.packets++;f.bytes+=orig;if(pkt.rst)f.resets++;if(pkt.syn)f.syn++;if(pkt.src!==f.src||pkt.sport!==f.sport)f.responsePackets++;if(time!==null){f.start=f.start===null?time:Math.min(f.start,time);f.end=f.end===null?time:Math.max(f.end,time);}if(['TLS','HTTP','DNS'].includes(pkt.protocol))f.protocol=pkt.protocol;}}
    }
    if(pkt.dns){for(const n of pkt.dns.names)domain(n,pkt.protocol,pkt.dns.response,!!pkt.dns.rcode);for(const a of pkt.dns.answers){if(!domains.has(a.name.toLowerCase()))domain(a.name,pkt.protocol,true,false);domains.get(a.name.toLowerCase())?.ips.add(a.ip);const h=host(a.ip);if(h&&h.names.size<20)h.names.add(a.name);}}
    if(pkt.hostname){domain(pkt.hostname,pkt.protocol);const h=host(pkt.dst);if(h&&h.names.size<20)h.names.add(pkt.hostname);}
    if(samples.length<2500)samples.push({number:stats.packets,time,src:pkt.src||'—',dst:pkt.dst||'—',sport:pkt.sport,dport:pkt.dport,protocol:pkt.protocol,length:orig,info:pkt.info});
    if(stats.packets%10000===0)progress(Math.round(at/u.length*100));
  }
  const magic=v.getUint32(0,false);let format;
  if(magic===0x0a0d0d0a){format='PCAPNG';let p=0,little=true,interfaces=[],section=false;
    while(p<u.length){if(p+12>u.length)throw Error('Truncated PCAPNG block header.');if(v.getUint32(p,false)===0x0a0d0d0a){if(p+28>u.length)throw Error('Truncated PCAPNG section.');const bom=v.getUint32(p+8,false);if(![0x1a2b3c4d,0x4d3c2b1a].includes(bom))throw Error('Invalid PCAPNG byte order.');little=bom===0x4d3c2b1a;interfaces=[];section=true;}
      const type=v.getUint32(p,little),len=v.getUint32(p+4,little);if(!section||len<12||len%4||p+len>u.length||v.getUint32(p+len-4,little)!==len)throw Error('Invalid or truncated PCAPNG block.');const end=p+len-4;
      if(type===0x0a0d0d0a){if(len<28||v.getUint16(p+12,little)!==1)throw Error('Unsupported PCAPNG section version.');}
      if(type===1){if(len<20)throw Error('Invalid interface description.');const intf={link:v.getUint16(p+8,little),snap:v.getUint32(p+12,little),resolution:1e-6,offset:0};let q=p+16;while(q+4<=end){const code=v.getUint16(q,little),n=v.getUint16(q+2,little);q+=4;if(!code)break;if(q+n>end)throw Error('Truncated interface option.');if(code===9&&n===1){const x=u[q];intf.resolution=(x&128)?2**-(x&127):10**-x;}if(code===14&&n===8)intf.offset=Number(v.getBigInt64(q,little));q+=Math.ceil(n/4)*4;}interfaces.push(intf);}
      if(type===6||type===2){if(len<32)throw Error('Invalid packet block.');const id=type===6?v.getUint32(p+8,little):v.getUint16(p+8,little),intf=interfaces[id];if(!intf)throw Error('Packet refers to an unknown interface.');const cap=v.getUint32(p+20,little),orig=v.getUint32(p+24,little);if(cap>orig||p+28+Math.ceil(cap/4)*4>end)throw Error('Invalid PCAPNG packet length.');const ticks=v.getUint32(p+12,little)*4294967296+v.getUint32(p+16,little);consume(p+28,cap,orig,ticks*intf.resolution+intf.offset,intf.link);}
      if(type===3){const intf=interfaces[0];if(!intf||len<16)throw Error('Invalid simple packet block.');const orig=v.getUint32(p+8,little),cap=Math.min(orig,intf.snap||orig);if(p+12+Math.ceil(cap/4)*4!==end)throw Error('Invalid simple packet length.');consume(p+12,cap,orig,null,intf.link);}
      p+=len;
    }
  }else if([0xa1b2c3d4,0xd4c3b2a1,0xa1b23c4d,0x4d3cb2a1].includes(magic)){format='PCAP';if(u.length<24)throw Error('Truncated PCAP header.');const little=[0xd4c3b2a1,0x4d3cb2a1].includes(magic),resolution=[0xa1b23c4d,0x4d3cb2a1].includes(magic)?1e-9:1e-6;if(v.getUint16(4,little)!==2||v.getUint16(6,little)!==4)throw Error('Unsupported PCAP version.');const link=v.getUint32(20,little)&0xffff;let p=24;
    while(p<u.length){if(p+16>u.length)throw Error('Truncated PCAP packet header.');const cap=v.getUint32(p+8,little),orig=v.getUint32(p+12,little);if(cap>orig||p+16+cap>u.length)throw Error('Invalid or truncated PCAP packet.');const sec=v.getUint32(p,little),frac=v.getUint32(p+4,little);if(frac>=1/resolution)throw Error('Invalid PCAP timestamp.');consume(p+16,cap,orig,sec+frac*resolution,link);p+=16+cap;}
  }else throw Error('Not a supported PCAP or PCAPNG file. Use Wireshark → File → Save As to save a packet capture.');
  if(!stats.packets)throw Error('This capture contains no packets.');
  const findings=[];function finding(level,title,detail,filter,next){findings.push({level,title,detail,filter,next});}
  if(stats.dnsFailures)finding('review','Some name lookups failed',`${stats.dnsFailures} DNS error responses were observed. NXDOMAIN can mean a typo or a name that no longer exists; it does not by itself prove a network outage.`, 'dns.flags.rcode != 0','Check the affected names and DNS response codes in Wireshark. Compare with a successful lookup from the same device.');
  if(stats.resets)finding('review','Connections were abruptly closed',`${stats.resets} TCP reset packets were observed. A reset can mean a closed port, an application rejecting a connection, or a connection being terminated.`, 'tcp.flags.reset == 1','Check the source of the reset and the preceding conversation. A reset alone does not identify the cause.');
  if(stats.cleartext)finding('review','Unencrypted web traffic is visible',`${stats.cleartext} packets contain recognizable HTTP request or response headers. Sensitive contents may be readable in the original capture.`, 'http','Check whether the application can use HTTPS. This app keeps only the request/status line, not the HTTP body.');
  if(stats.icmpErrors)finding('review','Network error messages appeared',`${stats.icmpErrors} ICMP error messages were observed, such as unreachable destinations or expired hop limits.`, '(icmp.type == 3 || icmp.type == 11 || icmp.type == 12) || icmpv6.type < 128','Inspect the message type and the original packet inside the error to identify the affected connection.');
  const unanswered=[...flows.values()].filter(f=>f.syn>=3&&f.responsePackets===0);if(unanswered.length)finding('review','Repeated connection attempts have no visible reply',`${unanswered.length} endpoint pairs have at least three initial TCP SYN packets and no reverse-direction packet in this capture. One-way capture visibility can produce the same pattern.`, 'tcp.flags.syn == 1 && tcp.flags.ack == 0','Check whether both traffic directions were captured, then inspect the destination and port.');
  if(stats.truncated)warnings.add(`${stats.truncated} packets were cut short by the capture snapshot length.`);if(stats.malformed)warnings.add(`${stats.malformed} frames were too short or malformed to fully decode.`);if(stats.undecoded)warnings.add(`${stats.undecoded} packets use unrecognized protocols or unsupported encapsulations.`);if(stats.fragments)warnings.add(`${stats.fragments} IP fragments observed; fragmented messages are not reassembled.`);if(stats.missingTime)warnings.add(`${stats.missingTime} packets have no timestamp and are omitted from the timeline.`);
  if(!findings.length)finding('info','No supported warning patterns were detected','The checks did not find DNS error responses, TCP resets, ICMP errors, readable HTTP, or repeated unanswered SYN attempts. This is not a security or network health verdict.','','Review the busiest devices and connections to confirm the activity matches what you expect.');
  const hostList=[...hosts.values()].map(h=>({...h,macs:[...h.macs],names:[...h.names],peers:h.peers.size})).sort((a,b)=>(b.sent+b.received)-(a.sent+a.received));
  const flowList=[...flows.values()].sort((a,b)=>b.bytes-a.bytes),domainList=[...domains.values()].map(d=>({...d,sources:[...d.sources],ips:[...d.ips]})).sort((a,b)=>b.observations-a.observations);
  const protocolList=[...protocols.values()].sort((a,b)=>b.bytes-a.bytes);
  const bins=Array.from({length:60},(_,i)=>({index:i,bytes:0,packets:0}));if(stats.start!==null)for(const [time,bytes] of timeline){const i=Math.min(59,Math.max(0,Math.floor((time-stats.start)/Math.max(1,stats.end-stats.start)*60)));bins[i].bytes+=bytes;}
  progress(100);return {format,stats,hosts:hostList,flows:flowList,domains:domainList,protocols:protocolList,timeline:bins,samples,findings,warnings:[...warnings],links:[...links],limits:LIMITS};
}

import {writeFile} from 'node:fs/promises';
import {pcap,demoPackets} from '../tests/fixtures.mjs';
await writeFile(new URL('../dist/demo.pcap',import.meta.url),pcap(demoPackets()));
console.log('Synthetic demo capture written.');

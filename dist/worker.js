import { analyzeCapture } from './parser.js';
self.onmessage=({data})=>{try{const report=analyzeCapture(data.buffer,p=>self.postMessage({progress:p}));self.postMessage({report});}catch(e){self.postMessage({error:e.message||'Could not read this capture.'});}};

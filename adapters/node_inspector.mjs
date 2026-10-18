#!/usr/bin/env node
// Explicit Inspector snapshot adapter. No Runtime.evaluate or target code injection.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const args = process.argv.slice(2), options = {};
for (let i=0;i<args.length;i++) {
  const key=args[i];
  if (['--run','--resume','--once'].includes(key)) options[key]=true;
  else if (['--pid','--url','--output','--runtime','--pause-ms','--timeout-ms','--match'].includes(key) && i+1<args.length) options[key]=args[++i];
  else throw new Error(`unknown/incomplete option ${key}`);
}
const pid=Number(options['--pid']), runtime=options['--runtime']||'javascript';
if (!Number.isInteger(pid)||pid<=0||!options['--url']||!options['--output']||!['javascript','wasm'].includes(runtime))
  throw new Error('usage: node node_inspector.mjs --pid PID --url ws://127.0.0.1:PORT/ID --output FILE [--runtime wasm] [--run --resume] [--pause-ms N] [--once]');
const timeout=Number(options['--timeout-ms']||30000), pauseMs=Number(options['--pause-ms']||0);
if (!(timeout>=100&&timeout<=3600000) || !(pauseMs===0||pauseMs>=20&&pauseMs<=3600000)) throw new Error('invalid adapter deadline/pause interval');
function identity(){const stat=fs.readFileSync(`/proc/${pid}/stat`,'utf8');return Number(stat.slice(stat.lastIndexOf(')')+1).trim().split(/\s+/)[19]);}
const started=identity(), endpoint=new URL(options['--url']);
if (endpoint.protocol!=='ws:'||!['127.0.0.1','localhost','[::1]','::1'].includes(endpoint.hostname)) throw new Error('Inspector endpoint must be a local unencrypted loopback socket');
// Resolve the only accepted hostname ourselves, keeping PID verification and
// the actual WebSocket/HTTP destination on one unambiguous address/family.
if(endpoint.hostname==='localhost')endpoint.hostname='127.0.0.1';
const socketTable=endpoint.hostname==='127.0.0.1'?'tcp':'tcp6';
const loopbackAddress=socketTable==='tcp'?'0100007F':'00000000000000000000000001000000';
const wildcardAddress=socketTable==='tcp'?'00000000':'00000000000000000000000000000000';
const endpointPort=Number(endpoint.port||80);
const socketInodes=new Set();
for(const fd of fs.readdirSync(`/proc/${pid}/fd`)){try{const match=fs.readlinkSync(`/proc/${pid}/fd/${fd}`).match(/^socket:\[(\d+)\]$/);if(match)socketInodes.add(match[1]);}catch{}}
let owned=false;
try{for(const line of fs.readFileSync(`/proc/${pid}/net/${socketTable}`,'utf8').split('\n').slice(1)){const fields=line.trim().split(/\s+/);if(fields.length<10)continue;const [address,port]=fields[1].split(':');if(fields[3]==='0A'&&[loopbackAddress,wildcardAddress].includes(address.toUpperCase())&&parseInt(port,16)===endpointPort&&socketInodes.has(fields[9]))owned=true;}}catch{}
if(!owned)throw new Error('Inspector listening socket address/family does not belong to the requested PID');
const versionResponse=await fetch(new URL('/json/version',`http://${endpoint.host}`),{signal:AbortSignal.timeout(timeout)});
const targetVersion=(await versionResponse.json()).Browser||'Inspector';
let WebSocketImpl=globalThis.WebSocket;
if(!WebSocketImpl){try{WebSocketImpl=(await import('ws')).default;}catch{throw new Error('Node 20 requires: npm ci --prefix adapters (no dependencies are installed automatically)');}}
const socket=new WebSocketImpl(endpoint), pending=new Map(), scripts=new Map();
let sequence=0, handling=false, ownPause=false, timer;
function send(method,params={}){return new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});}
function frame(item){const location=item.location||item, script=scripts.get(location.scriptId), url=item.url||script?.url||'<unknown script>';const name=item.functionName||'<anonymous>';return `${script?.wasm?'wasm:':''}${name} (${url}:${Number(location.lineNumber||0)+1}:${Number(location.columnNumber||0)+1})`;}
async function publish(event){
 if(identity()!==started)throw new Error('target identity changed');
 const frames=(event.callFrames||[]).slice(0,127).map(frame);
 let parent=event.asyncStackTrace, parentId=event.asyncStackTraceId, seen=new Set();
 for(let depth=0;depth<32&&frames.length<127;depth++){
  if(!parent&&parentId){const key=JSON.stringify(parentId);if(seen.has(key))break;seen.add(key);parent=(await send('Debugger.getStackTrace',{stackTraceId:parentId})).stackTrace;}
  if(!parent)break;
  frames.push(`--- async: ${parent.description||'parent'} ---`);
  for(const call of parent.callFrames||[]){if(frames.length>=127)break;frames.push(frame(call));}
  parentId=parent.parentId;parent=parent.parent;
 }
 if(runtime==='wasm'&&!frames.some(value=>value.startsWith('wasm:')||value.includes('wasm://')))return false;
 if(options['--match']&&!frames.some(value=>value.includes(options['--match'])))return false;
 const snapshot={version:1,pid,start_ticks:started,captured_unix_ms:Date.now(),runtime,runtime_version:targetVersion,threads:[{tid:null,name:`Inspector ${endpoint.pathname.slice(1)}`,state:'paused logical/async stack; endpoint-level association',frames}]};
 const data=JSON.stringify(snapshot);if(Buffer.byteLength(data)>1024*1024)throw new Error('snapshot exceeds 1 MiB');
 const output=path.resolve(options['--output']), temporary=path.join(path.dirname(output),`.poortrace-${crypto.randomUUID()}`);
 try{fs.writeFileSync(temporary,data,{flag:'wx',mode:0o600});fs.renameSync(temporary,output);}finally{try{fs.unlinkSync(temporary);}catch{}}
 return true;
}
async function finish(error){if(timer)clearInterval(timer);if(ownPause){try{await send('Debugger.resume');}catch{}}socket.close();if(error){console.error(`poortrace Inspector adapter: ${error.message}`);process.exitCode=1;}}
socket.addEventListener('message',async event=>{
 try{
  const text=typeof event.data==='string'?event.data:Buffer.from(event.data).toString();if(text.length>8*1024*1024)throw new Error('Inspector message exceeds 8 MiB');
  const message=JSON.parse(text);
  if(message.id){const request=pending.get(message.id);if(request){pending.delete(message.id);message.error?request.reject(new Error(message.error.message)):request.resolve(message.result||{});}return;}
  if(message.method==='Debugger.scriptParsed'){if(scripts.size>=10000)scripts.clear();scripts.set(message.params.scriptId,{url:message.params.url,wasm:message.params.scriptLanguage==='WebAssembly'||message.params.url?.startsWith('wasm://')});}
  if(message.method==='Debugger.paused'&&!handling){handling=true;try{const published=await publish(message.params);if(ownPause||options['--resume'])await send('Debugger.resume');ownPause=false;if(options['--once']&&published)await finish();}finally{handling=false;}}
 }catch(error){await finish(error);}
});
socket.addEventListener('open',async()=>{try{await send('Debugger.enable');await send('Debugger.setAsyncCallStackDepth',{maxDepth:32});if(options['--run'])await send('Runtime.runIfWaitingForDebugger');if(pauseMs)timer=setInterval(async()=>{if(!handling&&!ownPause){ownPause=true;try{await send('Debugger.pause');}catch(error){await finish(error);}}},pauseMs);}catch(error){await finish(error);}});
socket.addEventListener('error',()=>finish(new Error('Inspector WebSocket failed')));
const deadline=setTimeout(()=>finish(new Error('adapter deadline exceeded')),timeout);deadline.unref();
socket.addEventListener('close',()=>{clearTimeout(deadline);if(timer)clearInterval(timer);});

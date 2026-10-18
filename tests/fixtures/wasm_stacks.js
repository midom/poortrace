const bytes=Uint8Array.from([0,97,115,109,1,0,0,0,1,4,1,96,0,0,2,12,1,3,101,110,118,4,104,111,111,107,0,0,3,2,1,0,7,7,1,3,114,117,110,0,1,10,6,1,4,0,16,0,11]);
function pauseFromWasm(){debugger;}
const instance=new WebAssembly.Instance(new WebAssembly.Module(bytes),{env:{hook:pauseFromWasm}});
instance.exports.run();
setInterval(()=>{},1000);

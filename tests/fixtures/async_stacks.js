async function asyncLeaf() {
  await Promise.resolve();
  debugger;
}
async function asyncCaller() {
  await asyncLeaf();
}
asyncCaller();
setInterval(()=>{}, 1000);

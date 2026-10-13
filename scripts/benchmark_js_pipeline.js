// Complete HTTP requests. Includes synchronous finish callbacks/logging in server samples.
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const crypto = require('crypto');
const { performance } = require('perf_hooks');
const express = require('express');
const createNative = require('../js/lib/nativePipeline');
const { createIsolationForest } = require('../js/lib/wasmAdapter');
const count = Number(process.env.AIWAF_BENCH_REQUESTS || 300);
const rounds = Number(process.env.AIWAF_BENCH_ROUNDS || 3);
if (!Number.isInteger(count) || count < 1 || !Number.isInteger(rounds) || rounds < 1) throw new Error('Positive benchmark counts/rounds are required');
const output = process.env.AIWAF_BENCH_OUTPUT || path.join(os.tmpdir(),'aiwaf-js-pipeline-benchmark.json');
const stageNames = ['geo_block','ip_keyword_block','rate_limit','ai_anomaly','honeypot','uuid_tamper','header_validation','logging'];
const results=[];
process.env.NODE_ENV = 'test'; // Legacy comparison uses isolated in-memory SQLite, not a production database.
const headers={'user-agent':'Mozilla/5.0 Chrome/130.0 Safari/537.36',accept:'text/html','accept-language':'en','accept-encoding':'gzip',connection:'keep-alive'};
async function sample(mode) {
  const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'aiwaf-js-bench-'));
  const app=express();const samples=[];let measure=false;let middleware;
  app.use((req,_res,next)=>{req.benchStart=performance.now();next();});
  app.use(express.json({limit:'64kb'}));
  if(mode==='legacy') {
    const manager=require('../js/lib/blacklistManager');
    await manager.initialize();await manager.clear();
    const db=require('../js/utils/db');
    for(let start=0;start<1000;start+=100)await db('blocked_ips').insert(Array.from({length:100},(_,offset)=>{
      const i=start+offset;return {ip_address:`198.18.${Math.floor(i/250)}.${i%250}`,reason:'benchmark fixture',permanent:1};
    }));
    middleware=require('../js/lib/wafMiddleware')({AIWAF_MIDDLEWARES:stageNames,staticKeywords:['.php','xmlrpc','wp-','.env','.git','.bak','shell'],WINDOW_SEC:10,MAX_REQ:50000,FLOOD_REQ:100000,AIWAF_MIN_FORM_TIME:0,AIWAF_MAX_PAGE_TIME:240,AIWAF_HEADER_VALIDATION:true,AIWAF_REQUIRED_HEADERS:['user-agent','accept'],AIWAF_GEO_BLOCK_ENABLED:true,AIWAF_GEO_BLOCK_COUNTRIES:['XX'],geoResolver:()=>'',AIWAF_MIDDLEWARE_LOGGING:true,AIWAF_MIDDLEWARE_LOG_PATH:path.join(dataDir,'legacy.jsonl'),AIWAF_MIDDLEWARE_LOG_CSV:false,AIWAF_MIN_AI_LOGS:100000000,AIWAF_MODEL_PATH:path.join(dataDir,'absent.json')});
    app.use(middleware);
  } else if(mode!=='bare') {
    const blacklist=Object.fromEntries(Array.from({length:1000},(_,i)=>[`198.18.${Math.floor(i/250)}.${i%250}`,0]));
    let model;
    if(mode==='native_ai') {
      model=await createIsolationForest({nTrees:100,sampleSize:200,seed:42});
      if(!model.__aiwafWasm)throw new Error('Benchmark requires real WASM model');
      model.fit(Array.from({length:200},(_,i)=>[10+i%20,0,0,1+i%4,1+i%10,0]));
    }
    middleware=await createNative({dataDir,model,profile:{enabled:stageNames,blacklist,rate_max:50000,rate_flood:100000,min_form_time:0},countryLookup:()=>'',routeExists:req=>req.path==='/api/ok'});
    app.use(middleware);
    if(!middleware.diagnostics().native || middleware.diagnostics().model!==(mode==='native_ai'))throw new Error('Native/model activation mismatch');
  }
  // This listener is registered AFTER the native finish callback, so samples include it.
  app.use((req,res,next)=>{res.on('finish',()=>{if(measure)samples.push(performance.now()-req.benchStart);});next();});
  app.get('/api/ok',(_req,res)=>res.json({ok:true}));app.post('/api/ok',(_req,res)=>res.json({ok:true}));
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  const port=server.address().port;const agent=new http.Agent({keepAlive:true,maxSockets:1});
  const body=JSON.stringify(Object.fromEntries(Array.from({length:30},(_,i)=>[`field${i}`,`value${i}`])));
  const send=(method,url='/api/ok',payload=body)=>new Promise((resolve,reject)=>{
    const start=performance.now();const data=method==='POST'?payload:null;
    const req=http.request({host:'127.0.0.1',port,agent,method,path:url,headers:{...headers,...(data?{'content-type':'application/json','content-length':Buffer.byteLength(data)}:{})}},res=>{res.resume();res.on('end',()=>resolve({status:res.statusCode,total:performance.now()-start}));});req.on('error',reject);req.end(data);
  });
  let elapsed=0;const statuses={};
  try {
    for(let i=0;i<80;i++)await send(i%5===0?'POST':'GET');
    measure=true;
    for(let i=0;i<count;i++){const r=await send(i%5===0?'POST':'GET');statuses[r.status]=(statuses[r.status]||0)+1;elapsed+=r.total;if(r.status!==200)throw new Error(`Measured request returned ${r.status}`);}
    measure=false;
    if(samples.length!==count)throw new Error('Missing server processing samples');
    const diag=middleware?.diagnostics?.();
    if(mode==='native_ai' && diag.model_predictions!==count+80)throw new Error('AI timing must include actual model inference for every request');
    const sql=await send('POST','/api/ok',JSON.stringify({q:"' OR 1=1--"}));
    // A SQL denial blacklists the loopback client: use another engine for independent PHP checks in tests.
    const php=await send('GET','/wp-content/plugins/pods/init.php');
    if(mode==='bare' ? (sql.status!==200 || php.status!==404) : (sql.status!==403 || php.status!==403))throw new Error('Probe protection mismatch');
    return {mode,server_mean_ms:samples.reduce((a,b)=>a+b,0)/count,server_p95_ms:samples.slice().sort((a,b)=>a-b)[Math.floor(count*.95)],client_mean_ms:elapsed/count,statuses,diagnostics:diag,sql_status:sql.status,php_status:php.status};
  } finally {
    agent.destroy();await new Promise(resolve=>server.close(resolve));if(middleware?.close)middleware.close();fs.rmSync(dataDir,{recursive:true,force:true});
  }
}
function median(values){const s=values.slice().sort((a,b)=>a-b);return s[Math.floor(s.length/2)];}
async function run(){
  for(let round=0;round<rounds;round++) {
    const modes=round%2?['native_ai','native','legacy','bare']:['bare','legacy','native','native_ai'];
    for(const mode of modes){const r=await sample(mode);results.push({round,...r});console.log(`${round+1} ${mode}: server ${r.server_mean_ms.toFixed(3)}ms, client ${r.client_mean_ms.toFixed(3)}ms`);}
  }
  const bare=median(results.filter(r=>r.mode==='bare').map(r=>r.server_mean_ms));
  const summary=['bare','legacy','native','native_ai'].map(mode=>{const total=median(results.filter(r=>r.mode===mode).map(r=>r.server_mean_ms));return {mode,server_mean_ms:total,added_overhead_ms:total-bare};});
  const hashes=Object.fromEntries(['js/lib/nativePipeline.js','js/lib/wasmAdapter.js','rust/crates/aiwaf_wasm/src/request_pipeline.rs','scripts/benchmark_js_pipeline.js'].map(file=>[file,crypto.createHash('sha256').update(fs.readFileSync(path.resolve(__dirname,'..',file))).digest('hex')]));
  const wasmResolve=require('module').createRequire(path.resolve(__dirname,'../js/lib/wasmAdapter.js'));
  const wasmMetadata=wasmResolve.resolve('aiwaf-wasm/package.json');
  hashes.wasm_binary=crypto.createHash('sha256').update(fs.readFileSync(path.join(path.dirname(wasmMetadata),'aiwaf_wasm_bg.wasm'))).digest('hex');
  fs.writeFileSync(output,JSON.stringify({node:process.version,express:require('express/package.json').version,wasm:JSON.parse(fs.readFileSync(wasmMetadata)).version,platform:process.platform,arch:process.arch,count,rounds,method:'One client, keep-alive, 80% GET / 20% parsed JSON POST, 30 fields, 1000 blacklist entries, all eight stages, memory timing/rates. Native immediate CSV logging; legacy immediate JSONL logging and in-memory SQLite policy lookups. Native AI-on fits a 100-tree/200-row model and verifies one inference per request; legacy model is disabled. Server samples include synchronous finish callbacks. Medians of per-run means; overhead subtracts bare Express baseline. Legacy/native stores and policies differ; this is an integration comparison, not pure Rust-versus-JS equivalence. Synthetic local data, no throughput/production guarantee.',hashes,summary,results},null,2)+'\n');console.log(JSON.stringify(summary));
  await require('../js/utils/db').destroy();require('../js/lib/rateLimiter').cleanup();require('../js/lib/featureUtils').cleanup();
}
run().catch(error=>{console.error(error);process.exitCode=1;});

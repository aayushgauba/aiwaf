// Run against a built real WASM package, never a mocked/fallback engine.
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const request = require('supertest');
const createNative = require('../lib/nativePipeline');
const { createIsolationForest, createRequestPipeline } = require('../lib/wasmAdapter');
const ua = 'Mozilla/5.0 Chrome/130.0 Safari/537.36';
const roots = [];
const handles = [];
function temp() { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-native-')); roots.push(root); return root; }
function browser(req, ip = '203.0.113.10') {
  return req.set('User-Agent', ua).set('Accept','text/html').set('Accept-Language','en').set('Accept-Encoding','gzip').set('Connection','keep-alive').set('X-Forwarded-For',ip);
}
async function appWith(profile = {}, options = {}) {
  const app = express(); app.set('trust proxy','loopback'); app.use(express.json({limit:'64kb'})); app.use(express.urlencoded({extended:false,limit:'64kb'}));
  const middleware = await createNative({dataDir:temp(), profile, ...options}); handles.push(middleware);
  app.use(middleware);
  app.get('/api/ok', (_req,res)=>res.json({ok:true})); app.post('/api/ok',(_req,res)=>res.json({ok:true}));
  app.get('/stream', (_req,res)=>{res.write('a');res.end('b');});
  return { app, middleware };
}
async function run() {
  await assert.rejects(createNative(false),/options must be an object/);
  await assert.rejects(createNative({profile:false}),/profile must be an object/);
  await assert.rejects(createNative({ dataDir:temp(), profile:{unsupported:true} }));
  await assert.rejects(createNative({ dataDir:temp(), profile:{rate_backend:'redis'} }));
  await assert.rejects(createNative({ dataDir:temp(), authenticated:async()=>false }));
  const invalidLog=path.join(temp(),'invalid.csv');fs.writeFileSync(invalidLog,'bad header\n');
  await assert.rejects(createNative({dataDir:temp(),logPath:invalidLog}),/schema/);
  const { app, middleware } = await appWith({min_form_time:0, rate_max:1000,rate_flood:2000});
  assert.equal(middleware.diagnostics().native,true);
  assert.equal(middleware.inspectPayload({url:'/api/ok',headers:{},body:{name:"O'Reilly"}}),null);
  assert.equal(middleware.inspectPayload({url:'/api/ok',headers:{},body:Buffer.from('{"q":"\u0027 OR 1=1--"}')}).status,403);
  assert.equal((await browser(request(app).get('/api/ok'))).status,200);
  assert.equal((await browser(request(app).post('/api/ok')).send({name:"O'Reilly"})).status,200);
  assert.equal((await browser(request(app).get('/not-known'))).status,404);
  assert.equal((await browser(request(app).get('/wp-login.php'),'203.0.113.11')).status,403);
  assert.equal((await browser(request(app).get('/api/ok?q=%2527+OR+1%253D1--'),'203.0.113.12')).status,403);
  assert.equal((await browser(request(app).post('/api/ok'),'203.0.113.13').send({nested:{q:"' OR 1=1--"}})).status,403);
  assert.equal((await browser(request(app).post('/api/ok'),'203.0.113.14').send({nested:'{"q":"\\u0027 OR 1=1--"}'})).status,403);
  assert.equal((await browser(request(app).get('/user/not-a-uuid'),'203.0.113.15')).status,403);
  assert.equal((await browser(request(app).get('/api/ok'),'203.0.113.16').set('User-Agent','x'.repeat(501))).status,403);
  assert.equal((await browser(request(app).get('/stream'))).text,'ab');
  assert.equal(middleware.diagnostics().pending,0);
  const timing = await appWith({min_form_time:10});
  assert.equal((await browser(request(timing.app).get('/api/ok'))).status,200);
  assert.equal((await browser(request(timing.app).post('/api/ok')).send({})).status,403);
  const isolated = await appWith({min_form_time:10});
  assert.equal((await browser(request(isolated.app).post('/api/ok')).send({})).status,200);
  const rate = await appWith({rate_max:2,rate_flood:3,min_form_time:0});
  for (const status of [200,200,429,403,403]) assert.equal((await browser(request(rate.app).get('/api/ok'))).status,status);
  const capped = await appWith({max_bytes:32,min_form_time:0});
  assert.equal((await browser(request(capped.app).post('/api/ok')).send({large:'x'.repeat(100)})).status,413);
  const honeyField = await appWith({honeypot_field:'website',min_form_time:0});
  assert.equal((await browser(request(honeyField.app).post('/api/ok')).send({website:'bot'})).status,403);
  const dataDir = temp(); const errors=[];
  const durable = await appWith({min_form_time:0}, {dataDir,onError:e=>errors.push(e)});
  assert.equal((await browser(request(durable.app).get('/wp-login.php'),'203.0.113.22')).status,403);
  durable.middleware.close();
  const reload = await appWith({min_form_time:0}, {dataDir});
  assert.equal((await browser(request(reload.app).get('/api/ok'),'203.0.113.22')).status,403);
  assert.equal(errors.length,0);
  const state = fs.readFileSync(path.join(dataDir,'native_requests.csv'),'utf8');
  assert.equal(state.trim().split('\n').length,3); // header plus exactly two responses
  const learningDir=temp();
  const learning=await appWith({enabled:['ai_anomaly','logging'],static_keywords:['scan']},{dataDir:learningDir});
  assert.equal((await browser(request(learning.app).get('/scanprobe'))).status,404);
  assert.equal(learning.middleware.diagnostics().learned_keywords,1);learning.middleware.close();
  const learned=await appWith({static_keywords:[],min_form_time:0},{dataDir:learningDir});
  assert.equal((await browser(request(learned.app).get('/scanprobe'))).status,403);
  const writeErrors=[];const broken=await appWith({min_form_time:0},{onError:e=>writeErrors.push(e)});
  const oldWrite=fs.writeSync;
  try {
    fs.writeSync=()=>{throw new Error('fixture disk error');};
    assert.equal((await browser(request(broken.app).get('/api/ok'))).status,200);
  } finally { fs.writeSync=oldWrite; }
  assert.equal(writeErrors.length,1);assert.equal(broken.middleware.diagnostics().pending,0);
  const authenticated=await appWith({min_form_time:10},{authenticated:()=>true});
  assert.equal((await browser(request(authenticated.app).get('/api/ok'))).status,200);
  assert.equal((await browser(request(authenticated.app).post('/api/ok')).send({})).status,200);
  const model = await createIsolationForest({nTrees:20,sampleSize:100,seed:42});
  assert.equal(model.__aiwafWasm,true);
  model.fit(Array.from({length:200},(_,i)=>[7+i%20,i%3,0,1+i%4,1+i%10,i%3]));
  const ai = await appWith({min_form_time:0},{model});
  assert.equal(ai.middleware.diagnostics().model,true);
  assert.equal((await browser(request(ai.app).get('/api/ok'))).status,200);
  ai.middleware.setModel(null); assert.equal(ai.middleware.diagnostics().model,false);
  const {native:a} = await createRequestPipeline({enabled:[]}); const {native:b}=await createRequestPipeline({enabled:[]});
  const facts = JSON.stringify({ip:'a',path:'/',method:'GET',headers:{},query:'',body:null,now:100,country:'',authenticated:false,exists:true});
  const context = JSON.parse(a.begin(facts)).context;
  assert.throws(()=>b.finish(context,200,1,100));
  assert.throws(()=>a.finish(context,200,-1,100));
  a.finish(context,200,1,99); assert.throws(()=>a.finish(context,200,1,100));
  const longContext=JSON.parse(a.begin(facts)).context;
  const laterContext=JSON.parse(a.begin(JSON.stringify({...JSON.parse(facts),ip:'later',now:1000}))).context;
  a.finish(laterContext,200,1,1000);
  assert.doesNotThrow(()=>a.finish(longContext,200,901000,1001));
  a.free();b.free();
  console.log('Real WASM native pipeline: startup, structured payloads, all-stage requests, rate/flood, timing, persistence, model, streaming and context checks passed.');
}
function cleanup() {
  for(const handle of handles){try{handle.close();}catch(_) {}}
  for(const root of roots)fs.rmSync(root,{recursive:true,force:true});
}
module.exports = { run, cleanup };
if (require.main === module) run().then(cleanup).catch(error=>{console.error(error);process.exitCode=1;cleanup();});

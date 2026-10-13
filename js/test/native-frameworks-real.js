const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const roots = [];
const ua = 'Mozilla/5.0 Chrome/130.0 Safari/537.36';
const opts = () => { const dir=fs.mkdtempSync(path.join(os.tmpdir(),'aiwaf-native-fw-'));roots.push(dir);return {AIWAF_NATIVE_PIPELINE:{dataDir:dir,profile:{min_form_time:0,rate_max:1000,rate_flood:2000}}}; };
function call(port, method, url, body) {
  const data=body===undefined?null:JSON.stringify(body);
  return new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port,method,path:url,headers:{'user-agent':ua,accept:'text/html','accept-language':'en','accept-encoding':'gzip',connection:'close',...(data?{'content-type':'application/json','content-length':Buffer.byteLength(data)}:{})}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
    req.setTimeout(5000,()=>req.destroy(new Error('Native framework request timed out')));
    req.on('error',reject);req.end(data);
  });
}
async function check(port){assert.equal(await call(port,'POST','/api/ok',{hello:'world'}),200);assert.equal(await call(port,'POST','/api/ok',{nested:{q:"' OR 1=1--"}}),403);assert.equal(await call(port,'GET','/wp-content/plugins/pods/init.php'),403);}
async function run() {
  console.log('Checking native Fastify transport...');
  const fastify=require('fastify')();
  fastify.register(require('../lib/fastifyPlugin'),opts());fastify.post('/api/ok',async()=>({ok:true}));
  await fastify.listen({host:'127.0.0.1',port:0});try{await check(fastify.server.address().port);}finally{await fastify.close();}
  console.log('Checking native Hapi transport...');
  const hapi=require('@hapi/hapi').server({host:'127.0.0.1',port:0});
  const hapiOptions=opts();hapiOptions.AIWAF_NATIVE_PIPELINE.authenticated=req=>req.auth.isAuthenticated;
  await hapi.register({plugin:require('../lib/hapiPlugin'),options:hapiOptions});hapi.route({method:'POST',path:'/api/ok',handler:()=>({ok:true})});
  await hapi.start();try{await check(hapi.info.port);}finally{await hapi.stop();}
  console.log('Checking native Koa transport...');
  const Koa=require('koa');const koa=new Koa();koa.use(require('koa-bodyparser')());
  const middleware=require('../lib/koaMiddleware')(opts());const native=await middleware.ready;koa.use(middleware);koa.use(ctx=>{ctx.body={ok:true};});
  const server=koa.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));try{await check(server.address().port);}finally{await new Promise(r=>server.close(r));native.close();}
  console.log('Checking native Next transport...');
  const next=require('../lib/nextMiddleware')((_req,res)=>{res.statusCode=200;res.end('ok');},opts());const nextNative=await next.ready;
  // Next API routes normally supply parsed bodies. This test supplies the same transport contract.
  const nextServer=http.createServer(async(req,res)=>{let data='';for await(const chunk of req)data+=chunk;req.body=data?JSON.parse(data):undefined;try{await next(req,res);}catch(error){res.statusCode=500;res.end(error.message);}});
  nextServer.listen(0,'127.0.0.1');await new Promise(r=>nextServer.once('listening',r));try{await check(nextServer.address().port);}finally{await new Promise(r=>nextServer.close(r));nextNative.close();}
  console.log('Checking native Nest and Adonis transports...');
  const express=require('express');const app=express();app.use(express.json());
  const Nest=require('../lib/nestMiddleware')(opts());const nestNative=await Nest.ready;const instance=new Nest();
  app.use((req,res,next)=>instance.use(req,res,next));app.post('/api/ok',(_req,res)=>res.json({ok:true}));
  const nestServer=app.listen(0,'127.0.0.1');await new Promise(r=>nestServer.once('listening',r));try{await check(nestServer.address().port);}finally{await new Promise(r=>nestServer.close(r));nestNative.close();}
  const adonis=require('../lib/adonisMiddleware')(opts());const adonisNative=await adonis.ready;
  const adonisServer=http.createServer(async(req,res)=>{
    let data='';for await(const chunk of req)data+=chunk;req.body=data?JSON.parse(data):undefined;
    const ctx={request:{request:req,url:()=>req.url,ip:()=>req.socket.remoteAddress,body:()=>req.body},response:{response:res,status:code=>{res.statusCode=code;},json:value=>{res.end(JSON.stringify(value));},send:value=>res.end(value)}};
    try{await adonis(ctx,()=>{res.statusCode=200;res.end('ok');});}catch(error){res.statusCode=500;res.end(error.message);}
  });
  adonisServer.listen(0,'127.0.0.1');await new Promise(r=>adonisServer.once('listening',r));try{await check(adonisServer.address().port);}finally{await new Promise(r=>adonisServer.close(r));adonisNative.close();}
  assert.throws(()=>require('../lib/wafMiddleware')({AIWAF_NATIVE_PIPELINE:{},cache:{}}),/mix legacy/);
  const wrapped=require('../lib/wafMiddleware')(opts());const wrappedNative=await wrapped.ready;
  assert.equal((await wrapped.inspectPayload({url:'/api/ok',headers:{},body:{q:"' OR 1=1--"}})).status,403);wrappedNative.close();
  console.log('Native Fastify, Hapi, Koa, Next, Nest and Adonis transport: parsed POST allowed, nested SQL blocked, lifecycle closed.');
}
async function cleanup(){await require('../utils/db').destroy();for(const root of roots)fs.rmSync(root,{recursive:true,force:true});}
module.exports={run,cleanup};
if(require.main===module)run().then(cleanup).catch(error=>{console.error(error);process.exitCode=1;});

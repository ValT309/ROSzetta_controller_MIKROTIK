// Run with node --test tests/sessionRefresh.test.cjs (requires TypeScript).
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');const ts=require('typescript');
const source=ts.transpileModule(fs.readFileSync(path.join(__dirname,'../src/api/client.ts'),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,esModuleInterop:true,target:ts.ScriptTarget.ES2022}}).outputText;
function fixture(){
 let state={accessToken:'a1',refreshToken:'r1',sessionEpoch:1,email:'admin'};let logout=0,refreshes=0;let handle,requestHandler;const replays=[];let resolve,reject;const refresh=new Promise((r,j)=>{resolve=r;reject=j});
 state.logout=()=>{logout++;state={...state,accessToken:null,refreshToken:null,sessionEpoch:state.sessionEpoch+1}};
 const useAuth={getState:()=>state,setState:p=>{state={...state,...p}}};
 const api={interceptors:{request:{use:f=>requestHandler=f},response:{use:(_,f)=>handle=f}},request:async cfg=>{requestHandler(cfg);replays.push(cfg);return {data:'ok'}}};
 const refreshApi={post:(url,body)=>{assert.equal(url,'/auth/refresh');assert.equal(body.refresh_token,'r1');refreshes++;return refresh}};
 let n=0;const axios={create:()=>n++?refreshApi:api};const context={exports:{},require:name=>name==='axios'?axios:name==='@/store/auth'?{useAuth}:assert.fail(name)};vm.runInNewContext(source,context);
 function err(marker='session',status=401){const cfg=requestHandler({headers:{},method:'post',data:{x:1}});return {config:cfg,response:{status,headers:{'x-roszetta-auth':marker}}};}
 return {handle,err,resolve,reject,replays,get refreshes(){return refreshes},get logout(){return logout},get state(){return state},signOut:()=>state.logout(),login:()=>{state={...state,accessToken:'newLogin',refreshToken:'newRefresh',sessionEpoch:state.sessionEpoch+1}}};
}
test('parallel expired requests share one refresh and each replays once',async()=>{const f=fixture();const p=f.handle(f.err()), q=f.handle(f.err());assert.equal(f.refreshes,1);f.resolve({data:{access_token:'a2',refresh_token:'r2'}});await Promise.all([p,q]);assert.equal(f.replays.length,2);assert.equal(f.replays[0].headers.Authorization,'Bearer a2');assert.equal(f.state.email,'admin');assert.equal(f.logout,0);});
test('unmarked 401 does not refresh or log out',async()=>{const f=fixture();await assert.rejects(f.handle(f.err('device')));assert.equal(f.refreshes,0);assert.equal(f.logout,0)});
test('refresh timeout preserves session and does not replay writes',async()=>{const f=fixture();const p=f.handle(f.err());f.reject(new Error('timeout'));await assert.rejects(p);assert.equal(f.logout,0);assert.equal(f.state.accessToken,'a1');assert.equal(f.replays.length,0)});
test('invalid refresh logs out once',async()=>{const f=fixture();const p=f.handle(f.err()),q=f.handle(f.err());f.reject({response:{status:401}});await Promise.allSettled([p,q]);assert.equal(f.logout,1);assert.equal(f.replays.length,0)});
test('logout and login during refresh cannot resurrect prior session',async()=>{const f=fixture();const p=f.handle(f.err());f.signOut();f.login();f.resolve({data:{access_token:'a2',refresh_token:'r2'}});await assert.rejects(p);assert.equal(f.state.accessToken,'newLogin');assert.equal(f.replays.length,0)});
test('late 401 from old token reuses current token without new refresh',async()=>{const f=fixture();const e=f.err(),later=f.err();const p=f.handle(e);f.resolve({data:{access_token:'a2',refresh_token:'r2'}});await p;await f.handle(later);assert.equal(f.refreshes,1);assert.equal(f.replays.length,2)});
test('retried 401 is never replayed again',async()=>{const f=fixture();const e=f.err();e.config._sessionRetried=true;await assert.rejects(f.handle(e));assert.equal(f.refreshes,0)});

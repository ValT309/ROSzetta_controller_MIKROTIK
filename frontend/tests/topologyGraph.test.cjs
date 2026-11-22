// Compile src/utils/topologyGraph.ts with tsc --module commonjs --target es2022, then pass the JS path.
const test=require('node:test'),assert=require('node:assert/strict');
const {portRate,edgeKey,loadGraph,visibleEdges}=require(process.env.TOPOLOGY_UTIL||'../src/utils/topologyGraph.js');
const sample=(rx='90071992547409930',tx='12',t=100000,u=100)=>({rx,tx,running:true,speed:'1G',sampled_at_ms:t,uptime:u});
test('precise rates above safe integer',()=>assert.deepEqual(portRate(sample(),sample('90071992548409930','1000012',110000,110)),{rx:800000,tx:800000,seconds:10}));
test('counter reset',()=>assert.equal(portRate(sample(),sample('42','20',110000,110)),null));
test('reboot',()=>assert.equal(portRate(sample(),sample('90071992548409930','1000012',110000,2)),null));
test('invalid interval',()=>assert.equal(portRate(sample(),sample('90071992548409930','1000012',100000,100)),null));
test('old samples',()=>assert.equal(portRate(sample(),sample('90071992548409930','1000012',1000000,1000)),null));
test('missing uptime',()=>assert.equal(portRate(sample(),sample('90071992548409930','1000012',110000,null)),null));
test('link down',()=>assert.equal(portRate(sample(),{...sample(),running:false}),null));
test('bad counter',()=>assert.equal(portRate(sample(),sample('xxx','12',110000,110)),null));
test('edge key orientation independent',()=>assert.equal(edgeKey({a:'d1',b:'d2',a_port:'p1',b_port:'p2'}),edgeKey({a:'d2',b:'d1',a_port:'p2',b_port:'p1'})));
test('parallel edges distinct',()=>assert.notEqual(edgeKey({a:'d1',b:'d2',a_port:'p1',b_port:'p2'}),edgeKey({a:'d1',b:'d2',a_port:'p2',b_port:'p1'})));
test('invalid local storage',()=>assert.deepEqual(loadGraph('broken'),{positions:{},manual:[]}));
test('loaded position constraints',()=>assert.deepEqual(loadGraph(JSON.stringify({positions:{d1:{cx:100,y:100},d2:{cx:-1,y:100},bad:{cx:100,y:100}}})).positions,{d1:{cx:100,y:100}}));
test('manual source only',()=>assert.equal(loadGraph(JSON.stringify({manual:[{a:'d1',b:'d2',a_port:null,b_port:null,evidence:'manual'},{a:'d1',b:'d2',a_port:null,b_port:null,evidence:'confirmed'}]})).manual.length,1));

test('physical excludes logical and MAC',()=>assert.deepEqual(visibleEdges(['confirmed','neighbor','fdb','manual'].map(evidence=>({evidence})),'physical').map(e=>e.evidence),['confirmed','manual']));
test('logical excludes MAC',()=>assert.deepEqual(visibleEdges(['confirmed','neighbor','fdb'].map(evidence=>({evidence})),'logical').map(e=>e.evidence),['confirmed','neighbor']));
test('full preserves observations',()=>assert.equal(visibleEdges(['confirmed','neighbor','fdb'].map(evidence=>({evidence})),'full').length,3));

test('one-way LLDP visible in physical, VPN only logical',()=>{const edges=['confirmed','probable','neighbor','vpn','fdb'].map(evidence=>({evidence}));assert.deepEqual(visibleEdges(edges,'physical').map(e=>e.evidence),['confirmed','probable']);assert.deepEqual(visibleEdges(edges,'logical').map(e=>e.evidence),['confirmed','probable','neighbor','vpn']);});

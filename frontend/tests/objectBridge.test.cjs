const assert=require('node:assert/strict');
const path=require('node:path');
const libs=process.argv[2];
const {bridgeNetwork,defaultBridge}=require(path.join(libs,'objectBridge.js'));
const {buildRouting}=require(path.join(libs,'objectRouting.js'));
const {buildDns,defaultDns}=require(path.join(libs,'objectDns.js'));
const native={...defaultBridge(),enabled:true,address:'10.180.10.1/23'};
const bridge=bridgeNetwork(native);
const base={wanMode:'dhcp',wanPort:'ether1',vlans:[],ports:[{name:'ether1'}],tunnels:[{enabled:true,name:'l2tp-test',server:'vpn.example.com',user:'test',password:'test',ipsecSecret:'',ospfKey:'',cost:'10'}],routerId:'10.0.0.99',area:'backbone',profile:'standard',management:'10.180.10.10/32',guests:'',corporate:'',bridge};
let n=0;function test(label,fn){fn();n++;console.log('PASS '+label)}
test('bridge defaults and canonical subnet',()=>{assert.equal(bridgeNetwork(defaultBridge()),undefined);assert.deepEqual(bridge,{subnet:'10.180.10.0/23',gateway:'10.180.10.1',ospf:true});assert.equal(bridgeNetwork({...native,address:'10.0.0.999/23'}),undefined);});
test('native LAN and passive OSPF',()=>{const r=buildRouting(base);assert.deepEqual(r.errors,[]);assert.match(r.config,/list=LAN interface=bridge-lan/);assert.match(r.config,/interfaces=bridge-lan passive/);assert.match(r.config,/action=masquerade out-interface-list=WAN/);});
test('OSPF opt out',()=>assert.doesNotMatch(buildRouting({...base,bridge:{...bridge,ospf:false}}).config,/interfaces=bridge-lan passive/));
test('loopback collision',()=>assert(buildRouting({...base,loopbackAddress:'10.180.10.7/32'}).errors.length));
test('non RFC1918 bridge is in CORP_LAN',()=>assert.match(buildRouting({...base,bridge:{subnet:'198.51.100.0/24',gateway:'198.51.100.1',ospf:true}}).config,/list=CORP_LAN address=198\.51\.100\.0\/24/));
test('DNS firewall bridge input TCP and UDP',()=>{const r=buildDns(defaultDns(),'77.88.8.8,8.8.4.4',[],'','standard',[],bridge);assert.deepEqual(r.errors,[]);assert.equal(r.inputRules.length,2);assert(r.inputRules.every(x=>x.includes('in-interface=bridge-lan src-address=10.180.10.0/23')));assert(r.inputRules.some(x=>x.includes('protocol=tcp')));});
test('disabled split DNS no bridge rules',()=>{assert.deepEqual(buildDns({...defaultDns(),splitDns:false},'77.88.8.8,8.8.4.4',[],'','standard',[],bridge).inputRules,[]);});
console.log(`${n} tests passed`);

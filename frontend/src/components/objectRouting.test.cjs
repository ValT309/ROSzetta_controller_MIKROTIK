// Run: tsc objectRouting.ts --target ES2020 --module commonjs --outDir /tmp/roszetta-v03-test
// node objectRouting.test.cjs /tmp/roszetta-v03-test/objectRouting.js
const assert = require('node:assert/strict');
const {buildRouting,rosQuote,validIPv4,suggestPool}=require(process.argv[2]);
const base={wanMode:'dhcp',wanPort:'ether1',vlans:[{id:'60',subnet:'192.168.60.0/24'},{id:'140',subnet:'192.168.140.0/24'}],ports:[{name:'ether1'}],tunnels:[],routerId:'',area:'backbone',profile:'standard',management:'192.168.60.10/32',guests:'140',corporate:''};
const tunnel=(i,cost)=>({name:'l2tp-central-'+i,server:'vpn'+i+'.example.com',user:'test',password:'test',ipsecSecret:'test',ospfKey:'test',cost:String(cost)});
let n=0;const test=(name,fn)=>{fn(); console.log('PASS '+name);n++};
test('IPv4 firewall and DHCP WAN',()=>{const r=buildRouting(base);assert.deepEqual(r.errors,[]);assert.match(r.config,/list=WAN interface=ether1/);assert.match(r.config,/src-port=67 dst-port=68/);assert.match(r.config,/masquerade out-interface-list=WAN/)});
test('guest policy before general forwarding',()=>{const c=buildRouting(base).config;assert(c.indexOf('action=drop in-interface-list=GUEST dst-address-list=CORP_LAN')<c.indexOf('action=accept in-interface-list=LAN out-interface-list=WAN'));assert.match(c,/action=drop out-interface-list=GUEST/)});
test('PPPoE logical WAN',()=>assert.match(buildRouting({...base,wanMode:'pppoe'}).config,/list=WAN interface=pppoe-out1/));
test('dual VPN and passive OSPF excluding guest',()=>{const r=buildRouting({...base,routerId:'10.0.0.1',tunnels:[tunnel(1,10),tunnel(2,100)]});assert.deepEqual(r.errors,[]);assert.match(r.config,/cost=100/);assert.match(r.config,/interfaces=vlan60 passive/);assert.doesNotMatch(r.config,/interfaces=vlan140 passive/);assert.match(r.config,/auth=md5 auth-id=1 auth-key=/)});
test('optional PSK and OSPF key',()=>{const r=buildRouting({...base,routerId:'10.0.0.1',tunnels:[{...tunnel(1,10),ipsecSecret:'',ospfKey:''}]});assert.deepEqual(r.errors,[]);assert.match(r.config,/use-ipsec=no/);assert.doesNotMatch(r.config,/ipsec-secret=|auth=md5|ROSZETTA_VPN_PEERS/);assert.match(r.config,/type=ptp cost=10/);});
test('address lists compact and peers deduplicated',()=>{const r=buildRouting({...base,corporate:'10.180.0.0/24,192.168.1.0/24,203.0.113.0/24,203.0.113.5',tunnels:[tunnel(1,10),{...tunnel(2,100),server:'VPN1.EXAMPLE.COM'}],routerId:'10.0.0.1'});assert.deepEqual(r.errors,[]);assert.equal(r.config.split('add list=CORP_LAN address=').length-1,4);assert.equal(r.config.split('add list=ROSZETTA_VPN_PEERS address=').length-1,1);});
test('reverse OSPF cost rejected',()=>assert(buildRouting({...base,routerId:'10.0.0.1',tunnels:[tunnel(1,100),tunnel(2,10)]}).errors.length));
test('invalid IP and guest VLAN rejected',()=>{assert(!validIPv4('999.1.1.1'));assert(buildRouting({...base,guests:'999'}).errors.length)});
test('management required',()=>assert(buildRouting({...base,management:''}).errors.length));
test('strict profile does not permit new VPN to LAN',()=>assert.doesNotMatch(buildRouting({...base,profile:'strict'}).config,/action=accept in-interface-list=VPN out-interface-list=LAN/));
test('escaping dollar quotes backslash',()=>assert.equal(rosQuote('a$"\\b'),'"a\\$\\"\\\\b"'));
test('disabled tunnel ignores stale credentials',()=>assert.doesNotMatch(buildRouting({...base,tunnels:[{...tunnel(1,10),enabled:false}]}).config,/l2tp-client add/));
test('enabled empty tunnel blocks export',()=>assert(buildRouting({...base,tunnels:[{...tunnel(1,10),enabled:true,server:'',user:'',password:'',ipsecSecret:''}]}).errors.length));
test('pool excludes gateway',()=>assert.deepEqual(suggestPool('192.168.60.0/24','192.168.60.1'),{poolStart:'192.168.60.2',poolEnd:'192.168.60.254'}));
test('pool /30 and invalid inputs',()=>{assert.deepEqual(suggestPool('10.0.0.0/30','10.0.0.2'),{poolStart:'10.0.0.1',poolEnd:'10.0.0.1'});assert.equal(suggestPool('10.0.0.0/31','10.0.0.1'),null);assert.equal(suggestPool('10.0.0.0/24','10.0.1.1'),null)});
test('loopback and passive OSPF with automatic router ID',()=>{const r=buildRouting({...base,loopbackAddress:'10.0.0.50/32',tunnels:[tunnel(1,10)]});assert.deepEqual(r.errors,[]);assert.match(r.config,/address=10.0.0.50\/32 interface=lo/);assert.match(r.config,/router-id=10.0.0.50/);assert.match(r.config,/interfaces=lo passive/)});
test('loopback without OSPF',()=>{const r=buildRouting({...base,loopbackAddress:'10.0.0.50'});assert.deepEqual(r.errors,[]);assert.match(r.config,/interface=lo/);assert.doesNotMatch(r.config,/ospf instance add/)});
test('loopback address and subnet validation',()=>{for(const ip of ['10.0.0.1/24','192.168.0.1','10.999.0.1','10.0.0.1;bad'])assert(buildRouting({...base,loopbackAddress:ip}).errors.length);assert(buildRouting({...base,loopbackAddress:'10.0.0.50',vlans:[...base.vlans,{id:'20',subnet:'10.0.0.0/24'}]}).errors.length)});
test('loopback name reserved and static WAN collision',()=>{assert(buildRouting({...base,ports:[{name:'lo'}]}).errors.length);assert(buildRouting({...base,loopbackAddress:'10.0.0.50',wanMode:'static',wanAddress:'10.0.0.1/24'}).errors.length)});
console.log(`${n} tests passed`);

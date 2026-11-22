const assert=require('node:assert/strict');const p=require(process.argv[2]);const h=require(process.argv[3]);
assert.equal(p.profileLabel('production'),'Стройка');assert.equal(p.profileLabel('retail'),'Отдел продаж');
assert(p.recommendedRoles('office').some(x=>x.name==='guest'));assert(!p.recommendedRoles('production').some(x=>x.name==='guest'));assert(!p.recommendedRoles('retail').some(x=>x.name==='access-control'));
assert.deepEqual(p.planProfile('office',[{id:'60',name:'video'}],{video:'61',users:'120',guest:'140'}),[{id:'120',name:'users'},{id:'140',name:'guest'}]);
assert.throws(()=>p.planProfile('office',[{id:'60',name:'video'}],{users:'060'}));assert.throws(()=>p.planProfile('office',[],{users:'120',guest:'120'}));assert.throws(()=>p.planProfile('office',[],{users:'4095'}));assert.deepEqual(p.planProfile('warehouse',[],{guest:'140'}),[]);
assert.deepEqual(p.vpnServers,['vpngate1.gk-nvm.ru','vpngate2.gk-nvm.ru']);
const config=h.buildHardening('standard','10.40.0.0/16');assert.match(config,/name=api\] address=10.40.0.0\/16/);assert.match(config,/mac-winbox set allowed-interface-list=none/);assert.match(config,/ipv6 firewall filter add chain=forward action=drop/);assert.equal(h.buildHardening('custom','10.40.0.0/16'),'');assert.equal(h.buildHardening('standard','0.0.0.0/0'),'');console.log('16 assertions passed');

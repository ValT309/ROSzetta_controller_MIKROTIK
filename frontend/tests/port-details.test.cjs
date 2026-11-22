// node frontend/tests/port-details.test.cjs (typescript required; npm install in frontend)
const fs=require('node:fs'), path=require('node:path'), test=require('node:test'), assert=require('node:assert/strict');
const ts=require('typescript');
const source=fs.readFileSync(path.join(__dirname,'../src/components/portDetails.ts'),'utf8');
const mod={exports:{}};new Function('exports','module',ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS}}).outputText)(mod.exports,mod);
const {findPort,isWiredPort,portState,formatBytes}=mod.exports;
const p=(name,extra={})=>({name,type:'ether',running:true,disabled:false,rx_bytes:0,tx_bytes:0,...extra});
test('factory name wins over renamed port',()=>assert.equal(findPort([p('ether1',{default_name:'ether2'}),p('WAN',{default_name:'ether1'})],'ether1').name,'WAN'));
test('known different factory name is not guessed',()=>assert.equal(findPort([p('ether1',{default_name:'ether2'})],'ether1'),undefined));
test('legacy exact and suffix',()=>{assert.equal(findPort([p('ether1-WAN')],'ether1').name,'ether1-WAN');assert.equal(findPort([p('ether1-WAN'),p('ether1')],'ether1').name,'ether1')});
test('ether10 is not ether1',()=>assert.equal(findPort([p('ether10')],'ether1'),undefined));
test('ambiguous prefix ignored',()=>assert.equal(findPort([p('ether1-WAN'),p('ether1-LAN')],'ether1'),undefined));
test('duplicate factory name ignored',()=>assert.equal(findPort([p('A',{default_name:'ether1'}),p('B',{default_name:'ether1'})],'ether1'),undefined));
test('logical interface cannot impersonate physical port',()=>assert.equal(findPort([p('ether1',{type:'vlan'})],'ether1'),undefined));
test('wired port types',()=>{for(const type of ['ether','ethernet','sfp','qsfp'])assert.equal(isWiredPort(p('x',{type})),true);for(const type of ['vlan','bridge','wlan',null])assert.equal(isWiredPort(p('x',{type})),false)});
test('link flags and unknown',()=>{assert.equal(portState(p('x')),'Link UP');assert.equal(portState(p('x',{running:false})),'Link Down');assert.equal(portState(p('x',{disabled:true})),'Отключён');assert.equal(portState(undefined),'Нет данных')});
test('counter units and invalid data',()=>{assert.equal(formatBytes(0),'0 Б');assert.equal(formatBytes(1024),'1.0 КиБ');assert.equal(formatBytes(1048576),'1.0 МиБ');assert.equal(formatBytes(-1),'—');assert.equal(formatBytes(NaN),'—')});

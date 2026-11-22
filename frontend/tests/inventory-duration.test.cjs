const test=require('node:test'),assert=require('node:assert/strict');
const {formatDuration,displayAlertMessage}=require(process.env.DURATION_UTIL);
const {filterAutomationDevices,initialDeviceFilters}=require(process.env.AUTOMATION_UTIL);
test('historical alert',()=>assert.equal(displayAlertMessage('uptime 62725s → 668s'),'Время работы: 17 ч 25 мин 25 с → 11 мин 8 с'));
test('non-uptime alert unchanged',()=>assert.equal(displayAlertMessage('TCP 22 timeout'),'TCP 22 timeout'));
test('days and zero',()=>{assert.equal(formatDuration(90061),'1 д 1 ч 1 мин 1 с');assert.equal(formatDuration(0),'0 с')});
test('bad durations',()=>{assert.equal(formatDuration(-1),'—');assert.equal(formatDuration(NaN),'—')});
test('search inventory fields',()=>{const devices=[{id:1,name:'a',host:'192.0.2.1',location:'Серверная',purpose:'Шлюз',inventory_number:'IT-32',comment:'Стойка №3'},{id:2,name:'b',host:'192.0.2.2'}];for(const search of ['серверная','шлюз','it-32','стойка'])assert.deepEqual(filterAutomationDevices(devices,[],{...initialDeviceFilters,search}).map(d=>d.id),[1]);});

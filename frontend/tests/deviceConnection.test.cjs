const {test}=require('node:test');const assert=require('node:assert/strict');const ts=require('typescript');const fs=require('fs');const path=require('path');
const code=ts.transpileModule(fs.readFileSync(path.join(__dirname,'../src/utils/deviceConnection.ts'),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS}}).outputText;
const mod={exports:{}};new Function('exports','module',code)(mod.exports,mod);
const {portForTLS,normalizePin}=mod.exports;
test('standard API -> API-SSL',()=>assert.equal(portForTLS(8728,true),8729));
test('standard API-SSL -> API',()=>assert.equal(portForTLS(8729,false),8728));
test('custom port preserved',()=>assert.equal(portForTLS(18728,true),18728));
test('normalizes hex fingerprint',()=>assert.equal(normalizePin(' AA:BB '),'aabb'));
test('accepts SHA256 prefix',()=>assert.equal(normalizePin('SHA256: AA:BB'),'aabb'));

// In-memory byte fixtures only: no file, driver, DLL, subprocess or network operations.
import test from 'node:test';
import assert from 'node:assert/strict';
import observed from './apiset-observed-hosts.json' with {type:'json'};
import {parseApiSetSchemaPE,inspectPEBytes} from './pe.mjs';

const contract='api-ms-win-core-synthetic-l1-1-0';
function schemaPE(rows=[{contract,values:[{alias:'',host:'kernelbase.dll'}]}]) {
  const values=rows.reduce((sum,row)=>sum+row.values.length,0);
  const textBytes=rows.reduce((sum,row)=>sum+Buffer.byteLength(row.contract,'utf16le')+row.values.reduce((n,value)=>n+Buffer.byteLength(value.alias,'utf16le')+Buffer.byteLength(value.host,'utf16le'),0),0);
  const size=28+rows.length*24+values*20+textBytes, raw=512;
  const bytes=Buffer.alloc(raw+size);bytes.write('MZ');bytes.writeUInt32LE(0x80,0x3c);bytes.write('PE\0\0',0x80);
  bytes.writeUInt16LE(0x8664,0x84);bytes.writeUInt16LE(1,0x86);bytes.writeUInt16LE(240,0x94);bytes.writeUInt16LE(0x20b,0x98);
  bytes.writeBigUInt64LE(0x140000000n,0xb0);bytes.writeUInt32LE(raw,0xd4);bytes.writeUInt32LE(16,0x104);
  const section=0x188;bytes.write('.apiset',section);bytes.writeUInt32LE(0x1000,section+12);bytes.writeUInt32LE(size,section+16);bytes.writeUInt32LE(raw,section+20);
  bytes.writeUInt32LE(6,raw);bytes.writeUInt32LE(size,raw+4);bytes.writeUInt32LE(rows.length,raw+12);bytes.writeUInt32LE(28,raw+16);
  let valueAt=28+rows.length*24,textAt=valueAt+values*20;
  const text=value=>{const data=Buffer.from(value,'utf16le'),at=textAt;data.copy(bytes,raw+at);textAt+=data.length;return [at,data.length];};
  const entries=[];
  for(const [index,row] of rows.entries()) {
    const at=raw+28+index*24,[nameAt,nameLength]=text(row.contract);
    bytes.writeUInt32LE(nameAt,at+4);bytes.writeUInt32LE(nameLength,at+8);bytes.writeUInt32LE(nameLength,at+12);
    bytes.writeUInt32LE(valueAt,at+16);bytes.writeUInt32LE(row.values.length,at+20);
    const valueOffsets=[];
    for(const value of row.values) {
      const v=raw+valueAt,[aliasAt,aliasLength]=text(value.alias),[hostAt,hostLength]=text(value.host);
      bytes.writeUInt32LE(aliasAt,v+4);bytes.writeUInt32LE(aliasLength,v+8);bytes.writeUInt32LE(hostAt,v+12);bytes.writeUInt32LE(hostLength,v+16);
      valueOffsets.push(v);valueAt+=20;
    }
    entries.push({at,values:valueOffsets});
  }
  return {bytes,raw,section,entries};
}
function one(host,alias='',name=contract) { return schemaPE([{contract:name,values:[{alias,host}]}]); }
function valuesOf(fixture,name=contract) { return parseApiSetSchemaPE(fixture.bytes).get(name.toLowerCase()+'.dll').values; }

assert.equal(observed.cases.length,32);
for(const row of observed.cases) test(`observed .sys host ${row.entryIndex}:${row.valueIndex} ${row.host}`,()=>{
  assert.deepEqual(valuesOf(one(row.host,'',row.contract),row.contract),[{alias:'',host:row.host.toLowerCase()}]);
});
test('all retained names in one bounded synthetic namespace',()=>{
  const result=parseApiSetSchemaPE(schemaPE(observed.cases.map(row=>({contract:row.contract,values:[{alias:'',host:row.host}]}))).bytes);
  assert.equal(result.size,32);
});
test('host values normalize case while DLL aliases stay separate',()=>{
  assert.deepEqual(valuesOf(one('Win32kBase.SYS','Importer.DLL')),[{alias:'importer.dll',host:'win32kbase.sys'}]);
});
test('DLL hosts and empty/stub fields retain their prior values',()=>{
  assert.deepEqual(valuesOf(one('KERNELBASE.DLL','Importer.DLL')),[{alias:'importer.dll',host:'kernelbase.dll'}]);
  assert.deepEqual(valuesOf(one('')),[{alias:'',host:''}]);
});
for(const host of ['driver.exe','winspool.drv','driver.sys.exe','driver','driver.sys/other.dll','../driver.sys','..\\driver.sys','C:driver.sys','driver.sys ',' driver.sys','driver\0.sys','drivér.sys','driver\u0130.sys']) {
  test(`invalid API-set host ${JSON.stringify(host)}`,()=>assert.throws(()=>valuesOf(one(host))));
}
for(const alias of ['driver.sys','driver.exe','../importer.dll','..\\importer.dll','C:importer.dll','importer.dll ','importer\0.dll']) {
  test(`DLL alias guard ${JSON.stringify(alias)}`,()=>assert.throws(()=>valuesOf(one('win32kbase.sys',alias))));
}
for(const name of ['kernelbase','api-../bad','ext-bad.dll','api-bad\0name']) {
  test(`contract-name guard ${JSON.stringify(name)}`,()=>assert.throws(()=>valuesOf(one('kernelbase.dll','',name),name)));
}
const mutations=[
  ['truncated PE header',f=>{f.bytes=f.bytes.subarray(0,63);} ],
  ['zero PE sections',f=>f.bytes.writeUInt16LE(0,0x86)],
  ['over-budget PE sections',f=>f.bytes.writeUInt16LE(97,0x86)],
  ['missing API-set section',f=>f.bytes.write('.other\0\0',f.section)],
  ['duplicate API-set sections',f=>{f.bytes.writeUInt16LE(2,0x86);f.bytes.copy(f.bytes,f.section+40,f.section,f.section+40);} ],
  ['section outside file',f=>f.bytes.writeUInt32LE(0xfffffff0,f.section+20)],
  ['unsupported namespace version',f=>f.bytes.writeUInt32LE(7,f.raw)],
  ['undersized namespace',f=>f.bytes.writeUInt32LE(27,f.raw+4)],
  ['namespace outside section',f=>f.bytes.writeUInt32LE(f.bytes.length,f.raw+4)],
  ['zero namespace entries',f=>f.bytes.writeUInt32LE(0,f.raw+12)],
  ['over-budget namespace entries',f=>f.bytes.writeUInt32LE(16385,f.raw+12)],
  ['entry table outside namespace',f=>f.bytes.writeUInt32LE(0xfffffff0,f.raw+16)],
  ['zero value count',f=>f.bytes.writeUInt32LE(0,f.entries[0].at+20)],
  ['over-budget values',f=>f.bytes.writeUInt32LE(65,f.entries[0].at+20)],
  ['value table outside namespace',f=>f.bytes.writeUInt32LE(0xfffffff0,f.entries[0].at+16)],
  ['odd UTF-16 host length',f=>f.bytes.writeUInt32LE(3,f.entries[0].values[0]+16)],
  ['UTF-16 host outside namespace',f=>f.bytes.writeUInt32LE(0xfffffff0,f.entries[0].values[0]+12)],
  ['truncated schema body',f=>{f.bytes=f.bytes.subarray(0,-1);} ],
];
for(const [name,mutate] of mutations) test(name,()=>{const fixture=one('kernelbase.dll');mutate(fixture);assert.throws(()=>parseApiSetSchemaPE(fixture.bytes));});
test('duplicate contract names after case normalization are rejected',()=>{
  assert.throws(()=>parseApiSetSchemaPE(schemaPE([{contract,values:[{alias:'',host:'kernelbase.dll'}]},{contract:contract.toUpperCase(),values:[{alias:'',host:'kernelbase.dll'}]}]).bytes),/Duplicate/);
});
test('64 values remain admissible',()=>{
  const rows=[{contract,values:Array.from({length:64},()=>({alias:'',host:'kernelbase.dll'}))}];
  assert.equal(parseApiSetSchemaPE(schemaPE(rows).bytes).get(contract+'.dll').values.length,64);
});
test('text length budget is preserved at and beyond its boundary',()=>{
  const maximum='api-'+ 'a'.repeat(1020);
  assert.equal(parseApiSetSchemaPE(one('kernelbase.dll','',maximum).bytes).size,1);
  assert.throws(()=>parseApiSetSchemaPE(one('kernelbase.dll','',maximum+'a').bytes));
});

function importPE(normal='kernel32.dll',delayed='user32.dll') {
  const bytes=Buffer.alloc(2048);bytes.write('MZ');bytes.writeUInt32LE(0x80,0x3c);bytes.write('PE\0\0',0x80);
  bytes.writeUInt16LE(0x8664,0x84);bytes.writeUInt16LE(1,0x86);bytes.writeUInt16LE(240,0x94);bytes.writeUInt16LE(0x20b,0x98);
  bytes.writeBigUInt64LE(0x140000000n,0xb0);bytes.writeUInt32LE(512,0xd4);bytes.writeUInt32LE(16,0x104);
  bytes.write('.rdata',0x188);bytes.writeUInt32LE(0x1000,0x194);bytes.writeUInt32LE(1536,0x198);bytes.writeUInt32LE(512,0x19c);
  bytes.writeUInt32LE(0x1000,0x108+8);bytes.writeUInt32LE(40,0x108+12);bytes.writeUInt32LE(0x1100,512+12);
  bytes.writeUInt32LE(0x1040,0x108+13*8);bytes.writeUInt32LE(64,0x108+13*8+4);bytes.writeUInt32LE(1,512+64);bytes.writeUInt32LE(0x1200,512+68);
  Buffer.from(normal+'\0','utf8').copy(bytes,512+256);Buffer.from(delayed+'\0','utf8').copy(bytes,512+512);
  return bytes;
}
test('ordinary and delayed DLL imports retain their exact lists',()=>{
  const result=inspectPEBytes(importPE('KERNEL32.DLL','USER32.DLL'));
  assert.deepEqual(result.imports,['KERNEL32.DLL']);assert.deepEqual(result.delayImports,['USER32.DLL']);assert.equal(result.machine,'x64');
});
test('the pre-existing named winspool.drv import exception remains supported',()=>{
  const result=inspectPEBytes(importPE('winspool.drv','WINSPOOL.DRV'));
  assert.deepEqual(result.imports,['winspool.drv']);assert.deepEqual(result.delayImports,['WINSPOOL.DRV']);
});
for(const name of ['win32kbase.sys','program.exe','other.drv','../bad.dll','..\\bad.dll','C:bad.dll','bad.dll ','bad.dll\u0080']) {
  for(const kind of ['ordinary','delayed']) test(`${kind} import guard ${JSON.stringify(name)}`,()=>{
    assert.throws(()=>inspectPEBytes(kind==='ordinary'?importPE(name,'user32.dll'):importPE('kernel32.dll',name)));
  });
}
test('import directory bounds, terminators and delayed attributes remain guarded',()=>{
  let bytes=importPE();bytes.writeUInt32LE(19,0x108+12);assert.throws(()=>inspectPEBytes(bytes),/directory/);
  bytes=importPE();bytes.writeUInt32LE(20,0x108+12);assert.throws(()=>inspectPEBytes(bytes),/terminator/);
  bytes=importPE();bytes.writeUInt32LE(2,512+64);assert.throws(()=>inspectPEBytes(bytes),/attributes/);
});

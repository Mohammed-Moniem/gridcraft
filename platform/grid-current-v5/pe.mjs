import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

// Byte inspection only: this module never loads or executes the PE file.
export function inspectPEBytes(b) {
  const bounds = (offset, count) => { assert(Number.isSafeInteger(offset) && offset >= 0 && offset + count <= b.length, 'PE offset outside file'); return offset; };
  const u16 = offset => b.readUInt16LE(bounds(offset, 2));
  const u32 = offset => b.readUInt32LE(bounds(offset, 4));
  assert.equal(b.subarray(0, 2).toString(), 'MZ', 'Missing MZ header');
  const pe = u32(0x3c); assert.equal(b.subarray(pe, pe + 4).toString('hex'), '50450000', 'Missing PE signature');
  const machineCode = u16(pe + 4), sections = u16(pe + 6), optionalSize = u16(pe + 20), optional = pe + 24;
  const magic = u16(optional); assert([0x10b, 0x20b].includes(magic), 'Unsupported PE optional header');
  const bits = magic === 0x20b ? 64 : 32;
  const imageBase = bits === 64 ? Number(b.readBigUInt64LE(bounds(optional + 24, 8))) : u32(optional + 28);
  const numberOfDirs = u32(optional + (bits === 64 ? 108 : 92));
  const dirs = optional + (bits === 64 ? 112 : 96);
  const table = optional + optionalSize;
  assert(optionalSize >= (bits === 64 ? 112 : 96) + numberOfDirs * 8, 'PE data directories exceed optional header');
  bounds(table, sections * 40);
  const headerSize = u32(optional + 60);
  bounds(0, headerSize);
  const backed = [{ start: 0, end: headerSize, raw: 0 }];
  for (let n = 0; n < sections; n++) {
    const p = table + n * 40, size = u32(p + 16), start = u32(p + 12), raw = u32(p + 20);
    if (!size) continue;
    bounds(raw, size);
    assert(start + size <= 0x100000000, 'PE section RVA wraps');
    backed.push({ start, end: start + size, raw });
  }
  backed.sort((a, b) => a.start - b.start);
  for (let n = 1; n < backed.length; n++) assert(backed[n].start >= backed[n - 1].end, 'Overlapping PE RVA-backed ranges');
  const rva = (value, count = 1) => {
    for (const section of backed) if (value >= section.start && value + count <= section.end) return bounds(section.raw + value - section.start, count);
    throw new Error(`Unmapped PE RVA ${value}`);
  };
  const string = value => {
    const start = rva(value); let count = 0;
    while (count < 1024 && b[rva(value + count)] !== 0) count++;
    assert(count < 1024, 'Unterminated PE import name');
    rva(value, count + 1); // Require the whole name and terminator in one backed range.
    for (const byte of b.subarray(start, start + count)) {
      assert((byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57) || byte === 95 || byte === 46 || byte === 45, 'Invalid raw byte in PE import DLL name');
    }
    const name = b.toString('ascii', start, start + count);
    // Windows exposes its documented print spooler imports from winspool.drv.
    // Keep this named OS module exception narrower than arbitrary suffixes.
    assert(/^[a-zA-Z0-9_.-]+\.dll$/i.test(name) || /^winspool\.drv$/i.test(name), `Invalid import DLL name ${name}`); return name;
  };
  const imports = (index, stride, delayed = false) => {
    if (numberOfDirs <= index) return [];
    const address = u32(dirs + index * 8), size = u32(dirs + index * 8 + 4);
    if (!address && !size) return [];
    assert(address && size >= stride, 'Invalid PE import directory address or size');
    const out = []; rva(address, size);
    for (let n = 0; (n + 1) * stride <= size; n++) {
      const p = rva(address + n * stride, stride);
      if (b.subarray(p, p + stride).every(value => value === 0)) return [...new Set(out)].sort();
      let name = u32(p + (delayed ? 4 : 12));
      if (delayed) assert([0, 1].includes(u32(p)), 'Unsupported delay-import attributes');
      if (delayed && !(u32(p) & 1)) name -= imageBase;
      try { out.push(string(name)); } catch (error) { throw new Error(`PE import index ${index}, descriptor ${n}, name RVA ${name}: ${error.message}`); }
    }
    throw new Error('PE import table lacks terminator within declared size');
  };
  return { size: b.length, sha256: createHash('sha256').update(b).digest('hex'), machine: ({ 0x8664: 'x64', 0x14c: 'x86', 0xaa64: 'arm64' })[machineCode] ?? `unknown-${machineCode}`, machineCode: `0x${machineCode.toString(16)}`, bits, imports: imports(1, 20), delayImports: imports(13, 32, true) };
}

export function assertStaticCRT(pe) {
  assert.equal(pe.machine,'x64');assert.equal(pe.bits,64);
  assert.deepEqual([...pe.imports,...pe.delayImports].filter(name=>/^(?:vcruntime|msvcp|concrt|msvcr).*\.dll$/i.test(name)),[],'Microsoft VC runtime dependency remains');
  return true;
}

export function bindWindowsImports(pe,shippedFiles,contract,osRelease) {
  assertStaticCRT(pe);
  assert.equal(contract?.kind,'WINDOWS_TARGET_SYSTEM_MODULE_CONTRACT');assert.equal(contract.selected,true,'Windows system contract is not selected');assert.equal(contract.osRelease,osRelease,'Windows OS identity differs');
  const system=new Map();for(const entry of contract.entries){assert.match(entry.name,/^[a-z0-9_.-]+\.(?:dll|drv)$/);assert(!system.has(entry.name),'Duplicate system module');assert(['system-file','api-set'].includes(entry.kind));system.set(entry.name,entry);}
  const bound=[];for(const name of [...new Set([...pe.imports,...pe.delayImports].map(s=>s.toLowerCase()))]) {
    const siblings=shippedFiles.filter(row=>row.path.toLowerCase()==='bin/'+name);assert(siblings.length<=1,'Ambiguous shipped module');
    if(siblings.length)bound.push({name,source:'shipped-sibling',file:siblings[0]});
    else {const entry=system.get(name);assert(entry,'Unbound Windows import: '+name);if(entry.kind==='system-file'){assert(entry.file);assert.match(entry.file.sha256,/^[a-f0-9]{64}$/);}else {assert(entry.schema&&entry.mappingEvidence&&entry.hostFiles?.length>0,'Missing captured API-set mapping');assert.equal(entry.mappingIndependentlyReviewed,true,'API-set mapping is not reviewed');}bound.push({name,source:'target-system-contract',entry});}
  }
  return bound;
}

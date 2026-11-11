import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

export const LIMITS=Object.freeze({fileBytes:4*1024**2,sections:96,entries:16384,valuesPerEntry:64,totalValues:65536,textBytes:2048,totalTextBytes:32*1024**2,retainedRejections:32});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');

// Data inspection only. No file access, loader, subprocess, network, or production imports.
export function diagnoseSchemaBytes(bytes){
 assert(Buffer.isBuffer(bytes)&&bytes.length<=LIMITS.fileBytes,'DIAG_FILE_LIMIT');
 const bounds=(at,length,limit=bytes.length)=>{assert(Number.isSafeInteger(at)&&Number.isSafeInteger(length)&&at>=0&&length>=0&&at+length<=limit,'DIAG_BOUNDS');return at;};
 const u16=at=>bytes.readUInt16LE(bounds(at,2)),u32=at=>bytes.readUInt32LE(bounds(at,4));
 bounds(0,64);assert.equal(bytes.subarray(0,2).toString('hex'),'4d5a','DIAG_MZ');const pe=u32(0x3c);bounds(pe,24);assert.equal(bytes.subarray(pe,pe+4).toString('hex'),'50450000','DIAG_PE');assert.equal(u16(pe+4),0x8664,'DIAG_X64');
 const count=u16(pe+6),optionalSize=u16(pe+20),optional=pe+24;assert(count>0&&count<=LIMITS.sections,'DIAG_SECTION_COUNT');assert(optionalSize>=2,'DIAG_OPTIONAL_SIZE');bounds(optional,optionalSize);assert.equal(u16(optional),0x20b,'DIAG_PE64');const table=optional+optionalSize;bounds(table,count*40);
 const sections=[];for(let i=0;i<count;i++){const at=table+i*40;if(bytes.subarray(at,at+8).equals(Buffer.from('.apiset\0'))){const raw=u32(at+20),size=u32(at+16);assert(raw>=table+count*40,'DIAG_SECTION_OVERLAPS_HEADERS');assert(size>=28,'DIAG_SECTION_SIZE');bounds(raw,size);sections.push({raw,bytes:size});}}
 assert.equal(sections.length,1,'DIAG_UNIQUE_APISET');const section=sections[0],schema=bytes.subarray(section.raw,section.raw+section.bytes),word=at=>schema.readUInt32LE(bounds(at,4,schema.length));
 assert.equal(word(0),6,'DIAG_NAMESPACE_VERSION');const size=word(4),entries=word(12),offset=word(16);assert(size>=28&&size<=schema.length,'DIAG_NAMESPACE_SIZE');assert(entries>0&&entries<=LIMITS.entries,'DIAG_ENTRY_COUNT');bounds(offset,entries*24,size);
 let textBytes=0,totalValues=0,emptyHosts=0,rejectionCount=0,currentContract=null;const rejected=[],seen=new Set(),counts={text_contains_nul:0,contract_name_shape:0,duplicate_contract:0,alias_name_shape:0,host_name_shape:0};
 const snapshot=value=>({original:value.original,normalized:value.normalized,byteLength:value.raw.length,utf16leHex:value.raw.toString('hex'),codeUnits:Array.from({length:value.raw.length/2},(_,i)=>value.raw.readUInt16LE(i*2)),rawSha256:hash(value.raw)});
 function reject(kind,entry,valueIndex,field,value){counts[kind]++;rejectionCount++;if(rejected.length<LIMITS.retainedRejections)rejected.push({kind,entryIndex:entry,valueIndex,contract:currentContract,field,value:snapshot(value)});}
 function text(at,length,entry,valueIndex,field){bounds(at,length,size);assert(length>0&&length<=LIMITS.textBytes&&length%2===0,'DIAG_TEXT_LENGTH');textBytes+=length;assert(textBytes<=LIMITS.totalTextBytes,'DIAG_TOTAL_TEXT_LIMIT');const raw=schema.subarray(at,at+length),original=raw.toString('utf16le'),value={raw,original,normalized:original.toLowerCase()};if(original.includes('\0'))reject('text_contains_nul',entry,valueIndex,field,value);return value;}
 const empty=()=>({raw:Buffer.alloc(0),original:'',normalized:''});
 for(let i=0;i<entries;i++){
  currentContract=null;const at=offset+i*24,name=text(word(at+4),word(at+8),i,null,'contract');currentContract={original:name.original,normalized:name.normalized};if(!/^(api|ext)-[a-z0-9-]+$/.test(name.normalized))reject('contract_name_shape',i,null,'contract',name);
  const valueAt=word(at+16),valueCount=word(at+20);assert(valueCount>0&&valueCount<=LIMITS.valuesPerEntry,'DIAG_VALUE_COUNT');bounds(valueAt,valueCount*20,size);totalValues+=valueCount;assert(totalValues<=LIMITS.totalValues,'DIAG_TOTAL_VALUE_LIMIT');
  if(seen.has(name.normalized))reject('duplicate_contract',i,null,'contract',name);seen.add(name.normalized);
  for(let j=0;j<valueCount;j++){
   const v=valueAt+j*20,aliasLength=word(v+8),hostLength=word(v+16);
   // Preserve the production parser's order: decode both fields, then check alias, then host.
   const alias=aliasLength?text(word(v+4),aliasLength,i,j,'alias'):empty(),host=hostLength?text(word(v+12),hostLength,i,j,'host'):empty();
   if(alias.normalized&&!/^[a-z0-9_.-]+\.dll$/.test(alias.normalized))reject('alias_name_shape',i,j,'alias',alias);
   if(host.normalized&&!/^[a-z0-9_.-]+\.dll$/.test(host.normalized))reject('host_name_shape',i,j,'host',host);if(!hostLength)emptyHosts++;
  }
 }
 return{kind:'APISET_V6_REJECTED_VALUE_DIAGNOSTIC',file:{bytes:bytes.length,sha256:hash(bytes)},section,namespace:{version:6,bytes:size,entries,values:totalValues,textBytes,emptyHosts},firstRejected:rejected[0]??null,rejectionCount,rejected,rejectionsOmitted:rejectionCount-rejected.length,rejectionCounts:counts,productionRule:'Lowercase ASCII DLL-only alias/host shape; empty fields accepted by that parser',sourceParserWouldStopAtFirstRejection:true,subsequentDiagnosticsDoNotProveProductionReachedThem:true,hashTableOrWindowsLoaderSemanticsValidated:false,sourceRepairSelected:false,hostSelected:false,runtimeQualified:false,fullGoalComplete:false};
}

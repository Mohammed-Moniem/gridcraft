// Fixed pure query plans shared by capture and evidence validation.
import assert from 'node:assert/strict';
import {win32} from 'node:path';
import {PYTHON_FLAGS} from '../grid-current-v5/python-plan.mjs';
export const PYTHON_MODULES=Object.freeze(['gzip','hashlib','json','pathlib','shutil','tarfile','unicodedata','zipfile','lzma','zlib','sysconfig','importlib','bz2','struct']);
export const PYTHON_QUERY=[
 'import gzip,hashlib,json,os,pathlib,shutil,stat,tarfile,unicodedata,zipfile,lzma,zlib,sys,struct,sysconfig,importlib,bz2',
 'records=[]; loaded=set(); caches=set(); directories=set(); optional=set()',
 'for name,module in sorted(list(sys.modules.items())):',
 ' if module is None or name=="__main__": continue',
 ' spec=getattr(module,"__spec__",None); loader=getattr(spec,"loader",None) or getattr(module,"__loader__",None)',
 ' if loader is None: continue',
 ' loader_name=getattr(loader,"__name__",None) if isinstance(loader,type) else type(loader).__name__',
 ' file=getattr(module,"__file__",None); archive=getattr(loader,"archive",None)',
 ' loader_module=sys.modules.get(getattr(loader,"__module__",type(loader).__module__)); loader_file=getattr(loader_module,"__file__",None)',
 // Both fields are retained; module.__cached__ may be absent in Python3.15.
 ' cached=getattr(module,"__cached__",None); spec_cached=getattr(spec,"cached",None)',
 ' if loader_name=="zipimporter": cached=spec_cached=None',
 ' for candidate in [file,loader_file,archive]:',
 '  if candidate and os.path.isfile(candidate): loaded.add(candidate); directories.add(os.path.dirname(candidate))',
 ' for candidate in [cached,spec_cached]:',
 '  if candidate: caches.add(candidate)',
 ' records.append({"name":name,"loader":loader_name,"origin":getattr(spec,"origin",None),"file":file if file and os.path.isfile(file) else None,"loaderFile":loader_file if loader_file and os.path.isfile(loader_file) else None,"archive":archive,"cached":cached,"specCached":spec_cached})',
 'for candidate in sys.path:',
 ' if candidate and os.path.isdir(candidate): directories.add(candidate)',
 ' elif candidate: optional.add(candidate)',
 'for candidate in caches:',
 ' if os.path.isdir(os.path.dirname(candidate)): directories.add(os.path.dirname(candidate))',
 'exe=os.path.realpath(sys.executable); parents={os.path.dirname(exe),os.path.dirname(os.path.dirname(exe)),sys.prefix,sys.base_prefix}',
 'for parent in parents:',
 ' for name in ["pyvenv.cfg","python._pth","python%d%d._pth"%sys.version_info[:2]]: optional.add(os.path.join(parent,name))',
 'library=sysconfig.get_config_var("LDLIBRARY")',
 'if library:',
 ' for parent in parents|{sysconfig.get_config_var("LIBDIR"),sysconfig.get_config_var("BINDIR")}:',
 '  if parent: optional.add(os.path.join(parent,library))',
 'framework=sysconfig.get_config_var("PYTHONFRAMEWORK"); framework_prefix=sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX")',
 'if framework and framework_prefix: optional.add(os.path.join(framework_prefix,framework+".framework","Versions",sysconfig.get_config_var("VERSION"),framework))',
 'print(json.dumps({"version":".".join(map(str,sys.version_info[:3])),"executable":sys.executable,"prefix":sys.prefix,"pycachePrefix":sys.pycache_prefix,"pointerBits":struct.calcsize("P")*8,"isolated":bool(sys.flags.isolated),"noSite":bool(sys.flags.no_site),"bytecodeWritesDisabled":bool(sys.flags.dont_write_bytecode),"modules":'+JSON.stringify(PYTHON_MODULES)+',"loadedFiles":sorted(loaded),"moduleLoaders":records,"cacheCandidates":sorted(caches),"supportCandidates":sorted(optional),"searchDirectoryCandidates":sorted(directories),"runtimeRootCandidates":sorted(set([sys.prefix,sys.base_prefix,sys.exec_prefix,sys.base_exec_prefix])),"importSearchCandidates":list(dict.fromkeys(sys.path))}))'
].join('\n');
export const QUERY_LABELS={mac:['python-isolated-stdlib','mac-developer-path','mac-os-version'],windows:['python-isolated-stdlib','windows-host-registry','vswhere-supported-installations']};
export function queryLabels(target){assert(['macos-arm64','macos-x64','windows-x64'].includes(target));return QUERY_LABELS[target==='windows-x64'?'windows':'mac'];}
export function queryArgs(target,label,packetDirectory) {
 assert(queryLabels(target).includes(label),'Unexpected target query');
 return {'python-isolated-stdlib':[...PYTHON_FLAGS,'-c',PYTHON_QUERY],'mac-developer-path':['-p'],'mac-os-version':[],'windows-host-registry':['-NoProfile','-NonInteractive','-File',win32.join(packetDirectory,'windows-host.ps1')],'vswhere-supported-installations':['-all','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-format','json','-utf8']}[label];
}

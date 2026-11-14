import ast,difflib,hashlib,json,os,pathlib,stat,sys,traceback
B=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-arm-resume-20261114-v1")
O=B/"offline-corrected-inspection-v1";P=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/resume_r1_arm64_cost_artifact_v1.py")
Z=B/"14119000610.complete.zip"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,cap):
 need(p.resolve()==p,"canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,"regular bounded")
  b=f.read(cap+1);z=os.fstat(f.fileno())
 need(ident(a)==ident(z)==ident(p.lstat()) and len(b)==a.st_size,"stable")
 return b,ident(a)
raw,pver=read(P,65536);need(len(raw)==29683 and sha(raw)=="6aec3684388395ae38f6d871f5d764dce419a41ba1c62d425c81dabcb415b3f9","fixed reviewed source")
zr,zver=read(Z,16*1024*1024);need(len(zr)==9927038 and sha(zr)=="8249d0279e12e95bb59da7644b3d62ca1243589f9488b26e3b2b95560c9735ff","official full ZIP")
original_summary,sver=read(B/"summary.json",16384);need(sha(original_summary)=="a8bc3bb1da7b0e049185f0846efd4e71da29cb255fa21b00462a739a57679889","original HOLD")
need(not O.exists(),"create only");O.mkdir(mode=0o700)
def put(name,b):
 p=O/name
 with p.open("xb") as f:f.write(b)
 need(p.read_bytes()==b,"readback")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
put("observe-original-inspection.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
original_raw=raw
old=b"need(kind in (0, stat.S_ISREG, stat.S_IFDIR) and not info.flag_bits & 0x41,"
new=b"need(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not info.flag_bits & 0x41,"
need(raw.count(old)==1,"one exact incorrect type-constant site")
raw=raw.replace(old,new,1)
need(raw.count(new)==1 and raw.replace(new,old,1)==original_raw,"exact one identifier correction")
correction={"original":{"path":str(P),"bytes":len(original_raw),"sha256":sha(original_raw)},"corrected":{"bytes":len(raw),"sha256":sha(raw)},"exact_changed_identifier":"stat.S_ISREG function to stat.S_IFREG regular-file type constant","link_special_and_encryption_guards_unchanged":True,"source_file_not_modified":True}
put("source-correction.json",jb(correction))
put("corrected-validator-source.py",raw)
put("exact-one-identifier.patch","".join(difflib.unified_diff(original_raw.decode().splitlines(True),raw.decode().splitlines(True),fromfile=str(P),tofile="corrected-in-memory-inspector")).encode())
tree=ast.parse(raw)
allowed=(ast.Import,ast.ImportFrom,ast.Assign,ast.AnnAssign,ast.FunctionDef)
nodes=[]
for n in tree.body:
 if isinstance(n,ast.FunctionDef):
  if n.name not in ("main","capture"):nodes.append(n)
 elif isinstance(n,ast.Import):
  keep=[x for x in n.names if x.name not in ("subprocess","selectors","time")]
  if keep:nodes.append(ast.Import(names=keep))
 elif isinstance(n,allowed):nodes.append(n)
 elif isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str):nodes.append(n)
 else:
  need(isinstance(n,ast.If) and ast.get_source_segment(raw.decode(),n).startswith('if __name__ == "__main__":'),"only remove main guard")
module=ast.Module(body=nodes,type_ignores=[]);scope={"__name__":"closed_arm_inspection_only","__file__":str(P)}
exec(compile(ast.fix_missing_locations(module),str(P),"exec",dont_inherit=True,optimize=0),scope)
need("main" not in scope and "capture" not in scope and "subprocess" not in scope,"no main capture or subprocess imported")
scope["OUT"]=O
f=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="inspect_complete_zip")
funcraw=ast.get_source_segment(raw.decode(),f).encode()
put("exact-inspect-function.txt",funcraw)
runtime={"executable":sys.executable,"version":sys.version,"stat_module":getattr(scope["stat"],"__file__",None),"zipfile_module":getattr(scope["zipfile"],"__file__",None),"constants":{"S_IFREG":scope["stat"].S_IFREG,"S_IFDIR":scope["stat"].S_IFDIR},"compiled_source_sha256":sha(raw),"function_source_sha256":sha(funcraw),"main_not_loaded_as_call":True,"capture_not_called":True,"new_OUT_only":str(O)}
result=None;error=None;frames=[]
try:result=scope["inspect_complete_zip"](Z)
except Exception as e:
 error={"type":type(e).__name__,"message":str(e)}
 tb=e.__traceback__
 while tb:
  frame=tb.tb_frame;d={"function":frame.f_code.co_name,"source":frame.f_code.co_filename,"line":tb.tb_lineno}
  info=frame.f_locals.get("info")
  if info is not None and hasattr(info,"filename"):
   kind=frame.f_locals.get("kind");flags=info.flag_bits
   d["entry"]={"path":info.filename,"external_attr":info.external_attr,"mode":info.external_attr>>16,"kind":kind,"flag_bits":flags,"flags_and_0x41":flags&0x41,"predicate":kind in (0,stat.S_IFREG,stat.S_IFDIR) and not flags&0x41}
  frames.append(d);tb=tb.tb_next
 put("exception.txt",traceback.format_exc().encode())
out={"schema":"trnm-arm-original-inspector-independent-observation-v1","runtime":runtime,"result":result,"error":error,"frames":frames,"original_HOLD_preserved":True,"source_correction":correction,"network_or_native_calls":0,"only_original_offline_inspector_called":True}
need(ident(P.lstat())==pver and ident(Z.lstat())==zver and ident((B/"summary.json").lstat())==sver,"original source/ZIP/HOLD unchanged")
pin=put("summary.json",jb(out))
print(json.dumps({"summary":pin,"error":error,"frames":frames,"runtime":runtime,"manifest_outcome":None if result is None else result["manifest_outcome"],"confirmation_facts":None if result is None else result["confirmation_facts"]},sort_keys=True))

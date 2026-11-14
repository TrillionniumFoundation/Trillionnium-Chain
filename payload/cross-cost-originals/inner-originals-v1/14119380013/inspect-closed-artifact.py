import datetime,hashlib,json,os,pathlib,stat,sys,zipfile
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3")
ART=int(sys.argv[1]);need_ids={14119000610:("arm64",9927038,"8249d0279e12e95bb59da7644b3d62ca1243589f9488b26e3b2b95560c9735ff"),14119380013:("x64",9851618,"d46ce31d5db37912f19115160d8b46e0bf32597fb3c4976a9c80b70bcc3df456")}
def need(v,m):
 if not v:raise ValueError(m)
need(ART in need_ids,"fixed artifact")
ARCH,SIZE,SHA=need_ids[ART]
O=E/"inner-originals-v1"/str(ART)
need(not O.exists(),"create only inner review")
O.parent.mkdir(mode=0o700,exist_ok=True);need(O.parent.resolve()==O.parent,"canonical evidence parent");O.mkdir(mode=0o700)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def fi(p):
 a=p.lstat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and p.resolve()==p,"regular pinned evidence")
 b=p.read_bytes();z=p.lstat();need((a.st_dev,a.st_ino,a.st_mode,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_mode,z.st_size,z.st_mtime_ns,z.st_ctime_ns),"stable")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def put(p,b):
 p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);need(p.parent.resolve()==p.parent,"canonical output")
 with p.open("xb") as f:f.write(b)
 return fi(p)
put(O/"inspect-closed-artifact.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
completion_path=E/(str(ART)+".completion.json");cpin=fi(completion_path);comp=json.loads(completion_path.read_bytes())
need(comp["errors"]==[] and comp["member_index"] is not None,"actual per-artifact completed")
index_path=pathlib.Path(comp["member_index"]["path"]);ipin=fi(index_path);need(ipin==comp["member_index"],"original index pin")
index=json.loads(index_path.read_bytes());need(index["all_members_CRC_SHA256_verified"] is True,"original complete CRC proof")
zip_path=E/(str(ART)+".zip");zpin=fi(zip_path);need(zpin["bytes"]==SIZE and zpin["sha256"]==SHA and zpin==index["zip"],"closed official full ZIP")
members={x["path"]:x for x in index["files"]};need(len(members)==len(index["files"]),"member uniqueness")
extracted=[]
with zipfile.ZipFile(zip_path) as z:
 def read_member(name,cap):
  need(name in members and members[name]["bytes"]<=cap,"bounded declared ZIP member")
  raw=z.read(name);need(len(raw)==members[name]["bytes"] and sha(raw)==members[name]["sha256"],"member full SHA")
  return raw
 prefix="from-zero-native/"
 manifest_name=prefix+"manifest.json"
 manifest_raw=read_member(manifest_name,2*1024*1024);manifest=json.loads(manifest_raw)
 fmap=manifest.get("files");need(isinstance(fmap,dict),"native manifest filemap")
 missing=[];mismatches=[];declared=set()
 for name,digest in fmap.items():
  need(isinstance(name,str) and isinstance(digest,str) and len(digest)==64,"filemap type")
  path=pathlib.PurePosixPath(name);need(str(path)==name and not path.is_absolute() and all(x not in ("",".","..") for x in path.parts),"filemap relative")
  member=prefix+name;declared.add(member)
  if member not in members:missing.append(member)
  elif members[member]["sha256"]!=digest:mismatches.append({"path":member,"expected":digest,"actual":members[member]["sha256"]})
 actual={name for name in members if name.startswith(prefix)}-{manifest_name}
 extras=sorted(actual-declared)
 filemap={"declared_files":len(fmap),"actual_non_manifest_files_under_prefix":len(actual),"missing":missing,"hash_mismatches":mismatches,"extra_non_manifest_files_under_prefix":extras,"all_declared_hashes_match":not missing and not mismatches,"exact_prefix_closure":not missing and not mismatches and not extras}
 put(O/"manifest-filemap-verification.json",jb(filemap))
 need(filemap["exact_prefix_closure"],"native filemap exact closure; preserve proof and do not extract on mismatch")
 def extract(name):
  raw=read_member(name,2*1024*1024)
  pin=put(O/"members"/pathlib.PurePosixPath(name),raw);extracted.append({**pin,"zip_member":name,"artifact_id":ART})
  return pin
 manifest_pin=extract(manifest_name)
 runs=[]
 for r in manifest.get("runs",[]):
  name=r.get("name");need(isinstance(name,str) and "/" not in name and name not in ("",".",".."),"selector path")
  logs={}
  for kind in ["stdout","stderr","process.json"]:
   member=prefix+name+"/"+kind
   if member in members:logs[kind]=extract(member)
  runs.append({"name":name,"process":r.get("process"),"passed":r.get("passed"),"named_execution":r.get("named_execution"),"failure":r.get("failure"),"failure_diagnostic":r.get("failure_diagnostic"),"originals":logs})
 source={"source_before":manifest.get("source_before"),"source_after":manifest.get("source_after")}
 put(O/"source-before-after-extracted.json",jb(source))
 def shape(v,depth=0):
  if isinstance(v,dict):
   if depth>=3:return {"type":"object","keys":list(v)}
   return {k:shape(x,depth+1) for k,x in v.items()}
  if isinstance(v,list):
   if len(v)<=6 and depth<3:return [shape(x,depth+1) for x in v]
   return {"type":"array","length":len(v),"first_element_keys":list(v[0]) if v and isinstance(v[0],dict) else None}
  if isinstance(v,str) and len(v)>240:return {"type":"string","length":len(v),"prefix":v[:240]}
  return v
 report_shape=None
 report_member=prefix+"confirmation/report.json"
 if report_member in members:
  report_raw=read_member(report_member,128*1024*1024);report=json.loads(report_raw)
  report_shape={"member":report_member,"bytes":len(report_raw),"sha256":sha(report_raw),"shape":shape(report),"original_head_lines":[{"line":i+1,"raw":s} for i,s in enumerate(report_raw.decode().splitlines()[:55])],"raw_kept_in_verified_ZIP_not_copied":True}
  put(O/"confirmation-report-shape.json",jb(report_shape))
 summary={"schema":"trnm-R1-cross-arch-native-original-inspection-v1","artifact_id":ART,"architecture":ARCH,"zip":zpin,"completion":cpin,"member_index":ipin,"manifest":manifest_pin,"manifest_schema":manifest.get("schema"),"filemap":filemap,"source_before":manifest.get("source_before"),"source_after":manifest.get("source_after"),"source_before_after_equal":manifest.get("source_before")==manifest.get("source_after"),"runs":runs,"manifest_outcome":{k:manifest.get(k) for k in ["source_recompiled","all_named_tests_passed","format_passed","failures","passed","execution_finished","independent_wan_accepted","work_hardness_accepted","production_activation","service_report","sustained_report","confirmation_report","binary_sha256_before","binary_sha256_after"]},"extracted_files":extracted,"report_member":members.get(report_member),"report_kept_in_original_ZIP":True,"no_inner_code_executed":True,"no_retest":True}
 need(fi(zip_path)==zpin and fi(index_path)==ipin and fi(completion_path)==cpin,"input source fence")
 sp=put(O/"summary.json",jb(summary))
 print(json.dumps({"summary":sp,"artifact_id":ART,"architecture":ARCH,"manifest":manifest_pin,"filemap":filemap,"outcome":summary["manifest_outcome"],"runs":[{"name":r["name"],"passed":r["passed"],"exit_code":(r["process"] or {}).get("exit_code"),"named_execution":r["named_execution"],"originals":r["originals"]} for r in runs],"report_shape_path":str(O/"confirmation-report-shape.json")},sort_keys=True))

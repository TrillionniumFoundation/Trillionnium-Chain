import os,stat,json,pathlib,hashlib,datetime,re,sys
R=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root/final-repository-truth-offline-ed0d35-v1")
HEAD="ed0d35487f2a67239e4d646fd41c2c7acb5cc740";TREE="1aa9c21812489080980bdc3c1c2bb43611e88354"
SHA="61fd6d1d2054b78908d2caab5e3c946a4e32cef4dbbf082659a0b1f51427e806"
SSHA="a74be5eb0131658ed16c8e1988806ffa8886a3a6580a6cca2c5a41a1ee88538d"
def sg(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def op(p):
 p=pathlib.PurePosixPath(str(p));assert p.is_absolute() and ".."not in p.parts
 d=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in p.parts[1:-1]:
   q=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);os.close(d);d=q
  f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=d)
 finally:os.close(d)
 s=os.fstat(f);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=16*1024*1024
 return f,s
def inventory():
 assert R.resolve(strict=True)==R
 a={};dsall=[]
 for b,ds,fs in os.walk(R,followlinks=False):
  for n in ds:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode);dsall.append(str(p.relative_to(R)))
  for n in fs:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1;a[str(p.relative_to(R))]=sg(s)
 assert len(a)<=295
 return {"files":a,"directories":sorted(dsall)}
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
inv=inventory();held=[];data={};rows=[]
try:
 for name in sorted(inv["files"]):
  p=R/name;fd,s=op(p);held.append((fd,sg(s),p))
  with os.fdopen(fd,"rb",closefd=False)as f:raw=f.read(s.st_size+1)
  assert len(raw)==s.st_size and sg(os.fstat(fd))==sg(s)==inv["files"][name]
  data[name]=raw;rows.append({"path":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"source_version":sg(s),"origin":{"host":"rog","path":str(p)}})
  assert sum(len(x)for x in data.values())<=32*1024*1024
 raw=data["summary.json"];assert len(raw)==21340 and hashlib.sha256(raw).hexdigest()==SHA
 s=json.loads(raw);assert s["head"]==HEAD and s["tree"]==TREE and s["status"]=="passed" and s["lane_exit"]==0 and s["errors"]==[] and s["source_before_after_verified"]is True
 assert len(s["steps"])==18 and all(type(t["exit"])is int and t["exit"]==0 for t in s["steps"])
 expected={"summary.json","source-before.json","source-after.json"}
 for step in s["steps"]:
  for k in ("stdout","stderr"):
   name=step["label"]+"."+k;assert step[k+"_path"]==str(R/name) and name not in expected;expected.add(name)
   assert len(data[name])==step[k+"_bytes"] and hashlib.sha256(data[name]).hexdigest()==step[k+"_sha256"]
 assert len(expected)==39
 for name in ("source-before.json","source-after.json","verify-source-before.stdout","verify-source-after.stdout"):
  assert len(data[name])==423 and hashlib.sha256(data[name]).hexdigest()==SSHA and data[name]==data["source-before.json"]
 extras=sorted(set(data)-expected)
 for name in extras:
  p=pathlib.PurePosixPath(name);assert name.startswith("ci-observations/") and not p.is_absolute() and ".."not in p.parts and str(p)==name and re.fullmatch(r"[A-Za-z0-9._/-]+",name)
 assert len(extras)<=256
 assert inventory()==inv
 for fd,version,p in held:
  assert sg(os.fstat(fd))==version
  fd2,st=op(p)
  try:assert sg(st)==version
  finally:os.close(fd2)
 by={r["path"]:r for r in rows}
 manifest={"schema":"trnm-closed-original-sublogs-manifest-v1","head":HEAD,"tree":TREE,"receipt_directory":str(R),"terminal_summary_sha256":SHA,"files":[{k:by[n][k]for k in ("path","bytes","sha256")}for n in extras]}
 mb=(json.dumps(manifest,indent=2)+"\n").encode()
 report={"schema":"trnm-M8-closed-full-roster-observation-v1","started_at":started,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"status":"closed_inputs_verified","original_status":s["status"],"original_summary":{"bytes":len(raw),"sha256":SHA},"source_identity":{"bytes":423,"sha256":SSHA},"original_lane":next({k:t[k]for k in ("label","argv","exit","timeout_seconds","elapsed_seconds")}for t in s["steps"]if t["label"]=="repository-truth"),"original_step_count":18,"required_flat_count":39,"nested_count":len(extras),"total_count":len(rows),"total_bytes":sum(r["bytes"]for r in rows),"nested_bytes":sum(by[n]["bytes"]for n in extras),"rows":rows,"directories":inv["directories"],"closed_manifest":manifest,"closed_manifest_identity":{"bytes":len(mb),"sha256":hashlib.sha256(mb).hexdigest()},"source_receipt_files_unchanged":True,"source_or_git_mutations":False,"tests_run":False,"package_executed":False,"hosted_qualification":False}
 print(json.dumps(report),flush=True)
finally:
 for fd,_,_ in held:os.close(fd)

import os,sys,pathlib,json,hashlib,stat,datetime
ROOT=pathlib.Path("/private/tmp/chain-R1-pq-witness-deadline-source-review-20261114-v1")
OUT=ROOT/"final-review-v1"
LOG=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1/132475258045-original-log.stdout")
def fail(m): raise RuntimeError(m)
def ident(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,cap=2*1024*1024):
 s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>cap: fail("unsafe input "+str(p))
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  f=os.fstat(fd)
  if ident(s)!=ident(f): fail("initial identity "+str(p))
  chunks=[]; n=0
  while True:
   b=os.read(fd,65536)
   if not b: break
   chunks.append(b); n+=len(b)
   if n>cap: fail("cap")
  if ident(f)!=ident(os.fstat(fd)): fail("FD changed")
 finally: os.close(fd)
 if ident(f)!=ident(p.lstat()): fail("path changed")
 return b"".join(chunks),ident(f)
def pin(p,raw): return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
raw,ls=read(LOG)
if len(raw)!=818816 or hashlib.sha256(raw).hexdigest()!="39f05164eaaeb530d90ecae6dda34ef6176d90889d55931519c0b2b4a9109fa0": fail("original log pin")
if not ROOT.is_dir() or ROOT.is_symlink(): fail("root")
OUT.mkdir()
def put(name,data):
 p=OUT/name
 if isinstance(data,str): data=data.encode()
 with p.open("xb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
 r,_=read(p)
 if r!=data: fail("write readback")
 return pin(p,r)
def js(obj): return json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
data=json.loads(sys.argv[2])
put("producer.py",sys.argv[1])
put("actual-tool-records.json",js(data["actual_tools"]))
lines=raw.splitlines(keepends=True)
put("original-log-source-before-1224-1236.txt",b"".join(lines[1223:1236]))
put("original-log-failure-1760-1860.txt",b"".join(lines[1759:1860]))
indexes={}
for d in ["immutable-source-v1","admission-source-v1","crypto-signing-source-v1"]:
 p=ROOT/d/"source-index.json"; x,_=read(p); indexes[d]={"pin":pin(p,x),"data":json.loads(x)}
put("source-provenance.json",js(indexes))
data["summary"]["closed_at_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
data["summary"]["hosted"]["original_log"]=pin(LOG,raw)
put("summary.json",js(data["summary"]))
put("review.md",data["review"])
entries=[]; total=0
for dp,dns,fns in os.walk(ROOT,followlinks=False):
 for d in dns:
  p=pathlib.Path(dp)/d
  if p.is_symlink() or not stat.S_ISDIR(p.lstat().st_mode): fail("unsafe dir")
 for n in sorted(fns):
  p=pathlib.Path(dp)/n
  if p in (OUT/"EVIDENCE_INDEX.json",OUT/"SEAL.json"): fail("unexpected preexisting final")
  b,st=read(p); total+=len(b)
  if total>4*1024*1024: fail("closed scope cap")
  entries.append({"path":p.relative_to(ROOT).as_posix(),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"origin":{"host":"mac","path":str(p)},"identity":list(st)})
entries.sort(key=lambda e:e["path"])
idx=put("EVIDENCE_INDEX.json",js({"schema":"trnm-r1-pq-static-review-evidence-index-v1","root":str(ROOT),"file_count":len(entries),"total_bytes":total,"files":entries,"external_original_log":pin(LOG,raw)}))
for e in entries:
 p=ROOT/e["path"]; b,s=read(p)
 if list(s)!=e["identity"] or len(b)!=e["bytes"] or hashlib.sha256(b).hexdigest()!=e["sha256"]: fail("final input drift")
raw2,ls2=read(LOG)
if ls2!=ls or raw2!=raw: fail("original drift")
seal=put("SEAL.json",js({"schema":"trnm-readonly-review-seal-v1","status":"CLOSED","index":idx,"indexed_files":len(entries),"indexed_bytes":total,"new_tests":0,"source_changed":False,"git_refs_changed":False,"stage_changed":False,"full_log_original_preserved":True}))
print(js({"status":"CLOSED_STATIC_REVIEW","summary":pin(OUT/"summary.json",read(OUT/"summary.json")[0]),"review":pin(OUT/"review.md",read(OUT/"review.md")[0]),"index":idx,"seal":seal,"indexed_files":len(entries),"indexed_bytes":total}).strip())

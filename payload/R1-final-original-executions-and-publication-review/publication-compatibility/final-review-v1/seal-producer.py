import os,sys,pathlib,stat,hashlib,json,datetime
plan=json.loads(sys.argv[1])
out=pathlib.Path(plan["dir"])/"final-review-v1"
def sh(b): return hashlib.sha256(b).hexdigest()
def fp(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,expected=None):
 p=pathlib.Path(path); b=p.lstat()
 assert p.resolve(strict=True)==p and stat.S_ISREG(b.st_mode) and b.st_nlink==1 and b.st_size<262144
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as f:
  assert fp(os.fstat(f.fileno()))==fp(b); raw=f.read(b.st_size+1); assert fp(os.fstat(f.fileno()))==fp(b)
 assert fp(p.lstat())==fp(b) and len(raw)==b.st_size
 if expected: assert (len(raw),sh(raw))==expected
 return raw,fp(b)
versions={}
for row in plan["pins"]:
 expected=(row["bytes"],row["sha256"])
 a,va=read(row["path"],expected); b,vb=read(row["snapshot_path"],expected); assert a==b
 versions[row["path"]]=va; versions[row["snapshot_path"]]=vb
idx=pathlib.Path(plan["dir"])/"input-index.json"
indexraw,indexversion=read(idx)
assert sh(indexraw)=="5dfc153186dc186a431f3364573fb8b5d68226ffd26ef6dc6f25d89dc57c0838"
out.mkdir(mode=0o700,exist_ok=False)
created=[]
def write(name,raw):
 p=out/name
 with p.open("xb") as f: f.write(raw)
 got,_=read(p); assert got==raw
 row={"path":name,"bytes":len(raw),"sha256":sh(raw)}; created.append(row); return row
now=datetime.datetime.now(datetime.timezone.utc).isoformat()
review=plan["review"];review["sealed_at"]=now;review["input_index"]={"path":str(idx),"bytes":len(indexraw),"sha256":sh(indexraw)}
write("review.json",(json.dumps(review,indent=2,ensure_ascii=False)+"\n").encode())
write("REVIEW.md",plan["md"].encode())
write("review-input.json",(sys.argv[1]+"\n").encode())
write("seal-producer.py",sys.argv[2].encode())
for path,version in versions.items(): assert fp(pathlib.Path(path).lstat())==version
assert fp(idx.lstat())==indexversion
ev={"schema":"trnm-r1-publication-static-review-index-v1","sealed_at":now,"self_excluded":"EVIDENCE_INDEX.json","source_files_unchanged":True,"files":list(created)}
r=write("EVIDENCE_INDEX.json",(json.dumps(ev,indent=2)+"\n").encode())
print(json.dumps({"status":"sealed","directory":str(out),"files":created,"source_files_unchanged":True,"helpers_executed":False,"remote_actions":False,"stage_actions":False}),flush=True)

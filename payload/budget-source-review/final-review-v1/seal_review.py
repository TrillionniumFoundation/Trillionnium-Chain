import os,sys,json,hashlib,stat,datetime
from pathlib import Path
assert sys.flags.optimize == 0
payload=json.loads(sys.argv[1])
OUT=Path("/private/tmp/chain-prci-R1-budget-input-identity-source-review-20261114-v1/final-review-v1")
ROOTS=[Path("/private/tmp/chain-prci-R1-budget-three-artifact-originals-20261114-v1"),OUT.parent]
def stamp(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,expected=None):
 p=Path(path)
 if not p.is_absolute() or p.resolve(strict=True)!=p:raise ValueError("NONCANONICAL")
 fd=os.open(str(p),os.O_RDONLY|os.O_NOFOLLOW)
 try:
  b=os.fstat(fd)
  if not stat.S_ISREG(b.st_mode) or b.st_nlink!=1 or b.st_size>4*1024*1024:raise ValueError("SOURCE_KIND_OR_SIZE")
  if stamp(p.lstat())!=stamp(b):raise ValueError("SOURCE_IDENTITY")
  chunks=[]
  while True:
   c=os.read(fd,1048576)
   if not c:break
   chunks.append(c)
  raw=b"".join(chunks)
  if stamp(os.fstat(fd))!=stamp(b) or stamp(p.lstat())!=stamp(b):raise ValueError("SOURCE_CHANGED")
 finally:os.close(fd)
 pin={"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
 if expected is not None and any(pin[k]!=expected[k] for k in ("path","bytes","sha256")):raise ValueError("PIN_MISMATCH "+str(p))
 return raw,pin,stamp(b)
if OUT.exists():raise ValueError("OUTPUT_ALREADY_EXISTS")
records={}
for pin in payload["pins"]:
 raw,actual,fingerprint=read(pin["path"],pin)
 records[actual["path"]]={"pin":actual,"fingerprint":fingerprint,"role":"explicit_causal_input"}
for root in ROOTS:
 for parent,dirs,files in os.walk(root,followlinks=False):
  dirs.sort();files.sort()
  for d in dirs:
   p=Path(parent)/d
   s=p.lstat()
   if not stat.S_ISDIR(s.st_mode) or p.is_symlink():raise ValueError("UNEXPECTED_DIRECTORY_KIND")
  for n in files:
   p=Path(parent)/n
   raw,pin,fingerprint=read(p)
   if pin["path"] not in records:records[pin["path"]]={"pin":pin,"fingerprint":fingerprint,"role":"closed_original_support"}
if sum(r["pin"]["bytes"] for r in records.values())>16*1024*1024:raise ValueError("SCOPE_CAP")
OUT.mkdir()
def put(name,raw):
 p=OUT/name
 with p.open("xb") as f:
  f.write(raw);f.flush();os.fsync(f.fileno())
 actual=read(p)[1]
 return actual
def jbytes(v):return (json.dumps(v,ensure_ascii=False,indent=2,sort_keys=True,allow_nan=False)+"\n").encode()
producer=put("seal_review.py",sys.argv[2].encode())
review=payload["review"];review["review_sealed_at"]=datetime.datetime.now(datetime.timezone.utc).isoformat();review["review_producer"]=producer
outputs=[producer,put("review.json",jbytes(review)),put("review.md",payload["markdown"].encode()),put("completed-tool-return-objects.json",jbytes(payload["terminal_returns"]))]
for path,rec in records.items():
 raw,pin,fp=read(path,rec["pin"])
 if fp!=rec["fingerprint"]:raise ValueError("FINAL_ORIGINAL_FENCE "+path)
entries=[dict(rec["pin"],role=rec["role"],origin=rec["pin"]["path"]) for path,rec in sorted(records.items())]
entries.extend(dict(p,role="derived_readonly_review",origin=p["path"]) for p in outputs)
index={"schema":"trnm-r1-budget-failure-causal-evidence-index-v1","sealed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"entries":entries,"count":len(entries),"bytes":sum(x["bytes"] for x in entries),"includes_self":False,"source_git_stage_modified":False,"network_native_tests_executed_by_sealer":False}
indexpin=put("EVIDENCE_INDEX.json",jbytes(index))
seal={"schema":"trnm-r1-budget-review-seal-v1","status":"CLOSED","review":next(x for x in outputs if x["path"].endswith("review.json")),"readable_review":next(x for x in outputs if x["path"].endswith("review.md")),"index":indexpin,"indexed_files":index["count"],"indexed_bytes":index["bytes"],"actual_native_result_remains":"FAIL_BEFORE_COMPILATION","implementation_or_rerun_performed":False,"archivable_roots":[str(p) for p in ROOTS],"external_explicit_inputs_preserved_by_reference":True}
sealpin=put("seal-summary.json",jbytes(seal))
print(json.dumps({"status":"CLOSED","review":seal["review"],"readable_review":seal["readable_review"],"index":indexpin,"seal":sealpin,"indexed_files":index["count"],"indexed_bytes":index["bytes"]},sort_keys=True),flush=True)

import os,sys,json,hashlib,stat
from pathlib import Path
O=Path("/private/tmp/chain-R1-nonhost-performance-review-20261114-v1")
F=O/"final-review-v1";F.mkdir(mode=0o700,exist_ok=False)
(F/"producer.py").write_text(sys.argv[1])
(F/"summary.json").write_text(json.dumps(json.loads(sys.argv[2]),indent=2,sort_keys=True)+"\n")
(F/"review.md").write_text(sys.argv[3])
(F/"original-tool-records.json").write_text(sys.argv[4]+"\n")
D=Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1")
selected=[
 (D/"trillionnium--crates--trnm-pon-node--src--ingress--public_v3.rs","0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a",[(967,1140),(1877,1915),(2376,2483),(3776,3940),(4010,4034)]),
 (D/"immutable-w1-kernel-source-v1/trillionnium--crates--trnm-pon-node--src--store.rs","5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c",[(1200,1220),(4974,5148)]),
 (D/"runtime-critical-path-source-v1/trillionnium--crates--trnm-pon-node--src--ingress--public_v3--scalar_cpu.rs","799cfe0fab3fb8e0b3796eee7748cb63a98c02b74d3083af98b4368c5895e384",[(678,879)])]
parts=[];sources=[]
for path,sha,windows in selected:
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=sha:raise RuntimeError("source_pin")
 lines=raw.decode().splitlines()
 sources.append({"path":str(path),"bytes":len(raw),"sha256":sha,"windows":windows})
 for a,b in windows:
  parts.append(str(path)+":"+str(a)+"-"+str(b)+"\n"+"\n".join(str(i)+": "+lines[i-1] for i in range(a,b+1))+"\n")
(F/"source-excerpts.txt").write_text("\n".join(parts))
(F/"source-excerpt-pins.json").write_text(json.dumps(sources,indent=2,sort_keys=True)+"\n")
rows=[];total=0
for path in sorted(O.rglob("*")):
 if path.is_dir(): continue
 st=path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:raise RuntimeError("not_regular_singlelink")
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  before=os.fstat(f.fileno());raw=f.read(4*1024*1024+1);after=os.fstat(f.fileno())
 if len(raw)>4*1024*1024:raise RuntimeError("file_cap")
 sig=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_nlink)
 if sig(st)!=sig(before) or sig(before)!=sig(after) or sig(after)!=sig(path.lstat()):raise RuntimeError("unstable")
 rows.append({"path":str(path.relative_to(O)),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"origin":{"host":"mac","path":str(path)}})
 total+=len(raw)
 if total>4*1024*1024:raise RuntimeError("total_cap")
index={"schema":"trnm-r1-nonhost-performance-evidence-index-v1","root":str(O),"file_count":len(rows),"total_bytes":total,"files":rows,"scope":"read-only source/previous originals; no new test or qualified optimization"}
raw=(json.dumps(index,indent=2,sort_keys=True)+"\n").encode()
(F/"EVIDENCE_INDEX.json").write_bytes(raw)
pin=lambda p:{"path":str(p),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
print(json.dumps({"status":"CLOSED_READONLY_NO_PATCH","indexed_files":len(rows),"indexed_bytes":total,"index":pin(F/"EVIDENCE_INDEX.json"),"summary":pin(F/"summary.json"),"review":pin(F/"review.md")},sort_keys=True))

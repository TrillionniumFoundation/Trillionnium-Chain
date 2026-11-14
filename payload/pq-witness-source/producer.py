import os,sys,json,hashlib,stat,re,subprocess
from pathlib import Path
O=Path("/private/tmp/chain-R1-pq-witness-deadline-source-review-20261114-v1")
O.mkdir(mode=0o700,exist_ok=False)
(O/"producer.py").write_text(sys.argv[1])
p=Path("/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1/132475258045-original-log.stdout")
st=p.lstat(); fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,"rb") as f:
 before=os.fstat(f.fileno());raw=f.read(2*1024*1024+1);after=os.fstat(f.fileno())
sig=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_mode,x.st_nlink)
if sig(st)!=sig(before) or sig(before)!=sig(after) or sig(after)!=sig(p.lstat()) or not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:raise RuntimeError("unstable")
if len(raw)!=818816 or hashlib.sha256(raw).hexdigest()!="39f05164eaaeb530d90ecae6dda34ef6176d90889d55931519c0b2b4a9109fa0":raise RuntimeError("raw_pin")
lines=raw.decode().splitlines()
patterns=("trnm-ci-source-v1","witness_selected_binary_dispatches","PQ_WITNESS_DEADLINE","PQ_NETWORK_CRYPTO","panicked at","tests/pq","Source identity","source-before.json","source-after.json")
hits=[]
for i,line in enumerate(lines):
 if any(x in line for x in patterns):
  hits.append({"line":i+1,"text":line[:20000]})
used=set()
for h in hits:
 for i in range(max(1,h["line"]-6),min(len(lines),h["line"]+14)+1):used.add(i)
excerpt="\n".join(str(i)+": "+lines[i-1] for i in sorted(used))+"\n"
if len(excerpt.encode())>192*1024:raise RuntimeError("excerpt_cap")
(O/"original-log-selected-context.txt").write_text(excerpt)
summary={"schema":"trnm-r1-pq-witness-original-log-selected-context-v1","source":{"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"line_count":len(lines),"hits":hits,"excerpts":{"path":str(O/"original-log-selected-context.txt"),"bytes":len(excerpt.encode()),"sha256":hashlib.sha256(excerpt.encode()).hexdigest()},"new_test_or_network":False}
(O/"original-log-index.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
print(json.dumps({"out":str(O),"line_count":len(lines),"hits":hits,"excerpt":summary["excerpts"]},sort_keys=True))

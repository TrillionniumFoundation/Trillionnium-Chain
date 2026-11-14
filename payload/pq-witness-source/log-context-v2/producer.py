import os,sys,json,hashlib,re
from pathlib import Path
O=Path("/private/tmp/chain-R1-pq-witness-deadline-source-review-20261114-v1/log-context-v2");O.mkdir(mode=0o700,exist_ok=False)
(O/"producer.py").write_text(sys.argv[1])
p=Path("/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1/132475258045-original-log.stdout")
raw=p.read_bytes()
if len(raw)!=818816 or hashlib.sha256(raw).hexdigest()!="39f05164eaaeb530d90ecae6dda34ef6176d90889d55931519c0b2b4a9109fa0":raise RuntimeError("pin")
lines=raw.decode().splitlines()
pat=re.compile(r'trnm-ci-source-v1|witness_selected_binary_dispatches|PQ_WITNESS_DEADLINE|PQ_NETWORK_CRYPTO|panicked at|source-before.json|source-after.json')
hit=[i for i,l in enumerate(lines) if pat.search(l)]
selected=sorted({j for i in hit for j in range(max(0,i-5),min(len(lines),i+14))})
rows=[]
for i in selected:
 l=lines[i]
 rows.append({"line":i+1,"original_line_utf8_bytes":len(l.encode()),"prefix":l[:4096],"prefix_truncated":len(l)>4096,
 "matched_spans":[{"offset_chars":m.start(),"text":l[max(0,m.start()-160):min(len(l),m.end()+700)]} for m in list(pat.finditer(l))[:10]]})
data=(json.dumps({"scope":"Locator excerpts only; original complete raw remains pinned and unchanged.","raw":{"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"line_count":len(lines),"lines":rows},indent=2,sort_keys=True)+"\n").encode()
(O/"context.json").write_bytes(data)
small=[{"line":i+1,"bytes":len(lines[i].encode()),"text":lines[i][:600]} for i in hit]
(O/"hit-locators.json").write_text(json.dumps(small,indent=2,sort_keys=True)+"\n")
print(json.dumps({"context":{"path":str(O/"context.json"),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},"hits":small},sort_keys=True))

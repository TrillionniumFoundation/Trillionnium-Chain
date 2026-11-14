import pathlib,zipfile,hashlib,json,io,os,sys
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1")
D=pathlib.Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/measurement-boundaries-v1")
out=[]
def walk(x,p=""):
 if isinstance(x,dict):
  for k,v in x.items():
   q=p+"/"+k
   if k in ["cpu.stat","cpu_stat","nr_periods","nr_throttled","throttled_usec","usage_usec","user_usec","system_usec","cpu.max"] or "counter" in k:yield(q,v)
   else:yield from walk(v,q)
 elif isinstance(x,list):
  for i,v in enumerate(x):yield from walk(v,p+"/"+str(i))
for aid,sha in [(14117751904,"b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8"),(14117403147,"2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a")]:
 zraw=(E/(str(aid)+".zip")).read_bytes();assert hashlib.sha256(zraw).hexdigest()==sha
 rec={"artifact":aid,"archive_sha256":sha,"scope":"Whole child runner, including both original and fresh selectors and its source checks; NOT the isolated four-second phase or a single W1 work interval.","members":[]}
 with zipfile.ZipFile(io.BytesIO(zraw)) as z:
  for n in ["fresh-service-host/inside-before.json","fresh-service-host/inside-after.json"]:
   i=z.getinfo(n);assert i.file_size<65536
   raw=z.read(i);j=json.loads(raw)
   rec["members"].append({"name":n,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"keys":list(j),"counter_fields":[{"pointer":p,"value":v} for p,v in walk(j)]})
 out.append(rec)
b=(json.dumps({"schema":"trnm-R1-W1-whole-child-host-counter-references-v1","artifacts":out},indent=2,sort_keys=True)+"\n").encode()
p=D/"whole-child-host-counter-references.json";p.write_bytes(b);(D/"whole-child-host-counter-reader.py").write_text(sys.argv[1])
print(json.dumps({"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"data":out}))

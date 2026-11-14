import hashlib,io,json,pathlib,sys,zipfile
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1")
I=E/"R1-W1-inner-originals-v1";Z=E/"R1-W1-complete-artifacts-v1";O=E/"inner-cause-review-v1";O.mkdir(mode=0o700)
def put(p,b):
 with p.open("xb") as f:f.write(b)
def jb(v):return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
sha=lambda b:hashlib.sha256(b).hexdigest()
put(O/"inspect-verified-report-structure.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
def shape(v,depth=0):
 if isinstance(v,dict):
  if depth>=2:return {"type":"object","keys":list(v)}
  return {k:shape(x,depth+1) for k,x in v.items()}
 if isinstance(v,list):
  return {"type":"array","count":len(v),"sample_shapes":[shape(x,depth+1) for x in v[:2]]}
 if isinstance(v,str) and len(v)>600:return {"type":"string","length":len(v)}
 return v
out=[]
for aid in [14117751904,14117403147]:
 idx=json.loads((I/(str(aid)+"-index.json")).read_bytes());rows={r["path"]:r for r in idx["files"]}
 data=(Z/(str(aid)+".zip")).read_bytes()
 if sha(data)!=idx["complete_archive"]["sha256"]:raise ValueError("ZIP identity")
 mf=json.loads((I/str(aid)/"fresh-service/manifest.json").read_bytes())
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  for phase in ["original","fresh"]:
   member="fresh-service/"+phase+"/report.json";raw=z.read(member)
   if len(raw)!=rows[member]["bytes"] or sha(raw)!=rows[member]["sha256"] or sha(raw)!=mf["files"][phase+"/report.json"]:raise ValueError("report identity")
   doc=json.loads(raw)
   out.append({"artifact_id":aid,"member":member,"bytes":len(raw),"sha256":sha(raw),"structure":shape(doc)})
put(O/"report-structure.json",jb(out))
print(json.dumps(out,sort_keys=True))

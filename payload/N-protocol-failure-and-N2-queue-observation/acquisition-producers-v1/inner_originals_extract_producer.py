import hashlib,json,pathlib,zipfile
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1");D=R/"inner-originals-v1";D.mkdir(mode=0o700)
originals=R/"official-complete-artifacts-v1"
allrows=[];facts=[]
for ident in [14111407094,14111816359]:
 index=json.loads((originals/(str(ident)+".index.json")).read_bytes());by={x["path"]:x for x in index["files"]}
 assert hashlib.sha256((originals/(str(ident)+".zip")).read_bytes()).hexdigest()==index["original_zip_sha256"]
 wanted=[p for p in by if p=="from-zero-native/manifest.json" or (p.startswith("from-zero-native/") and p.count("/")==2 and pathlib.PurePosixPath(p).name in ("stdout","stderr","process.json")) or p in ["from-zero-native-host/systemd-run.log","from-zero-native-host/child-result.json","from-zero-native-host/controller-result.json","from-zero-native-host/inside-before.json","from-zero-native-host/inside-after.json","from-zero-native-host/prepare-build.json"]]
 prefix=D/str(ident);prefix.mkdir(mode=0o700)
 with zipfile.ZipFile(originals/(str(ident)+".zip")) as z:
  for name in wanted:
   b=z.read(name);row=by[name];assert len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"]
   p=prefix/name;p.parent.mkdir(parents=True,exist_ok=True)
   with p.open("xb") as f:f.write(b)
   allrows.append({"path":str(p.relative_to(R)),"bytes":len(b),"sha256":row["sha256"],"original_zip":str(originals/(str(ident)+".zip")),"zip_member":name})
  m=json.loads(z.read("from-zero-native/manifest.json"));report=json.loads(z.read("from-zero-native/confirmation/report.json"))
  reportrow=by["from-zero-native/confirmation/report.json"]
 def shape(v):
  if isinstance(v,dict):return {"type":"dict","keys":list(v)}
  if isinstance(v,list):return {"type":"list","length":len(v),"first_shape":shape(v[0]) if v else None}
  return v
 def failures(v,p=""):
  found=[]
  if isinstance(v,dict):
   for k,val in v.items():
    ptr=p+"/"+k
    if k in ("error","failure","failure_type","errors") and val not in (None,[],{},False,""):
     found.append({"pointer":ptr,"value":val})
    else:found+=failures(val,ptr)
  elif isinstance(v,list):
   for n,x in enumerate(v):found+=failures(x,p+"/"+str(n))
  return found
 fact={"artifact_id":ident,"manifest_top":{k:shape(v) for k,v in m.items()},"manifest_failure_fields":failures(m),"report_origin":{"zip":str(originals/(str(ident)+".zip")),"member":"from-zero-native/confirmation/report.json",**reportrow},"report_top":{k:shape(v) for k,v in report.items()},"phase_shapes":[{"phase":i,"fields":{k:shape(v) for k,v in phase.items()}} for i,phase in enumerate(report.get("phases",[]))]}
 facts.append(fact)
with (D/"selected-original-member-index.json").open("xb") as f:f.write((json.dumps(allrows,sort_keys=True,indent=2)+"\n").encode())
with (D/"manifest-and-report-structure.json").open("xb") as f:f.write((json.dumps(facts,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(facts,sort_keys=True))

import hashlib,json,pathlib,zipfile
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1");out=[]
for ident in [14111407094,14111816359]:
 D=R/"inner-originals-v1"/str(ident)
 m=json.loads((D/"from-zero-native/manifest.json").read_bytes())
 with zipfile.ZipFile(R/"official-complete-artifacts-v1"/(str(ident)+".zip")) as z:raw=z.read("from-zero-native/confirmation/report.json")
 report=json.loads(raw)
 def small(v):return v is None or isinstance(v,(bool,int,float)) or isinstance(v,str) and len(v)<300
 phases=[]
 for n,p in enumerate(report["phases"]):
  replays=p.get("independent_history_page_replay",[])
  rows=[]
  for i,rec in enumerate(replays):
   rows.append({"index":i,"scalars":{k:v for k,v in rec.items() if small(v)},"nested_keys":{k:list(v) for k,v in rec.items() if isinstance(v,dict)}})
  phases.append({"index":n,"scalars":{k:v for k,v in p.items() if small(v)},"container_lengths":{k:len(v) for k,v in p.items() if isinstance(v,(list,dict))},"replays":rows,"phase_keys":list(p)})
 mf={k:v for k,v in m.items() if small(v)}
 mf["failures"]=m.get("failures");mf["terminal"]=m.get("terminal")
 fact={"artifact_id":ident,"manifest":mf,"manifest_list_shapes":{k:{"count":len(v),"first_keys":list(v[0]) if v and isinstance(v[0],dict) else None} for k,v in m.items() if isinstance(v,list)},"report_sha256":hashlib.sha256(raw).hexdigest(),"report_bytes":len(raw),"report_top_scalars":{k:v for k,v in report.items() if small(v)},"phases":phases}
 out.append(fact)
raw=(json.dumps(out,sort_keys=True,indent=2)+"\n").encode()
p=R/"inner-originals-v1"/"bounded-confirmation-cause-facts.json"
with p.open("xb") as f:f.write(raw)
print(json.dumps(out,sort_keys=True))

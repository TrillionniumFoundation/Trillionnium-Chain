from pathlib import Path,PurePosixPath
import gzip,hashlib,json,re,zipfile
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
NEW=[(128660701711,"from-zero-native"),(128660701605,"from-zero-native"),(128660701948,"fresh-service"),(128660701637,"history-native")]
def write_json(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("x") as f:json.dump(obj,f,sort_keys=True,indent=2);f.write("\n")
def shape(v):
 if isinstance(v,dict):return {"scalars":{k:x for k,x in v.items() if not isinstance(x,(dict,list))},
  "nested":{k:list(x)[:60] if isinstance(x,dict) else {"length":len(x)} for k,x in v.items() if isinstance(x,(dict,list))}}
 return v
for jid,prefix in NEW:
 base=OUT/"new-jobs"/str(jid);fetch=json.loads((base/"artifact-fetch.json").read_text())
 assert fetch["exit_code"]==0 and fetch["metadata_digest_matches"] and fetch["metadata_size_matches"]
 selected=[]
 with zipfile.ZipFile(fetch["cache_path"]) as z:
  for i in z.infolist():
   p=PurePosixPath(i.filename)
   if not (i.filename.startswith(prefix+"/") or i.filename.startswith(prefix+"-host/")):continue
   if not (p.suffix in (".json",".log",".txt") or p.name in ("stdout","stderr")):continue
   if i.file_size>24*1024*1024:raise ValueError(("member too large",i.filename,i.file_size))
   raw=z.read(i);raw.decode("utf-8")
   target=base/"artifact-selected"/i.filename
   if len(raw)>256*1024:target=Path(str(target)+".gz");encoded=gzip.compress(raw,compresslevel=6,mtime=0)
   else:encoded=raw
   target.parent.mkdir(parents=True,exist_ok=True)
   with target.open("xb") as f:f.write(encoded)
   selected.append({"zip_member":i.filename,"raw_bytes":len(raw),"raw_sha256":hashlib.sha256(raw).hexdigest(),
    "stored_path":str(target.relative_to(OUT)),"stored_bytes":len(encoded),"stored_sha256":hashlib.sha256(encoded).hexdigest(),
    "encoding":"gzip-lossless-utf8" if target.suffix==".gz" else "utf8"})
 write_json(base/"selected-artifact-manifest.json",{"archive_sha256":fetch["archive_sha256"],"members":selected})
rows=[]
for jid in [128662229865,128662229758,128662229491,128660701711,128660701605,128660701948,128660701637]:
 base=OUT/"new-jobs"/str(jid);fetch=json.loads((base/"artifact-fetch.json").read_text())
 with zipfile.ZipFile(fetch["cache_path"]) as z:
  if jid in [128662229865,128662229758,128662229491,128660701711,128660701605]:
   m=json.loads(z.read("from-zero-native/manifest.json"));r=json.loads(z.read("from-zero-native/confirmation/report.json"))
   row={"job_id":jid,"classification_stage":"from-zero-confirmation","failures":m["failures"],
    "all_named_tests_passed":m["all_named_tests_passed"],"passed":m["passed"],"terminal":m["terminal"],
    "confirmation_observation":m["confirmation_observation"],"raw_confirmation_phases":[shape(x) for x in r["phases"]],
    "raw_finite_target_met":r["finite_target_met"],"raw_invariant_target_met":r["invariant_target_met"]}
  elif jid==128660701948:
   m=json.loads(z.read("fresh-service/manifest.json"))
   row={"job_id":jid,"manifest":{k:v for k,v in m.items() if k!="files"},
    "original":shape(json.loads(z.read("fresh-service/original/report.json"))),
    "fresh":shape(json.loads(z.read("fresh-service/fresh/report.json"))),
    "original_log":z.read("fresh-service/original.log").decode(),
    "fresh_log":z.read("fresh-service/fresh.log").decode()}
  else:
   row={"job_id":jid,"manifest":json.loads(z.read("history-native/manifest.json")),
    "summary":json.loads(z.read("history-native/long-history/summary.json")),
    "history_log":z.read("history-native/history.log").decode(),
    "resources":z.read("history-native/history-resources.txt").decode()}
  write_json(base/"business-readback.json",row);rows.append(row)
  if "confirmation_observation" in row:
   print(json.dumps({"job_id":jid,"failures":row["failures"],"all_named_tests_passed":row["all_named_tests_passed"],
    "passed":row["passed"],"finite":row["raw_finite_target_met"],
    "confirmation_observation":row["confirmation_observation"],"phases":row["raw_confirmation_phases"]}),flush=True)
  else:print(json.dumps(row),flush=True)
write_json(OUT/"business-readback-first7.json",{"schema":"TRNM-W1-C6-BUSINESS-READBACK1","rows":rows,"mutations":0})

from pathlib import Path,PurePosixPath
import gzip,hashlib,json,re,stat,time,zipfile
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
records=[]
for jid in [128662229865,128662229758,128662229491]:
 base=OUT/"new-jobs"/str(jid);fetch=json.loads((base/"artifact-fetch.json").read_text())
 assert fetch["exit_code"]==0 and fetch["metadata_digest_matches"] and fetch["metadata_size_matches"]
 selected=[]
 with zipfile.ZipFile(fetch["cache_path"]) as z:
  for i in z.infolist():
   p=PurePosixPath(i.filename)
   if not (i.filename.startswith("from-zero-native/") or i.filename.startswith("from-zero-native-host/")):continue
   if not (p.suffix in (".json",".log",".txt") or p.name in ("stdout","stderr")):continue
   if i.file_size>24*1024*1024:raise ValueError(("member too large",i.filename,i.file_size))
   raw=z.read(i);raw.decode("utf-8")
   target=base/"artifact-selected"/i.filename
   if len(raw)>256*1024:
    target=Path(str(target)+".gz");encoded=gzip.compress(raw,compresslevel=6,mtime=0)
   else:encoded=raw
   target.parent.mkdir(parents=True,exist_ok=True)
   with target.open("xb") as f:f.write(encoded)
   selected.append({"zip_member":i.filename,"raw_bytes":len(raw),"raw_sha256":hashlib.sha256(raw).hexdigest(),
    "stored_path":str(target.relative_to(OUT)),"stored_bytes":len(encoded),"stored_sha256":hashlib.sha256(encoded).hexdigest(),
    "encoding":"gzip-lossless-utf8" if target.suffix==".gz" else "utf8"})
  def shape(v):
   if isinstance(v,dict):return {"keys":list(v),"scalars":{k:x for k,x in v.items() if not isinstance(x,(dict,list))},
    "nested":{k:list(x)[:35] if isinstance(x,dict) else {"length":len(x)} for k,x in v.items() if isinstance(x,(dict,list))}}
   return {"type":type(v).__name__}
  manifest=json.loads(z.read("from-zero-native/manifest.json"))
  confirmation=json.loads(z.read("from-zero-native/confirmation/report.json"))
  result={"job_id":jid,"manifest_shape":shape(manifest),"confirmation_shape":shape(confirmation),
   "stdout":z.read("from-zero-native/from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline/stdout").decode(),
   "process":json.loads(z.read("from-zero-native/from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline/process.json"))}
 with (base/"selected-artifact-manifest.json").open("x") as f:json.dump({"archive_sha256":fetch["archive_sha256"],"members":selected},f,sort_keys=True,indent=2);f.write("\n")
 with (base/"business-shape.json").open("x") as f:json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
 print(json.dumps(result,sort_keys=True),flush=True);records.append({"job_id":jid,"selected":len(selected)})
with (OUT/"artifact-selection-first3.json").open("x") as f:json.dump({"records":records,"source_mutations":0,"CI_mutations":0},f,indent=2);f.write("\n")

from pathlib import Path,PurePosixPath
import collections,gzip,hashlib,json,re,zipfile
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
def jput(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("x") as f:json.dump(obj,f,sort_keys=True,indent=2);f.write("\n")
def shape(v):
 if not isinstance(v,dict):return {"type":type(v).__name__,"length":len(v) if isinstance(v,list) else None}
 return {"scalars":{k:x for k,x in v.items() if not isinstance(x,(dict,list))},
  "nested":{k:list(x)[:50] if isinstance(x,dict) else {"length":len(x)} for k,x in v.items() if isinstance(x,(dict,list))}}
def select(base,predicate):
 fetch=json.loads((base/"artifact-fetch.json").read_text())
 assert fetch["exit_code"]==0 and fetch["metadata_digest_matches"] and fetch["metadata_size_matches"]
 selected=[]
 with zipfile.ZipFile(fetch["cache_path"]) as z:
  for i in z.infolist():
   if not predicate(i.filename):continue
   assert i.file_size<=64*1024*1024,(i.filename,i.file_size)
   raw=z.read(i);raw.decode("utf-8")
   target=base/"artifact-selected"/i.filename
   if len(raw)>256*1024:target=Path(str(target)+".gz");encoded=gzip.compress(raw,compresslevel=6,mtime=0)
   else:encoded=raw
   assert len(encoded)<25*1024*1024
   target.parent.mkdir(parents=True,exist_ok=True)
   with target.open("xb") as f:f.write(encoded)
   selected.append({"zip_member":i.filename,"raw_bytes":len(raw),"raw_sha256":hashlib.sha256(raw).hexdigest(),
    "stored_path":str(target.relative_to(OUT)),"stored_bytes":len(encoded),"stored_sha256":hashlib.sha256(encoded).hexdigest(),
    "encoding":"gzip-lossless-utf8" if target.suffix==".gz" else "utf8"})
 jput(base/"selected-artifact-manifest.json",{"archive_sha256":fetch["archive_sha256"],"members":selected})
 return fetch
base=OUT/"history"/"replica-1"
fetch=select(base,lambda n:(n.startswith("history-diagnostic/") or n.startswith("history-diagnostic-host/")) and (PurePosixPath(n).suffix in (".json",".jsonl",".log",".txt",".stderr") or PurePosixPath(n).name in ("stdout","stderr")))
with zipfile.ZipFile(fetch["cache_path"]) as z:
 m=json.loads(z.read("history-diagnostic/manifest.json"));s=json.loads(z.read("history-diagnostic/long-history/summary.json"))
 log=z.read("history-diagnostic/history.log").decode();records=[];counts=collections.Counter();last={}
 for line_no,line in enumerate(log.splitlines(),1):
  if not line.startswith("{"):continue
  try:v=json.loads(line)
  except ValueError:continue
  key=str(v.get("schema",v.get("kind","unlabelled")));counts[key]+=1;last[key]=(line_no,v)
  if "failure_location" in v or "loop_exit_before_internal_shutdown" in v or "sync_error" in v:
   records.append({"line":line_no,"record":{k:x for k,x in v.items() if not isinstance(x,(dict,list)) or k in ("failure_location","loop_exit_before_internal_shutdown")}})
 brief={"job_id":128655993256,"summary":s,"config":json.loads(z.read("history-diagnostic/long-history/config.json")),
  "failures":m.get("failures"),"process":m.get("process"),"manifest_passed":m.get("passed"),
  "history_log_sha256":hashlib.sha256(log.encode()).hexdigest(),"history_log_lines":len(log.splitlines()),
  "schema_counts":dict(counts),"exit_records":records,
  "last_by_schema":[{"line":ln,"schema":k,"shape":shape(v)} for k,(ln,v) in last.items()],
  "error_lines":[{"line":i+1,"text":x} for i,x in enumerate(log.splitlines()) if not x.startswith("{") and re.search(r"panicked|called|FAILED|test result|Error|error",x)],
  "resources":z.read("history-diagnostic/history-resources.txt").decode()}
jput(base/"business-readback.json",brief);print(json.dumps(brief),flush=True)
base=OUT/"new-jobs"/"128660701377"
def campaign_allowed(n):
 if n in ("results.json","source-before.json","source-after.json","build.stderr.log","build.stdout.log"):return True
 if re.fullmatch(r"run-[123]\.(stdout|stderr)\.log",n):return True
 if re.fullmatch(r"run-[123]-raw/(report|campaign-failure)\.json",n):return True
 if re.fullmatch(r"run-[123]-raw/(baseline|from-zero|late-product)-host-control/host/[^/]+\.(json|log|txt)",n):return True
 return False
fetch=select(base,campaign_allowed)
with zipfile.ZipFile(fetch["cache_path"]) as z:
 result=json.loads(z.read("results.json"));attempts=[]
 for n in (1,2,3):
  r=json.loads(z.read(f"run-{n}-raw/report.json"))
  attempts.append({"number":n,"failure":json.loads(z.read(f"run-{n}-raw/campaign-failure.json")),
   "report_shape":shape(r),"phases":[shape(x) for x in r.get("phases",[])],
   "stderr":z.read(f"run-{n}.stderr.log").decode(),"stdout":z.read(f"run-{n}.stdout.log").decode()})
 brief={"job_id":128660701377,"results":result,"attempts":attempts}
jput(base/"business-readback.json",brief)
print(json.dumps({"job_id":128660701377,"result_shape":shape(result),"attempts":attempts}),flush=True)
base=OUT/"new-jobs"/"128660701948";fetch=json.loads((base/"artifact-fetch.json").read_text());fresh=[]
with zipfile.ZipFile(fetch["cache_path"]) as z:
 for label in ("original","fresh"):
  r=json.loads(z.read(f"fresh-service/{label}/report.json"))
  fresh.append({"label":label,"shape":shape(r),"phases":[shape(x) for x in r.get("phases",[])]})
jput(base/"raw-phase-shapes.json",fresh);print(json.dumps({"job_id":128660701948,"reports":fresh}),flush=True)
jput(OUT/"remaining-readback-status.json",{"completed_jobs":[128655993256,128660701377,128660701948],
 "history_replica_2_artifact":"120-second-download-timeout; partial preserved; no retry; metadata/job log success unchanged",
 "source_mutations":0,"CI_mutations":0})

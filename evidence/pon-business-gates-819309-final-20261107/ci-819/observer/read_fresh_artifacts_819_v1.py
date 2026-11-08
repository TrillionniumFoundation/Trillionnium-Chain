#!/usr/bin/env python3
"""GET-only retained fresh artifacts; strict readers and native gates stay separate."""
import concurrent.futures,datetime,hashlib,json,os,pathlib,re,stat,subprocess,sys,zipfile
ROOT=pathlib.Path("/home/qian-qi/throughput-final-ci-observation-20261107")
PIN=ROOT/"pinned-readers-819309fd-v1"
sys.path.insert(0,str(PIN/"scripts/ci"))
import run_from_zero_native as native
import run_w1_fresh_service_v1 as fresh
import integration_push_source as src
H="819309fd312298e099642e1253b1d4ba07113e98";B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0";M="28df21f965e0348690836c9c854dab645827a03d";T="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
SNAP=pathlib.Path(sys.argv[1]).resolve();assert SNAP.parent==ROOT
OUT=SNAP/"fresh-artifact-read-v1";OUT.mkdir(exist_ok=False)
core=json.loads((SNAP/"observer-core-v1.json").read_bytes());assert core["head"]==H
jobs=[j for a in core["attempts"] for j in a["native"] if j["family"]=="fresh"]
artifacts=[a for a in core["artifacts"] if a["name"].startswith("w1-fresh-service-")]
def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
 return h.hexdigest()
def require(v,msg):
 if not v:raise ValueError(msg)
def safe(name):
 p=pathlib.PurePosixPath(name)
 require(not p.is_absolute() and ".." not in p.parts and "\\" not in name,"unsafe path")
 return p
def fetch(endpoint,path):
 row={"argv":["/usr/bin/gh","api","--hostname","github.com","--method","GET",endpoint],"started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()}
 try:
  with path.open("xb") as out,path.with_suffix(path.suffix+".stderr").open("xb") as err:p=subprocess.run(row["argv"],stdout=out,stderr=err,timeout=120)
  row["exit_code"]=p.returncode
 except Exception as e:row["exit_code"]=None;row["error"]=type(e).__name__+": "+str(e)
 row.update(bytes=path.stat().st_size,sha256=file_sha(path),finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
 return row
def paths_observation(phase):
 records=(phase.get("observations") or {}).get("records")
 if not isinstance(records,list):return {"status":"UNKNOWN missing records"}
 relevant=[x for x in records if isinstance(x,dict) and x.get("full_work_started") is True]
 bools=("key_hashed","lookup_contended","lookup_poisoned","exact_fact_found","cached_rejection_returned","native_verifier_started","native_verifier_returned","full_replay_started")
 result={"records":len(records),"relation_attempts":len(relevant),"extension_present":0,"completed":0,"incomplete_or_unknown":0,"flags":{k:{"true":0,"false":0,"unknown":0} for k in bools},"configurations":[]}
 for row in relevant:
  ob=row.get("work_rejection")
  if not isinstance(ob,dict):
   result["incomplete_or_unknown"]+=1
   for k in bools:result["flags"][k]["unknown"]+=1
   continue
  result["extension_present"]+=1
  config={k:ob.get(k) for k in ("schema","slots","retained_software_bytes","lifetime_ms","lifetime_seconds","lifetime_subsec_nanos")}
  if config not in result["configurations"]:result["configurations"].append(config)
  facts=ob.get("cache")
  complete=ob.get("completed") is True and isinstance(facts,dict)
  result["completed" if complete else "incomplete_or_unknown"]+=1
  for k in bools:
   value=facts.get(k) if complete else None
   result["flags"][k]["true" if value is True else "false" if value is False else "unknown"]+=1
 return result
def phase_summary(p):
 result={k:p.get(k) for k in ("mode","requested_window_ns","business_started_ns","confirmation_ended_ns","client_confirmation_latency_ns","client_confirmed_transactions","client_confirmed_before_original_window_end","finite_business_target_met","finite_target_met","verification_errors","complete_denominators","attacker_workers_cpu_ns","construction_count")}
 result.update(attack_workers=len(p.get("attacks",[])),attack_calls=sum(len(w.get("calls",[])) for w in p.get("attacks",[])),honest_submissions=len(p.get("honest_submissions",[])),honest_history=len(p.get("honest_history",[])),cache_observation=paths_observation(p))
 for field in ("honest_submissions","honest_history"):
  result[field+"_outcomes"]=[{k:r.get(k) for k in ("status","error","started_ns","ended_ns","elapsed_wall_ns","returned_after_deadline","returned_after_window")} for r in p.get(field,[])]
 result["independent_history_page_replay"]=p.get("independent_history_page_replay")
 return result
def one(a):
 d=OUT/str(a["id"]);d.mkdir()
 result={"artifact":a,"errors":[],"artifact_authenticated":False,"source_bound":False,"native_gate_validated":False}
 try:
  require(a["workflow_run"]["head_sha"]==H and a["workflow_run"]["id"]==42402618462 and not a["expired"],"artifact identity")
  require(a["size_in_bytes"]<=32*1024*1024,"fresh ZIP size bound")
  require(os.statvfs(OUT).f_bavail*os.statvfs(OUT).f_frsize>512*1024*1024,"observer disk")
  result["download"]=fetch("repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/"+str(a["id"])+"/zip",d/"artifact.zip")
  require(result["download"].get("exit_code")==0 and result["download"]["bytes"]==a["size_in_bytes"] and a["digest"]=="sha256:"+result["download"]["sha256"],"GitHub ZIP identity mismatch")
  inventory=[];manifests=[]
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist()
   require(len(infos)<=8192 and len({i.filename for i in infos})==len(infos),"ZIP duplicate/count")
   require(sum(i.file_size for i in infos)<=768*1024*1024,"ZIP expanded bytes")
   for i in infos:
    p=safe(i.filename);mode=stat.S_IFMT(i.external_attr>>16)
    require(mode in (0,stat.S_IFREG,stat.S_IFDIR) and not(i.flag_bits&1),"ZIP entry type")
    require(i.file_size<=256*1024*1024,"ZIP member bytes")
    inventory.append({"name":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size})
    if i.is_dir():continue
    if p.suffix in (".json",".jsonl",".log") or p.name in ("stdout","stderr"):
     require(i.file_size<=native.REPORT_LIMIT,"selected text bytes")
     data=z.read(i);target=d/i.filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
     if p.name=="manifest.json":
      doc=native.json_load(data)
      if doc.get("schema")==fresh.SCHEMA:manifests.append((i.filename,doc))
   require(len(manifests)==1,"unique fresh native manifest")
   manifest_name,manifest=manifests[0];prefix=str(pathlib.PurePosixPath(manifest_name).parent)
   files=manifest.get("files");require(isinstance(files,dict),"manifest files required")
   checked=[]
   for name,expected in files.items():
    safe(name);member=prefix+"/"+name if prefix!="." else name;info=z.getinfo(member)
    h=hashlib.sha256()
    with z.open(info) as f:
     for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    require(h.hexdigest()==expected,"manifest digest "+name);checked.append(name)
   result["manifest_files_verified"]=len(checked)
  result["archive_inventory"]=inventory;result["artifact_authenticated"]=True
  kind="prospective-merge" if a["name"].startswith("w1-fresh-service-prospective-merge-") else "head"
  expected=H if kind=="head" else M
  matches=[j for j in jobs if j["source"]==kind];require(len(matches)==1,"unique fresh job")
  job=matches[0];result["job"]={k:job.get(k) for k in ("id","run_id","run_attempt","name","status","conclusion","source_controls")}
  source=src.load_json((d/"source.json").read_bytes());mat=src.load_json((d/"push-source-context.json").read_bytes())
  resolver=src.load_json((ROOT/"20261107T184658Z-819309fd3122-78a49720/source-artifact-read-v1/13584974949/context.json").read_bytes())
  require(source["tested_commit"]==expected and source["tested_tree"]==T and source["candidate"]==H and source["kind"]==kind and source["tracked_worktree_verified"] is True,"source binding")
  require(source["base"]==(B if kind=="prospective-merge" else None) and source["prospective_merge"]==(M if kind=="prospective-merge" else None),"source parents")
  require(mat["context"]==resolver and mat["source"]==source and mat["context_sha256"]==src.digest(resolver) and mat["github_event_name"]=="push" and mat["github_sha"]==H,"materialization binding")
  result["job_log"]=fetch("repos/TrillionniumFoundation/Trillionnium-Chain/actions/jobs/"+str(job["id"])+"/logs",d/"job.log")
  require(result["job_log"]["exit_code"]==0,"job log required")
  text=(d/"job.log").read_text(encoding="utf-8-sig")
  clean="\n".join(re.sub(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z ?","",x) for x in text.splitlines())
  identities=[];decoder=json.JSONDecoder()
  for match in re.finditer(r"(?m)^\{",clean):
   try:obj,_=decoder.raw_decode(clean,match.start())
   except (ValueError,TypeError):continue
   if isinstance(obj,dict) and obj.get("schema")=="trnm-ci-source-v1":identities.append(obj)
  require(len(identities)>=2 and identities[0]==source and identities[-1]==source,"native source-after log")
  require(job["source_controls"]["after"].get("conclusion")=="success" and job["source_controls"]["context"].get("conclusion")=="success","source-after/context step")
  result["source_bound"]=True;result["source"]=source;result["source_before_after_equal"]=True
  result["manifest"]={k:manifest.get(k) for k in ("schema","source_expected","source_recompiled","execution_finished","passed","all_named_tests_passed","failures","requested_window_ns","attack_workers","binary_sha256_before","binary_sha256_after")}
  result["manifest"]["source_before_after_equal"]=manifest.get("source_before")==manifest.get("source_after")
  result["native_runs"]=[];result["reports"]={}
  base=d/pathlib.PurePosixPath(manifest_name).parent
  for row in manifest.get("runs",[]):
   tag="original" if row.get("name")==fresh.ORIGINAL else "fresh" if row.get("name")==fresh.FRESH else "UNKNOWN"
   result["native_runs"].append({k:row.get(k) for k in ("name","process","passed","failure","failure_diagnostic","report_path","log_sha256")})
   relative=row.get("report_path");safe(relative);report=base/relative
   if not report.exists():result["reports"][tag]={"missing":True};continue
   doc,raw=fresh.load_report(report)
   observed={"path":str(report),"sha256":sha(raw),"schema":doc.get("schema"),"finite_target_met":doc.get("finite_target_met"),"negative_cache_enabled":doc.get("negative_cache_enabled"),"negative_cache_observation_source":doc.get("negative_cache_observation_source"),"construction_coverage":doc.get("construction_coverage"),"phases":[phase_summary(x) for x in doc.get("phases",[])]}
   validator=native.validate_confirmation_report if tag=="original" else fresh.validate_fresh_report if tag=="fresh" else None
   try:
    require(validator is not None,"unknown selector");observed["strict_report_read"]=validator(report)
   except Exception as e:observed["strict_report_error"]=type(e).__name__+": "+str(e)
   if tag=="fresh":
    try:observed["cache_path_subcheck"]=fresh.validate_negative_cache_observation(doc,doc["phases"])
    except Exception as e:observed["cache_path_subcheck_error"]=type(e).__name__+": "+str(e)
   else:observed["cache_path_subcheck"]=None;observed["cache_path_subcheck_status"]="not_applicable_original_retained_proof"
   result["reports"][tag]=observed
  result["host"]={}
  for p in d.rglob("*.json"):
   if p.name not in ("controller-result.json","child-result.json"):continue
   doc=native.json_load(p.read_bytes());result["host"][str(p.relative_to(d))]={k:doc.get(k) for k in ("schema","passed","failure","host_errors","final_host_errors","native_child_exit","systemd_run_exit","cleanup","preparation_execution_binding")}
 except Exception as e:result["errors"].append(type(e).__name__+": "+str(e))
 result["finished_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
 (d/"readback.json").write_text(json.dumps(result,indent=2)+"\n")
 return result
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(one,artifacts))
summary={"head":H,"base":B,"merge":M,"tree":T,"expected_fresh_lanes":2,"observed_artifacts":len(artifacts),"results":results,"native_gate_validated":False}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
small=[]
for r in results:
 small.append({"artifact":r["artifact"]["id"],"errors":r["errors"],"source_bound":r["source_bound"],"manifest_files_verified":r.get("manifest_files_verified"),"manifest":r.get("manifest"),"native_runs":r.get("native_runs"),"host":r.get("host"),"reports":{k:{"path":v.get("path"),"sha256":v.get("sha256"),"strict_error":v.get("strict_report_error"),"cache_path_subcheck_error":v.get("cache_path_subcheck_error"),"cache_path_subcheck_status":v.get("cache_path_subcheck_status"),"cache_path_subcheck":v.get("cache_path_subcheck"),"phases":[{a:x.get(a) for a in ("mode","client_confirmation_latency_ns","client_confirmed_transactions","verification_errors","attack_workers","attack_calls","honest_submissions","honest_history","cache_observation")} for x in v.get("phases",[])]} for k,v in r.get("reports",{}).items()}})
print(json.dumps({"directory":str(OUT),"results":small,"native_gate_validated":False}))

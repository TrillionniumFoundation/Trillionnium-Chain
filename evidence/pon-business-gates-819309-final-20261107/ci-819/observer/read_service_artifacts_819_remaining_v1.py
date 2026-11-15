from pathlib import Path,PurePosixPath
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib,json,os,stat,subprocess,sys,zipfile,re
ROOT=Path("/home/qian-qi/throughput-final-ci-observation-20261107")
sys.path.insert(0,str(ROOT))
from read_ci_metadata import parse_http
PIN=ROOT/"pinned-readers-819309fd-v1"
sys.path.insert(0,str(PIN/"scripts/ci"))
import run_from_zero_native as native
H="819309fd312298e099642e1253b1d4ba07113e98"
M="28df21f965e0348690836c9c854dab645827a03d"
B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TREE="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
REPO="TrillionniumFoundation/Trillionnium-Chain"
SNAP=Path(sys.argv[1])
OUT=SNAP/"service-artifact-read-remaining-v1"
OUT.mkdir()
def sha(v):return hashlib.sha256(v).hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
s=json.loads((SNAP/"snapshot.json").read_bytes())
arts=[];jobs=[]
for q in s["queries"]:
 if "/artifacts?" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());arts+=obj["artifacts"]
 if "/jobs?filter=all" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());jobs+=obj["jobs"]
retained_path=ROOT/"20261107T185919Z-819309fd3122-f4da8b5c/service-artifact-read-v1/13586194181/readback.json"
retained=json.loads(retained_path.read_bytes())
require(retained["errors"]==[] and retained["source_binding"]["before_after_equal"] is True and retained["manifest_file_hashes_verified"]==50,"previous service readback not verified")
matching=[a for a in arts if a["id"]==13586194181]
require(len(matching)==1 and all(matching[0][key]==retained["metadata"][key] for key in ("id","name","digest","size_in_bytes","workflow_run")),"previous artifact metadata changed")
selected=[a for a in arts if a["workflow_run"]["id"]==42402618518 and "-service-model-" in a["name"] and a["id"]!=13586194181]
def fetch(endpoint,path,timeout=90):
 argv=["/usr/bin/gh","api","--hostname","github.com","--method","GET",endpoint]
 with path.open("xb") as out,path.with_suffix(path.suffix+".stderr").open("xb") as err:
  p=subprocess.run(argv,stdout=out,stderr=err,timeout=timeout)
 return {"argv":argv,"exit_code":p.returncode,"bytes":path.stat().st_size,"sha256":sha(path.read_bytes())}
def one(a):
 row={"artifact_id":a["id"],"metadata":a,"errors":[],"native_gate_validated":False}
 d=OUT/str(a["id"]);d.mkdir()
 try:
  require(a["workflow_run"]["head_sha"]==H and not a["expired"],"artifact source/expiry")
  require(a["size_in_bytes"]<=16*1024*1024,"service zip byte bound")
  free=os.statvfs(OUT);require(free.f_bavail*free.f_frsize>256*1024*1024,"observer free disk")
  row["download"]=fetch("repos/"+REPO+"/actions/artifacts/"+str(a["id"])+"/zip",d/"artifact.zip")
  require(row["download"]["exit_code"]==0 and row["download"]["bytes"]==a["size_in_bytes"]
          and a["digest"]=="sha256:"+row["download"]["sha256"],"ZIP metadata mismatch")
  contents={};inventory=[]
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist()
   require(len(infos)<=8192 and len({x.filename for x in infos})==len(infos),"entry count/duplicates")
   require(sum(x.file_size for x in infos)<=256*1024*1024,"uncompressed bound")
   for i in infos:
    p=PurePosixPath(i.filename)
    require(not p.is_absolute() and ".." not in p.parts and "\\" not in i.filename
            and not stat.S_ISLNK(i.external_attr>>16),"zip path/type")
    inventory.append({"name":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size})
    if i.is_dir():continue
    chosen=(i.filename in ("source.json","push-source-context.json")
            or i.filename.endswith("/manifest.json") or i.filename.endswith("/report.json")
            or ("host/" in i.filename and i.filename.endswith(".json"))
            or p.name in ("stdout","stderr") or i.filename.endswith(".log"))
    if not chosen:continue
    require(i.file_size<=64*1024*1024,"selected file bound")
    data=z.read(i);target=d/i.filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    contents[i.filename]={"bytes":len(data),"sha256":sha(data)}
   row["archive_inventory"]=inventory;row["selected_files"]=contents
   manifest=json.loads((d/"from-zero-native/manifest.json").read_bytes())
   files=manifest.get("files")
   require(isinstance(files,dict),"manifest hash map missing")
   checked=[]
   for name,expected in files.items():
    require(type(name) is str and not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,"manifest path")
    zi=z.getinfo("from-zero-native/"+name)
    require(zi.file_size<=64*1024*1024 and sha(z.read(zi))==expected,"manifest file digest "+name)
    checked.append(name)
   row["manifest_file_hashes_verified"]=len(checked)
  source=json.loads((d/"source.json").read_bytes())
  mat=json.loads((d/"push-source-context.json").read_bytes())
  resolver=json.loads((ROOT/"20261107T184658Z-819309fd3122-78a49720/source-artifact-read-v1/13585647797/context.json").read_bytes())
  kind="head" if "-head-" in a["name"] else "prospective-merge"
  tested=H if kind=="head" else M
  require(source["tested_commit"]==tested and source["tested_tree"]==TREE and source["candidate"]==H
          and source["kind"]==kind and source["tracked_worktree_verified"] is True,"lane source")
  if kind=="prospective-merge":require(source["base"]==B and source["prospective_merge"]==M,"merge source")
  require(mat["context"]==resolver and mat["source"]==source and mat["github_event_name"]=="push"
          and mat["github_sha"]==H and mat["is_github_pr_merge"] is False
          and mat["context_sha256"]==sha(json.dumps(resolver,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()),"materialization")
  runner="ubuntu-24.04-arm" if "ubuntu-24.04-arm-" in a["name"] else "ubuntu-24.04"
  jobname="native priorities ("+runner+", "+kind+", service-model)"
  matches=[j for j in jobs if j["name"]==jobname]
  require(len(matches)==1,"unique service job")
  job=matches[0];row["job_id"]=job["id"];row["job_status"]=job["status"];row["job_conclusion"]=job["conclusion"]
  row["job_log"]=fetch("repos/"+REPO+"/actions/jobs/"+str(job["id"])+"/logs",d/"job.log")
  require(row["job_log"]["exit_code"]==0,"job log unavailable")
  identities=[]
  clean="\n".join(re.sub(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z ?", "", line) for line in (d/"job.log").read_text(errors="strict").splitlines())
  decoder=json.JSONDecoder()
  for match in re.finditer(r"(?m)^\{",clean):
   try:obj,_=decoder.raw_decode(clean,match.start())
   except (ValueError,TypeError):continue
   if isinstance(obj,dict) and obj.get("schema")=="trnm-ci-source-v1":identities.append(obj)
  after_steps=[x for x in job["steps"] if x["name"]=="Reverify exact unchanged source"]
  require(len(after_steps)==1 and after_steps[0]["status"]=="completed" and after_steps[0]["conclusion"]=="success","native source-after step")
  require(len(identities)>=2 and identities[0]==source and identities[-1]==source,"native source-after log")
  row["source_binding"]={"kind":kind,"tested_commit":tested,"tree":TREE,"before_after_equal":True,
                         "resolver_context_equal":True,"log_source_identity_count":len(identities)}
  row["manifest"]={k:manifest.get(k) for k in ("schema","passed","failures","execution_finished","all_named_tests_passed","format_passed","source_recompiled","binary_sha256_before","binary_sha256_after","terminal")}
  row["manifest"]["source_before_after_equal"]=manifest.get("source_before")==manifest.get("source_after")
  row["native_runs"]=[{k:r.get(k) for k in ("name","passed","failure","named_execution")}|{"process":r.get("process")} for r in manifest.get("runs",[])]
  row["host"]={}
  for name in contents:
   if "host/" not in name or not name.endswith(".json"):continue
   if PurePosixPath(name).name not in ("controller-result.json","child-result.json"):continue
   doc=json.loads((d/name).read_bytes())
   row["host"][name]={k:doc.get(k) for k in ("schema","passed","failure","host_errors","final_host_errors","native_child_exit","systemd_run_exit","cleanup","preparation_execution_binding")}
  row["reports"]={}
  for tag,rel,validator in (("service","native/report.json",native.validate_service_report),
                             ("sustained","native/sustained/report.json",native.validate_sustained_report),
                             ("confirmation","confirmation/report.json",native.validate_confirmation_report)):
   p=d/"from-zero-native"/rel
   if not p.exists():row["reports"][tag]={"missing":True};continue
   doc=json.loads(p.read_bytes());r={"path":str(p),"sha256":sha(p.read_bytes()),"schema":doc.get("schema"),"finite_target_met":doc.get("finite_target_met")}
   try:r["strict_pure_read"]=validator(p)
   except Exception as e:r["strict_pure_error"]=type(e).__name__+": "+str(e)
   r["phases"]=[]
   for ph in doc.get("phases",[]):
    v={k:ph.get(k) for k in ("phase","mode","requested_window_ns","workers","business_started_ns","confirmation_ended_ns","client_confirmation_latency_ns","client_confirmed_transactions","client_confirmed_before_original_window_end","finite_business_target_met","finite_target_met","verification_errors","honest_read_successes","complete_denominators","construction_count")}
    v.update(attacker_workers=len(ph.get("attacks",[])),attack_calls=sum(len(x.get("calls",[])) for x in ph.get("attacks",[])),
             honest_submissions=len(ph.get("honest_submissions",[])),honest_history=len(ph.get("honest_history",[])))
    if tag=="confirmation":
     v["independent_history_page_replay"]=ph.get("independent_history_page_replay")
     v["honest_submission_outcomes"]=[{k:x.get(k) for k in ("status","error","started_ns","ended_ns","returned_after_deadline","returned_after_window")} for x in ph.get("honest_submissions",[])]
     v["honest_history_outcomes"]=[{k:x.get(k) for k in ("status","error","started_ns","ended_ns","returned_after_deadline","returned_after_window")} for x in ph.get("honest_history",[])]
    r["phases"].append(v)
   if tag=="confirmation":
    try:
     obs=native.summarize_confirmation_report(p)
     (d/"confirmation-observation-independent-v2.json").write_text(json.dumps(obs,indent=2)+"\n")
     r["independent_observation"]={"path":str(d/"confirmation-observation-independent-v2.json"),
       "original_gate_validated":obs.get("original_gate_validated"),"original_gate_validation_error":obs.get("original_gate_validation_error")}
    except Exception as e:r["independent_observation_error"]=type(e).__name__+": "+str(e)
   row["reports"][tag]=r
 except Exception as e:row["errors"].append(type(e).__name__+": "+str(e))
 row["finished_utc"]=datetime.now(timezone.utc).isoformat()
 (d/"readback.json").write_text(json.dumps(row,indent=2)+"\n")
 return row
with ThreadPoolExecutor(max_workers=2) as ex:results=list(ex.map(one,selected))
summary={"directory":str(OUT),"artifact_count":len(results),"native_lane_denominator":4,
         "native_gate_validated":False,"retained_previously_verified":[{"artifact_id":13586194181,"readback":str(retained_path)}],"combined_observed_artifact_count":len(results)+1,"results":results}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps({"directory":str(OUT),"artifact_count":len(results),"results":[{k:r.get(k) for k in ("artifact_id","job_id","errors","source_binding","manifest_file_hashes_verified","manifest","native_runs","host","reports")} for r in results]}))

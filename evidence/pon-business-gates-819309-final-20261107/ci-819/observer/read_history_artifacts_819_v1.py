from pathlib import Path,PurePosixPath
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib,json,os,stat,subprocess,sys,zipfile,re
sys.dont_write_bytecode=True
ROOT=Path("/home/qian-qi/throughput-final-ci-observation-20261107")
sys.path.insert(0,str(ROOT))
from read_ci_metadata import parse_http
PIN=ROOT/"pinned-readers-819309fd-v1"
sys.path.insert(0,str(PIN/"scripts/ci"))
from check_required_native_test import validate as validate_named
import run_history_native as original_history
H="819309fd312298e099642e1253b1d4ba07113e98"
M="28df21f965e0348690836c9c854dab645827a03d"
B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TREE="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
REPO="TrillionniumFoundation/Trillionnium-Chain"
SNAP=Path(sys.argv[1]);OUT=SNAP/"history-artifact-read-v1";OUT.mkdir()
def sha(v):return hashlib.sha256(v).hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
def fetch(endpoint,path,timeout=90):
 argv=["/usr/bin/gh","api","--hostname","github.com","--method","GET",endpoint]
 result={"argv":argv,"exit_code":None,"timeout":False,"error":None}
 try:
  with path.open("xb") as out,path.with_suffix(path.suffix+".stderr").open("xb") as err:
   p=subprocess.run(argv,stdout=out,stderr=err,timeout=timeout)
  result["exit_code"]=p.returncode
 except subprocess.TimeoutExpired as e:result.update(timeout=True,error=type(e).__name__+": "+str(e))
 except Exception as e:result["error"]=type(e).__name__+": "+str(e)
 result.update(bytes=path.stat().st_size if path.exists() else None,sha256=sha(path.read_bytes()) if path.exists() else None)
 return result
identity=fetch("user",OUT/"identity-before.json")
require(identity["exit_code"]==0,"observer identity GET failed")
who=json.loads((OUT/"identity-before.json").read_bytes())
require(who.get("login")=="ProfHepta" and who.get("id")==102159240,"specified GitHub identity required")
s=json.loads((SNAP/"snapshot.json").read_bytes());arts=[];jobs=[]
for q in s["queries"]:
 if "/artifacts?" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());arts+=obj["artifacts"]
 if "/jobs?filter=all" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());jobs+=obj["jobs"]
selected=[a for a in arts if a["workflow_run"]["id"]==42402618518 and "-history-" in a["name"]]
if len(sys.argv)>2:selected=[a for a in selected if str(a["id"]) in sys.argv[2:]]
def one(a):
 row={"artifact_id":a["id"],"metadata":a,"errors":[],"readback_complete":False,"original_business_passed":None,
      "scope":"original 4105 History outcome and retained bytes; no recovery, rerun, or substitute oracle"}
 d=OUT/str(a["id"]);d.mkdir()
 try:
  require(a["workflow_run"]["head_sha"]==H and not a["expired"],"artifact source/expiry")
  require(a["size_in_bytes"]<=256*1024*1024,"History ZIP bound")
  free=os.statvfs(OUT);require(free.f_bavail*free.f_frsize>2*1024**3,"observer free disk")
  row["download"]=fetch("repos/"+REPO+"/actions/artifacts/"+str(a["id"])+"/zip",d/"artifact.zip",240)
  require(row["download"]["exit_code"]==0 and row["download"]["bytes"]==a["size_in_bytes"] and a["digest"]=="sha256:"+row["download"]["sha256"],"ZIP metadata mismatch")
  contents={};inventory=[]
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist();require(len(infos)<=8192 and len({i.filename for i in infos})==len(infos),"entry count/duplicates")
   require(sum(i.file_size for i in infos)<=2*1024**3,"uncompressed bound")
   for i in infos:
    p=PurePosixPath(i.filename)
    require(not p.is_absolute() and ".." not in p.parts and "\\" not in i.filename and not stat.S_ISLNK(i.external_attr>>16),"ZIP path/type")
    inventory.append({"name":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size})
    if i.is_dir():continue
    require(i.file_size<=1024**3,"member bound")
    target=d/i.filename;target.parent.mkdir(parents=True,exist_ok=True)
    digest=hashlib.sha256();count=0
    with z.open(i) as inp,target.open("xb") as out:
     while True:
      chunk=inp.read(1024*1024)
      if not chunk:break
      count+=len(chunk);require(count<=i.file_size,"inflated member bound");digest.update(chunk);out.write(chunk)
    require(count==i.file_size,"member length")
    contents[i.filename]={"bytes":count,"sha256":digest.hexdigest()}
  row["archive_inventory"]=inventory;row["retained_files"]=contents
  source=json.loads((d/"source.json").read_bytes());mat=json.loads((d/"push-source-context.json").read_bytes())
  resolver=json.loads((ROOT/"20261107T184658Z-819309fd3122-78a49720/source-artifact-read-v1/13585647797/context.json").read_bytes())
  kind="head" if "-head-" in a["name"] else "prospective-merge";tested=H if kind=="head" else M
  require(source["tested_commit"]==tested and source["tested_tree"]==TREE and source["candidate"]==H and source["kind"]==kind and source["tracked_worktree_verified"] is True,"lane source")
  if kind=="prospective-merge":require(source["base"]==B and source["prospective_merge"]==M,"merge source")
  require(mat["context"]==resolver and mat["source"]==source and mat["github_event_name"]=="push" and mat["github_sha"]==H and mat["is_github_pr_merge"] is False and mat["context_sha256"]==sha(json.dumps(resolver,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()),"materialization")
  runner="ubuntu-24.04-arm" if "ubuntu-24.04-arm-" in a["name"] else "ubuntu-24.04"
  matches=[j for j in jobs if j["name"]=="native priorities ("+runner+", "+kind+", history)"]
  require(len(matches)==1,"unique history job")
  job=matches[0];row.update(job_id=job["id"],job_status=job["status"],job_conclusion=job["conclusion"])
  row["job_log"]=fetch("repos/"+REPO+"/actions/jobs/"+str(job["id"])+"/logs",d/"job.log")
  require(row["job_log"]["exit_code"]==0,"job log unavailable")
  clean="\n".join(re.sub(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z ?","",x) for x in (d/"job.log").read_text().splitlines())
  identities=[];decoder=json.JSONDecoder()
  for match in re.finditer(r"(?m)^\{",clean):
   try:obj,_=decoder.raw_decode(clean,match.start())
   except (ValueError,TypeError):continue
   if isinstance(obj,dict) and obj.get("schema")=="trnm-ci-source-v1":identities.append(obj)
  after=[x for x in job["steps"] if x["name"]=="Reverify exact unchanged source"]
  require(len(after)==1 and after[0]["status"]=="completed" and after[0]["conclusion"]=="success","native source-after step")
  require(len(identities)>=2 and identities[0]==source and identities[-1]==source,"native source-after log")
  row["source_binding"]={"kind":kind,"tested_commit":tested,"tree":TREE,"before_after_equal":True,"resolver_context_equal":True,"log_source_identity_count":len(identities)}
  row["history_steps"]=[{k:x.get(k) for k in ("name","status","conclusion","started_at","completed_at")} for x in job["steps"] if x["name"] in ("Build the original long-history test separately from measurement","Execute 4105 real work blocks and paid public full sync")]
  hd=d/"history-native";manifest=json.loads((hd/"manifest.json").read_bytes());prep=json.loads((hd/"preparation.json").read_bytes())
  require(prep["schema"]==original_history.PREPARATION_SCHEMA and prep["completed"] is True and prep["failures"]==[],"History preparation")
  require(prep["source_before"]==prep["source_after"] and prep["source_before"]["tracked_source_identity"]==source,"History build source")
  require(manifest["schema"]==original_history.EXECUTION_SCHEMA and manifest["source_before"]==manifest["source_after"]==prep["source_before"],"History execution source")
  require(manifest["preparation_sha256"]==sha((hd/"preparation.json").read_bytes()),"preparation digest")
  require(manifest["binary_before"]==manifest["binary_after"]==prep["binary"],"History observed binary before/after")
  retained_hashes=[]
  for owner,key,rel in [(prep,"build_log","history-native/build.jsonl"),(manifest,"log","history-native/history.log"),(manifest,"resources","history-native/history-resources.txt"),(manifest,"summary_file","history-native/long-history/summary.json")]:
   observed=owner.get(key)
   if observed is None:
    retained_hashes.append({"field":key,"path":rel,"observed":False});continue
   got=contents.get(rel);require(got is not None and got["sha256"]==observed["sha256"] and got["bytes"]==observed["size_bytes"],"retained manifest identity "+key)
   retained_hashes.append({"field":key,"path":rel,"observed":True,**got,"digest_verified":True})
  row["retained_manifest_file_identities"]=retained_hashes
  row["preparation"]={k:prep.get(k) for k in ("schema","completed","failures","job","process","binary","native_tests_executed","service_resource_observation")}
  row["manifest"]={k:manifest.get(k) for k in ("schema","target","selector","job","process","named_execution","failures","passed","compilation_in_native_measurement","whole_test_command_preserved","native_execution_authenticated","summary","public_network_ready","hardness_accepted","independent_accepted","production_activation")}
  row["manifest"]["source_before_after_equal"]=True;row["manifest"]["binary_before_after_equal"]=True
  row["manifest"]["binary_sha256"]=prep["binary"]["sha256"]
  raw=(hd/"history.log").read_bytes();lines=raw.decode().splitlines()
  row["original_reader"]={}
  try:row["original_reader"]["named_execution"]=validate_named(lines,original_history.SELECTOR)
  except Exception as e:row["original_reader"]["named_execution_error"]=type(e).__name__+": "+str(e)
  sp=hd/"long-history/summary.json"
  if sp.exists():
   summary=json.loads(sp.read_bytes())
   try:original_history.validate_summary(summary);row["original_reader"]["summary_passed"]=True
   except Exception as e:row["original_reader"]["summary_error"]=type(e).__name__+": "+str(e)
   row["original_reader"]["summary"]=summary
  else:row["original_reader"]["summary_missing"]=True
  row["log_summary_lines"]=[{"line":i+1,"text":x} for i,x in enumerate(lines) if x.startswith("test result:") or "panicked at" in x or "successful imports" in x or "imported " in x or "native-ancestry-public-server-exit-evidence-v1" in x or "PUBLIC_REQUEST_DEADLINE" in x]
  row["structured_native_log_records"]=[]
  decoder=json.JSONDecoder()
  for i,line in enumerate(lines):
   if "{" not in line:continue
   try:obj,_=decoder.raw_decode(line,line.index("{"))
   except (ValueError,TypeError):continue
   if isinstance(obj,dict) and str(obj.get("schema","")).startswith("native-ancestry"):
    row["structured_native_log_records"].append({"line":i+1,"record":obj})
  row["host"]={}
  for name in contents:
   if "host/" not in name or PurePosixPath(name).name not in ("controller-result.json","child-result.json"):continue
   doc=json.loads((d/name).read_bytes())
   row["host"][name]={k:doc.get(k) for k in ("schema","passed","failure","host_errors","final_host_errors","native_child_exit","systemd_run_exit","cleanup","preparation_execution_binding")}
  row["sqlite_files"]=[{"path":str(d/n),**v} for n,v in contents.items() if n.endswith(".sqlite")]
  process=manifest.get("process") or {}
  row["original_business_passed"]=(manifest.get("passed") is True and manifest.get("failures")==[] and process.get("exit_code")==0 and row["original_reader"].get("summary_passed") is True and "named_execution" in row["original_reader"])
  row["readback_complete"]=True
 except Exception as e:row["errors"].append(type(e).__name__+": "+str(e))
 row["finished_utc"]=datetime.now(timezone.utc).isoformat()
 (d/"readback.json").write_text(json.dumps(row,indent=2)+"\n")
 print(json.dumps({"progress":"retained-history-artifact","artifact_id":a["id"],"readback_complete":row["readback_complete"],"errors":row["errors"]}),flush=True)
 return row
with ThreadPoolExecutor(max_workers=2) as pool:rows=list(pool.map(one,selected))
identity_after=fetch("user",OUT/"identity-after.json")
after=json.loads((OUT/"identity-after.json").read_bytes()) if identity_after["exit_code"]==0 else {}
summary={"directory":str(OUT),"candidate":H,"history_lane_denominator":4,"artifact_count":len(rows),"identity_before":identity,"identity_after":identity_after,
 "identity_unchanged":after.get("login")==who["login"] and after.get("id")==who["id"],"results":rows}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
core={"schema":"trnm-final819-history-native-outcome-core-v1","directory":str(OUT),"candidate":H,"history_lane_denominator":4,"artifact_count":len(rows),"identity_unchanged":summary["identity_unchanged"],
 "results":[{k:r.get(k) for k in ("artifact_id","job_id","errors","readback_complete","original_business_passed","source_binding","history_steps","manifest","original_reader","log_summary_lines","host","sqlite_files")} for r in rows]}
(OUT/"native-outcome-core-v1.json").write_text(json.dumps(core,indent=2)+"\n")
print(json.dumps({"directory":str(OUT),"artifact_count":len(rows),"identity_unchanged":summary["identity_unchanged"],"core_path":str(OUT/"native-outcome-core-v1.json"),
 "results":[{k:r.get(k) for k in ("artifact_id","job_id","errors","readback_complete","original_business_passed","log_summary_lines")} for r in rows]}))

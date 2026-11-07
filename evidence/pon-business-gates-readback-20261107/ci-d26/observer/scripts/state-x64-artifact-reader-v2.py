from pathlib import Path,PurePosixPath
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,os,re,stat,subprocess,sys,zipfile
ROOT=Path("/home/qian-qi/throughput-ci-observation-20261107")
SNAP=ROOT/"20261107T155220Z-d26e047dedfc-bb63e773"
OUT=SNAP/"state-x64-artifact-read-v2";OUT.mkdir()
sys.path.insert(0,str(ROOT));from read_ci_metadata import parse_http
sys.path.insert(0,str(ROOT/"pinned-readers-d26-v1/scripts/ci"));from check_required_native_test import validate
H="d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89";M="7805f1445aec6a31152b50c3d28f5eb6db63305c";B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0";TREE="cef3563653b982a8043326ad4b53a4b93ab63906"
REPO="TrillionniumFoundation/Trillionnium-Chain"
s=json.loads((SNAP/"snapshot.json").read_bytes());arts=[];jobs=[]
for q in s["queries"]:
 if "/artifacts?" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());arts+=obj["artifacts"]
 if "/jobs?filter=all" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());jobs+=obj["jobs"]
selected=[a for a in arts if "-state-" in a["name"] and "-arm-" not in a["name"]]
def sha(v):return hashlib.sha256(v).hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
def fetch(endpoint,d,name):
 argv=["/usr/bin/gh","api","--hostname","github.com","--method","GET",endpoint]
 with (d/name).open("xb") as out,(d/(name+".stderr")).open("xb") as err:p=subprocess.run(argv,stdout=out,stderr=err,timeout=90)
 return {"argv":argv,"exit_code":p.returncode,"bytes":(d/name).stat().st_size,"sha256":sha((d/name).read_bytes())}
def one(a):
 d=OUT/str(a["id"]);d.mkdir();row={"artifact_id":a["id"],"metadata":a,"errors":[],"native_gate_validated":False}
 try:
  require(a["workflow_run"]["id"]==42383368690 and a["workflow_run"]["head_sha"]==H and not a["expired"],"metadata source")
  require(a["size_in_bytes"]<=2*1024*1024,"state zip bound")
  row["download"]=fetch("repos/"+REPO+"/actions/artifacts/"+str(a["id"])+"/zip",d,"artifact.zip")
  require(row["download"]["exit_code"]==0 and row["download"]["bytes"]==a["size_in_bytes"] and a["digest"]=="sha256:"+row["download"]["sha256"],"ZIP digest")
  files={}
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist();require(len(infos)<=256 and sum(i.file_size for i in infos)<=8*1024*1024,"state archive bound")
   for i in infos:
    path=PurePosixPath(i.filename)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in i.filename and not stat.S_ISLNK(i.external_attr>>16),"archive member")
    if i.is_dir():continue
    require(i.file_size<=2*1024*1024,"state member bound")
    payload=z.read(i);p=d/i.filename;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(payload)
    files[i.filename]={"bytes":len(payload),"sha256":sha(payload)}
  row["files"]=files
  source=json.loads((d/"source.json").read_bytes());mat=json.loads((d/"push-source-context.json").read_bytes())
  resolver=json.loads((ROOT/"20261107T145028Z-d26e047dedfc-a2c5a3df/source-artifact-read-v1/13578352816/context.json").read_bytes())
  kind="head" if "-head-" in a["name"] else "prospective-merge";tested=H if kind=="head" else M
  require(source["kind"]==kind and source["tested_commit"]==tested and source["tested_tree"]==TREE and source["candidate"]==H and source["tracked_worktree_verified"] is True,"source before")
  if kind=="prospective-merge":require(source["base"]==B and source["prospective_merge"]==M,"merge binding")
  require(mat["context"]==resolver and mat["source"]==source and mat["github_event_name"]=="push" and mat["github_sha"]==H and mat["is_github_pr_merge"] is False and mat["context_sha256"]==sha(json.dumps(resolver,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()),"materialization")
  runner="ubuntu-24.04-arm" if "ubuntu-24.04-arm-" in a["name"] else "ubuntu-24.04"
  found=[j for j in jobs if j["name"]=="native priorities ("+runner+", "+kind+", state)"];require(len(found)==1,"job denominator")
  job=found[0];row["job_id"]=job["id"];row["job_status"]=job["status"];row["job_conclusion"]=job["conclusion"]
  row["job_log"]=fetch("repos/"+REPO+"/actions/jobs/"+str(job["id"])+"/logs",d,"job.log")
  require(row["job_log"]["exit_code"]==0,"log GET")
  clean="\n".join(re.sub(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z ?", "", line) for line in (d/"job.log").read_text().splitlines())
  dec=json.JSONDecoder();identities=[]
  for match in re.finditer(r"(?m)^\{",clean):
   try:obj,_=dec.raw_decode(clean,match.start())
   except ValueError:continue
   if isinstance(obj,dict) and obj.get("schema")=="trnm-ci-source-v1":identities.append(obj)
  after=[x for x in job["steps"] if x["name"]=="Reverify exact unchanged source"]
  require(len(after)==1 and after[0]["conclusion"]=="success" and len(identities)>=2 and identities[0]==source and identities[-1]==source,"source-after")
  row["source_binding"]={"kind":kind,"tested_commit":tested,"tree":TREE,"before_after_equal":True,"resolver_context_equal":True}
  selectors={
   "large-state-admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.log":"store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner",
   "large-state-authenticated_large_parent_original_schedule_supplementary_denominator.log":"store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator",
   "capacity.log":"account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover",
   "state-monetary_ranges_preserve_nonmonetary_cleanup_and_refuse_raw_m06_projection_omission.log":"monetary_ranges_preserve_nonmonetary_cleanup_and_refuse_raw_m06_projection_omission",
   "state-test_every_reorg_process_cut_and_admission_gap_recovers_once.log":"test_every_reorg_process_cut_and_admission_gap_recovers_once",
   "state-test_packet_status_non_tip_height_and_512_bit_work_match_one_active_ancestry.log":"test_packet_status_non_tip_height_and_512_bit_work_match_one_active_ancestry"
  }
  row["named_tests"]=[]
  for name,selector in selectors.items():
   lines=(d/name).read_text().splitlines()
   row["named_tests"].append({"log":name,"sha256":files[name]["sha256"],"required":selector,"strict_reader":validate(lines,selector),"terminal_lines":[x for x in lines if x.startswith("test result:")],"observation_lines":[x for x in lines if x.startswith("{")][:16]})
  lines=(d/"migration.log").read_text().splitlines()
  terminal=[x for x in lines if re.fullmatch(r"test result: ok\. [1-9][0-9]* passed; 0 failed;.*",x)]
  require(bool(terminal) and len(terminal)==len([x for x in lines if x.startswith("test result:")]),"migration original nonzero-positive terminal gate")
  row["migration"]={"sha256":files["migration.log"]["sha256"],"terminal":terminal,"named_ok":[x for x in lines if x.startswith("test ") and x.endswith(" ... ok")]}
  row["component_controls_readback_passed"]=True
 except Exception as e:row["errors"].append(type(e).__name__+": "+str(e))
 (d/"readback.json").write_text(json.dumps(row,indent=2)+chr(10))
 return row
with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(one,selected))
summary={"schema":"trnm-independent-state-artifact-read-v1","expected_matrix_lanes":4,"retained_completed_lanes":len(results),"native_gate_validated":False,"results":results}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2)+chr(10))
print(json.dumps({"directory":str(OUT),"retained_completed_lanes":len(results),"results":[{k:r.get(k) for k in ("artifact_id","job_id","job_conclusion","source_binding","errors","migration","component_controls_readback_passed")} for r in results]}))

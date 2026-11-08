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
H="819309fd312298e099642e1253b1d4ba07113e98"
M="28df21f965e0348690836c9c854dab645827a03d"
B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TREE="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
REPO="TrillionniumFoundation/Trillionnium-Chain"
SNAP=Path(sys.argv[1]);OUT=SNAP/"state-artifact-read-v1";OUT.mkdir()
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
selected=[a for a in arts if a["workflow_run"]["id"]==42402618518 and "-state-" in a["name"]]
if len(sys.argv)>2:selected=[a for a in selected if str(a["id"]) in sys.argv[2:]]
SELECTORS=[
 ("large-state-admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.log","store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner"),
 ("large-state-authenticated_large_parent_original_schedule_supplementary_denominator.log","store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator"),
 ("capacity.log","account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover"),
 ("state-monetary_ranges_preserve_nonmonetary_cleanup_and_refuse_raw_m06_projection_omission.log","monetary_ranges_preserve_nonmonetary_cleanup_and_refuse_raw_m06_projection_omission"),
 ("state-test_every_reorg_process_cut_and_admission_gap_recovers_once.log","test_every_reorg_process_cut_and_admission_gap_recovers_once"),
 ("state-test_packet_status_non_tip_height_and_512_bit_work_match_one_active_ancestry.log","test_packet_status_non_tip_height_and_512_bit_work_match_one_active_ancestry")]
def one(a):
 row={"artifact_id":a["id"],"metadata":a,"errors":[],"state_control_readback_passed":False,
      "scope":"original State controls only; not service/History or throughput qualification"}
 d=OUT/str(a["id"]);d.mkdir()
 try:
  require(a["workflow_run"]["head_sha"]==H and not a["expired"],"artifact source/expiry")
  require(a["size_in_bytes"]<=8*1024*1024,"state ZIP bound")
  row["download"]=fetch("repos/"+REPO+"/actions/artifacts/"+str(a["id"])+"/zip",d/"artifact.zip")
  require(row["download"]["exit_code"]==0 and row["download"]["bytes"]==a["size_in_bytes"] and a["digest"]=="sha256:"+row["download"]["sha256"],"ZIP metadata mismatch")
  contents={};inventory=[]
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist();require(len(infos)<=1024 and len({i.filename for i in infos})==len(infos),"entry count/duplicates")
   require(sum(i.file_size for i in infos)<=64*1024*1024,"uncompressed bound")
   for i in infos:
    p=PurePosixPath(i.filename)
    require(not p.is_absolute() and ".." not in p.parts and "\\" not in i.filename and not stat.S_ISLNK(i.external_attr>>16),"zip path/type")
    inventory.append({"name":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size})
    if i.is_dir():continue
    require(i.file_size<=16*1024*1024,"selected file bound")
    data=z.read(i);target=d/i.filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    contents[i.filename]={"bytes":len(data),"sha256":sha(data)}
  row["archive_inventory"]=inventory;row["retained_files"]=contents
  row["internal_file_manifest"]="not supplied by original state workflow; all archive members retained with independent SHA256"
  source=json.loads((d/"source.json").read_bytes());mat=json.loads((d/"push-source-context.json").read_bytes())
  resolver=json.loads((ROOT/"20261107T184658Z-819309fd3122-78a49720/source-artifact-read-v1/13585647797/context.json").read_bytes())
  kind="head" if "-head-" in a["name"] else "prospective-merge";tested=H if kind=="head" else M
  require(source["tested_commit"]==tested and source["tested_tree"]==TREE and source["candidate"]==H and source["kind"]==kind and source["tracked_worktree_verified"] is True,"lane source")
  if kind=="prospective-merge":require(source["base"]==B and source["prospective_merge"]==M,"merge source")
  require(mat["context"]==resolver and mat["source"]==source and mat["github_event_name"]=="push" and mat["github_sha"]==H and mat["is_github_pr_merge"] is False and mat["context_sha256"]==sha(json.dumps(resolver,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()),"materialization")
  runner="ubuntu-24.04-arm" if "ubuntu-24.04-arm-" in a["name"] else "ubuntu-24.04"
  matches=[j for j in jobs if j["name"]=="native priorities ("+runner+", "+kind+", state)"]
  require(len(matches)==1,"unique state job")
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
  row["state_steps"]=[{k:x.get(k) for k in ("name","status","conclusion","started_at","completed_at")} for x in job["steps"] if x["name"] in ("Execute original large-state CPU-budget tests","Execute original native full-capacity test","Execute original source-preserving migration tests","Execute actual obligation ranges and native reorganization regressions")]
  row["named_controls"]=[]
  for name,selector in SELECTORS:
   r={"path":str(d/name),"selector":selector,"pass":False}
   try:
    raw=(d/name).read_bytes();r.update(bytes=len(raw),sha256=sha(raw),readback=validate_named(raw.decode().splitlines(),selector),pass_=True)
    r["pass"]=True;r.pop("pass_",None)
   except Exception as e:r["error"]=type(e).__name__+": "+str(e)
   row["named_controls"].append(r)
  mp=d/"migration.log";raw=mp.read_bytes();lines=raw.decode().splitlines()
  summaries=[x for x in lines if x.startswith("test result:")]
  names=[x for x in lines if re.fullmatch(r"test [A-Za-z0-9_:]+ \.\.\. ok",x)]
  running=[x for x in lines if re.fullmatch(r"running \d+ tests?",x)]
  pattern=r"test result: ok\. 40 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s"
  migration_ok=bool(summaries) and re.fullmatch(pattern,summaries[-1]) is not None
  row["migration"]={"path":str(mp),"bytes":len(raw),"sha256":sha(raw),"running_lines":running,"all_summary_lines":summaries,
      "main_summary":summaries[-1] if summaries else None,"main_executed_tests":40 if migration_ok else None,
      "standalone_ok_line_count":len(names),"named_ok_lines":names,"main_40_summary_passed":migration_ok,
      "fifo_subprocesses_are_not_additional_main_tests":True}
  row["state_control_readback_passed"]=(len(row["named_controls"])==6 and all(x["pass"] for x in row["named_controls"]) and migration_ok and len(row["state_steps"])==4 and all(x["conclusion"]=="success" for x in row["state_steps"]) and job["conclusion"]=="success")
 except Exception as e:row["errors"].append(type(e).__name__+": "+str(e))
 row["finished_utc"]=datetime.now(timezone.utc).isoformat()
 (d/"readback.json").write_text(json.dumps(row,indent=2)+"\n")
 return row
with ThreadPoolExecutor(max_workers=2) as pool:rows=list(pool.map(one,selected))
identity_after=fetch("user",OUT/"identity-after.json")
after=json.loads((OUT/"identity-after.json").read_bytes()) if identity_after["exit_code"]==0 else {}
summary={"directory":str(OUT),"candidate":H,"state_lane_denominator":4,"artifact_count":len(rows),"identity_before":identity,"identity_after":identity_after,
 "identity_unchanged":after.get("login")==who["login"] and after.get("id")==who["id"],"results":rows}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps({"directory":str(OUT),"artifact_count":len(rows),"identity_unchanged":summary["identity_unchanged"],"results":[{k:r.get(k) for k in ("artifact_id","job_id","errors","state_control_readback_passed","source_binding","state_steps","named_controls","migration")} for r in rows]}))

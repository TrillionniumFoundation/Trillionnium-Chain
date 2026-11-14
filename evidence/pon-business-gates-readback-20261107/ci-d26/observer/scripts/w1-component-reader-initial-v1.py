from pathlib import Path,PurePosixPath
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import collections,hashlib,json,os,stat,subprocess,sys,zipfile
ROOT=Path("/home/qian-qi/throughput-ci-observation-20261107")
sys.path.insert(0,str(ROOT))
from read_ci_metadata import parse_http
SNAP=ROOT/"20261107T151751Z-d26e047dedfc-35b656b0"
OUT=SNAP/"w1-component-artifact-read-v1";OUT.mkdir()
H="d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89"
M="7805f1445aec6a31152b50c3d28f5eb6db63305c"
B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TREE="cef3563653b982a8043326ad4b53a4b93ab63906"
REPO="TrillionniumFoundation/Trillionnium-Chain"
def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  while data:=f.read(1024*1024):h.update(data)
 return h.hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
snap=json.loads((SNAP/"snapshot.json").read_bytes());arts=[];jobs=[]
for q in snap["queries"]:
 if "/artifacts?" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());arts+=obj["artifacts"]
 if "/jobs?filter=all" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());jobs+=obj["jobs"]
selected=[a for a in arts if a["workflow_run"]["id"]==42383368504 and a["name"].startswith("w1-") and not a["name"].startswith("w1-fresh-service-")]
require(len(selected)==20 and len({a["id"] for a in selected})==20,"20 component artifact denominator")
free=os.statvfs(OUT);budget=sum(a["size_in_bytes"] for a in selected)
require(free.f_bavail*free.f_frsize>budget+2*1024**3,"insufficient observer scratch reserve")
resolver=json.loads((ROOT/"20261107T145028Z-d26e047dedfc-a2c5a3df/source-artifact-read-v1/13578437522/context.json").read_bytes())
def one(a):
 d=OUT/str(a["id"]);d.mkdir()
 row={"artifact_id":a["id"],"metadata":a,"started_utc":datetime.now(timezone.utc).isoformat(),"errors":[],"native_gate_validated":False}
 try:
  require(a["workflow_run"]["head_sha"]==H and not a["expired"] and a["size_in_bytes"]<=256*1024*1024,"artifact source/expiry/size")
  argv=["/usr/bin/gh","api","--hostname","github.com","--method","GET","repos/"+REPO+"/actions/artifacts/"+str(a["id"])+"/zip"]
  row["download_argv"]=argv
  with (d/"artifact.zip").open("xb") as out,(d/"download.stderr").open("xb") as err:
   p=subprocess.run(argv,stdout=out,stderr=err,timeout=300)
  row.update(download_exit=p.returncode,zip_bytes=(d/"artifact.zip").stat().st_size,zip_sha256=file_sha(d/"artifact.zip"))
  require(p.returncode==0 and row["zip_bytes"]==a["size_in_bytes"] and a["digest"]=="sha256:"+row["zip_sha256"],"ZIP metadata digest mismatch")
  files={};inventory=[];manifests=[]
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist()
   require(len(infos)<=20000 and len({i.filename for i in infos})==len(infos),"archive entry bound/duplicates")
   total_selected=0
   for i in infos:
    path=PurePosixPath(i.filename)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in i.filename and not stat.S_ISLNK(i.external_attr>>16),"unsafe archive member")
    inventory.append({"path":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size})
    if i.is_dir():continue
    chosen=(i.filename in ("source.json","source-after.json","push-source-context.json") or path.name=="manifest.json")
    if not chosen:continue
    total_selected+=i.file_size
    require(i.file_size<=16*1024*1024 and total_selected<=64*1024*1024,"selected receipt byte bound")
    payload=z.read(i);out=d/i.filename;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(payload)
    files[i.filename]={"bytes":len(payload),"sha256":sha(payload)}
    if path.name=="manifest.json":manifests.append((i.filename,json.loads(payload)))
   row["archive_inventory"]=inventory;row["selected_files"]=files
   row["manifests"]=[]
   for name,manifest in manifests:
    entry={k:manifest.get(k) for k in ("schema","result","error","final_check_error","expected_source_commit","expected_commit","execution_context","architecture","source_changed","binary_sha256_before","binary_sha256_after","retained_binary_sha256_before","retained_binary_sha256_after","failed_commands","commands_without_wait4_usage","production_activation","public_network_ready","work_profile_qualified","resource_fairness_qualified")}
    entry["path"]=name
    entry["source_before_after_equal"]=manifest.get("source_before")==manifest.get("source_after")
    entry["source_before"]=manifest.get("source_before")
    entry["runner_context"]=manifest.get("runner_context")
    observations=manifest.get("observations",[])
    entry["observation_denominator"]=len(observations)
    entry["nonzero_or_timedout_observations"]=[{k:x.get(k) for k in ("name","command","exit_code","timed_out","error")} for x in observations if x.get("exit_code")!=0 or x.get("timed_out")]
    entry["shards"]=[{k:x.get(k) for k in ("configuration","result","error")} for x in manifest.get("shards",[])]
    entries=manifest.get("artifact_sha256",{})
    prefix=PurePosixPath(name).parent
    checked=0
    for rel,expected in entries.items():
     require(type(rel) is str and not PurePosixPath(rel).is_absolute() and ".." not in PurePosixPath(rel).parts,"manifest member path")
     zi=z.getinfo(str(prefix/rel))
     require(zi.file_size<=1024**3,"hashed member bound")
     h=hashlib.sha256()
     with z.open(zi) as f:
      while data:=f.read(1024*1024):h.update(data)
     require(h.hexdigest()==expected,"manifest file digest "+str(prefix/rel))
     checked+=1
    entry["artifact_file_hashes_verified"]=checked
    row["manifests"].append(entry)
  def load(name):return json.loads((d/name).read_bytes())
  source=load("source.json");after=load("source-after.json");mat=load("push-source-context.json")
  kind="head" if "-head-" in a["name"] else "prospective-merge";tested=H if kind=="head" else M
  require(source==after and source["tested_commit"]==tested and source["tested_tree"]==TREE and source["candidate"]==H and source["kind"]==kind and source["tracked_worktree_verified"] is True,"lane source before/after")
  if kind=="prospective-merge":require(source["base"]==B and source["prospective_merge"]==M,"ordered merge binding")
  require(mat["context"]==resolver and mat["source"]==source and mat["github_event_name"]=="push" and mat["github_sha"]==H and mat["is_github_pr_merge"] is False and mat["context_sha256"]==sha(json.dumps(resolver,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()),"lane materialization")
  row["source_binding"]={"kind":kind,"tested_commit":tested,"tree":TREE,"before_after_equal":True,"resolver_context_equal":True}
 except Exception as e:row["errors"].append(type(e).__name__+": "+str(e))
 row["finished_utc"]=datetime.now(timezone.utc).isoformat()
 (d/"readback.json").write_text(json.dumps(row,indent=2)+chr(10))
 print(json.dumps({"artifact_id":a["id"],"name":a["name"],"errors":row["errors"],"source_binding":row.get("source_binding"),"manifests":[{k:m.get(k) for k in ("path","schema","result","error","source_before_after_equal","artifact_file_hashes_verified","observation_denominator","nonzero_or_timedout_observations")} for m in row.get("manifests",[])]}),flush=True)
 return row
with ThreadPoolExecutor(max_workers=2) as ex:results=list(ex.map(one,selected))
summary={"schema":"trnm-independent-w1-component-artifact-read-v1","head":H,"expected_artifacts":20,"observed_artifacts":len(results),"reader_failures":sum(bool(r["errors"]) for r in results),"results":results,"native_gate_validated":False}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2)+chr(10))
print(json.dumps({"finished":True,"directory":str(OUT),"observed_artifacts":len(results),"reader_failures":summary["reader_failures"],"native_gate_validated":False}),flush=True)

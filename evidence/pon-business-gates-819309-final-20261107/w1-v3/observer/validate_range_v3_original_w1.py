from pathlib import Path,PurePosixPath
from datetime import datetime,timezone
import hashlib,json,os,stat,subprocess,sys,zipfile
sys.dont_write_bytecode=True
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107");O=R/"w1-range-v3";d=O/"13586509176"
H="819309fd312298e099642e1253b1d4ba07113e98";M="28df21f965e0348690836c9c854dab645827a03d";B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0";T="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
def require(v,m):
 if not v:raise ValueError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
range_receipt=json.loads((O/"receipt.json").read_bytes())
require(range_receipt["completed"] is True and range_receipt["artifact_id"]==13586509176 and not range_receipt["errors"],"complete authenticated Range receipt required")
old=json.loads((R/"w1-components-transport-v2/13586509176/readback-stage1.json").read_bytes());a=old["metadata"]
require(a["id"]==13586509176 and a["workflow_run"]["id"]==42402618462 and a["workflow_run"]["head_sha"]==H,"original metadata source")
require((d/"artifact.zip").stat().st_size==a["size_in_bytes"] and "sha256:"+sha(d/"artifact.zip")==a["digest"],"restored original GitHub ZIP bytes")
kind="head";tested=H;arch="arm64";family="factorial"
resolver=json.loads((R/"20261107T184658Z-819309fd3122-78a49720/source-artifact-read-v1/13584974949/context.json").read_bytes())
r={"artifact_id":a["id"],"metadata":a,"errors":[],"warnings":[],"archive_authenticated":True,"source_bound":False,"manifest_hashes_complete":False,"pure_read_status":"NOT_RUN","business_qualification":False,"family":family,"arch":arch,"source_kind":kind,"tested_commit":tested,"job":old["job"],"assembly_provenance":{"range_receipt_path":str(O/"receipt.json"),"range_receipt_sha256":sha(O/"receipt.json"),"complete_original_zip_bytes_verified":True,"new_full_zip_get_used":False}}
try:
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist();require(len(infos)<=8192 and len({x.filename for x in infos})==len(infos),"entries/duplicates")
   require(sum(x.file_size for x in infos)<=4*1024**3,"uncompressed archive bound")
   selected=[]
   for i in infos:
    p=PurePosixPath(i.filename);require(not p.is_absolute() and ".." not in p.parts and "\\" not in i.filename and not stat.S_ISLNK(i.external_attr>>16),"safe ZIP member")
    if i.is_dir():continue
    require(i.file_size<=1024**3,"member size bound")
    keep=(p.suffix in (".json",".jsonl",".stdout",".stderr",".log",".txt") or p.name in ("stdout","stderr"))
    if keep:selected.append(i)
   free=os.statvfs(O);require(free.f_bavail*free.f_frsize>sum(i.file_size for i in selected)+4*1024**3,"local readback free disk")
   hashes={};inventory=[]
   for i in infos:
    if i.is_dir():continue
    p=PurePosixPath(i.filename);keep=i in selected;target=d/"members"/i.filename
    if keep:target.parent.mkdir(parents=True,exist_ok=True)
    out=target.open("xb") if keep else None;h=hashlib.sha256();n=0;prefix=b""
    try:
     with z.open(i) as inp:
      while True:
       b=inp.read(1024*1024)
       if not b:break
       if len(prefix)<64:prefix=(prefix+b)[:64]
       n+=len(b);require(n<=i.file_size,"inflated size");h.update(b)
       if out is not None:out.write(b)
    finally:
     if out is not None:out.close()
    require(n==i.file_size,"member size")
    item={"name":i.filename,"bytes":n,"sha256":h.hexdigest(),"retained_expanded":keep}
    if prefix.startswith(b"\x7fELF") and len(prefix)>=20:item["elf_machine"]=int.from_bytes(prefix[18:20],"little" if prefix[5]==1 else "big")
    inventory.append(item);hashes[i.filename]=item
   r["archive_inventory"]=inventory
   before=json.loads((d/"members/source-before.json").read_bytes());after=json.loads((d/"members/source-after.json").read_bytes());mat=json.loads((d/"members/push-source-context.json").read_bytes())
   require(before==after and before["kind"]==kind and before["tested_commit"]==tested and before["tested_tree"]==T and before["candidate"]==H and before["tracked_worktree_verified"] is True,"source before/after")
   if kind=="prospective-merge":require(before["base"]==B and before["prospective_merge"]==M,"ordered merge")
   require(mat["source"]==before and mat["context"]==resolver and mat["github_sha"]==H and mat["github_event_name"]=="push" and mat["is_github_pr_merge"] is False,"materialized actual push source")
   require(mat["context_sha256"]==hashlib.sha256(json.dumps(resolver,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest(),"context digest")
   r["source_bound"]=True;r["source_before"]=before;r["source_after"]=after
   manifests=[]
   for name in sorted(hashes):
    if PurePosixPath(name).name!="manifest.json":continue
    path=d/"members"/name;doc=json.loads(path.read_bytes());files=doc.get("artifact_sha256")
    if not isinstance(files,dict):continue
    checked=[]
    for rel,h in files.items():
     q=PurePosixPath(rel);require(not q.is_absolute() and ".." not in q.parts and "\\" not in rel,"manifest member path")
     member=str(PurePosixPath(name).parent/q);require(member in hashes and hashes[member]["sha256"]==h,"manifest file digest "+member);checked.append(member)
    manifests.append({"path":str(path),"member":name,"schema":doc.get("schema"),"result":doc.get("result"),"file_hashes_verified":len(checked),"observations":len(doc.get("observations",[])),"planned_shards":len(doc.get("planned_shards",[])),"shards":len(doc.get("shards",[])),"manifest_sha256":hashes[name]["sha256"]})
   require(len(manifests)==(2 if family=="false-trace" else 1),"expected manifest denominator")
   r["manifests"]=manifests;r["manifest_hashes_complete"]=True

  r["coverage_status"]="ARCHIVE_SOURCE_MANIFEST_VERIFIED_PURE_READER_PENDING"
  r["job_log_scope"]="No new job-log GET in Range v3; original CI metadata and authenticated source/native logs retained inside original ZIP."
except Exception as e:r["errors"].append(type(e).__name__+": "+str(e));r["coverage_status"]="UNKNOWN"
r["finished_utc"]=datetime.now(timezone.utc).isoformat()
with (d/"readback-stage1.json").open("x") as f:json.dump(r,f,indent=2);f.write("\n")
print(json.dumps({"artifact_id":a["id"],"source_archive_manifest_status":r["coverage_status"],"errors":r["errors"]}),flush=True)
if r["errors"]:raise SystemExit(1)
cmd=["/usr/bin/python3",str(R/"read_w1_pure_records_819_v2.py"),str(d)]
outcome={"schema":"trnm-final819-range-v3-original-pure-reader","command":cmd,"original_wrapper_sha256":sha(R/"read_w1_pure_records_819_v2.py"),"observer_timeout_seconds":240,"source_or_ci_or_native_recreated":False}
require(outcome["original_wrapper_sha256"]=="d6de643b9440731fc23272f3c5f81fccdcfa62f6d8d57e1729540b715fc8d2ca","same original pure wrapper")
with (d/"pure.stdout").open("xb") as out,(d/"pure.stderr").open("xb") as err:
 try:
  run=subprocess.run(cmd,stdout=out,stderr=err,timeout=240,check=False);outcome.update(exit_code=run.returncode,timed_out=False)
 except subprocess.TimeoutExpired:outcome.update(exit_code=None,timed_out=True)
q=d/"readback-pure-v2.json"
result=json.loads(q.read_bytes()) if q.exists() else {}
outcome.update(complete_component_readback=bool(outcome["exit_code"]==0 and not outcome["timed_out"] and result.get("complete_component_readback") is True and not result.get("errors")),native_campaign_commands=result.get("native_invocations"),errors=result.get("errors"),business_qualification=False)
for stream in ("stdout","stderr"):
 p=d/("pure."+stream);outcome[stream]={"bytes":p.stat().st_size,"sha256":sha(p)}
with (d/"pure-outcome.json").open("x") as f:json.dump(outcome,f,indent=2);f.write("\n")
print(json.dumps(outcome),flush=True)
raise SystemExit(0 if outcome["complete_component_readback"] else 1)

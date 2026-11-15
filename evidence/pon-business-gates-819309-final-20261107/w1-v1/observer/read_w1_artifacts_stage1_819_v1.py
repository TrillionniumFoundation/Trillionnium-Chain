from pathlib import Path,PurePosixPath
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib,json,os,re,stat,subprocess,sys,zipfile
sys.dont_write_bytecode=True
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107")
S=R/"20261107T194212Z-819309fd3122-7d6a9641"
O=R/"w1-components-read-v1";O.mkdir()
H="819309fd312298e099642e1253b1d4ba07113e98";M="28df21f965e0348690836c9c854dab645827a03d";B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0";T="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
REPO="TrillionniumFoundation/Trillionnium-Chain"
def require(v,m):
 if not v:raise ValueError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
def fetch(endpoint,p,timeout):
 a=["/usr/bin/gh","api","--hostname","github.com","--method","GET",endpoint];r={"argv":a,"exit_code":None,"timed_out":False,"error":None}
 try:
  with p.open("xb") as out,p.with_suffix(p.suffix+".stderr").open("xb") as err:r["exit_code"]=subprocess.run(a,stdout=out,stderr=err,timeout=timeout).returncode
 except subprocess.TimeoutExpired as e:r.update(timed_out=True,error=type(e).__name__+": "+str(e))
 except Exception as e:r["error"]=type(e).__name__+": "+str(e)
 r.update(bytes=p.stat().st_size if p.exists() else None,sha256=sha(p) if p.exists() else None)
 return r
who=fetch("user",O/"identity-before.json",60);require(who["exit_code"]==0,"identity GET")
identity=json.loads((O/"identity-before.json").read_bytes());require(identity["login"]=="ProfHepta" and identity["id"]==102159240,"specified identity")
core=json.loads((S/"observer-core-v1.json").read_bytes());jobs=core["attempts"][0]["native"]
arts=[a for a in core["artifacts"] if a["name"].startswith("w1-") and not a["name"].startswith("w1-fresh-service-")]
require(len(arts)==20 and len({a["id"] for a in arts})==20,"complete twenty artifact denominator")
arts.sort(key=lambda a:(a["size_in_bytes"],a["id"]))
resolver=json.loads((R/"20261107T184658Z-819309fd3122-78a49720/source-artifact-read-v1/13584974949/context.json").read_bytes())
def one(a):
 d=O/str(a["id"]);d.mkdir();r={"artifact_id":a["id"],"metadata":a,"errors":[],"warnings":[],"archive_authenticated":False,"source_bound":False,"manifest_hashes_complete":False,"pure_read_status":"NOT_RUN","business_qualification":False}
 try:
  name=a["name"];kind="head" if "-head-" in name else "prospective-merge";tested=H if kind=="head" else M;arch="arm64" if "-arm64-" in name else "x64"
  family=("false-trace" if name.startswith("w1-false-trace-") else "factorial" if name.startswith("w1-legal-factorial-") else "rank-batch" if name.startswith("w1-rank-batch-") else "legal-v2" if name.startswith("w1-legal-strategy-v2-") else "legal-v1")
  r.update(family=family,arch=arch,source_kind=kind,tested_commit=tested)
  j=[x for x in jobs if x["family"]==family and x["arch"]==arch and x["source"]==kind];require(len(j)==1,"unique matching native job");job=j[0];r["job"]={k:job.get(k) for k in ("id","name","family","arch","source","status","conclusion")}
  require(a["workflow_run"]["head_sha"]==H and a["workflow_run"]["id"]==42402618462 and not a["expired"] and name.endswith(tested+"-1"),"artifact metadata source")
  require(a["size_in_bytes"]<=256*1024**2,"compressed bound")
  r["download"]=fetch("repos/"+REPO+"/actions/artifacts/"+str(a["id"])+"/zip",d/"artifact.zip",240)
  require(r["download"]["exit_code"]==0 and r["download"]["bytes"]==a["size_in_bytes"] and a["digest"]=="sha256:"+r["download"]["sha256"],"GitHub ZIP digest/size mismatch")
  r["archive_authenticated"]=True
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
  r["job_log"]=fetch("repos/"+REPO+"/actions/jobs/"+str(job["id"])+"/logs",d/"job.log",120)
  if r["job_log"]["exit_code"]!=0:r["warnings"].append("job-log GET incomplete; artifact and source receipts preserved separately")
  r["coverage_status"]="ARCHIVE_SOURCE_MANIFEST_VERIFIED_PURE_READER_PENDING"
 except Exception as e:r["errors"].append(type(e).__name__+": "+str(e));r["coverage_status"]="UNKNOWN"
 r["finished_utc"]=datetime.now(timezone.utc).isoformat()
 with (d/"readback-stage1.json").open("x") as f:json.dump(r,f,indent=2);f.write("\n")
 print(json.dumps({"artifact_id":a["id"],"family":r.get("family"),"status":r["coverage_status"],"errors":r["errors"],"zip_bytes":r.get("download",{}).get("bytes"),"manifest_count":len(r.get("manifests",[]))}),flush=True)
 return r
with ThreadPoolExecutor(max_workers=2) as pool:rows=list(pool.map(one,arts))
after=fetch("user",O/"identity-after.json",60);user=json.loads((O/"identity-after.json").read_bytes()) if after["exit_code"]==0 else {}
result={"schema":"trnm-final819-w1-stage1-readback-v1","candidate":H,"native_job_success_denominator":20,"artifact_denominator":20,"attempted":len(rows),"verified_archive_source_manifest":sum(r["coverage_status"]!="UNKNOWN" for r in rows),"unknown":sum(r["coverage_status"]=="UNKNOWN" for r in rows),"identity_before":who,"identity_after":after,"identity_unchanged":user.get("id")==102159240 and user.get("login")=="ProfHepta","pure_readers_executed":False,"business_qualification":False,"results":rows}
with (O/"summary-stage1.json").open("x") as f:json.dump(result,f,indent=2);f.write("\n")
print(json.dumps({k:v for k,v in result.items() if k!="results"}))

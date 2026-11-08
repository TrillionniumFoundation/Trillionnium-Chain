from pathlib import Path,PurePosixPath
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import json,hashlib,subprocess,sys,os,stat,zipfile
ROOT=Path("/home/qian-qi/throughput-ci-observation-20261107");SNAP=ROOT/"20261107T155220Z-d26e047dedfc-bb63e773"
OUT=SNAP/"history-artifact-read-v1";OUT.mkdir()
sys.path.insert(0,str(ROOT));from read_ci_metadata import parse_http
s=json.loads((SNAP/"snapshot.json").read_bytes());arts=[]
for q in s["queries"]:
 if "/artifacts?" in q["endpoint"]:
  _,_,obj=parse_http((SNAP/q["http_file"]).read_bytes());arts+=obj["artifacts"]
selected=[a for a in arts if "-history-" in a["name"]];assert len(selected)==4
def filehash(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  while data:=f.read(1024*1024):h.update(data)
 return h.hexdigest()
def req(v,msg):
 if not v:raise ValueError(msg)
def one(a):
 d=OUT/str(a["id"]);d.mkdir();row={"artifact_id":a["id"],"metadata":a,"errors":[],"started_utc":datetime.now(timezone.utc).isoformat(),"native_gate_validated":False}
 try:
  req(a["workflow_run"]["id"]==42383368690 and a["workflow_run"]["head_sha"]=="d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89" and not a["expired"],"artifact identity")
  req(a["size_in_bytes"]<=128*1024*1024,"ZIP bound")
  argv=["/usr/bin/gh","api","--hostname","github.com","--method","GET","repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/"+str(a["id"])+"/zip"];row["download_argv"]=argv
  with (d/"artifact.zip").open("xb") as out,(d/"download.stderr").open("xb") as err:p=subprocess.run(argv,stdout=out,stderr=err,timeout=600)
  row.update(download_exit=p.returncode,zip_bytes=(d/"artifact.zip").stat().st_size,zip_sha256=filehash(d/"artifact.zip"))
  req(p.returncode==0 and row["zip_bytes"]==a["size_in_bytes"] and a["digest"]=="sha256:"+row["zip_sha256"],"ZIP digest/size/exit mismatch")
  inventory=[];files={};manifests=[]
  with zipfile.ZipFile(d/"artifact.zip") as z:
   infos=z.infolist()
   req(len(infos)<=10000 and len({i.filename for i in infos})==len(infos) and sum(i.file_size for i in infos)<=2*1024**3,"archive denominator/expansion bound")
   for i in infos:
    path=PurePosixPath(i.filename);req(not path.is_absolute() and ".." not in path.parts and "\\" not in i.filename and not stat.S_ISLNK(i.external_attr>>16),"archive member")
    inventory.append({"path":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size})
    if i.is_dir():continue
    suffix=path.suffix.lower()
    chosen=(suffix in (".json",".jsonl",".log",".txt",".csv",".tsv",".sqlite",".sqlite3",".db") or path.name in ("stdout","stderr","time","resource-usage") or path.name.endswith(("-wal","-shm")))
    if not chosen:continue
    req(i.file_size<=512*1024*1024,"selected member bound")
    pth=d/i.filename;pth.parent.mkdir(parents=True,exist_ok=True)
    h=hashlib.sha256()
    with z.open(i) as inp,pth.open("xb") as out:
     while data:=inp.read(1024*1024):h.update(data);out.write(data)
    files[i.filename]={"bytes":i.file_size,"sha256":h.hexdigest()}
    if path.name=="manifest.json":manifests.append((i.filename,json.loads(pth.read_bytes())))
   row["inventory"]=inventory;row["files"]=files;row["manifests"]=[]
   for name,m in manifests:
    item={k:m.get(k) for k in ("schema","result","error","native_exit","native_exit_code","execution_finished","native_execution_completed","failed_commands","source_changed","source_before","source_after","production_activation","public_network_ready")}
    item["path"]=name;item["keys"]=list(m)
    prefix=PurePosixPath(name).parent;entries=m.get("artifact_sha256",{});checked=0
    for rel,want in entries.items():
     rp=PurePosixPath(rel);req(not rp.is_absolute() and ".." not in rp.parts,"manifest member")
     member=z.getinfo(str(prefix/rp));req(member.file_size<=1024**3,"hashed member bound")
     hh=hashlib.sha256()
     with z.open(member) as inp:
      while data:=inp.read(1024*1024):hh.update(data)
     req(hh.hexdigest()==want,"manifest file hash "+str(prefix/rp));checked+=1
    item["artifact_file_hashes_verified"]=checked;row["manifests"].append(item)
 except Exception as e:row["errors"].append(type(e).__name__+": "+str(e))
 row["finished_utc"]=datetime.now(timezone.utc).isoformat()
 (d/"readback.json").write_text(json.dumps(row,indent=2)+chr(10))
 print(json.dumps({"artifact_id":a["id"],"name":a["name"],"errors":row["errors"],"zip_bytes":row.get("zip_bytes"),"zip_sha256":row.get("zip_sha256"),"selected_files":list(row.get("files",{})),"manifests":[{k:m.get(k) for k in ("schema","result","error","native_exit","native_exit_code","execution_finished","native_execution_completed","artifact_file_hashes_verified","path","keys")} for m in row.get("manifests",[])]}),flush=True)
 return row
with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(one,selected))
summary={"expected_lanes":4,"retained_lanes":len(results),"results":results,"native_gate_validated":False}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2)+chr(10))
print(json.dumps({"finished":True,"directory":str(OUT),"retained_lanes":len(results)}),flush=True)

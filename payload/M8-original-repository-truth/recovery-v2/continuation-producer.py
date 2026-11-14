import os,sys,pathlib,stat,json,hashlib,datetime
D=json.loads(sys.argv[1]);SELF=sys.argv[2];S=pathlib.Path(D["stage"]);O=pathlib.Path(D["output"]);P=D["prefix"];R=O/"continuation-v2"
assert not R.exists() and S.resolve(strict=True)==S and O.resolve(strict=True)==O
def js(x):return (json.dumps(x,indent=2)+"\n").encode()
def sg(x):return [x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def rd(p,limit=16*1024*1024):
 q=pathlib.PurePosixPath(str(p));assert q.is_absolute() and ".."not in q.parts
 d=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in q.parts[1:-1]:
   z=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);os.close(d);d=z
  fd=os.open(q.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=d)
 finally:os.close(d)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=limit
  with os.fdopen(fd,"rb",closefd=False)as f:b=f.read(s.st_size+1)
  assert len(b)==s.st_size and sg(os.fstat(fd))==sg(s)
  return b,sg(s)
 finally:os.close(fd)
def save(p,b):
 p.parent.mkdir(parents=True,exist_ok=True);assert p.parent.resolve(strict=True)==p.parent
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 bb,v=rd(p);assert bb==b
 return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def inv(root):
 a={}
 for b,ds,fs in os.walk(root,followlinks=False):
  for n in ds:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
  for n in fs:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
   a[str(p.relative_to(root))]={"bytes":s.st_size,"version":sg(s)}
 return a
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
bl,bv=rd(O/"stage-before.json");assert hashlib.sha256(bl).hexdigest()==D["baseline_sha256"]
baseline=json.loads(bl);old=baseline["files"];assert len(old)==3276 and sum(x["bytes"]for x in old.values())==180978142
selraw,selv=rd(O/"selection.json");selection=json.loads(selraw);planned=list(selection["files"])
for name,role in [("selection.json","frozen selection and source identities"),("README.md","scope explanation")]:
 raw,version=rd(O/name);planned.append({"path":P+"/manifests/"+name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"origin":{"host":"mac","path":str(O/name)},"source_path":str(O/name),"role":role})
want={x["path"]:x for x in planned};assert len(want)==len(planned)
before=inv(S);existing={n:v for n,v in before.items()if n not in old}
assert all(before.get(n)==v for n,v in old.items()) and set(existing).issubset(want)
for n in existing:
 b,_=rd(S/n);w=want[n];assert len(b)==w["bytes"] and hashlib.sha256(b).hexdigest()==w["sha256"],n
t=D["previous_terminal"];assert t["status"]["exit_code"]==1 and t["output_complete"]is True and "Too many open files"in t["text"]
raw_terminal=bytes.fromhex(t["bytes_hex"]);assert hashlib.sha256(raw_terminal).hexdigest()==t["chunk_sha256"] and len(raw_terminal)==t["next_offset"]-t["offset"]
R.mkdir(mode=0o700)
extra=[]
for name,raw in [
 ("previous-materializer-terminal.json",js(t)),
 ("previous-materializer-terminal.log",raw_terminal),
 ("continuation-producer.py",SELF.encode()),
 ("continuation-inputs.json",js({k:v for k,v in D.items()if k!="previous_terminal"})),
 ("initial-partial-stage.json",js({"schema":"trnm-M8-full-owned-partial-stage-v1","previous_exit":1,"prior_stage_unchanged":True,"existing_count":len(existing),"existing_bytes":sum(v["bytes"]for v in existing.values()),"existing_files":existing,"rule":"existing exact targets are verified and retained; missing targets are create-only; no prior stage overwrite"}))
]:
 f=save(R/name,raw);extra.append({"path":P+"/recovery-v2/"+name,"bytes":f["bytes"],"sha256":f["sha256"],"origin":{"host":"mac","path":f["path"]},"source_path":f["path"],"role":"actual failed v1 and deterministic continuation provenance"})
planned+=extra
cache={};versions={}
for row in planned:
 raw,v=rd(pathlib.Path(row["source_path"]));assert len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
 assert row["path"]not in cache and row["path"]not in old
 cache[row["path"]]=raw;versions[row["source_path"]]=v
assert sum(len(b)for b in cache.values())<=8*1024*1024
for root,snapshot in selection["source_rosters"].items():assert inv(pathlib.Path(root))==snapshot
for path,v in versions.items():
 _,v2=rd(pathlib.Path(path));assert v2==v
assert inv(S)==before
created=[];retained=[]
for row in planned:
 p=S/row["path"]
 if row["path"]in existing:
  raw,_=rd(p);assert raw==cache[row["path"]];retained.append(row["path"])
 else:
  f=save(p,cache[row["path"]]);assert f["bytes"]==row["bytes"] and f["sha256"]==row["sha256"];created.append(row["path"])
for path,v in versions.items():
 raw,v2=rd(pathlib.Path(path));assert v2==v
for root,snapshot in selection["source_rosters"].items():assert inv(pathlib.Path(root))==snapshot
after=inv(S);assert set(after)==set(old)|set(cache)
for n,v in old.items():assert after[n]==v
for row in planned:
 raw,_=rd(S/row["path"]);assert raw==cache[row["path"]] and hashlib.sha256(raw).hexdigest()==row["sha256"]
strict=sorted([{k:r[k]for k in ("path","bytes","sha256","origin")}for r in planned],key=lambda x:x["path"])
files=save(O/"files.json",js({"files":strict}))
summary={"schema":"trnm-M8-full-original-materialization-completion-v2","status":"materialized_verified","started_at":started,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"prefix":P,"new_count":len(strict),"new_bytes":sum(r["bytes"]for r in strict),"prior_count":3276,"prior_bytes":180978142,"final_count":len(after),"final_bytes":sum(v["bytes"]for v in after.values()),"all_selected_sources_preverified":True,"all_new_target_bytes_sha_readback":True,"old_stage_identities_unchanged":True,"previous_materializer":{"exit":1,"cause":"OSError 24 Too many open files during target readback","preserved":True,"exact_existing_targets_retained":len(retained),"missing_targets_created":len(created)},"source_descriptor_policy":"bounded per-file stable held-FD read; close after complete read; pinned bytes plus pre/post source identity fences","original_full_result":"passed","original_full_elapsed_seconds":546.128,"external_result":"launch_only_not_observed","source_git_network_test_actions":False,"hosted_qualification":False,"files":files,"baseline":{"path":str(O/"stage-before.json"),"sha256":D["baseline_sha256"]},"writer_released":True}
summ=save(O/"materialization-summary-v2.json",js(summary))
print(json.dumps({"files":files,"summary":summ,"new_count":summary["new_count"],"new_bytes":summary["new_bytes"],"final_count":summary["final_count"],"final_bytes":summary["final_bytes"],"retained_existing":len(retained),"created":len(created),"writer_released":True}),flush=True)

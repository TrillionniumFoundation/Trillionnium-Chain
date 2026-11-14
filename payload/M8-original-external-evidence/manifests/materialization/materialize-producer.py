import pathlib,os,stat,sys,json,hashlib,datetime,re
D=json.loads(sys.argv[1]);SELF=sys.argv[2];S=pathlib.Path(D["stage"]);P=D["prefix"];A=pathlib.Path(D["preparation"]);O=A/"materialize-v1"
assert S.resolve(strict=True)==S and A.resolve(strict=True)==A and not O.exists() and not (S/P).exists()
def js(v):return (json.dumps(v,indent=2)+"\n").encode()
def sg(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def rd(p,limit=16*1024*1024):
 q=pathlib.PurePosixPath(str(p));assert q.is_absolute() and ".."not in q.parts
 dr=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in q.parts[1:-1]:
   c=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dr);os.close(dr);dr=c
  f=os.open(q.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dr)
 finally:os.close(dr)
 try:
  v=os.fstat(f);assert stat.S_ISREG(v.st_mode) and v.st_nlink==1 and 0<=v.st_size<=limit
  with os.fdopen(f,"rb",closefd=False)as st:b=st.read(v.st_size+1)
  assert len(b)==v.st_size and sg(os.fstat(f))==sg(v)
  return b,sg(v)
 finally:os.close(f)
def save(p,b):
 p.parent.mkdir(parents=True,exist_ok=True);assert p.parent.resolve(strict=True)==p.parent
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert rd(p)[0]==b
 return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def inv(root):
 assert root.resolve(strict=True)==root;a={};dsall={}
 for b,ds,fs in os.walk(root,followlinks=False):
  for n in ds:
   p=pathlib.Path(b)/n;v=p.lstat();assert stat.S_ISDIR(v.st_mode) and not stat.S_ISLNK(v.st_mode);dsall[str(p.relative_to(root))]=sg(v)
  for n in fs:
   p=pathlib.Path(b)/n;v=p.lstat();assert stat.S_ISREG(v.st_mode) and v.st_nlink==1
   a[str(p.relative_to(root))]={"bytes":v.st_size,"version":sg(v)}
 return {"root":sg(root.lstat()),"files":a,"directories":dsall}
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
raw,mv=rd(A/"proposed-source-manifest.json");assert hashlib.sha256(raw).hexdigest()==D["manifest_sha256"]
m=json.loads(raw);assert m["status"]=="prepared_sources_verified_not_materialized" and m["prefix"]==P and m["count"]==D["expected_source_count"] and m["bytes"]==D["expected_source_bytes"]
assert len(m["files"])==91 and sum(r["bytes"]for r in m["files"])==1594255
pb,_=rd(A/"publisher-files-proposed.json");proposed=json.loads(pb);assert proposed["materialized"]is False and proposed["files"]==[{k:r[k]for k in ("path","bytes","sha256","origin")}for r in m["files"]]
before=inv(S);assert len(before["files"])==D["expected_stage_count"] and sum(v["bytes"]for v in before["files"].values())==D["expected_stage_bytes"]
O.mkdir(mode=0o700)
base=save(O/"stage-before.json",js({"schema":"trnm-M8-external-materialization-prior-stage-identity-v1","stage":str(S),"observed_at":started,"count":D["expected_stage_count"],"bytes":D["expected_stage_bytes"],"identity":before,"scope":"stat identity baseline for existing files and directories; no credential/content rescan"}))
producer=save(O/"materialize-producer.py",SELF.encode());inputs=save(O/"materialize-inputs.json",js(D))
rows=[];cache={};versions={}
for r in m["files"]:
 assert re.fullmatch(r"[A-Za-z0-9._/-]+",r["path"]) and r["path"].startswith(P+"/") and ".."not in pathlib.PurePosixPath(r["path"]).parts
 b,v=rd(pathlib.Path(r["source_path"]));assert len(b)==r["bytes"] and hashlib.sha256(b).hexdigest()==r["sha256"] and v==r["source_version"]
 assert r["path"]not in cache and r["path"]not in before["files"]
 rows.append(dict(r));cache[r["path"]]=b;versions[r["source_path"]]=v
# Necessary frozen preparation provenance, explicitly separate from the 91 approved source payloads.
prep_names=["proposed-source-manifest.json","publisher-files-proposed.json","preparation-summary.json","selection-producer.py","selection-inputs.json","README.md"]
extra=[(A/n,P+"/manifests/preparation/"+n,"closed source-selection provenance")for n in prep_names]
extra += [(pathlib.Path(x["path"]),P+"/manifests/materialization/"+pathlib.Path(x["path"]).name,"materialization producer/input/prior identity")for x in (base,producer,inputs)]
for src,dest,role in extra:
 b,v=rd(src);assert dest not in cache and dest not in before["files"]
 row={"path":dest,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"origin":{"host":"mac","path":str(src)},"source_path":str(src),"source_version":v,"role":role}
 rows.append(row);cache[dest]=b;versions[str(src)]=v
assert len(rows)==100 and sum(len(b)for b in cache.values())<=8*1024*1024
source_dirs={}
for path,old in m["source_rosters"].items():
 a=inv(pathlib.Path(path));assert {n:v["version"]for n,v in a["files"].items()}==old;source_dirs[path]=a
for path,v in versions.items():assert rd(pathlib.Path(path))[1]==v
assert inv(S)==before
(S/P).mkdir()
for row in rows:
 info=save(S/row["path"],cache[row["path"]]);assert info["bytes"]==row["bytes"] and info["sha256"]==row["sha256"]
for path,v in versions.items():assert rd(pathlib.Path(path))[1]==v
for path,old in source_dirs.items():assert inv(pathlib.Path(path))==old
after=inv(S);assert set(after["files"])==set(before["files"])|set(cache)
for name,value in before["files"].items():assert after["files"][name]==value
for name,value in before["directories"].items():assert after["directories"][name]==value
assert after["root"][:3]==before["root"][:3] # Only root directory entry timestamps/link count may change due to the new owned child.
for row in rows:
 b,_=rd(S/row["path"]);assert b==cache[row["path"]] and hashlib.sha256(b).hexdigest()==row["sha256"]
strict=sorted([{k:r[k]for k in ("path","bytes","sha256","origin")}for r in rows],key=lambda x:x["path"])
assert all(set(x)=={"path","bytes","sha256","origin"}for x in strict)
files=save(O/"files.json",js({"files":strict}))
summary={"schema":"trnm-M8-external-and-full-materializer-materialization-v1","status":"materialized_verified","started_at":started,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"prefix":P,"approved_source_count":91,"approved_source_bytes":1594255,"additional_preparation_and_materialization_provenance_count":9,"new_count":len(rows),"new_bytes":sum(x["bytes"]for x in rows),"prior_count":len(before["files"]),"prior_bytes":D["expected_stage_bytes"],"final_count":len(after["files"]),"final_bytes":sum(x["bytes"]for x in after["files"].values()),"all_old_file_and_subdirectory_identities_unchanged":True,"root_directory_inode_and_mode_unchanged":True,"root_directory_timestamp_change_reason":"new unique owned prefix added","source_rosters_and_identities_unchanged":True,"source_fd_policy":"per-file stable descriptor reads with immediate close; frozen SHA bytes and pre/post path/version fences","all_new_target_bytes_sha_readback":True,"original_external_result":"passed","original_external_elapsed_seconds":219.327,"original_readiness":{"methods":78,"seconds":35.003,"result":"OK"},"prior_full_materializer_v1_EMFILE_failure_preserved":True,"prior_full_materializer_continuation_verified":True,"new_remote_observation_included":False,"source_git_network_test_actions":False,"hosted_qualification":False,"files":files,"input_manifest_sha256":D["manifest_sha256"],"writer_released":True}
sm=save(O/"summary.json",js(summary))
print(json.dumps({"files":files,"summary":sm,"new_count":len(rows),"new_bytes":summary["new_bytes"],"final_count":summary["final_count"],"final_bytes":summary["final_bytes"],"writer_released":True}),flush=True)

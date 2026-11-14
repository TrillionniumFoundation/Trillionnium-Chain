import pathlib,os,stat,sys,json,hashlib,datetime,re
D=json.loads(sys.argv[1]);SELF=sys.argv[2];S=pathlib.Path(D["stage"]);O=pathlib.Path(D["output"]);P=D["prefix"]
assert S.resolve(strict=True)==S and O.resolve(strict=True)==O and re.fullmatch(r"[A-Za-z0-9._-]+",P)
def js(d):return (json.dumps(d,indent=2)+"\n").encode()
def sig(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
held=[]
def read(p,limit=16*1024*1024):
 q=pathlib.PurePosixPath(str(p));assert q.is_absolute() and ".."not in q.parts
 dr=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in q.parts[1:-1]:
   nxt=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dr);os.close(dr);dr=nxt
  fd=os.open(q.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dr)
 finally:os.close(dr)
 s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=limit
 with os.fdopen(fd,"rb",closefd=False)as f:r=f.read(s.st_size+1)
 assert len(r)==s.st_size and sig(os.fstat(fd))==sig(s)
 held.append((fd,sig(s),p));return r
def save(p,raw):
 assert not p.exists()
 p.parent.mkdir(parents=True,exist_ok=True);assert p.parent.resolve(strict=True)==p.parent
 with p.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 r=read(p);assert r==raw
 return {"path":str(p),"bytes":len(r),"sha256":hashlib.sha256(r).hexdigest()}
def inv(root):
 assert root.resolve(strict=True)==root
 a={}
 for b,ds,fs in os.walk(root,followlinks=False):
  for n in ds:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
  for n in fs:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
   a[str(p.relative_to(root))]={"bytes":s.st_size,"version":sig(s)}
 return a
def fence():
 for fd,v,p in held:assert sig(os.fstat(fd))==v and sig(p.lstat())==v,str(p)
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
baseline_raw=read(pathlib.Path(D["baseline_path"]));assert hashlib.sha256(baseline_raw).hexdigest()==D["baseline_sha256"]
baseline=json.loads(baseline_raw);old=baseline["files"];assert len(old)==D["expected_count"] and sum(x["bytes"]for x in old.values())==D["expected_bytes"]
assert inv(S)==old and not(S/P).exists()
# These are completed tool records kept outside stage before freezing the input selection.
tool_dir=O/"closed-tool-records";tool_dir.mkdir()
for name,value in D["tool_records"].items():
 assert value["status"]["exit_code"]==0 and value["output_complete"]is True
 save(tool_dir/name,js(value))
producer_info=save(O/"materialize-producer.py",SELF.encode())
inputs_info=save(O/"materialize-inputs.json",js({k:v for k,v in D.items()if k!="tool_records"}))
source_spec=list(D["sources"])+[{"path":str(tool_dir),"target":"closed-tool-records","role":"completed preparation/copy tool terminal records"}]
special_raw=read(pathlib.Path(D["special_origins_path"]));assert hashlib.sha256(special_raw).hexdigest()==D["special_origins_sha256"]
special=json.loads(special_raw);origin_map={x["path"]:x for x in special["files"]};assert len(origin_map)==len(special["files"])==63
allrows=[];cache={};snapshots={}
for item in source_spec:
 root=pathlib.Path(item["path"]);snapshot=inv(root);snapshots[str(root)]=snapshot
 for rel in sorted(snapshot):
  assert re.fullmatch(r"[A-Za-z0-9._/-]+",rel) and ".."not in pathlib.PurePosixPath(rel).parts
  src=root/rel;target=P+"/"+item["target"]+"/"+rel
  assert target not in cache and target not in old and not (S/target).exists()
  raw=read(src);info={"path":target,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"origin":{"host":"mac","path":str(src)},"source_path":str(src),"role":item["role"]}
  if str(src)in origin_map:
   orig=origin_map[str(src)];assert len(raw)==orig["bytes"] and info["sha256"]==orig["sha256"]
   info["origin"]=orig["origin"]
  cache[target]=raw;allrows.append(info)
# Preserve the prior stage identity evidence and the exact materialization producer/inputs.
for src,target,role in [(pathlib.Path(D["baseline_path"]),"manifests/stage-before.json","original stage stat identity baseline"),(pathlib.Path(producer_info["path"]),"manifests/materialize-producer.py","materialization producer"),(pathlib.Path(inputs_info["path"]),"manifests/materialize-inputs.json","fixed materialization input selection")]:
 raw=read(src);dest=P+"/"+target;assert dest not in cache and dest not in old
 cache[dest]=raw;allrows.append({"path":dest,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"origin":{"host":"mac","path":str(src)},"source_path":str(src),"role":role})
assert sum(len(v)for v in cache.values())<=8*1024*1024
by_src={x["source_path"]:x for x in allrows}
for pin in D["pins"]:
 x=by_src[pin["path"]];assert x["bytes"]==pin["bytes"] and x["sha256"]==pin["sha256"]
# Validate the explicitly sealed root terminal directory against all 21 indexed originals.
td=pathlib.Path(D["sources"][4]["path"]);ti=json.loads(read(td/"EVIDENCE_INDEX.json"))
assert ti["head"]=="ed0d35487f2a67239e4d646fd41c2c7acb5cc740" and ti["tree"]=="1aa9c21812489080980bdc3c1c2bb43611e88354" and ti["external_result"]=="launch_only_not_observed"
assert set(snapshots[str(td)])=={x["path"]for x in ti["files"]}|{"EVIDENCE_INDEX.json"} and len(ti["files"])==21
for pin in ti["files"]:
 x=by_src[str(td/pin["path"])];assert x["bytes"]==pin["bytes"] and x["sha256"]==pin["sha256"]
selection={"schema":"trnm-M8-full-closed-materialization-selection-v1","head":"ed0d35487f2a67239e4d646fd41c2c7acb5cc740","tree":"1aa9c21812489080980bdc3c1c2bb43611e88354","prior_count":len(old),"prior_bytes":D["expected_bytes"],"selected_count":len(allrows),"selected_bytes":sum(x["bytes"]for x in allrows),"files":allrows,"source_rosters":snapshots,"original_full_result":"passed","external_result":"launch_only_not_observed","tests_rerun":False,"source_or_git_actions":False,"hosted_qualification":False}
sel=save(O/"selection.json",js(selection));sr=read(pathlib.Path(sel["path"]));cache[P+"/manifests/selection.json"]=sr;allrows.append({"path":P+"/manifests/selection.json","bytes":len(sr),"sha256":sel["sha256"],"origin":{"host":"mac","path":sel["path"]},"source_path":sel["path"],"role":"frozen selection and source identities"})
readme=save(O/"README.md",("# M8 original repository-truth evidence\n\nThe original M8 full lane passed on ed0d35487f2a67239e4d646fd41c2c7acb5cc740 / tree 1aa9c21812489080980bdc3c1c2bb43611e88354. This group preserves all 51 original execution files, original driver, package, exact index, official version-pinned copy provenance, 55-member CRC/SHA verification, and preparation/independent review records. Original ROG origins remain attached to copied originals. Source and tests were not rerun during preservation.\n\nThe external packager in the preparation directory is a prepared program. The root external tool record in this frozen group is launch-only and explicitly not a PASS result. Worker terminal observations retain their actual narrower scope. No hosted CI, future revision, or four-second confirmation qualification is asserted. Prior stage contents were protected by exact stat identity comparison, not rescanned for credentials by this operation.\n").encode())
rr=read(pathlib.Path(readme["path"]));cache[P+"/manifests/README.md"]=rr;allrows.append({"path":P+"/manifests/README.md","bytes":len(rr),"sha256":readme["sha256"],"origin":{"host":"mac","path":readme["path"]},"source_path":readme["path"],"role":"scope explanation"})
assert inv(S)==old
for root,snapshot in snapshots.items():assert inv(pathlib.Path(root))==snapshot
fence()
# Publish only the unique new prefix after every selected source has been checked.
(S/P).mkdir()
for row in allrows:
 out=save(S/row["path"],cache[row["path"]]);assert out["bytes"]==row["bytes"] and out["sha256"]==row["sha256"]
for root,snapshot in snapshots.items():assert inv(pathlib.Path(root))==snapshot
fence();after=inv(S)
assert set(after)==set(old)|set(cache)
for n,v in old.items():assert after[n]==v
for row in allrows:
 raw=read(S/row["path"]);assert len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
strict=sorted([{k:r[k]for k in ("path","bytes","sha256","origin")}for r in allrows],key=lambda r:r["path"])
assert all(set(r)=={"path","bytes","sha256","origin"}for r in strict)
files=save(O/"files.json",js({"files":strict}))
summary={"schema":"trnm-M8-full-original-materialization-completion-v1","status":"materialized_verified","started_at":started,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"prefix":P,"new_count":len(strict),"new_bytes":sum(r["bytes"]for r in strict),"prior_count":len(old),"prior_bytes":D["expected_bytes"],"final_count":len(after),"final_bytes":sum(v["bytes"]for v in after.values()),"all_selected_sources_preverified":True,"all_new_target_bytes_sha_readback":True,"old_stage_identities_unchanged":True,"original_full_result":"passed","original_full_elapsed_seconds":546.128,"external_result":"launch_only_not_observed","source_git_network_test_actions":False,"hosted_qualification":False,"files":files,"selection":sel,"baseline":{"path":D["baseline_path"],"sha256":D["baseline_sha256"]},"groups":[{"target":r["target"],"files":len(snapshots[r["path"]]),"bytes":sum(v["bytes"]for v in snapshots[r["path"]].values())}for r in source_spec],"writer_released":True}
sm=save(O/"materialization-summary.json",js(summary))
print(json.dumps({"files":files,"summary":sm,"new_count":summary["new_count"],"new_bytes":summary["new_bytes"],"final_count":summary["final_count"],"final_bytes":summary["final_bytes"],"writer_released":True}),flush=True)
for f,_,_ in held:os.close(f)

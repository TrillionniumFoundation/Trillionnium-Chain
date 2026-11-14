import pathlib,os,stat,sys,json,hashlib,datetime
D=json.loads(sys.argv[1]);SELF=sys.argv[2];O=pathlib.Path("/private/tmp/chain-prci-M8-external-and-full-materializer-followup-20261114-v1");O.mkdir(mode=0o700)
def js(v):return (json.dumps(v,indent=2)+"\n").encode()
def sg(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def rd(p):
 q=pathlib.PurePosixPath(str(p));assert q.is_absolute() and ".."not in q.parts;d=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in q.parts[1:-1]:
   c=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);os.close(d);d=c
  f=os.open(q.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=d)
 finally:os.close(d)
 try:
  s=os.fstat(f);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=16*1024*1024
  with os.fdopen(f,"rb",closefd=False)as z:r=z.read(s.st_size+1)
  assert len(r)==s.st_size and sg(os.fstat(f))==sg(s);return r,sg(s)
 finally:os.close(f)
def save(p,r):
 with p.open("xb")as f:f.write(r);f.flush();os.fsync(f.fileno())
 assert rd(p)[0]==r
 return {"path":str(p),"bytes":len(r),"sha256":hashlib.sha256(r).hexdigest()}
def inv(root):
 assert root.resolve(strict=True)==root;a={}
 for b,ds,fs in os.walk(root,followlinks=False):
  for n in ds:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
  for n in fs:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1;a[str(p.relative_to(root))]=sg(s)
 return a
T=O/"closed-tool-records";T.mkdir(mode=0o700)
for name in ("copy","package"):
 t=D[name+"_terminal"];assert t["status"]["exit_code"]==0 and t["output_complete"]is True and t["offset"]==0 and t["next_offset"]==t["available_end"]
 raw=bytes.fromhex(t["bytes_hex"]);assert len(raw)==t["next_offset"] and hashlib.sha256(raw).hexdigest()==t["chunk_sha256"]
 save(T/(name+"-terminal.json"),js(t));save(T/(name+"-terminal.log"),raw);save(T/(name+"-launch.json"),js(D[name+"_launch"]))
producer=save(O/"selection-producer.py",SELF.encode());inp=save(O/"selection-inputs.json",js({k:v for k,v in D.items()if k not in ("copy_terminal","copy_launch","package_terminal","package_launch")}))
maps,_=rd(pathlib.Path(D["origin_map_path"]));assert hashlib.sha256(maps).hexdigest()==D["origin_map_sha256"];m=json.loads(maps);origins={r["path"]:r for r in m["files"]};assert len(origins)==39
sources=D["sources"]+[{"path":str(T),"target":"closed-tool-records","role":"completed package and official copy tool records"}]
rows=[];rosters={};groups=[]
for item in sources:
 root=pathlib.Path(item["path"]);before=inv(root);rosters[str(root)]=before;start=len(rows)
 for rel in sorted(before):
  p=root/rel;b,v=rd(p);assert v==before[rel];h=hashlib.sha256(b).hexdigest();origin={"host":"mac","path":str(p)}
  if str(p)in origins:
   r=origins[str(p)];assert r["bytes"]==len(b) and r["sha256"]==h;origin=r["origin"]
  rows.append({"path":D["prefix"]+"/"+item["target"]+"/"+rel,"bytes":len(b),"sha256":h,"origin":origin,"source_path":str(p),"source_version":v,"role":item["role"]})
 assert inv(root)==before
 groups.append({"target":item["target"],"count":len(rows)-start,"bytes":sum(r["bytes"]for r in rows[start:])})
assert sum(r["bytes"]for r in rows)<=8*1024*1024 and len({r["path"]for r in rows})==len(rows)
for root,before in rosters.items():assert inv(pathlib.Path(root))==before
manifest={"schema":"trnm-M8-external-followup-proposed-source-manifest-v1","status":"prepared_sources_verified_not_materialized","head":"ed0d35487f2a67239e4d646fd41c2c7acb5cc740","tree":"1aa9c21812489080980bdc3c1c2bb43611e88354","prefix":D["prefix"],"files":rows,"source_rosters":rosters,"groups":groups,"count":len(rows),"bytes":sum(r["bytes"]for r in rows),"stage_read_or_written":False,"original_external_result":"passed","original_external_elapsed_seconds":219.327,"original_readiness":{"methods":78,"seconds":35.003,"result":"OK"},"prior_full_materializer_failed_v1_preserved":True,"prior_full_materializer_continuation_status":"materialized_verified","hosted_qualification":False,"prepared_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
man=save(O/"proposed-source-manifest.json",js(manifest))
pf=save(O/"publisher-files-proposed.json",js({"materialized":False,"files":[{k:r[k]for k in ("path","bytes","sha256","origin")}for r in rows]}))
readme=save(O/"README.md",("# M8 external original receipts and full materializer execution\n\nPrepared source selection only. Nothing has been written into the shared stage. This selection includes all 27 original M8 external files, the original driver, 31-member package and official version-pinned copy proof, the actual external terminal and exact empty nested-log manifest. It also preserves the entire earlier full materializer directory, including the first EMFILE failure, partial-file identity proof, deterministic continuation and its actual successful terminal. Source and tests were not rerun. Existing launch-only observations are retained as historical observations, not overwritten. No hosted or future-revision qualification is asserted.\n").encode())
sm=save(O/"preparation-summary.json",js({"status":"prepared_not_materialized","manifest":man,"proposed_files":pf,"producer":producer,"inputs":inp,"readme":readme,"groups":groups,"selected_count":len(rows),"selected_bytes":sum(r["bytes"]for r in rows),"stage_changed":False,"writer_not_owned":True}))
print(json.dumps({"summary":sm,"manifest":man,"proposed_files":pf,"count":len(rows),"bytes":sum(r["bytes"]for r in rows),"groups":groups,"stage_changed":False}),flush=True)

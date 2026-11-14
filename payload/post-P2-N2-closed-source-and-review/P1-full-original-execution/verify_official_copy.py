import pathlib,os,sys,stat,json,hashlib,zipfile,datetime,io,re
D=json.loads(sys.argv[1]);SELF=sys.argv[2];C=pathlib.Path(D["destination"]);assert C.resolve(strict=True)==C
def js(d):return (json.dumps(d,indent=2)+"\n").encode()
def sig(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
held=[]
def read(p):
 q=pathlib.PurePosixPath(str(p));assert q.is_absolute() and ".."not in q.parts
 dr=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in q.parts[1:-1]:
   nxt=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dr);os.close(dr);dr=nxt
  fd=os.open(q.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dr)
 finally:os.close(dr)
 s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=32*1024*1024
 with os.fdopen(fd,"rb",closefd=False)as f:r=f.read(s.st_size+1)
 assert len(r)==s.st_size and sig(os.fstat(fd))==sig(s)
 held.append((fd,sig(s),p));return r
def save(p,r):
 p.parent.mkdir(parents=True,exist_ok=True)
 assert p.parent.resolve(strict=True)==p.parent
 with p.open("xb")as f:f.write(r);f.flush();os.fsync(f.fileno())
 assert read(p)==r
 return {"path":str(p),"bytes":len(r),"sha256":hashlib.sha256(r).hexdigest()}
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
copies=[{"source":D["source_infos"][0],"destination":D["zip_upload"]["spec"]["path"]}]+[{"source":x["source"],"destination":x["destination"]}for x in D["small_writes"]]
buffers={};direct=[]
for x in copies:
 r=read(pathlib.Path(x["destination"]));s=x["source"];assert len(r)==s["size"] and hashlib.sha256(r).hexdigest()==s["sha256"]
 buffers[pathlib.Path(x["destination"]).name]=r;direct.append({"path":x["destination"],"bytes":len(r),"sha256":s["sha256"],"origin":{"host":"rog","path":s["path"]}})
assert len(copies)==9
for src in D["source_infos"]:
 chunks=[x for x in D["read_chunks"]if x["path"]==src["path"]];off=0
 data=buffers[pathlib.Path(next(x["destination"]for x in copies if x["source"]["path"]==src["path"])).name]
 for ch in chunks:
  assert ch["version"]==src["version"] and ch["size"]==src["size"] and ch["offset"]==off
  assert hashlib.sha256(data[ch["offset"]:ch["next_offset"]]).hexdigest()==ch["chunk_sha256"]
  off=ch["next_offset"]
 assert off==src["size"] and chunks[-1]["eof"]is True
assert D["zip_upload"]["commit"]["committed"]is True and D["zip_upload"]["commit"]["sha256"]==D["source_infos"][0]["sha256"]
assert D["package_terminal"]["status"]["exit_code"]==0 and D["package_terminal"]["output_complete"]is True and D["package_terminal"]["offset"]==0 and D["package_terminal"]["next_offset"]==D["package_terminal"]["available_end"]
index=json.loads(buffers["EVIDENCE_INDEX.json"]);summary=json.loads(buffers["original-package-summary.json"])
assert index["source_head"]=="6a8cd55573065ceb50cdb65a7834615f79b521ae" and index["source_tree"]=="cbd6b4552c87af27c72c0189806baeb33ecb8bf5"
assert index["original_status"]==summary["original_status"]=="passed" and index["original_lane_exit"]==summary["original_lane_exit"]==0
assert index["operator_terminal_summary_sha256"]=="a61aca5c4745c4a4e6f89c8cdc18b489679662b135061bee1357ca4072ca0f3b"
assert index["required_flat_original_file_count"]==39 and index["nested_original_log_count"]==12 and index["original_file_count"]==51 and index["original_bytes"]==886983
assert summary["zip_member_count"]==55 and summary["payload_file_count"]==54 and summary["all_member_crc_size_sha_verified"]is True
rows=index["files"];by={r["path"]:r for r in rows};assert len(rows)==len(by)==54
orig=[r for r in rows if r["role"].startswith("original-execution")]
assert len(orig)==51
actual=D["observed_roster"];old={r["path"]:r for r in actual["rows"]}
assert {r["path"][9:]for r in orig}==set(old)
for r in orig:assert r["bytes"]==old[r["path"][9:]]["bytes"] and r["sha256"]==old[r["path"][9:]]["sha256"] and r["origin"]==old[r["path"][9:]]["origin"]
assert not (C/"flat").exists()
verified=[];flat=[];flatdata={}
with zipfile.ZipFile(io.BytesIO(buffers["original-repository-truth-6a8cd5-v2.zip"]))as z:
 zs=z.infolist();assert len(zs)==55 and len({i.filename for i in zs})==55 and {i.filename for i in zs}==set(by)|{"EVIDENCE_INDEX.json"}
 for item in zs:
  n=item.filename;p=pathlib.PurePosixPath(n);assert str(p)==n and not p.is_absolute() and ".."not in p.parts and re.fullmatch(r"[A-Za-z0-9._/-]+",n) and not item.is_dir() and not item.flag_bits&1
  mode=item.external_attr>>16;assert not stat.S_ISLNK(mode) and (stat.S_IFMT(mode) in (0,stat.S_IFREG))
  raw=z.read(item)
  if n=="EVIDENCE_INDEX.json":assert raw==buffers["EVIDENCE_INDEX.json"]
  else:
   row=by[n];assert len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
   flatdata[n]=raw
  verified.append({"path":n,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"crc32":format(item.CRC,"08x")})
assert len(flatdata)==54
# All members verified before any flat publication.
for n,raw in flatdata.items():
 out=save(C/"flat"/n,raw);flat.append({**out,"origin":by[n]["origin"],"role":by[n]["role"]})
for fd,v,p in held:
 assert sig(os.fstat(fd))==v and sig(p.lstat())==v
for x in direct+flat:
 raw=read(pathlib.Path(x["path"]));assert len(raw)==x["bytes"] and hashlib.sha256(raw).hexdigest()==x["sha256"]
producer=save(C/"verify_official_copy.py",SELF.encode())
provenance=save(C/"official-copy-provenance.json",js(D))
verification={"schema":"trnm-P1-original-full-official-copy-verification-v2","started_at":started,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"status":"verified","source_head":index["source_head"],"source_tree":index["source_tree"],"original_lane_status":"passed","original_lane_elapsed_seconds":summary["original_lane_elapsed_seconds"],"original_summary_sha256":index["operator_terminal_summary_sha256"],"zip_source":D["source_infos"][0],"direct_copies":direct,"flat_copies":flat,"zip_member_count":55,"members_verified":verified,"all_member_crc_sha_size_verified":True,"all_binary_read_chunks_verified":True,"required_flat_originals":39,"actual_originals":51,"original_driver_flat_present":True,"flat_payload_count":54,"no_extractall":True,"tests_rerun":False,"source_git_or_stage_mutation":False,"hosted_qualification":False,"future_revision_qualification":False,"producer":producer,"copy_provenance":provenance}
vf=save(C/"copy-verification.json",js(verification))
copyindex=save(C/"copy-files.json",js({"schema":"trnm-P1-official-copy-source-origins-v2","files":direct+flat}))
print(json.dumps({"verification":vf,"copy_files":copyindex,"producer":producer,"provenance":provenance,"originals":51,"flat":54,"members":55,"status":"verified"}),flush=True)
for f,_,_ in held:os.close(f)

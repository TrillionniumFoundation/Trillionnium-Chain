import pathlib,json,hashlib,sys,os,stat,datetime
assert not sys.flags.optimize
r=json.loads(sys.argv[1]); root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root"); out=root/"official-source-input-transfers-v1"
assert not out.exists() and root.resolve(strict=True)==root
def sha(b):return hashlib.sha256(b).hexdigest()
for f in r["files"]:
 s=f["source"]; d=f["destination"]; w=f["write_result"]; path=pathlib.Path(s["path"]); assert path.resolve(strict=True)==path
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=4*1024*1024
  with os.fdopen(os.dup(fd),"rb") as z:b=z.read()
  e=os.fstat(fd);assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(e.st_dev,e.st_ino,e.st_size,e.st_mtime_ns,e.st_ctime_ns)
 finally:os.close(fd)
 assert s["version"]==f"{a.st_dev}:{a.st_ino}:{a.st_size}:{a.st_mtime_ns}:{a.st_ctime_ns}"
 assert len(b)==s["size"]==d["size"]==w["size"] and sha(b)==s["sha256"]==d["sha256"]==w["sha256"] and d["version"]==w["version"]
 off=0
 for j,c in enumerate(f["chunks"]):
  assert c["path"]==s["path"] and c["version"]==s["version"] and c["offset"]==off and c["size"]==len(b)
  nxt=c["next_offset"];assert off<nxt<=len(b) and sha(b[off:nxt])==c["chunk_sha256"] and c["eof"]==(j==len(f["chunks"])-1);off=nxt
 assert off==len(b)
 if "upload" in f:
  u=f["upload"];assert w["committed"] is True and u["path"]==d["path"] and u["size"]==len(b) and u["sha256"]==sha(b)
  off=0
  for q in f["upload_chunks"]:
   assert q["upload_id"]==u["upload_id"] and q["visible"] is False and q["next_offset"]==min(off+262140,len(b));off=q["next_offset"]
  assert off==len(b)
 else:assert w["written"]==len(b)
 f["source_raw_chunks_reverified"]=True;f["destination_independent_file_info_verified"]=True
out.mkdir(mode=0o700)
for launch in r["launches"]:
 b=launch.pop("program").encode();p=out/(launch["name"]+"-actual-launch.py")
 with p.open("xb") as z:z.write(b)
 launch["program_file"]={"path":str(p),"bytes":len(b),"sha256":sha(b)}
p=out/"record_transfer_receipts.py";b=sys.argv[2].encode()
with p.open("xb") as z:z.write(b)
r["receipt_producer"]={"path":str(p),"bytes":len(b),"sha256":sha(b)}
r["recorded_at"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
b=(json.dumps(r,indent=2,sort_keys=True)+"\n").encode();p=out/"summary.json"
with p.open("xb") as z:z.write(b)
print(json.dumps({"path":str(p),"bytes":len(b),"sha256":sha(b),"files_verified":len(r["files"]),"source_bytes":sum(f["source"]["size"] for f in r["files"])}),flush=True)

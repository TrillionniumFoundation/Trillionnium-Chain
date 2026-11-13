from pathlib import Path
import datetime,hashlib,json,os,shutil,stat,subprocess,time
src=Path("/home/qian-qi/work/chain-w1-four-gates-target-20261108-ec265b")
dst=Path("/home/qian-qi/work/chain-w1-base62-owner-target-20261108-ec265b")
out=Path("/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/owner-cache-copy-01")
expected="41c2d70d80282414bef23a90f22130e5da26e1ac30c8fddc8c5aec6e9de54d24"
elfrel=Path("debug/deps/trnm_pon_node-2c98293081e75af8")
out.mkdir(parents=True,exist_ok=False)
(out/"preflight.stdout.jsonl").write_text("{\"observed_utc\": \"2026-11-08T05:56:33.874916+00:00\", \"source\": \"/home/qian-qi/work/chain-w1-four-gates-target-20261108-ec265b\", \"source_exists\": true, \"destination\": \"/home/qian-qi/work/chain-w1-base62-owner-target-20261108-ec265b\", \"destination_exists\": false, \"rsync\": \"/usr/bin/rsync\", \"cp\": \"/usr/bin/cp\", \"disk_usage\": {\"total\": 982240026624, \"used\": 821201756160, \"free\": 141039996928}, \"commands\": [{\"argv\": [\"df\", \"-B1\", \"/home/qian-qi/work\"], \"exit\": 0, \"stdout\": \"\\u6587\\u4ef6\\u7cfb\\u7edf             1B\\u7684\\u5757         \\u5df2\\u7528         \\u53ef\\u7528 \\u5df2\\u7528% \\u6302\\u8f7d\\u70b9\\n/dev/sda2      982240026624 821201756160 141039996928   86% /\\n\", \"stderr\": \"\"}, {\"argv\": [\"du\", \"-s\", \"-B1\", \"/home/qian-qi/work/chain-w1-four-gates-target-20261108-ec265b\"], \"exit\": 0, \"stdout\": \"14991142912\\t/home/qian-qi/work/chain-w1-four-gates-target-20261108-ec265b\\n\", \"stderr\": \"\"}, {\"argv\": [\"du\", \"-s\", \"-B1\", \"--exclude=incremental\", \"/home/qian-qi/work/chain-w1-four-gates-target-20261108-ec265b\"], \"exit\": 0, \"stdout\": \"14990659584\\t/home/qian-qi/work/chain-w1-four-gates-target-20261108-ec265b\\n\", \"stderr\": \"\"}], \"elf\": {\"path\": \"/home/qian-qi/work/chain-w1-four-gates-target-20261108-ec265b/debug/deps/trnm_pon_node-2c98293081e75af8\", \"bytes\": 468126952, \"sha256\": \"41c2d70d80282414bef23a90f22130e5da26e1ac30c8fddc8c5aec6e9de54d24\", \"device\": 2050, \"inode\": 415622, \"nlink\": 1, \"mtime_ns\": 1794113748434594589, \"regular\": true}}\n")
(out/"preflight.stderr.log").write_text("")
(out/"preflight-transport.json").write_text(json.dumps({"first_response":"MCP request timed out","same_idempotency_readback":{"job_id":"1a1b9ba3814-12894-1665","reused":True,"retried_launch":False,"exit_code":0,"output_complete":True,"output_durable":True},"duplicate_job_started":False},indent=2)+"\n")
def fileinfo(p):
 st=p.stat();h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return {"path":str(p),"bytes":st.st_size,"sha256":h.hexdigest(),"device":st.st_dev,"inode":st.st_ino,"nlink":st.st_nlink,"mtime_ns":st.st_mtime_ns,"regular":stat.S_ISREG(st.st_mode)}
def snapshot(root,exclude):
 regular={};symlinks=[];other=[];incremental=[]
 for parent,dirs,files in os.walk(root,followlinks=False):
  rel=Path(parent).relative_to(root)
  for name in list(dirs):
   p=Path(parent)/name
   if name=="incremental":
    incremental.append(str(p.relative_to(root)))
    if exclude:dirs.remove(name)
   if p.is_symlink():
    symlinks.append({"path":str(p.relative_to(root)),"target":os.readlink(p)})
    if name in dirs:dirs.remove(name)
  for name in files:
   p=Path(parent)/name;st=p.lstat()
   if stat.S_ISREG(st.st_mode):regular[str(p.relative_to(root))]={"device":st.st_dev,"inode":st.st_ino,"bytes":st.st_size,"mtime_ns":st.st_mtime_ns}
   elif stat.S_ISLNK(st.st_mode):symlinks.append({"path":str(p.relative_to(root)),"target":os.readlink(p)})
   else:other.append({"path":str(p.relative_to(root)),"mode":st.st_mode})
 return regular,symlinks,other,incremental
record={"schema":"TRNM-W1-INDEPENDENT-OWNER-CACHE-COPY1","started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source":str(src),"destination":str(dst),"expected_original_C5_owner_sha256":expected,"cleanroom_build":False,"independent_reproducible_build_established":False,"cache_basis":"copy of stable C5 development target; incremental directories excluded; no shared writable hardlinks","source_modified":False,"cargo_invoked":False,"tests_run":False,"proof_generation_started":False,"old_targets_deleted":False,"source_elf_before":fileinfo(src/elfrel),"destination_existed_before":dst.exists(),"disk_before":dict(zip(["total","used","free"],shutil.disk_usage(src.parent))),"copy_exit_code":None,"copy_complete":False}
assert record["source_elf_before"]["sha256"]==expected
assert not dst.exists()
sr,ss,so,si=snapshot(src,True)
record["source_snapshot"]={"regular_files":len(sr),"regular_bytes":sum(v["bytes"] for v in sr.values()),"symlinks":ss,"unsupported_entries":so,"excluded_incremental_directories":si}
assert not so
assert record["disk_before"]["free"]>sum(v["bytes"] for v in sr.values())+10*1024**3
argv=["/usr/bin/rsync","-a","--exclude=incremental/","--stats",str(src)+"/",str(dst)+"/"]
record["copy_command"]=argv
(out/"declaration.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
dst.mkdir(exist_ok=False)
start=time.monotonic_ns();error=None
with (out/"copy.stdout.log").open("xb") as sofd,(out/"copy.stderr.log").open("xb") as sefd:
 try:p=subprocess.run(argv,stdout=sofd,stderr=sefd,timeout=1800);record["copy_exit_code"]=p.returncode
 except Exception as e:error=type(e).__name__+": "+str(e)
record["copy_wall_ns"]=time.monotonic_ns()-start;record["copy_exception"]=error
record["source_elf_after"]=fileinfo(src/elfrel)
record["source_original_elf_unchanged"]=record["source_elf_before"]==record["source_elf_after"]
record["destination_elf"]=fileinfo(dst/elfrel) if (dst/elfrel).is_file() else None
dr,ds,do,di=snapshot(dst,False)
source_inodes={(v["device"],v["inode"]) for v in sr.values()}
shared=[k for k,v in dr.items() if (v["device"],v["inode"]) in source_inodes]
missing=sorted(set(sr)-set(dr));extra=sorted(set(dr)-set(sr));different=[k for k in set(sr)&set(dr) if sr[k]["bytes"]!=dr[k]["bytes"]]
symlink_aliases=[]
for s in ds:
 p=dst/s["path"]
 try:
  target=p.resolve(strict=False)
  if target==src or src in target.parents:symlink_aliases.append({"path":s["path"],"target":str(target)})
 except OSError as e:symlink_aliases.append({"path":s["path"],"error":str(e)})
record["destination_snapshot"]={"regular_files":len(dr),"regular_bytes":sum(v["bytes"] for v in dr.values()),"symlinks":ds,"unsupported_entries":do,"incremental_directories":di,"regular_paths_missing":missing,"regular_paths_extra":extra,"regular_size_mismatches":different,"regular_inode_shared_with_source":shared,"symlinks_resolving_into_source_target":symlink_aliases}
record["no_shared_writable_hardlinks"]=not shared
record["incremental_excluded"]=not di
record["destination_owner_matches_C5_bytes"]=record["destination_elf"] is not None and record["destination_elf"]["sha256"]==expected and record["destination_elf"]["bytes"]==record["source_elf_before"]["bytes"]
record["disk_after"]=dict(zip(["total","used","free"],shutil.disk_usage(src.parent)))
record["copy_complete"]=record["copy_exit_code"]==0 and error is None and record["source_original_elf_unchanged"] and record["destination_owner_matches_C5_bytes"] and not missing and not extra and not different and not shared and not symlink_aliases and not do and not di
record["completed_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
record["all_cache_content_hashed"]=False
record["cache_content_scope"]="Exact original and copied owner ELF hashed; all cache regular-file paths, lengths and source/destination inode separation checked. Other cache bytes rely on successful rsync copy, not a full-file hash attestation."
(out/"copy-result.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
manifest=[]
for p in sorted(out.iterdir()):
 if p.is_file():
  b=p.read_bytes();manifest.append({"path":p.name,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()})
(out/"SHA256SUMS.json").write_text(json.dumps({"files":manifest,"self_excluded":True},indent=2,sort_keys=True)+"\n")
print(json.dumps(record),flush=True)
print(json.dumps({"record_path":str(out/"copy-result.json"),"record_sha256":hashlib.sha256((out/"copy-result.json").read_bytes()).hexdigest(),"manifest_sha256":hashlib.sha256((out/"SHA256SUMS.json").read_bytes()).hexdigest()}),flush=True)
raise SystemExit(0 if record["copy_complete"] else 1)

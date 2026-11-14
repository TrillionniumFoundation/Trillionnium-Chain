import difflib,hashlib,json,os,pathlib,stat,sys
assert sys.flags.optimize == 0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
out=root/"concurrent-head-root-closure-v1"
assert root.resolve(strict=True)==root
out.mkdir(mode=0o700,exist_ok=False)
def sha(b): return hashlib.sha256(b).hexdigest()
def read(p):
 p=pathlib.Path(p); a=p.lstat()
 assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
 def ident(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  assert ident(os.fstat(f.fileno()))==ident(a)
  raw=f.read()
  assert ident(os.fstat(f.fileno()))==ident(a)
 assert ident(p.lstat())==ident(a)
 return raw
items=[]
def emit(name,raw):
 assert pathlib.PurePath(name).name==name
 with (out/name).open("xb") as f:f.write(raw)
 assert read(out/name)==raw
 items.append({"path":str(out/name),"bytes":len(raw),"sha256":sha(raw)})
emit("producer.py",sys.argv[1].encode())
for name,value in json.loads(sys.argv[2]):
 emit(name,value.encode())
 if name.endswith("-terminal.json"):
  v=json.loads(value); raw=bytes.fromhex(v["bytes_hex"])
  assert len(raw)==v["next_offset"]-v["offset"] and v["offset"]==0
  assert sha(raw)==v["chunk_sha256"] and v["output_complete"] is True
  assert v["status"]["state"]=="exited" and v["status"]["output_complete"] is True
  assert v["truncated_before_offset"] is False and v["text_is_lossy"] is False
  emit(name[:-5]+".log",raw)
rows=[
 ("publish_followup_candidate_execution_archive_v1.py",71594,"8510653d14ac5e9870e624137197c0f7d2fd193a37dc4c57a5f65b127a45398d","publish_followup_candidate_execution_archive_v2.py",73492,"0d0a9153f6a0f8aed7201afc77ba52fd2e6ea36009b155ce24d2e59cf1caf0e2","publisher-precise.patch",9271,"3fd4bd06e74a51725638a43d723ec419f1a763e5d05b060640f2efe92a19ee55"),
 ("prepare_pr847_audit_update_v4.py",32628,"57e13006474151c9ce3006cf9c490e797ae73f0f16566eb1f3b33c08f94015c7","prepare_pr847_audit_update_v5.py",36663,"12776f0a436732589e46ef13548cb8f34180a532ab1ff63671560326c541cd6d","preparer-precise.patch",10540,"772e3d3bf43009e1674cd0c3536a82eec0435315b561257d13ccfeb81d7a0662"),
 ("apply_pr847_audit_update_and_ready_v2.py",20506,"ad29ad36815bd088d2b386bb996d28dc5cbe6b5a1b32766f51735598c6ff9776","apply_pr847_audit_update_and_ready_v3.py",20506,"d89eeaa8f7ba2514d411e8ed5b8bb8b3d1270d611b444f832f36fc4d60f9efdc","apply-precise.patch",3180,"0b1ce0a99792623e9dcd09098a434c914f6582c4054e2d3f89a4f5b9ecc83556")]
proof=[]
prep=pathlib.Path("/private/tmp/chain-prci-concurrent-publication-preparation-20261114-v1")
for old,oldn,oldsha,new,newn,newsha,patch,pn,psha in rows:
 a,b,c=read(root/old),read(root/new),read(prep/patch)
 assert (len(a),sha(a))==(oldn,oldsha)
 assert (len(b),sha(b))==(newn,newsha)
 assert (len(c),sha(c))==(pn,psha)
 actual="".join(difflib.unified_diff(a.decode().splitlines(True),b.decode().splitlines(True),fromfile=str(root/old),tofile=str(root/new))).encode()
 assert actual==c
 compile(b,str(root/new),"exec")
 proof.append({"old":old,"old_sha256":oldsha,"new":new,"new_sha256":newsha,"reviewed_diff_sha256":psha,"generated_actual_diff_equals_reviewed_diff":True})
value={"schema":"trnm-root-concurrent-publication-independent-source-review-v1","status":"STATIC_SOURCE_DIFF_VERIFIED_NOT_EXECUTED","reviewed_old_complete_sources_and_all_new_diff_lines":True,"producer_or_helpers_executed":False,"source_git_or_remote_changed":False,"records":proof}
emit("publication-independent-diff-verification.json",(json.dumps(value,indent=2,sort_keys=True)+"\n").encode())
emit("files.json",(json.dumps(items,indent=2,sort_keys=True)+"\n").encode())
print(json.dumps({"directory":str(out),"files":len(items),"bytes":sum(x["bytes"] for x in items),"verification":value["status"]}),flush=True)

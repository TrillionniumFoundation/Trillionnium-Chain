import hashlib,os,pathlib,stat,sys
if sys.flags.optimize:raise RuntimeError("optimized pinned launcher")
p=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-tag-dispatch-only-preparation-v1/dispatch_published_r1_stage1_v1.py")
a=p.lstat()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1 or a.st_size!=30284:raise RuntimeError("reviewed producer scope")
with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),"rb")as f:
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer open changed")
 raw=f.read(30285)
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer read changed")
if fp(p.lstat())!=fp(a)or len(raw)!=30284 or hashlib.sha256(raw).hexdigest()!="bf25839cb805e1005192125a1de5b916bf3017825465fff866ec6533fdb09dac":raise RuntimeError("reviewed producer bytes differ")
import json

def closed_pin_read(pin):
 q=pathlib.Path(pin["path"]);s=q.lstat()
 if q.resolve(strict=True)!=q or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size!=pin["bytes"] or s.st_size>8*1024*1024:raise RuntimeError("closed HOLD file scope")
 with os.fdopen(os.open(q,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),"rb") as f:
  if fp(os.fstat(f.fileno()))!=fp(s):raise RuntimeError("closed HOLD open changed")
  data=f.read(s.st_size+1)
  if fp(os.fstat(f.fileno()))!=fp(s):raise RuntimeError("closed HOLD read changed")
 if fp(q.lstat())!=fp(s) or len(data)!=pin["bytes"] or hashlib.sha256(data).hexdigest()!=pin["sha256"]:raise RuntimeError("closed HOLD pin mismatch")
 return data
prior_pins=json.loads("[{\"path\":\"/private/tmp/chain-consolidation-20261114-root/r1-diagnostic-stage1-dispatch-only-v1-r1-001/summary.json\",\"bytes\":26824,\"sha256\":\"284e649a800c461e7c6150c95ba02fe952dbaf8d65954e004b18cfe982aae765\"},{\"path\":\"/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-dispatch-only-actual-launch-v1/actual-terminal.json\",\"bytes\":4932,\"sha256\":\"e0d9dcbb7fa618cbe4d087098919a45ed8da5d72c31fed0b223378b379a0df02\"}]")
prior=json.loads(closed_pin_read(prior_pins[0]));terminal=json.loads(closed_pin_read(prior_pins[1]))
if prior["schema"]!="trnm-r1-diagnostic-stage1-dispatch-only-receipt-v1" or prior["status"]!="HOLD" or prior["dispatch_started"] is not False or prior["dispatch_status"]!="NOT_STARTED" or type(prior["dispatch_attempt_count"]) is not int or prior["dispatch_attempt_count"]!=0 or prior["dispatch_exit"] is not None or prior["dispatch_response"] is not None or "dispatch_request" in prior:raise RuntimeError("prior POST absent proof failed")
if prior["errors"]!=[{"phase":"single-dispatch","type":"ValueError","message":"actor-before failed; original output retained"}] or prior["remote_before"] is not None or prior["remote_final"] is not None:raise RuntimeError("unexpected prior failure")
if not all(prior[k] is True for k in ("publication_confirmed","source_after_valid","source_index_unchanged","local_ref_fence_valid","installed_hooks_unchanged")) or any(prior[k] is not False for k in ("Git_objects_created","Git_push_started","Git_refs_written","main_or_PR_or_policy_changed","qualification_granted","automatic_retry")):raise RuntimeError("prior local closure failed")
expected_labels=json.loads("[\"project-preflight-before-dispatch\",\"source-before-head\",\"source-before-tree\",\"source-before-status\",\"source-before-symbolic\",\"local-refs-before\",\"source-index-path\",\"hook-before-config\",\"hook-before-default\",\"hook-before-push\",\"hook-before-fetch\",\"actor-before\",\"project-preflight-after-dispatch\",\"verify-source-after\",\"source-after-head\",\"source-after-tree\",\"source-after-status\",\"source-after-symbolic\",\"hook-after-config\",\"hook-after-default\",\"hook-after-push\",\"hook-after-fetch\",\"local-refs-after\"]")
if [s["label"] for s in prior["steps"]]!=expected_labels:raise RuntimeError("closed steps differ")
prior_dir=pathlib.Path(prior_pins[0]["path"]).parent
for s in prior["steps"]:
 expected_exit=1 if s["label"] in ("hook-before-config","actor-before","hook-after-config") else 0
 if type(s["exit"]) is not int or s["exit"]!=expected_exit:raise RuntimeError("closed exit differs")
 for kind in ("stdout","stderr"):
  q=pathlib.Path(s[kind+"_path"])
  if q.parent!=prior_dir or q.name!=s["label"]+"."+kind:raise RuntimeError("prior stream path differs")
  data=closed_pin_read({"path":str(q),"bytes":s[kind+"_bytes"],"sha256":s[kind+"_sha256"]})
  if s["label"]=="actor-before" and kind=="stderr" and data!=b'Get "https://api.github.com/user": dial tcp 140.82.121.5:443: i/o timeout\n':raise RuntimeError("prior transport error differs")
  if s["label"]=="actor-before" and kind=="stdout" and data!=b"":raise RuntimeError("prior actor unexpected response")
read=terminal["read"];sid="dpty-0e429c568c3a3512e0d39c96462bb47c480d2f67bcfa67690fafabef20886b61"
if terminal["schema"]!="trnm-root-actual-pty-terminal-v1" or terminal["launch"]["session_id"]!=sid or read["session_id"]!=sid or read["status"]["state"]!="exited" or read["status"]["exit_code"]!=1 or read["output_complete"] is not True or read["status"]["capture_error"] is not None or read["truncated_before_offset"] is not False or read["offset"]!=0 or read["available_end"]!=1058 or read["next_offset"]!=1058:raise RuntimeError("prior actual natural terminal differs")
raw_terminal=bytes.fromhex(read["bytes_hex"])
if len(raw_terminal)!=1058 or hashlib.sha256(raw_terminal).hexdigest()!="e312f9f31169e1cfcf6d3d9e8cb9240e30efd997e0fe1b11cae166050b8ec3e6" or raw_terminal.decode()!=read["text"]:raise RuntimeError("prior actual terminal bytes differ")
line=json.loads(raw_terminal)
if line!={k:prior[k] for k in ("schema","status","subject_commit","control","publication_confirmed","dispatch_started","dispatch_exit","dispatch_status","dispatch_response","qualification_granted")}|{"receipt":prior_pins[0]["path"]}:raise RuntimeError("prior terminal does not report this receipt")
print(json.dumps({"phase":"closed_network_HOLD_verified","prior_natural_exit":1,"prior_POST_count":0,"new_attempt_has_no_automatic_retry":True}),flush=True)

os.environ.pop("GH_DEBUG",None)
os.environ["GH_HOST"]="github.com"
os.umask(0o077)
D=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-dispatch-only-explicit-resume-002-launch-v1");D.mkdir(mode=0o700,exist_ok=False)
with (D/"launcher.py").open("xb")as f:f.write(sys.argv[1].encode());f.flush();os.fsync(f.fileno())
sys.argv=["/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-tag-dispatch-only-preparation-v1/dispatch_published_r1_stage1_v1.py","--spec","/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-dispatch-only-explicit-resume-001-spec.json","--spec-bytes","2356","--spec-sha256","5fbf776cd821ac8c45789a672ac5e6aded0e179f3340b4ea4b800b4abb4954b2"]
exec(compile(raw,str(p),"exec",optimize=0),{"__name__":"__main__","__file__":str(p)})

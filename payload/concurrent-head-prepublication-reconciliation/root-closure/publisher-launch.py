import hashlib,json,os,pathlib,sys
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
assert root.resolve(strict=True)==root
raw=sys.argv[1].encode("utf-8"); spec=json.loads(raw)
assert spec["candidate_head"]=="2a62061177852dc3ebd200fa8d7c66c661a119a1" and spec["candidate_tree"]=="f8d170ff75990e879e93888a95e5408f36b36f6c"
p=root/"publish_followup_candidate_execution_archive_v1.py"; b=p.read_bytes()
assert len(b)==71594 and hashlib.sha256(b).hexdigest()==spec["publisher_sha256"]=="8510653d14ac5e9870e624137197c0f7d2fd193a37dc4c57a5f65b127a45398d"
for key in ("local_gate_receipt","rog_lane_receipt","execution_manifest"):
    pin=spec[key]; data=pathlib.Path(pin["path"]).read_bytes()
    assert len(data)==pin["bytes"] and hashlib.sha256(data).hexdigest()==pin["sha256"],key
scan=(root/"execution-receipts-followup-v1/execution-payload-scan-v1/scan/summary.json").read_bytes()
assert len(scan)==1117 and hashlib.sha256(scan).hexdigest()=="ef58b1712201ef8e14a956a02964468cc3af4a3c3ee574754ca150b9315d0983"
s=json.loads(scan);assert s["coverage_complete"] is True and s["status"]=="NO_PATTERN_HITS_IN_DECLARED_SCOPE" and s["files_scanned"]==2100 and s["bytes_scanned"]==150184002 and all(v==0 for v in s["counts"].values())
path=root/"followup-publication-spec-2a6206-v1.json"
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
assert path.read_bytes()==raw
sha=hashlib.sha256(raw).hexdigest()
print(json.dumps({"publication_spec":str(path),"bytes":len(raw),"sha256":sha,"candidate":spec["candidate_head"],"archive_tag":spec["archive_tag"],"normal_two_ref_atomic_publication":True,"main_merge_or_branch_deletion":False}),flush=True)
sys.argv=[str(p),"--spec",str(path),"--spec-sha256",sha]
exec(compile(b,str(p),"exec"),{"__name__":"__main__","__file__":str(p)})

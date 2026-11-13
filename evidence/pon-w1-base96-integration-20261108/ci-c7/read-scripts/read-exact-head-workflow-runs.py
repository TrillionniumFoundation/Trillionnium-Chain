from pathlib import Path
import hashlib,json,shutil,subprocess,time
OUT=Path("/home/qian-qi/work/chain-w1-c7-postpush-ci-observation-20261108-ec265b-01")
gh=shutil.which("gh");assert gh
argv=[gh,"api","repos/TrillionniumFoundation/Trillionnium-Chain/actions/runs?head_sha=40a3a45d6b8afc5c4706c5235fec47634f4aabbe&per_page=100"]
s=time.time_ns()
r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
assert len(r.stdout)<8*1024*1024
for name,raw in [("07-c7-workflow-runs.stdout",r.stdout),("07-c7-workflow-runs.stderr",r.stderr)]:
 with (OUT/name).open("xb") as f:f.write(raw)
d=json.loads(r.stdout) if r.returncode==0 else None
readback={"argv":argv,"started_unix_ns":s,"finished_unix_ns":time.time_ns(),"exit_code":r.returncode,
 "stdout_sha256":hashlib.sha256(r.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(r.stderr).hexdigest(),
 "total_count":None if d is None else d.get("total_count"),
 "runs":[] if d is None else [{k:x.get(k) for k in ["id","head_sha","head_branch","event","status","conclusion","run_attempt","created_at","updated_at","html_url"]} for x in d.get("workflow_runs",[])],
 "read_only":True,"CI_mutations":0,"source_mutations":0}
with (OUT/"07-c7-workflow-runs.command.json").open("x") as f:json.dump(readback,f,sort_keys=True,indent=2);f.write("\n")
print(json.dumps(readback),flush=True)

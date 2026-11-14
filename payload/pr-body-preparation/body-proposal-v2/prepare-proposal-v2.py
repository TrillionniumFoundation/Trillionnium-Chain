import os,sys,json,hashlib,difflib,datetime,ast
from pathlib import Path
assert sys.flags.optimize==0
I=json.loads(sys.argv[1]);B=Path("/private/tmp/chain-prci-H5DF-pr-body-preparation-20261114-v1");D=B/"body-proposal-v2";D.mkdir(exist_ok=False)
made=[]
def readpin(p):
 q=Path(p["path"]);need=q.resolve(strict=True)==q and q.is_file()and q.stat().st_nlink==1
 if not need:raise ValueError("noncanonical input")
 s=q.stat();raw=q.read_bytes();z=q.stat()
 assert(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 assert len(raw)==p["bytes"]and hashlib.sha256(raw).hexdigest()==p["sha256"];return raw
def put(name,b):
 p=D/name
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 q={"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()};readpin(q);made.append(q);return q
def js(name,x):return put(name,(json.dumps(x,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode())
pp=put("prepare-proposal-v2.py",sys.argv[2].encode())
src={"path":"/private/tmp/chain-consolidation-20261114-root/H5DF-required-ci-progress-v1-ready-002/pr847.stdout","bytes":27631,"sha256":"d823902b692fae24f6e9cf7fd576e50a6f6148b5081969ea99d741b2ed890629"}
pr=json.loads(readpin(src));old=pr["body"];new=I["body"]
assert old==I["original_body"]
syshead="## Original system acceptance conditions remain\n";syssuffix="## History retention and remaining repository actions\n"
assert old[old.index(syshead):old.index(syssuffix)]==new[new.index(syshead):new.index(syssuffix)]
assert old[old.index("Main integration must use the protected linear merge route"):]==new[new.index("Main integration must use the protected linear merge route"):]
assert"2026-11-14 17:56:47\u201317:56:55 UTC"in new and"**6 successes, 0 failures, 6 running and 2 absent**"in new
oldp=put("old-body.md",old.encode());newp=put("proposed-body.md",new.encode());pay=js("future-body-only-PATCH-payload.json",{"body":new})
patch=put("old-to-proposed-body.patch","".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile="PR847-old-body.md",tofile="PR847-proposed-body.md")).encode())
v1=json.loads((B/"body-proposal-v1/preparation.json").read_bytes())
v1body=readpin(v1["proposed_body"]).decode()
narrow=put("proposal-v1-to-v2.patch","".join(difflib.unified_diff(v1body.splitlines(True),new.splitlines(True),fromfile="body-proposal-v1.md",tofile="body-proposal-v2.md")).encode())
driver=put("execute_pr847_body_only_v1.py",I["driver"].encode())
compile(I["driver"],driver["path"],"exec",dont_inherit=True,optimize=0)
tree=ast.parse(I["driver"])
assert len([n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=="main"])==1
evidence=I["evidence"]
for pin in evidence:readpin(pin)
spec={"schema":"trnm-H5DF-pr847-body-only-spec-v1","producer":driver,"output":"/private/tmp/chain-consolidation-20261114-root/H5DF-pr847-body-only-update-v1-actual-001","old_body":oldp,"desired_body":newp,"body_payload":pay,"source_PR":src,"evidence":evidence}
specp=js("execution-spec.json",spec)
plan=js("execution-plan.json",{"status":"PREPARED_ONLY_NOT_EXECUTED","scope":"Only PR847 body. Fixed H5DF/B. No title/ready/auto-merge, CI, merge, protection, source or ref mutation.","spec":specp,"producer":driver,"future_launch":{"executable":"/opt/homebrew/bin/python3","args":["-B",driver["path"],"--spec-sha256",specp["sha256"]],"cwd":"/private/tmp"},"guards":["Stable reviewed spec/producer/body/evidence hashes before any GET","Four concurrent bounded GETs: actual actor ProfHepta id102159240; PR847 open/ready/no-auto/headH5DF/baseB/same title; candidate refH5DF/main refB","Exact old body or already exact desired body; concurrent different body is HOLD","At most one ordinary body-only PATCH, no retry; actual exit and HTTP kept separately","Three bounded post-GETs require exact desired body/title/ready/noauto/head/base/refs; UNKNOWN/HOLD on mismatch or incomplete evidence","Final input identities/hashes unchanged"],"budgets":{"each_request_seconds":120,"total_seconds":600,"maximum_requests":8,"normal_PATCH_maximum":1,"owned_TERM_then_KILL_reap_grace_seconds":[5,5]},"normal_API_CAS_limit":"Normal PR PATCH has no expected-head/body CAS. Before/after checks detect observed drift and cannot lock refs; no atomic CAS claim.","edited_trigger_finding":"Captured H5DF36/baseB1 repository workflows have default pull_request activities only; no edited subscription. External apps/future workflows are outside this finding.","not_run":True})
prep=js("preparation.json",{"schema":"trnm-H5DF-pr847-body-preparation-v2","status":"PREPARED_ONLY","prepared_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"producer":pp,"old_body":oldp,"proposed_body":newp,"exact_body_diff":patch,"v1_to_v2_body_diff":narrow,"executor":driver,"spec":specp,"plan":plan,"source_PR":src,"snapshot":"2026-11-14T17:56:47.093855+00:00 to 2026-11-14T17:56:55.210218+00:00","required_counts":{"success":6,"failure":0,"running":6,"absent":2},"original_R1_results_not_inherited_by_H5DF":True,"confirmed_archive_has_R1_scope_only":True,"preserved_system_acceptance_section_byte_equal":True,"preserved_main_protection_cleanup_tail_byte_equal":True,"static_compile_optimize_zero":True,"executor_or_network_not_executed":True})
idx=js("EVIDENCE_INDEX.json",{"schema":"trnm-prepared-body-proposal-index-v2","files":list(made),"count":len(made),"bytes":sum(p["bytes"]for p in made),"self_excluded":True,"prepared_only":True})
print(json.dumps({"status":"PREPARED_ONLY","body":newp,"diff":patch,"narrow_diff":narrow,"executor":driver,"spec":specp,"plan":plan,"preparation":prep,"index":idx},sort_keys=True))

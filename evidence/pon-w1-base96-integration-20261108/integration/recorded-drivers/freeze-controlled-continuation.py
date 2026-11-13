# Controlled continuation after recorded proof that the original launch never reached its entrypoint.
from pathlib import Path
import hashlib, os, subprocess
old_job="1a1ba24c731-12894-1899"
assert not os.path.lexists("/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs/"+old_job)
for args in (["systemctl","--user","show"],["systemctl","show"]):
    p=subprocess.run([*args,"--no-pager","--property=LoadState,ActiveState,SubState,ExecMainPID,InvocationID","hepta-runtime-job-"+old_job],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=30)
    assert p.returncode==0,(args,p.returncode,p.stderr)
    fields=dict(line.split("=",1) for line in p.stdout.decode().splitlines())
    assert fields=={"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","ExecMainPID":"0","InvocationID":""},fields
freeze_root=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
def exact_git(*args):return subprocess.check_output(["git",*args],cwd=freeze_root)
assert exact_git("rev-parse","HEAD").decode().strip()=="2bdd252aa6c300b7431b9ee897b254b7953cf562"
assert exact_git("rev-parse","MERGE_HEAD").decode().strip()=="96a241bf43f6a46d35dfb3d4ced9594ed8ceca75"
assert hashlib.sha256(exact_git("diff","--binary","2bdd252aa6c300b7431b9ee897b254b7953cf562")).hexdigest()=="511a8c21cf92b15451e43a8aa44f66dcf6f548f5a5b469ef8f39ef7848ffa9fa"

from pathlib import Path
import hashlib,json,os,re,subprocess,time
root=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
source=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
parentout=Path("/home/qian-qi/work/chain-w1-base96-adversarial-integration-20261108-ec265b-02")
out=parentout/"freeze-01";out.mkdir()
c6="2bdd252aa6c300b7431b9ee897b254b7953cf562"
base="96a241bf43f6a46d35dfb3d4ced9594ed8ceca75"
branch="fix/chain-w1-base96-integration-20261108-ec265b"
paths=[".github/workflows/pon-history-stage-diagnostic.yml","config/pon/pq-cross-branch-corpus-v1.json","docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md","scripts/ci/run_from_zero_host.py","scripts/ci/run_history_diagnostic.py","scripts/ci/test_history_stage_diagnostic.py","trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs","trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs"]
rows=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
def git(*args,cwd=root):return subprocess.check_output(["git",*args],cwd=cwd)
def run(name,argv,cwd=root):
 p=subprocess.run(argv,cwd=cwd,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=180)
 (out/(name+".stdout")).write_bytes(p.stdout);(out/(name+".stderr")).write_bytes(p.stderr)
 rows.append({"name":name,"argv":argv,"cwd":str(cwd),"exit_code":p.returncode,"stdout_bytes":len(p.stdout),"stdout_sha256":sha(p.stdout),"stderr_bytes":len(p.stderr),"stderr_sha256":sha(p.stderr)})
 dump(out/"commands.json",rows)
 assert p.returncode==0,(name,p.returncode,p.stderr.decode(errors="replace")[-3000:])
 return p.stdout
complete=False
result={}
try:
 prior=parentout/"precommit-repair-01/manifest.json"
 m=json.loads(prior.read_text());assert m["complete"] is True and all(c["exit_code"]==0 for c in m["commands"])
 assert git("rev-parse","HEAD").decode().strip()==c6
 assert git("rev-parse","MERGE_HEAD").decode().strip()==base
 assert git("branch","--show-current").decode().strip()==branch
 assert git("diff","--binary",c6)==(parentout/"precommit-repair-01/candidate-full-diff.patch").read_bytes()
 assert set(git("diff","--name-only",c6).decode().splitlines())==set(paths)
 assert not git("ls-files","--others","--exclude-standard")
 flags=git("ls-files","-v","-z").split(b"\0")
 assert not any(x and (x[:1].islower() or x[:1]==b"S") for x in flags)
 run("00-preflight-dev",["bash","scripts/project-preflight.sh","--dev"])
 run("01-stage-exact-paths",["git","add","--",*paths])
 assert not git("diff","--name-only")
 assert set(git("diff","--cached","--name-only",c6).decode().splitlines())==set(paths)
 run("02-preflight-staged",["bash","scripts/project-preflight.sh","--staged"])
 run("03-staged-whitespace",["git","diff","--cached","--check"])
 msg="Integrate base96 diagnostics with exact source inventory\n\nMerge the fixed base96 into C6 while retaining the strict CI event and source identity gates.\n\nRegister the added History diagnostic integration test in the embedded source inventory and rebind its exact corpus blob. Preserve the original inventory check failure and document the C6 lifecycle evidence plus the new C7 qualification boundary.\n\nThe candidate requires a new consistent event tuple and qualification on its exact committed source.\n"
 (out/"commit-message.txt").write_text(msg)
 run("04-local-merge-commit",["git","commit","--file",str(out/"commit-message.txt")])
 commit=git("rev-parse","HEAD").decode().strip();tree=git("rev-parse","HEAD^{tree}").decode().strip()
 parents=git("show","-s","--format=%P","HEAD").decode().split()
 assert parents==[c6,base]
 assert not git("status","--porcelain","--untracked-files=all")
 assert git("rev-parse","HEAD",cwd=source).decode().strip()==c6
 assert not git("status","--porcelain","--untracked-files=all",cwd=source)
 finalpaths=git("diff","--name-only",c6,commit).decode().splitlines();assert set(finalpaths)==set(paths)
 (out/"source-diff.patch").write_bytes(git("diff","--binary",c6,commit))
 (out/"source-diff-stat.txt").write_bytes(git("diff","--stat",c6,commit))
 (out/"source-name-status.txt").write_bytes(git("diff","--name-status",c6,commit))
 run("05-postcommit-preflight",["bash","scripts/project-preflight.sh","--dev"])
 suites=[]
 for namespace,names in [("precommit-checks-01",["05-history-diagnostic-controls","06-host-routing-controls","07-pq-rejection-controls","08-w1-ci-contract-controls"]),("precommit-repair-01",["06-pq-rejection-controls","07-w1-ci-contract-controls"])]:
  for name in names:
   b=(parentout/namespace/(name+".stderr")).read_bytes();text=b.decode()
   n=re.findall(r"^Ran ([0-9]+) tests in ",text,re.M)
   assert len(n)==1 and re.search(r"^OK$",text,re.M) and "skipped=" not in text
   suites.append({"attempt":namespace,"name":name,"methods":int(n[0]),"passed":int(n[0]),"failed":0,"skipped":0,"stderr_sha256":sha(b)})
 repair=json.loads((parentout/"precommit-repair-01/exact-repair.json").read_text())
 result={"source_commit":commit,"source_tree":tree,"parents":parents,"branch":branch,"worktree":str(root),"changed_paths":finalpaths,"preplan_merge_tree":"d73e57c9e7a5764a1ab33540c97af587bb6e4a69","preplan_tree_is_final_source_tree":False,"exact_repair":repair,"precommit_suites":suites,"first_precommit_methods":sum(x["methods"] for x in suites if x["attempt"]=="precommit-checks-01"),"repair_repeat_methods":sum(x["methods"] for x in suites if x["attempt"]=="precommit-repair-01"),"original_c6_head_unchanged":True,"original_c6_worktree_clean":True,"new_c7_worktree_clean":True,"precommit_repair_manifest_sha256":sha(prior.read_bytes()),"source_diff_sha256":sha((out/"source-diff.patch").read_bytes())}
 complete=True
finally:
 result.update(schema="TRNM-W1-C7-LOCAL-SOURCE-FREEZE1",complete=complete,commands=rows,pushed=False,postcommit_exact_source_qualification=False,new_pr_event_tuple_verified=False,full_proof_generations=0,new_operations=0,ci_reruns=0,original_setup_and_inventory_failures_retained=True)
 dump(out/"source-freeze.json",result)
 print(json.dumps({"complete":complete,"source_commit":result.get("source_commit"),"source_tree":result.get("source_tree"),"parents":result.get("parents"),"out":str(out),"source_freeze_sha256":sha((out/"source-freeze.json").read_bytes()),"first_precommit_methods":result.get("first_precommit_methods"),"repair_repeat_methods":result.get("repair_repeat_methods"),"pushed":False}),flush=True)


from pathlib import Path
import hashlib,json,subprocess,time
source=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
new=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
out=Path("/home/qian-qi/work/chain-w1-base96-adversarial-integration-20261108-ec265b-02")
c6="2bdd252aa6c300b7431b9ee897b254b7953cf562"
base="96a241bf43f6a46d35dfb3d4ced9594ed8ceca75"
branch="fix/chain-w1-base96-integration-20261108-ec265b"
preview="d73e57c9e7a5764a1ab33540c97af587bb6e4a69"
out.mkdir()
rows=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
def run(name,argv,cwd=source,ok=(0,)):
 p=subprocess.run(argv,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
 (out/(name+".stdout")).write_bytes(p.stdout);(out/(name+".stderr")).write_bytes(p.stderr)
 rows.append({"name":name,"argv":argv,"cwd":str(cwd),"exit_code":p.returncode,"stdout_bytes":len(p.stdout),"stdout_sha256":sha(p.stdout),"stderr_bytes":len(p.stderr),"stderr_sha256":sha(p.stderr)})
 dump(out/"commands.json",rows)
 assert p.returncode in ok,(name,p.returncode,p.stderr.decode(errors="replace")[:2000])
 return p.stdout.decode()
complete=False
try:
 run("00-source-preflight",["bash","scripts/project-preflight.sh","--dev"])
 assert run("01-source-head",["git","rev-parse","HEAD"]).strip()==c6
 assert run("02-source-status",["git","status","--porcelain","--untracked-files=all"])==""
 assert run("03-base-object",["git","cat-file","-t",base]).strip()=="commit"
 assert not new.exists()
 run("04a-branch-format",["git","check-ref-format","refs/heads/"+branch])
 assert run("04b-branch-absent",["git","for-each-ref","--format=%(refname)","refs/heads/"+branch])==""
 run("05-create-worktree",["git","worktree","add","-b",branch,str(new),c6])
 run("06-new-preflight",["bash","scripts/project-preflight.sh","--dev"],new)
 run("07-merge-base96",["git","merge","--no-commit","--no-ff",base],new)
 assert run("08-merge-head",["git","rev-parse","MERGE_HEAD"],new).strip()==base
 assert run("09-index-tree",["git","write-tree"],new).strip()==preview
 changed=run("10-merge-paths",["git","diff","--cached","--name-status",c6],new)
 run("11-merge-numstat",["git","diff","--cached","--numstat",c6],new)
 run("12-merge-patch",["git","diff","--cached","--binary",c6],new)
 run("13-base-log",["git","log","--format=%H %s","62d2d90c9e1f4c8450c89843f1e08360a24283ce.."+base],new)
 run("14-instruction-paths",["git","ls-files","*AGENTS.md"],new)
 plan=new/"docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
 (out/"plan-tail-before.txt").write_text(plan.read_text()[-10000:])
 expected={".github/workflows/pon-history-stage-diagnostic.yml","scripts/ci/run_history_diagnostic.py","scripts/ci/test_history_stage_diagnostic.py","trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs","scripts/ci/run_from_zero_host.py","config/pon/pq-cross-branch-corpus-v1.json"}
 paths={x.split("\t",1)[1] for x in changed.splitlines()}
 assert paths==expected,paths
 assert run("15-original-c6-head-after",["git","rev-parse","HEAD"]).strip()==c6
 assert run("16-original-c6-status-after",["git","status","--porcelain","--untracked-files=all"])==""
 complete=True
finally:
 result={"schema":"TRNM-W1-C7-BASE96-PRECOMMIT-MERGE1","complete":complete,"source_c6":c6,"base96":base,"branch":branch,"worktree":str(new),"preplan_expected_tree":preview,"commands":rows,"source_worktrees_modified_except_new_c7":False,"tests_executed":0,"committed":False,"pushed":False}
 dump(out/"merge-preparation.json",result)
 print(json.dumps({"complete":complete,"out":str(out),"worktree":str(new),"manifest_sha256":sha((out/"merge-preparation.json").read_bytes()),"commands":len(rows)}),flush=True)


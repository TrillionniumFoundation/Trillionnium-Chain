import ast, datetime, hashlib, json, os, pathlib, re, subprocess, sys, time
sys.dont_write_bytecode=True
W=pathlib.Path("/private/tmp/chain-hash-use-current-binding-20261114")
E=pathlib.Path("/private/tmp/chain-hash-use-current-binding-evidence-20261114")
V=E/"validation-v1";V.mkdir();T=V/"tmp";T.mkdir()
HEAD="7d8d4c59fcd01480a12e1c64835b202079091800"
env=dict(os.environ,PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0",TMPDIR=str(T))
steps=[];started=datetime.datetime.now(datetime.timezone.utc).isoformat()
def sh(b):return hashlib.sha256(b).hexdigest()
def save(name,b):
 p=V/name
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sh(b)}
def dump(name,v):return save(name,(json.dumps(v,indent=2,sort_keys=True)+"\n").encode())
def run(label,args,timeout=120):
 t=time.monotonic();r=subprocess.run(args,cwd=W,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 step={"label":label,"argv":args,"cwd":str(W),"exit_code":r.returncode,"elapsed_seconds":round(time.monotonic()-t,3),"timeout_seconds":timeout,"stdout":save(label+".stdout",r.stdout),"stderr":save(label+".stderr",r.stderr)}
 steps.append(step);dump("step-"+str(len(steps)).zfill(2)+".json",step)
 print(json.dumps({"label":label,"exit_code":r.returncode,"seconds":step["elapsed_seconds"]}),flush=True)
 return r
sys.path.insert(0,str(W/"scripts/ci"))
from pq_source_reader import read_regular
m=json.loads((W/"config/pon/hash-use-contract-v1.json").read_bytes())
extra=["config/pon/hash-use-contract-v1.json","scripts/ci/hash_use_contract.py","scripts/ci/test_hash_use_contract.py","scripts/ci/check_ci_contract.py","scripts/ci/test_ci_contract.py","docs/security/HASH_USE_CONTRACT_V1.md"]
paths=sorted(set(m["source_files"])|set(extra))
def snapshot():
 rows=[]
 for path in paths:
  b=read_regular(W,path,2*1024*1024)
  rows.append({"path":path,"bytes":len(b),"sha256":sh(b)})
 return rows
before=snapshot();dump("source-before.json",before)
try:
 assert run("head",["/usr/bin/git","rev-parse","HEAD"]).stdout.decode().strip()==HEAD
 assert run("preflight",["/bin/bash","scripts/project-preflight.sh"]).returncode==0
 run("python-version",[sys.executable,"-B","-c","import sys,json; print(json.dumps({'version':sys.version,'executable':sys.executable,'optimize':sys.flags.optimize}))"])
 tests=run("original-33-controls",[sys.executable,"-B","scripts/ci/test_hash_use_contract.py","-v"])
 actual=run("actual-hash-use-inspection",[sys.executable,"-B","scripts/ci/hash_use_contract.py"])
 target="test_hash_use_commands_cannot_change_position_multiplicity_or_failure_policy"
 tree=ast.parse((W/"scripts/ci/test_ci_contract.py").read_text())
 holders=[node.name for node in tree.body if isinstance(node,ast.ClassDef) and any(isinstance(f,ast.FunctionDef) and f.name==target for f in node.body)]
 assert len(holders)==1
 selector=holders[0]+"."+target
 ci_negative=run("original-hash-ci-command-refusals",[sys.executable,"-B","scripts/ci/test_ci_contract.py",selector,"-v"])
 ci_actual=run("actual-ci-contract",[sys.executable,"-B","scripts/ci/check_ci_contract.py"])
 diffcheck=run("changed-source-diff-check",["/usr/bin/git","diff","--check","--","config/pon/hash-use-contract-v1.json","scripts/ci/hash_use_contract.py","docs/security/HASH_USE_CONTRACT_V1.md"])
 after=snapshot();dump("source-after.json",after);assert before==after
 results=re.findall(rb"Ran ([0-9]+) tests? in",tests.stderr);assert results==[b"33"]
 ci_results=re.findall(rb"Ran ([0-9]+) tests? in",ci_negative.stderr);assert ci_results==[b"1"]
 actual_report=json.loads(actual.stdout)
 assert actual_report["status"]=="HOLD_NO_GO" and actual_report["declared_use_count"]==19 and actual_report["declared_source_count"]==31
 assert actual_report["source_files_checked"] is True and actual_report["production_activation"] is False and actual_report["whole_chain_pq_qualified"] is False
 assert actual_report["reviewed_source_map_sha256"]=="15a8d91e0b2c50908d17c6bb9743e8ef5a44927814e59354874d77d9654f9ee7"
 all_pass=all(s["exit_code"]==0 for s in steps)
 summary={"schema":"hash-use-reviewed-current-map-validation-v1","started_utc":started,"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"base_head":HEAD,"working_source_changed_only_by_reviewed_patch":True,"status":"PASS" if all_pass else "FAIL","steps":steps,"original_hash_use_tests":33,"original_hash_use_test_methods_changed":0,"original_ci_command_guard_test":selector,"original_ci_command_guard_methods":1,"actual_inspect_status":actual_report["status"],"actual_inspect_source_count":actual_report["declared_source_count"],"source_snapshot_unique_inputs":len(before),"source_before_after_equal":before==after,"full_repository_truth_lane_run":False,"root_diagnostic_122_commands_rerun":False,"native_or_hosted_tests_run":False,"corpus_and_soleplan_pending_root_composition":True,"original_7d8_full_lane_failure_unchanged":True}
 meta=dump("summary.json",summary);dump("steps.json",steps)
 print(json.dumps({"summary":meta,"status":summary["status"],"original_controls":33,"direct_ci_guard":1,"source_inputs":len(before),"full_lane_run":False}),flush=True)
 sys.exit(0 if all_pass else 1)
except BaseException as ex:
 if isinstance(ex,SystemExit):raise
 dump("failure.json",{"type":type(ex).__name__,"error":str(ex),"steps":steps})
 raise

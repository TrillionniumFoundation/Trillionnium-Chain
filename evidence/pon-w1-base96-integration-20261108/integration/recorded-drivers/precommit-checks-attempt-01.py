from pathlib import Path
import hashlib,json,os,re,subprocess,time
root=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
source=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
parentout=Path("/home/qian-qi/work/chain-w1-base96-adversarial-integration-20261108-ec265b-02")
out=parentout/"precommit-checks-01"
c6="2bdd252aa6c300b7431b9ee897b254b7953cf562"
base="96a241bf43f6a46d35dfb3d4ced9594ed8ceca75"
preview="d73e57c9e7a5764a1ab33540c97af587bb6e4a69"
paragraph="**2026-11-08：C7 固定 base96 最小整合，等待新事件与精确源码资格。** 已冻结 C6 `2bdd252aa6c300b7431b9ee897b254b7953cf562` 在独立新研究 Node/M12 operation 实际完成原 120 秒自然 deadline→Failure Unknown→独立 owner veto／本金退款→同一原 Cancel 的重组恢复及独立 cold；main 与 cold 各有 1 个实际 heavy 入口通过，Done 仅闭合派发，consumed=null、全 cap 保留、无 provider 付款、0 新完整 proof，确定性 NativeTask Cancel 与 C5 同 wire/packet，不能累计两轮本金。C6 首轮 staged 两项失败、原 backend 900 秒／124、唯一同源码同参数 32 项隔离复核及新 cached backend attempt 均各自保留，不把原失败改为通过。本 C7 仅将固定 base `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75` 正常合入 C6：新增 4 个独立 History 诊断路径、Host helper 增加 6 行、corpus 增加 5 项 pin／required；生产 Rust src、M12 与 W1 生成代码不变。已观察的 39 项远端 CI source-context 前置拒绝（38 个 prospective-merge lane 与 1 个 CodeQL export）绑定事件 base62，而实际 merge 父提交使用 base96/C6，属于正确拒绝；不更改 guard/context、不重写原事件，也不将其他 artifact／业务失败归入该原因。C7 必须独立核验新事件的 base/head/merge 有序父提交与 canonical tree，并在冻结的新 source commit/tree 上另取精确资格；本段不授予新候选、原业务预算、完整资源或部署安全资格，四门继续 HOLD。"
out.mkdir()
rows=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
def git(*args):return subprocess.check_output(["git",*args],cwd=root)
def run(name,argv,cwd=root,required=True):
 start=time.monotonic_ns()
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
 try:
  p=subprocess.run(argv,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=300)
  code=p.returncode;stdout=p.stdout;stderr=p.stderr;timed_out=False
 except subprocess.TimeoutExpired as e:
  code=124;stdout=e.stdout or b"";stderr=e.stderr or b"";timed_out=True
 (out/(name+".stdout")).write_bytes(stdout);(out/(name+".stderr")).write_bytes(stderr)
 row={"name":name,"argv":argv,"cwd":str(cwd),"exit_code":code,"timed_out":timed_out,"elapsed_ns":time.monotonic_ns()-start,"stdout_bytes":len(stdout),"stdout_sha256":sha(stdout),"stderr_bytes":len(stderr),"stderr_sha256":sha(stderr)}
 rows.append(row);dump(out/"commands.json",rows)
 print(json.dumps({"name":name,"exit_code":code,"timed_out":timed_out}),flush=True)
 if required:assert code==0,(name,code,stderr.decode(errors="replace")[-2000:])
 return code
complete=False
try:
 prep=json.loads((parentout/"merge-preparation.json").read_text())
 assert prep["complete"] is True
 assert git("rev-parse","HEAD").decode().strip()==c6
 assert git("rev-parse","MERGE_HEAD").decode().strip()==base
 assert git("write-tree").decode().strip()==preview
 run("00-preflight",["bash","scripts/project-preflight.sh","--dev"])
 corpus="config/pon/pq-cross-branch-corpus-v1.json"
 old=json.loads(git("show",c6+":"+corpus))
 merged=json.loads((root/corpus).read_text())
 keys={"pinned_blobs","required_paths"}
 assert {k:v for k,v in old.items() if k not in keys}=={k:v for k,v in merged.items() if k not in keys}
 added=set(merged["pinned_blobs"])-set(old["pinned_blobs"])
 expected={".github/workflows/pon-history-stage-diagnostic.yml","scripts/ci/run_history_diagnostic.py","scripts/ci/test_history_stage_diagnostic.py","trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs","scripts/ci/run_from_zero_host.py"}
 assert added==expected
 assert all(merged["pinned_blobs"].get(k)==v for k,v in old["pinned_blobs"].items())
 assert set(merged["required_paths"])-set(old["required_paths"])==expected
 assert [x for x in merged["required_paths"] if x not in added]==old["required_paths"]
 blobs=[]
 for rel in sorted(expected):
  raw=(root/rel).read_bytes()
  blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
  assert blob==merged["pinned_blobs"][rel]==git("rev-parse",base+":"+rel).decode().strip()
  blobs.append({"path":rel,"bytes":len(raw),"sha256":sha(raw),"git_blob":blob})
 identity={"old_pins":len(old["pinned_blobs"]),"new_pins":len(merged["pinned_blobs"]),"old_required":len(old["required_paths"]),"new_required":len(merged["required_paths"]),"all_old_pins_and_ordered_required_preserved":True,"other_corpus_fields_identical":True,"base96_nonconfig_blobs_exact":blobs,"preplan_tree":preview}
 dump(out/"merge-scope-and-pins.json",identity)
 plan=root/"docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
 before=plan.read_bytes()
 assert before==git("show",c6+":docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md")
 assert paragraph.encode() not in before
 append=("\n\n"+paragraph+"\n").encode()
 with plan.open("ab") as f:f.write(append)
 assert plan.read_bytes()==before+append
 dump(out/"plan-append.json",{"path":str(plan.relative_to(root)),"before_sha256":sha(before),"after_sha256":sha(before+append),"appended_bytes":len(append),"appended_text":append.decode(),"appended_paragraphs":1,"prior_bytes_preserved":True})
 checks=[
  ("01-format",["cargo","+1.95.0","fmt","--manifest-path","trillionnium/Cargo.toml","--all","--","--check"]),
  ("02-ci-contract",["python3","scripts/ci/check_ci_contract.py"]),
  ("03-pq-source-pins",["python3","scripts/ci/check_pq_research_integration.py"]),
  ("04-source-inventory",["python3","scripts/refresh_distributed_source_inventory.py","--check"]),
  ("05-history-diagnostic-controls",["python3","scripts/ci/test_history_stage_diagnostic.py","-v"]),
  ("06-host-routing-controls",["python3","scripts/ci/test_from_zero_host_ci.py","-v"]),
  ("07-pq-rejection-controls",["python3","scripts/ci/test_pq_research_integration.py","-v"]),
  ("08-w1-ci-contract-controls",["python3","scripts/ci/test_ci_contract.py","W1PostwinLaneTests","-v"]),
 ]
 for name,argv in checks:run(name,argv,required=False)
 run("09-diff-check",["git","diff","--check"],required=False)
 run("10-index-diff-check",["git","diff","--cached","--check"],required=False)
 run("11-source-c6-status",["git","status","--porcelain","--untracked-files=all"],source)
 assert (out/"11-source-c6-status.stdout").read_bytes()==b""
 changed=set(git("diff","--name-only",c6).decode().splitlines())
 assert changed==expected|{corpus,"docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"}
 assert not git("ls-files","--others","--exclude-standard")
 (out/"candidate-full-diff.patch").write_bytes(git("diff","--binary",c6))
 complete=all(x["exit_code"]==0 and not x["timed_out"] for x in rows)
finally:
 result={"schema":"TRNM-W1-C7-PRECOMMIT-NARROW-CHECKS1","complete":complete,"source_parent_c6":c6,"merge_parent_base96":base,"worktree":str(root),"commands":rows,"postcommit_qualification":False,"history_ignored_workload_executions":0,"full_proof_generations":0,"new_operations":0,"ci_reruns":0,"guard_or_event_context_changed":False,"committed":False,"pushed":False}
 dump(out/"manifest.json",result)
 print(json.dumps({"complete":complete,"out":str(out),"manifest_sha256":sha((out/"manifest.json").read_bytes()),"commands":len(rows)}),flush=True)
assert complete,"precommit gates failed; preserve all outputs before any decision"


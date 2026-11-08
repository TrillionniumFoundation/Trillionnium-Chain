from pathlib import Path
import hashlib,json,os,re,subprocess,time
root=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
source=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
parentout=Path("/home/qian-qi/work/chain-w1-base96-adversarial-integration-20261108-ec265b-02")
out=parentout/"precommit-repair-01"
c6="2bdd252aa6c300b7431b9ee897b254b7953cf562"
base="96a241bf43f6a46d35dfb3d4ced9594ed8ceca75"
corpus="config/pon/pq-cross-branch-corpus-v1.json"
inventory="trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs"
planrel="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
oldparagraph="**2026-11-08：C7 固定 base96 最小整合，等待新事件与精确源码资格。** 已冻结 C6 `2bdd252aa6c300b7431b9ee897b254b7953cf562` 在独立新研究 Node/M12 operation 实际完成原 120 秒自然 deadline→Failure Unknown→独立 owner veto／本金退款→同一原 Cancel 的重组恢复及独立 cold；main 与 cold 各有 1 个实际 heavy 入口通过，Done 仅闭合派发，consumed=null、全 cap 保留、无 provider 付款、0 新完整 proof，确定性 NativeTask Cancel 与 C5 同 wire/packet，不能累计两轮本金。C6 首轮 staged 两项失败、原 backend 900 秒／124、唯一同源码同参数 32 项隔离复核及新 cached backend attempt 均各自保留，不把原失败改为通过。本 C7 仅将固定 base `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75` 正常合入 C6：新增 4 个独立 History 诊断路径、Host helper 增加 6 行、corpus 增加 5 项 pin／required；生产 Rust src、M12 与 W1 生成代码不变。已观察的 39 项远端 CI source-context 前置拒绝（38 个 prospective-merge lane 与 1 个 CodeQL export）绑定事件 base62，而实际 merge 父提交使用 base96/C6，属于正确拒绝；不更改 guard/context、不重写原事件，也不将其他 artifact／业务失败归入该原因。C7 必须独立核验新事件的 base/head/merge 有序父提交与 canonical tree，并在冻结的新 source commit/tree 上另取精确资格；本段不授予新候选、原业务预算、完整资源或部署安全资格，四门继续 HOLD。"
newparagraph="**2026-11-08：C7 固定 base96 最小整合，等待新事件与精确源码资格。** 已冻结 C6 `2bdd252aa6c300b7431b9ee897b254b7953cf562` 在独立新研究 Node/M12 operation 实际完成原 120 秒自然 deadline→Failure Unknown→独立 owner veto／本金退款→同一原 Cancel 的重组恢复及独立 cold；main 与 cold 各有 1 个实际 heavy 入口通过，Done 仅闭合派发，consumed=null、全 cap 保留、无 provider 付款、0 新完整 proof，确定性 NativeTask Cancel 与 C5 同 wire/packet，不能累计两轮本金。C6 首轮 staged 两项失败、原 backend 900 秒／124、唯一同源码同参数 32 项隔离复核及新 cached backend attempt 均各自保留，不把原失败改为通过。本 C7 将固定 base `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75` 正常合入 C6：新增 4 个独立 History 诊断路径、Host helper 增加 6 行、corpus 增加 5 项 pin／required；集成检查保留了 embedded source inventory 的原失败，随后使用仓库原生成器仅注册新增 Rust integration test，并将该既有 inventory pin 精确重绑；全部既有 pin 路径和拒绝条件保留。生产 Rust src、M12 与 W1 生成代码不变，最终 C7 tree 不以未加计划段和清单修复的静态 d73 预览替代。已观察的 39 项远端 CI source-context 前置拒绝（38 个 prospective-merge lane 与 1 个 CodeQL export）绑定事件 base62，而实际 merge 父提交使用 base96/C6，属于正确拒绝；不更改 guard/context、不重写原事件，也不将其他 artifact／业务失败归入该原因。C7 必须独立核验新事件的 base/head/merge 有序父提交与 canonical tree，并在冻结的新 source commit/tree 上另取精确资格；本段不授予新候选、原业务预算、完整资源或部署安全资格，四门继续 HOLD。"
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
 rows.append({"name":name,"argv":argv,"cwd":str(cwd),"exit_code":code,"timed_out":timed_out,"elapsed_ns":time.monotonic_ns()-start,"stdout_bytes":len(stdout),"stdout_sha256":sha(stdout),"stderr_bytes":len(stderr),"stderr_sha256":sha(stderr)})
 dump(out/"commands.json",rows)
 print(json.dumps({"name":name,"exit_code":code,"timed_out":timed_out}),flush=True)
 if required:assert code==0,(name,code,stderr.decode(errors="replace")[-2000:])
 return code
complete=False
try:
 original=json.loads((parentout/"precommit-checks-01/manifest.json").read_text())
 assert original["complete"] is False
 assert [x["name"] for x in original["commands"] if x["exit_code"]!=0]==["04-source-inventory"]
 assert git("rev-parse","HEAD").decode().strip()==c6
 assert git("rev-parse","MERGE_HEAD").decode().strip()==base
 run("00-preflight",["bash","scripts/project-preflight.sh","--dev"])
 review=json.loads((parentout/"inventory-review-01/summary.json").read_text())
 before=(root/inventory).read_bytes();assert sha(before)==review["before_sha256"]
 oldblob=git("hash-object",inventory).decode().strip()
 c_before=(root/corpus).read_bytes();cm=json.loads(c_before)
 assert cm["pinned_blobs"][inventory]==oldblob and inventory in cm["required_paths"]
 mirrors=git("grep","-n",oldblob,"--",".github","config","scripts","trillionnium").decode()
 (out/"old-inventory-pin-references.txt").write_text(mirrors)
 assert {x.split(":",1)[0] for x in mirrors.splitlines()}=={corpus},mirrors
 run("01-refresh-inventory",["python3","scripts/refresh_distributed_source_inventory.py"])
 after=(root/inventory).read_bytes();assert sha(after)==review["after_sha256"]
 newblob=git("hash-object",inventory).decode().strip()
 assert c_before.count(oldblob.encode())==1
 c_after=c_before.replace(oldblob.encode(),newblob.encode())
 (root/corpus).write_bytes(c_after)
 cn=json.loads(c_after)
 expected=dict(cm["pinned_blobs"]);expected[inventory]=newblob
 assert cn["pinned_blobs"]==expected
 assert {k:v for k,v in cn.items() if k!="pinned_blobs"}=={k:v for k,v in cm.items() if k!="pinned_blobs"}
 plan=root/planrel
 plan_before=plan.read_bytes();baseline=git("show",c6+":"+planrel)
 assert plan_before==baseline+("\n\n"+oldparagraph+"\n").encode()
 plan_after=baseline+("\n\n"+newparagraph+"\n").encode();plan.write_bytes(plan_after)
 repair={"schema":"TRNM-W1-C7-INVENTORY-EXACT-PIN-REPAIR1","inventory_path":inventory,"inventory_before_sha256":sha(before),"inventory_after_sha256":sha(after),"inventory_before_blob":oldblob,"inventory_after_blob":newblob,"added_inventory_files":review["added"],"removed_inventory_files":[],"corpus_before_sha256":sha(c_before),"corpus_after_sha256":sha(c_after),"existing_pin_updates":{inventory:{"old":oldblob,"new":newblob}},"additional_existing_pin_mirrors":0,"pin_count":len(cn["pinned_blobs"]),"required_count":len(cn["required_paths"]),"all_other_corpus_fields_unchanged":True,"plan_prior_c6_bytes_preserved":True,"final_plan_appended_paragraphs":1,"guard_or_event_context_changed":False}
 dump(out/"exact-repair.json",repair)
 checks=[
  ("02-source-inventory",["python3","scripts/refresh_distributed_source_inventory.py","--check"]),
  ("03-pq-source-pins",["python3","scripts/ci/check_pq_research_integration.py"]),
  ("04-ci-contract",["python3","scripts/ci/check_ci_contract.py"]),
  ("05-format",["cargo","+1.95.0","fmt","--manifest-path","trillionnium/Cargo.toml","--all","--","--check"]),
  ("06-pq-rejection-controls",["python3","scripts/ci/test_pq_research_integration.py","-v"]),
  ("07-w1-ci-contract-controls",["python3","scripts/ci/test_ci_contract.py","W1PostwinLaneTests","-v"]),
  ("08-diff-check",["git","diff","--check"]),
 ]
 for name,argv in checks:run(name,argv,required=False)
 run("09-source-c6-status",["git","status","--porcelain","--untracked-files=all"],source)
 assert (out/"09-source-c6-status.stdout").read_bytes()==b""
 expected_paths={".github/workflows/pon-history-stage-diagnostic.yml","scripts/ci/run_history_diagnostic.py","scripts/ci/test_history_stage_diagnostic.py","trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs","scripts/ci/run_from_zero_host.py",corpus,inventory,planrel}
 assert set(git("diff","--name-only",c6).decode().splitlines())==expected_paths
 assert not git("ls-files","--others","--exclude-standard")
 (out/"candidate-full-diff.patch").write_bytes(git("diff","--binary",c6))
 (out/"candidate-diff-stat.txt").write_bytes(git("diff","--stat",c6))
 complete=all(x["exit_code"]==0 and not x["timed_out"] for x in rows)
finally:
 result={"schema":"TRNM-W1-C7-PRECOMMIT-REPAIR-CHECKS1","complete":complete,"source_parent_c6":c6,"merge_parent_base96":base,"worktree":str(root),"commands":rows,"original_failed_precommit_manifest_sha256":sha((parentout/"precommit-checks-01/manifest.json").read_bytes()),"postcommit_qualification":False,"history_ignored_workload_executions":0,"full_proof_generations":0,"new_operations":0,"ci_reruns":0,"guard_or_event_context_changed":False,"committed":False,"pushed":False}
 dump(out/"manifest.json",result)
 print(json.dumps({"complete":complete,"out":str(out),"manifest_sha256":sha((out/"manifest.json").read_bytes()),"commands":len(rows)}),flush=True)
assert complete,"repair gates failed; preserve all outputs before any decision"


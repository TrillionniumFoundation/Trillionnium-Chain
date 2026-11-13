from pathlib import Path
import hashlib,importlib.util,json,re,subprocess
repo=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
out=Path("/home/qian-qi/work/chain-w1-base91-impact-20261108-ec265b-01")
c7="40a3a45d6b8afc5c4706c5235fec47634f4aabbe";base91="91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c"
helper=repo/"scripts/ci/verify_ci_source.py";b=helper.read_bytes()
assert hashlib.sha256(b).hexdigest()=="0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946"
spec=importlib.util.spec_from_file_location("exact_canonical_review",helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
tree=m._canonical_merge_tree(repo,base91,c7)
assert tree=="e8550e15374ce6a0cc60f435ccd4a0c401741930"
def git(*args):return subprocess.check_output(["git","--no-replace-objects",*args],cwd=repo)
rel="config/pon/pq-cross-branch-corpus-v1.json"
old=json.loads(git("show",c7+":"+rel));new=json.loads(git("show",tree+":"+rel))
assert set(old)==set(new)
assert {k:v for k,v in old.items() if k!="pinned_blobs"}=={k:v for k,v in new.items() if k!="pinned_blobs"}
assert set(old["pinned_blobs"])==set(new["pinned_blobs"])
diff={p:{"old":v,"new":new["pinned_blobs"][p]} for p,v in old["pinned_blobs"].items() if v!=new["pinned_blobs"][p]}
expected={"scripts/ci/test_history_stage_diagnostic.py","trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs"}
assert set(diff)==expected
for p in expected:assert diff[p]["new"]==git("rev-parse",base91+":"+p).decode().strip()==git("rev-parse",tree+":"+p).decode().strip()
inventory="trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs"
assert new["pinned_blobs"][inventory]=="c4fd4e40d80c2a2d0387c23432c56c57ca3fe135"
selected={}
for p in ("scripts/ci/run_history_diagnostic.py","scripts/ci/run_history_native.py"):
 text=(repo/p).read_text()
 selected[p]={"sha256":hashlib.sha256(text.encode()).hexdigest(),"lines":[f"{i+1}:{line}" for i,line in enumerate(text.splitlines()) if re.search(r"test_source|source.json|SOURCE\s*=|SOURCES|source_hash|validate_preparation|validate_summary|ancestry_long_sync",line)]}
assert git("rev-parse","HEAD").decode().strip()==c7
assert git("rev-parse","HEAD^{tree}").decode().strip()=="4b25e3194a0682adff40bb476f2e7c0a395639fe"
assert not git("status","--porcelain","--untracked-files=all")
result={"schema":"TRNM-W1-C7-BASE91-ISOLATED-CANONICAL-REVIEW1","source_commit":c7,"base91":base91,"helper_sha256":hashlib.sha256(b).hexdigest(),"isolated_canonical_merge_tree":tree,"matches_prior_raw_merge_tree":True,"source_worktree_clean_unchanged":True,"actual_merge_performed":False,"pin_count":len(new["pinned_blobs"]),"required_count":len(new["required_paths"]),"only_changed_pins":diff,"all_other_corpus_fields_and_required_order_preserved":True,"c7_generated_inventory_pin_preserved":True,"reader_source_context":selected,"tests_executed":0,"new_operations":0}
raw=(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
(out/"isolated-canonical-review.json").write_bytes(raw)
print(json.dumps({"sha256":hashlib.sha256(raw).hexdigest(),"result":result},ensure_ascii=False,sort_keys=True),flush=True)

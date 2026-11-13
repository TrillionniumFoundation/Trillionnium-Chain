from pathlib import Path
import difflib,hashlib,importlib.util,json,re
r=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
o=Path("/home/qian-qi/work/chain-w1-base96-adversarial-integration-20261108-ec265b-02/inventory-review-01")
o.mkdir()
rel="trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs"
spec=importlib.util.spec_from_file_location("review_inventory",r/"scripts/refresh_distributed_source_inventory.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
before=(r/rel).read_text();after=m.render()
diff="".join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile=rel,tofile=rel))
(o/"generated-inventory.diff").write_text(diff)
extract=lambda s:set(re.findall(r'^        "([^"]+)",$',s,re.M))
old,new=extract(before),extract(after)
c=json.loads((r/"config/pon/pq-cross-branch-corpus-v1.json").read_text())
result={"schema":"TRNM-W1-C7-INVENTORY-MINIMAL-REPAIR-REVIEW1","before_sha256":hashlib.sha256(before.encode()).hexdigest(),"after_sha256":hashlib.sha256(after.encode()).hexdigest(),"before_files":len(old),"after_files":len(new),"added":sorted(new-old),"removed":sorted(old-new),"corpus_pin":c["pinned_blobs"].get(rel),"required":rel in c["required_paths"],"diff":diff,"source_modified":False}
(o/"summary.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
assert new-old=={"trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs"} and not old-new
print(json.dumps(result,sort_keys=True),flush=True)


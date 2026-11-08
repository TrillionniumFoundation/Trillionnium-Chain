from pathlib import Path
import json,hashlib
out=Path("/home/qian-qi/work/chain-w1-base96-impact-20261108-ec265b-01")
a=(out/"base-narrow-diff.stdout").read_bytes();b=(out/"merged-vs-C6-diff.stdout").read_bytes()
selected=[]
for block in a.decode("utf-8").split("diff --git "):
 if block.startswith("a/scripts/ci/run_from_zero_host.py ") or block.startswith("a/config/pon/pq-cross-branch-corpus-v1.json "):
  selected.append("diff --git "+block)
new={line.split("\t",1)[1] for line in (out/"base-name-status.stdout").read_text().splitlines()}
c6={line.split("\t",1)[1] for line in (out/"c6-own-name-status.stdout").read_text().splitlines()}
print(json.dumps({"selected_hunks":selected,"overlapping_changed_paths":sorted(new&c6),"merged_delta_name_status":(out/"merged-vs-C6-name-status.stdout").read_text(),"base_patch_sha256":hashlib.sha256(a).hexdigest(),"merged_patch_sha256":hashlib.sha256(b).hexdigest(),"patch_bytes_equal":a==b}))

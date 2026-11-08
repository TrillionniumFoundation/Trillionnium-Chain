from pathlib import Path
import hashlib,importlib.util,json,re,subprocess
repo=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
out=Path("/home/qian-qi/work/chain-w1-base91-impact-20261108-ec265b-01")
c7="40a3a45d6b8afc5c4706c5235fec47634f4aabbe";merged="e8550e15374ce6a0cc60f435ccd4a0c401741930"
inventory="trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs"
history="trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs"
generator="scripts/refresh_distributed_source_inventory.py"
def git(*args):return subprocess.check_output(["git","--no-replace-objects",*args],cwd=repo)
def sha(b):return hashlib.sha256(b).hexdigest()
oldpaths=git("ls-tree","-r","--name-only","-z",c7);newpaths=git("ls-tree","-r","--name-only","-z",merged)
assert oldpaths==newpaths
oldinv=git("show",c7+":"+inventory);newinv=git("show",merged+":"+inventory);assert oldinv==newinv
oldgen=git("show",c7+":"+generator);newgen=git("show",merged+":"+generator);assert oldgen==newgen
oldhist=git("show",c7+":"+history);newhist=git("show",merged+":"+history)
assert oldhist!=newhist and b'include_bytes!("history_stage_diagnostic.rs")' in newhist and b'include_bytes!("ancestry_long_sync.rs")' in oldhist
assert newhist==git("show","91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c:"+history)
assert oldinv.decode().count('"'+history+'"')==1
lines=oldinv.decode().splitlines();i=next(i for i,l in enumerate(lines) if l.strip()=='"'+history+'",')
entry="\n".join(lines[i-1:i+6])+"\n"
# The exact existing renderer reads path names and regular-file types only.
assert (repo/generator).read_bytes()==oldgen
spec=importlib.util.spec_from_file_location("readonly_existing_inventory_renderer",repo/generator)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
rendered=m.render().encode()
assert rendered==oldinv
corpus=json.loads(git("show",merged+":config/pon/pq-cross-branch-corpus-v1.json"))
blob=git("rev-parse",merged+":"+inventory).decode().strip()
assert corpus["pinned_blobs"][inventory]==blob=="c4fd4e40d80c2a2d0387c23432c56c57ca3fe135"
assert git("rev-parse","HEAD").decode().strip()==c7 and not git("status","--porcelain","--untracked-files=all")
result={"schema":"TRNM-W1-C7-BASE91-INVENTORY-STATIC-CONSISTENCY1","source_commit":c7,"hypothetical_merge_tree":merged,"same_all_tracked_path_set":True,"tracked_paths":len([x for x in oldpaths.split(b"\0") if x]),"path_set_sha256":sha(oldpaths),"generator_same_bytes":True,"generator_sha256":sha(oldgen),"inventory_same_bytes":True,"inventory_sha256":sha(oldinv),"inventory_blob":blob,"inventory_registered_file_count":len(re.findall(r'^        \"[^\"]+\",$',oldinv.decode(),re.M)),"history_registration":entry,"history_blob_c7":git("rev-parse",c7+":"+history).decode().strip(),"history_blob_base91_and_hypothetical_tree":git("rev-parse",merged+":"+history).decode().strip(),"c7_existing_readonly_renderer_matches_inventory":True,"new_tree_check_command_executed":False,"new_tree_worktree_created":False,"new_tree_compiled":False,"extra_generated_inventory_registration_fix_needed_for_this_delta":False,"reason":"The generated Rust file registers include_bytes paths; it stores neither a fixed digest nor literal old History bytes. Changed contents at the same registered path are incorporated at compilation. Unchanged path set and generator leave the generated registration text unchanged.","limits":["Static consistency does not imply complete source qualification or a completed gate on a new worktree.","A future integrated source must build/bind its own ELF and run exact source guards; the old C7 binary cannot borrow the new History bytes or commit identity.","C7 History local scope remains compile/list only; no 4105-block workload execution or qualification is asserted."],"tests_executed":0,"source_mutations":0,"actual_merge_performed":False}
raw=(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
(out/"inventory-static-consistency.json").write_bytes(raw)
print(json.dumps({"sha256":sha(raw),"result":result},ensure_ascii=False,sort_keys=True),flush=True)

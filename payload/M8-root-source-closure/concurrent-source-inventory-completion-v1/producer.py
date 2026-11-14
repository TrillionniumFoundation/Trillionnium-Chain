import difflib,hashlib,json,os,pathlib,re,sys,types
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
raw=(root/"root_merge_helpers.py").read_bytes()
assert hashlib.sha256(raw).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(raw,str(root/"root_merge_helpers.py"),"exec"),h.__dict__)
h.setup("concurrent-source-inventory-completion-v1")
(h.ev/"producer.py").write_text(sys.argv[1]);notes=json.loads(sys.argv[2]);(h.ev/"document-appends.json").write_text(json.dumps(notes,indent=2)+"\n")
h.env.update(GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONOPTIMIZE="0")
old="c3ae6e71d7b0da4b43b0c7aa6df34aeabf838f47";oldtree="9f24fd19d725f96e8ac42060054f1f8d4f3e57e9"
report="docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md"
record={"schema":"trnm-root-concurrent-source-inventory-completion-v1","old_head":old,"status":"HOLD","steps":h.steps,"errors":[],"remote_mutated":False,"tests_or_final_gates_executed":False}
def save():(h.ev/"summary.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.git("rev-parse","HEAD").decode().strip()==old and h.git("rev-parse","HEAD^{tree}").decode().strip()==oldtree
 assert h.run("source-before-status",["git","status","--porcelain","--untracked-files=all"],timeout=60).stdout==b""
 h.run("preflight-before-edit",["bash","scripts/project-preflight.sh","--audit"],timeout=900)
 script=h.src/"scripts/refresh_distributed_source_inventory.py";code=script.read_bytes()
 assert hashlib.sha256(code).hexdigest()=="6b2a785999e1117a95bbfd504053314f4a08c5cfb56d5e5ad780190163d277d9"
 module={"__name__":"review_only","__file__":str(script)};exec(compile(code,str(script),"exec"),module)
 before=(h.src/h.inventory).read_text();assert before.encode()==h.show(old,h.inventory)
 generated=module["render"]()
 original_paths=re.findall(r'^        "([^"]+)",$',before,re.M);new_paths=re.findall(r'^        "([^"]+)",$',generated,re.M)
 added=sorted(set(new_paths)-set(original_paths))
 assert added==["config/pon/pq128-lifetime-composition-current-v3.json","config/pon/pq128-source-correspondence-current-v2.json"]
 assert set(original_paths)<=set(new_paths) and len(original_paths)==len(set(original_paths)) and len(new_paths)==len(original_paths)+2
 opcodes=[op for op in difflib.SequenceMatcher(a=before.splitlines(True),b=generated.splitlines(True),autojunk=False).get_opcodes() if op[0]!="equal"]
 assert len(opcodes)==1 and opcodes[0][0]=="insert" and opcodes[0][4]-opcodes[0][3]==14
 patch="".join(difflib.unified_diff(before.splitlines(True),generated.splitlines(True),fromfile=h.inventory+" before",tofile=h.inventory+" after"))
 (h.ev/"exact-inventory.patch").write_text(patch)
 record.update(added_paths=added,original_inventory_paths=len(original_paths),new_inventory_paths=len(new_paths),original_generator_sha256=hashlib.sha256(code).hexdigest())
 save()
 h.run("original-inventory-generator",["/opt/homebrew/bin/python3","-B","scripts/refresh_distributed_source_inventory.py"],timeout=120)
 assert (h.src/h.inventory).read_text()==generated
 with (h.src/report).open("a") as f:f.write(notes["report"])
 with (h.src/h.plan).open("a") as f:f.write(notes["plan"])
 h.refresh_pins({h.inventory,h.plan,report})
 h.run("stage-bounded-completion",["git","add","--",h.inventory,h.manifest,h.plan,report],timeout=60)
 paths=set(h.git("diff","--cached","--name-only").decode().splitlines())
 assert paths=={h.inventory,h.manifest,h.plan,report}
 h.run("staged-diff-check",["git","diff","--cached","--check"],timeout=60)
 h.run("preflight-before-commit",["bash","scripts/project-preflight.sh","--staged"],timeout=900)
 h.run("normal-source-inventory-commit",["git","commit","-m","Include reconciled current PQ configs in native source inventory"],timeout=300)
 head=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip()
 assert h.git("show","-s","--format=%P",head).decode().strip()==old
 assert h.run("source-after-status",["git","status","--porcelain","--untracked-files=all"],timeout=60).stdout==b""
 h.run("preflight-after-commit",["bash","scripts/project-preflight.sh","--audit"],timeout=900)
 record.update(status="EXACT_TWO_CONFIG_INVENTORY_COMPLETION_COMMITTED",head=head,tree=tree,parent=old,source_clean_after=True)
except Exception as e:
 record["errors"].append(type(e).__name__+": "+str(e))
finally:save()
raw=(h.ev/"summary.json").read_bytes()
print(json.dumps({"status":record["status"],"head":record.get("head"),"tree":record.get("tree"),"errors":record["errors"],"summary":str(h.ev/"summary.json"),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}),flush=True)
raise SystemExit(0 if not record["errors"] else 1)

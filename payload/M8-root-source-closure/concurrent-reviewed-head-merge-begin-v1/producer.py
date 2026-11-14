import hashlib,json,os,pathlib,sys,types
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
helper=root/"root_merge_helpers.py"; raw=helper.read_bytes()
assert hashlib.sha256(raw).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(raw,str(helper),"exec"),h.__dict__)
h.setup("concurrent-reviewed-head-merge-begin-v1")
(h.ev/"producer.py").write_text(sys.argv[1])
for key in ("GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_INDEX_FILE","GIT_OBJECT_DIRECTORY","GIT_ALTERNATE_OBJECT_DIRECTORIES","GIT_CONFIG_COUNT","GIT_CONFIG_PARAMETERS"):
 h.env.pop(key,None)
h.env.update(GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",GH_PROMPT_DISABLED="1",PYTHONOPTIMIZE="0")
old="2a62061177852dc3ebd200fa8d7c66c661a119a1"; target="5a4b7fe8de1adce803184f262fd9f704ead1930c"; base="dc42ce4df5cff79cc61c5addbaf01074b56b06ca"
record={"schema":"trnm-root-concurrent-reviewed-head-merge-begin-v1","status":"HOLD","old_head":old,"reviewed_remote_head":target,"sole_merge_base":base,"commit_created":False,"remote_mutated":False,"steps":h.steps,"errors":[]}
def save(): (h.ev/"summary.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.run("source-head",["git","--no-replace-objects","rev-parse","HEAD"],timeout=60).stdout.decode().strip()==old
 assert h.run("source-tree",["git","--no-replace-objects","rev-parse","HEAD^{tree}"],timeout=60).stdout.decode().strip()=="f8d170ff75990e879e93888a95e5408f36b36f6c"
 assert h.run("source-status",["git","status","--porcelain","--untracked-files=all","--ignore-submodules=none"],timeout=60).stdout==b""
 assert h.run("source-branch",["git","symbolic-ref","--short","HEAD"],timeout=60).stdout.decode().strip()=="fix/chain-audit-final-20261114"
 assert h.run("sole-merge-base",["git","--no-replace-objects","merge-base","--all",old,target],timeout=60).stdout.decode().splitlines()==[base]
 h.run("preflight-before-source-merge",["bash","scripts/project-preflight.sh","--audit"],timeout=900)
 q=h.run("normal-merge-no-commit",["git","merge","--no-ff","--no-commit",target],allowed=(0,1),timeout=180)
 assert h.git("rev-parse","HEAD").decode().strip()==old
 assert h.git("rev-parse","MERGE_HEAD").decode().strip()==target
 unmerged=h.run("unmerged-paths",["git","diff","--no-ext-diff","--no-textconv","--name-only","--diff-filter=U"],timeout=60).stdout.decode().splitlines()
 record.update(status="MERGE_STARTED_AWAITING_REVIEWED_RESOLUTION",merge_exit=q.returncode,unmerged_paths=unmerged)
 record["changed_paths"]=h.run("merge-status",["git","status","--porcelain","--untracked-files=all","--ignore-submodules=none"],timeout=60).stdout.decode().splitlines()
except Exception as e:
 record["errors"].append(type(e).__name__+": "+str(e))
finally:
 save()
print(json.dumps({"status":record["status"],"errors":record["errors"],"unmerged_paths":record.get("unmerged_paths"),"summary":str(h.ev/"summary.json")}),flush=True)
raise SystemExit(0 if not record["errors"] else 1)

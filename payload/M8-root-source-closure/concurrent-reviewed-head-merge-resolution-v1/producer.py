import hashlib,json,os,pathlib,re,stat,sys,types
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
helper=root/"root_merge_helpers.py"; helper_raw=helper.read_bytes()
assert hashlib.sha256(helper_raw).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(helper_raw,str(helper),"exec"),h.__dict__)
h.setup("concurrent-reviewed-head-merge-resolution-v1")
(h.ev/"producer.py").write_text(sys.argv[1])
appends=json.loads(sys.argv[2]);(h.ev/"root-document-appends.json").write_text(json.dumps(appends,indent=2,ensure_ascii=False)+"\n")
for key in ("GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_INDEX_FILE","GIT_OBJECT_DIRECTORY","GIT_ALTERNATE_OBJECT_DIRECTORIES","GIT_CONFIG_COUNT","GIT_CONFIG_PARAMETERS"):
 h.env.pop(key,None)
h.env.update(GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",GH_PROMPT_DISABLED="1",PYTHONOPTIMIZE="0")
old="2a62061177852dc3ebd200fa8d7c66c661a119a1"; target="5a4b7fe8de1adce803184f262fd9f704ead1930c"; base="dc42ce4df5cff79cc61c5addbaf01074b56b06ca"
proposal=pathlib.Path("/private/tmp/chain-ci-new-candidate-5a4b7fe8-review-20261114-v1")
manifest_path=proposal/"final-review-v1/complete-selected-53-files.json"
report_path="docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def oid(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def fingerprint(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path):
 path=pathlib.Path(path);a=path.lstat()
 assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=8*1024*1024
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  assert fingerprint(os.fstat(f.fileno()))==fingerprint(a)
  raw=f.read(8*1024*1024+1)
  assert fingerprint(os.fstat(f.fileno()))==fingerprint(a)
 assert fingerprint(path.lstat())==fingerprint(a) and len(raw)==a.st_size
 return raw
def safe_relative(path):
 p=pathlib.PurePosixPath(path)
 assert path and not p.is_absolute() and str(p)==path and all(x not in ("",".","..",".git") for x in p.parts)
 return p
def write_selected(path,raw):
 p=safe_relative(path);dest=h.src/path
 parent=h.src
 for part in p.parts[:-1]:
  parent=parent/part
  if not parent.exists():parent.mkdir(mode=0o755)
  s=parent.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
 if dest.exists():
  a=dest.lstat();assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
  fd=os.open(dest,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  assert fingerprint(os.fstat(fd))==fingerprint(a)
  os.ftruncate(fd,0)
 else:fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
 with os.fdopen(fd,"wb") as f:
  f.write(raw);f.flush();os.fsync(f.fileno())
 assert read(dest)==raw
record={"schema":"trnm-root-reviewed-concurrent-merge-resolution-v1","status":"HOLD","expected_parents":[old,target],"common_base":base,"proposal_manifest":{"path":str(manifest_path),"bytes":53698,"sha256":"7cd35f9aa4f4cc11ba0b3dc10eb19148c1d5a087d464101573188afa9edb7d95"},"steps":h.steps,"errors":[],"commit_created":False,"remote_mutated":False,"final_gates_run":False}
def save():(h.ev/"summary.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.run("expected-head",["git","rev-parse","HEAD"],timeout=60).stdout.decode().strip()==old
 assert h.run("expected-merge-head",["git","rev-parse","MERGE_HEAD"],timeout=60).stdout.decode().strip()==target
 status=h.run("pending-status-before",["git","status","--porcelain","--untracked-files=all","--ignore-submodules=none"],timeout=60).stdout
 assert status==read(root/"concurrent-reviewed-head-merge-begin-v1/merge-status.log")
 raw=read(manifest_path);assert len(raw)==53698 and sha(raw)==record["proposal_manifest"]["sha256"]
 m=json.loads(raw);assert m["schema"]=="trnm-fixed-concurrent-merge-file-selection-v1" and m["base_head"]==old and m["merge_head"]==target and m["application_is_not_executed"] is True
 rows=m["files"];assert len(rows)==53 and len({r["path"] for r in rows})==53
 original_report=read(h.src/report_path);assert sha(original_report)=="b3765e2b9fec9b10872716870d55754935308e79e6bdb5251c5d3d3963fdc126"
 selected={}
 for row in rows:
  safe_relative(row["path"]);assert row["mode"]=="100644"
  path=pathlib.Path(row["payload_path"]);assert path.is_relative_to(proposal) and path.resolve(strict=True)==path
  data=read(path);assert (len(data),sha(data),oid(data))==(row["bytes"],row["sha256"],row["oid"])
  selected[row["path"]]=data
 assert sum(map(len,selected.values()))==3971370
 n_tree=h.git("ls-tree","-rz","--full-tree",target,"--",*sorted(selected))
 (h.ev/"N-selected-paths.raw").write_bytes(n_tree)
 nmap={}
 for item in n_tree.split(b"\0"):
  if not item:continue
  meta,name=item.split(b"\t",1);mode,kind,object_id=meta.decode().split()
  assert kind=="blob";nmap[name.decode()]=(mode,object_id)
 assert set(nmap)==set(selected)
 for row in rows:
  assert nmap[row["path"]]==("100644",row["N_input"]["oid"])
  inp=read(row["N_input"]["path"])
  assert (len(inp),sha(inp),oid(inp))==(row["N_input"]["bytes"],row["N_input"]["sha256"],row["N_input"]["oid"])
 delta=set(h.git("diff","--no-ext-diff","--no-textconv","--name-only","-z",base,target).decode().strip("\0").split("\0"))
 assert len(delta)==49 and delta<=set(selected)
 (h.ev/"reviewed-selection-manifest.json").write_bytes(raw)
 record["all_53_inputs_preverified"]=True;record["concurrent_49_paths_covered"]=True;save()
 h.run("preflight-before-resolution",["bash","scripts/project-preflight.sh","--audit"],timeout=900)
 for path,data in selected.items():write_selected(path,data)
 record["applied_53_selected_files"]=True;save()
 # Root additions record actual M6 observations; no successor result is invented.
 text=original_report.decode()
 old_heading="The selected runtime integration and current reader bindings are combined at\n"
 new_heading="The initial runtime integration and reader-binding checkpoint was\n"
 assert text.count(old_heading)==1
 write_selected(report_path,(text.replace(old_heading,new_heading,1)+appends["report"]).encode())
 write_selected(h.plan,read(h.src/h.plan)+appends["plan"].encode())
 prior_manifest=json.loads(selected[h.manifest])
 h.refresh_pins(set(selected)|{h.plan,report_path})
 current_manifest=json.loads(read(h.src/h.manifest))
 assert set(current_manifest["required_paths"])==set(prior_manifest["required_paths"]) and len(current_manifest["required_paths"])==2510
 assert set(current_manifest["pinned_blobs"])==set(prior_manifest["pinned_blobs"]) and len(current_manifest["pinned_blobs"])==2606
 changed_pins=[p for p in prior_manifest["pinned_blobs"] if prior_manifest["pinned_blobs"][p]!=current_manifest["pinned_blobs"][p]]
 assert set(changed_pins)<={h.plan,report_path}
 for row in rows:
  if row["path"] not in (h.plan,h.manifest):assert read(h.src/row["path"])==selected[row["path"]]
 for path in set(selected)|{h.plan,report_path}:
  if path in current_manifest["pinned_blobs"]:assert current_manifest["pinned_blobs"][path]==h.blob(path)
 record["root_appended_paths"]=[h.plan,report_path];record["final_pin_updates_after_appends"]=changed_pins
 h.run("stage-reviewed-selection",["git","add","--",*sorted(set(selected)|{report_path})],timeout=120)
 assert h.run("all-conflicts-resolved",["git","ls-files","--unmerged"],timeout=60).stdout==b""
 changed=h.git("diff","--cached","--name-only","-z",old).decode().strip("\0").split("\0")
 expected={row["path"] for row in rows if h.show(old,row["path"])!=selected[row["path"]]} if False else set()
 for row in rows:
  q=h.run("old-path-"+str(len(expected))+"-"+str(rows.index(row)),["git","cat-file","-e",old+":"+row["path"]],allowed=(0,128),timeout=60)
  old_raw=h.show(old,row["path"]) if q.returncode==0 else None
  if old_raw!=selected[row["path"]]:expected.add(row["path"])
 assert len(expected)==41
 assert set(changed)==expected|{report_path} and len(changed)==42
 record["changed_paths"]=sorted(changed)
 h.run("staged-diff-check",["git","diff","--cached","--check"],timeout=60)
 h.run("preflight-before-commit",["bash","scripts/project-preflight.sh","--staged"],timeout=900)
 record["staged_tree"]=h.git("write-tree").decode().strip();save()
 h.run("normal-reviewed-merge-commit",["git","commit","-m","Merge reviewed concurrent audit corrections and preserve source guards"],timeout=300)
 head=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip()
 record.update(commit_created=True,head=head,tree=tree);save()
 parents=h.git("show","-s","--format=%P",head).decode().strip().split()
 assert parents==[old,target] and tree==record["staged_tree"]
 assert h.run("source-status-after",["git","status","--porcelain","--untracked-files=all","--ignore-submodules=none"],timeout=60).stdout==b""
 h.run("preflight-after-commit",["bash","scripts/project-preflight.sh","--audit"],timeout=900)
 record.update(status="REVIEWED_CONCURRENT_MERGE_COMMITTED",parents=parents,source_clean_after=True)
except Exception as e:
 record["errors"].append(type(e).__name__+": "+str(e))
finally:
 save()
raw=read(h.ev/"summary.json")
print(json.dumps({"status":record["status"],"head":record.get("head"),"tree":record.get("tree"),"errors":record["errors"],"summary":str(h.ev/"summary.json"),"bytes":len(raw),"sha256":sha(raw)}),flush=True)
raise SystemExit(0 if not record["errors"] else 1)

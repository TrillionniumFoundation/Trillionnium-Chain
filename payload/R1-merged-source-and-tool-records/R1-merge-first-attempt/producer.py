import hashlib,json,pathlib,sys,types
assert not sys.flags.optimize
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");p=R/"root_merge_helpers.py";b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd";h=types.ModuleType("root_merge_helpers");exec(compile(b,str(p),"exec"),h.__dict__);h.setup("merge-concurrent-096c6b-into-1e54c4-v1");(h.ev/"producer.py").write_text(sys.argv[1]);inputs=json.loads(sys.argv[2]);(h.ev/"reviewed-inputs.json").write_text(json.dumps(inputs,indent=2,sort_keys=True)+"\n");h.env.update(GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONOPTIMIZE="0")
base=inputs["base"];ours=inputs["ours"];theirs=inputs["theirs"];assert (base,ours,theirs)==("5a4b7fe8de1adce803184f262fd9f704ead1930c","1e54c4ff66a92827c83bea8715f59f6b299e98cf","096c6b5f9b952c49389fd975515744074ba61317")
take=[".github/workflows/pon-w1-work-security.yml","scripts/ci/test_w1_v2_controls_gate.py","scripts/ci/w1_v2_controls_gate.py"]
keep=["config/pon/hash-use-contract-v1.json","scripts/ci/hash_use_contract.py",h.inventory]
report="docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md";expected=sorted(take+[h.manifest,h.plan,report]);s={"schema":"trnm-reviewed-concurrent-CI-normal-merge-v1","parents":[ours,theirs],"base":base,"steps":h.steps,"status":"HOLD","errors":[],"remote_mutation":False,"hosted_qualification":False}
def save():(h.ev/"summary.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.git("rev-parse","HEAD").decode().strip()==ours
 assert h.git("symbolic-ref","--short","HEAD").decode().strip()=="fix/chain-audit-final-20261114"
 assert h.run("status-before",["git","status","--porcelain=v1","--untracked-files=all"]).stdout==b""
 h.run("preflight-before-merge",["bash","scripts/project-preflight.sh","--audit"])
 assert h.git("merge-base","--all",ours,theirs).decode().splitlines()==[base]
 assert h.git("show","-s","--format=%P",theirs).decode().strip()==base
 for row in inputs["files"]:
  for v in row["versions"]:
   raw=h.git("show",v["commit"]+":"+row["path"]);assert len(raw)==v["bytes"] and hashlib.sha256(raw).hexdigest()==v["sha256"]
 patch=h.run("incoming-reviewed-diff",["git","diff","--no-ext-diff","--no-textconv","--no-renames",base,theirs]).stdout
 assert len(patch)==14850 and hashlib.sha256(patch).hexdigest()=="d469d1091d59939487cf37c3b06a3bd96a906b66135a9cc4a6d4feb8983a0896"
 h.run("normal-no-ff-merge",["git","merge","--no-ff","--no-commit",theirs],allowed=(0,1),timeout=120)
 assert h.git("rev-parse","MERGE_HEAD").decode().strip()==theirs
 unmerged=h.git("diff","--name-only","--diff-filter=U").decode().splitlines();assert set(unmerged)<={h.manifest,*keep}
 for path in take:(h.src/path).write_bytes(h.show(theirs,path))
 for path in keep:(h.src/path).write_bytes(h.show(ours,path))
 original_manifest=h.show(ours,h.manifest);(h.src/h.manifest).write_bytes(original_manifest);before=json.loads(original_manifest)
 for path,key in ((h.plan,"plan_append"),(report,"report_append")):
  original=h.show(ours,path);assert (h.src/path).read_bytes()==original
  marker=b"### 2026-11-14: Reconcile the later 096c6b CI increment";assert marker not in original
  (h.src/path).write_bytes(original+inputs[key].encode())
 h.refresh_pins(take+[h.plan]);after=json.loads((h.src/h.manifest).read_bytes())
 assert len(after["pinned_blobs"])==2606 and len(after["required_paths"])==2510
 assert {k:v for k,v in before.items()if k!="pinned_blobs"}=={k:v for k,v in after.items()if k!="pinned_blobs"}
 assert set(before["pinned_blobs"])==set(after["pinned_blobs"])
 changed_pins=[k for k in before["pinned_blobs"]if before["pinned_blobs"][k]!=after["pinned_blobs"][k]];assert set(changed_pins)==set(take+[h.plan])
 for path in keep:assert (h.src/path).read_bytes()==h.show(ours,path)
 for path in take:assert (h.src/path).read_bytes()==h.show(theirs,path)
 for path in ("config/pon/pq128-lifetime-budget-v1.json","config/pon/pq128-source-lock-v1.json","config/pon/pq128-lifetime-composition-v2.json","config/pon/pq128-source-correspondence-current-v2.json","config/pon/pq128-lifetime-composition-current-v3.json","trillionnium/crates/trnm-pon-node/src/store.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs"):
  assert (h.src/path).read_bytes()==h.show(ours,path)
 h.run("stage-exact-merge-resolution",["git","add","--",*sorted(set(take+keep+[h.manifest,h.plan,report]))])
 assert h.git("diff","--cached","--name-only").decode().splitlines()==expected and not h.git("diff","--name-only")
 assert not h.git("ls-files","-u")
 h.run("resolved-diff",["git","diff","--cached","--no-ext-diff","--no-textconv"])
 h.run("diff-check",["git","diff","--cached","--check"])
 h.run("preflight-before-controls",["bash","scripts/project-preflight.sh","--audit"])
 h.run("original-w1-v2-controls",["/opt/homebrew/bin/python3","-B","scripts/ci/test_w1_v2_controls_gate.py"],timeout=300)
 h.run("original-repository-check",["/opt/homebrew/bin/python3","-B","scripts/ci/check_repository.py"],timeout=300)
 h.run("original-distributed-inventory-check",["/opt/homebrew/bin/python3","-B","scripts/refresh_distributed_source_inventory.py","--check"],timeout=120)
 h.run("preflight-before-commit",["bash","scripts/project-preflight.sh","--audit"])
 h.run("normal-merge-commit",["git","commit","-m","Reconcile concurrent W1 CI corrections with audited source"])
 head=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip()
 assert h.git("show","-s","--format=%P",head).decode().strip().split()==[ours,theirs]
 assert h.git("diff-tree","--no-commit-id","--name-only","-r",ours,head).decode().splitlines()==expected
 assert h.run("status-after",["git","status","--porcelain=v1","--untracked-files=all"]).stdout==b""
 s.update(status="MERGED_REVIEWED_CONCURRENT_CI",head=head,tree=tree,clean=True,changed_paths=expected,adopted_paths=take,retained_paths=keep,changed_corpus_pins=changed_pins,actual_unmerged_paths_resolved=unmerged)
except BaseException as ex:s["errors"].append(type(ex).__name__+": "+str(ex))
finally:save()
print(json.dumps({k:v for k,v in s.items()if k!="steps"}),flush=True);raise SystemExit(0 if not s["errors"]else 1)

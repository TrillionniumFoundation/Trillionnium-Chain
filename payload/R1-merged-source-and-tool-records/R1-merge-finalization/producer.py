import hashlib,json,pathlib,sys,types
assert not sys.flags.optimize
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
p=R/"root_merge_helpers.py";b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(b,str(p),"exec"),h.__dict__);h.setup("merge-concurrent-096c6b-finalize-v1")
(h.ev/"producer.py").write_text(sys.argv[1]);h.env.update(GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONOPTIMIZE="0")
ours="1e54c4ff66a92827c83bea8715f59f6b299e98cf";theirs="096c6b5f9b952c49389fd975515744074ba61317"
report="docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md"
take=[".github/workflows/pon-w1-work-security.yml","scripts/ci/test_w1_v2_controls_gate.py","scripts/ci/w1_v2_controls_gate.py"]
expected=sorted(take+[h.manifest,h.plan,report])
prior=R/"merge-concurrent-096c6b-into-1e54c4-v1"
s={"schema":"trnm-reviewed-concurrent-CI-normal-merge-finalization-v1","parents":[ours,theirs],"steps":h.steps,"status":"HOLD","errors":[],"remote_mutation":False,"hosted_qualification":False,"prior_attempt_status":"HOLD","original_Mac_controls_result":"Ran 31 tests; failures=1, errors=6","original_Linux_controls_pending":True}
def save():(h.ev/"summary.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n")
save()
try:
 for name,size,digest in [("summary.json",7190,"f2ccd667803191567ef15deaf4dcfd3b6dc5a08f0f1747821bb21711cfbdda6f"),("original-w1-v2-controls.log",13196,"4a54ecfca9da12d73586deca39cb25fe79f0347e4964bfd5e57198269aa221d3"),("resolved-diff.log",12322,"ebf46cf3ea4114dc67c661b0cda0680b334b8bfec8b4f82c3019c2645e70b380")]:
  raw=(prior/name).read_bytes();assert len(raw)==size and hashlib.sha256(raw).hexdigest()==digest
 assert h.git("rev-parse","HEAD").decode().strip()==ours and h.git("rev-parse","MERGE_HEAD").decode().strip()==theirs
 assert h.git("symbolic-ref","--short","HEAD").decode().strip()=="fix/chain-audit-final-20261114"
 assert not h.git("ls-files","-u") and not h.git("diff","--name-only") and not h.git("ls-files","--others","--exclude-standard")
 assert h.git("diff","--cached","--name-only").decode().splitlines()==expected
 before=h.run("resolved-diff-before",["git","diff","--cached","--no-ext-diff","--no-textconv"]).stdout
 assert len(before)==12322 and hashlib.sha256(before).hexdigest()=="ebf46cf3ea4114dc67c661b0cda0680b334b8bfec8b4f82c3019c2645e70b380"
 for path in take:assert (h.src/path).read_bytes()==h.show(theirs,path)
 manifest=json.loads((h.src/h.manifest).read_bytes());assert report not in manifest["pinned_blobs"]
 h.run("preflight-before-report-append",["bash","scripts/project-preflight.sh","--audit"])
 original=(h.src/report).read_bytes();assert original==h.show("",report)
 addition=("\nThe first local merge-validation attempt invoked the unchanged Linux-oriented\n"
 "W1 controls on macOS and stopped with 'Ran 31 tests; failures=1, errors=6'.\n"
 "All six error events report the missing '/proc/sys/kernel/random/boot_id';\n"
 "the cancellation test separately reports '0 != 1'. These are preserved as\n"
 "failures, without inferring that every failure has the same cause. No test\n"
 "or producer is altered to make macOS pass. The normal merge is finalized\n"
 "after its repository and inventory checks; the original Linux lane must\n"
 "validate this merged source separately before publication.\n").encode()
 assert addition not in original;(h.src/report).write_bytes(original+addition)
 h.run("stage-report-append",["git","add","--",report])
 assert h.git("diff","--cached","--name-only").decode().splitlines()==expected and not h.git("diff","--name-only") and not h.git("ls-files","-u")
 h.run("resolved-diff",["git","diff","--cached","--no-ext-diff","--no-textconv"])
 h.run("diff-check",["git","diff","--cached","--check"])
 h.run("preflight-before-repository-checks",["bash","scripts/project-preflight.sh","--audit"])
 h.run("original-repository-check",["/opt/homebrew/bin/python3","-B","scripts/ci/check_repository.py"],timeout=300)
 h.run("original-distributed-inventory-check",["/opt/homebrew/bin/python3","-B","scripts/refresh_distributed_source_inventory.py","--check"],timeout=120)
 h.run("preflight-before-commit",["bash","scripts/project-preflight.sh","--audit"])
 h.run("normal-merge-commit",["git","commit","-m","Reconcile concurrent W1 CI corrections with audited source"])
 head=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip()
 assert h.git("show","-s","--format=%P",head).decode().strip().split()==[ours,theirs]
 assert h.git("diff-tree","--no-commit-id","--name-only","-r",ours,head).decode().splitlines()==expected
 assert h.run("status-after",["git","status","--porcelain=v1","--untracked-files=all"]).stdout==b""
 s.update(status="MERGED_REVIEWED_CONCURRENT_CI",head=head,tree=tree,clean=True,changed_paths=expected,report_appended_bytes=len(addition))
except BaseException as ex:s["errors"].append(type(ex).__name__+": "+str(ex))
finally:save()
print(json.dumps({k:v for k,v in s.items()if k!="steps"}),flush=True)
raise SystemExit(0 if not s["errors"]else 1)

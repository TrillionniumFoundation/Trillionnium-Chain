import hashlib,json,pathlib,re,sys,types
assert not sys.flags.optimize
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");q=R/"root_merge_helpers.py";b=q.read_bytes();assert hashlib.sha256(b).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(b,str(q),"exec"),h.__dict__);h.setup("historical-budget-count-correction-v2");(h.ev/"producer.py").write_text(sys.argv[1]);h.env.update(GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONOPTIMIZE="0")
base="6a8cd55573065ceb50cdb65a7834615f79b521ae";path="docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md";s={"preserved_prewrite_guard_failure":"historical-budget-count-correction-v1/summary.json","schema":"trnm-historical-budget-count-document-correction-v2","parent":base,"status":"HOLD","steps":h.steps,"errors":[],"source_logic_changed":False,"original_failed_observation_preserved":True,"remote_mutation":False}
def save():(h.ev/"summary.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.git("rev-parse","HEAD").decode().strip()==base
 assert h.run("status-before",["git","status","--porcelain=v1","--untracked-files=all"]).stdout==b""
 h.run("preflight-before-edit",["bash","scripts/project-preflight.sh","--audit"])
 log=pathlib.Path("/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1/current-consumer-validation-v1/original-frozen-budget-58.stderr").read_bytes()
 assert len(log)==16485 and hashlib.sha256(log).hexdigest()=="6fc70d6c1b733db71a2a70514f2f07f09daec6e86c7410d6cb337abde2b4b523"
 text=log.decode();assert text.endswith("Ran 58 tests in 0.089s\n\nFAILED (failures=1, errors=4)\n")
 assert sum(x.startswith("test_") and x.endswith(" ... ok") for x in text.splitlines())==54
 assert sum(x.startswith("  test_") and x.endswith(" ... ERROR") for x in text.splitlines())==2
 raw=(h.src/path).read_bytes();assert hashlib.sha256(raw).hexdigest()=="cc44eeae1dc20baecc0a0371494f8f3fe06f6732090e8805756d4b8de3bbeb2d"
 (h.ev/"report.before").write_bytes(raw)
 old=b"  symlink ancestor: 53 passed, one failed and four errored. That failure is\n  preserved. With only a canonical temporary directory selected, unchanged\n"
 new=b"  symlink ancestor: Ran 58 tests; failures=1, errors=4, including two\n  subtest errors in one method. That failure is preserved. With only a\n  canonical temporary directory selected, unchanged\n"
 assert raw.count(old)==1;updated=raw.replace(old,new);(h.src/path).write_bytes(updated);(h.ev/"report.after").write_bytes(updated)
 corpus=json.loads((h.src/h.manifest).read_bytes());assert path not in corpus["pinned_blobs"]
 assert h.git("diff","--name-only").decode().splitlines()==[path]
 h.run("reviewed-diff",["git","diff","--no-ext-diff","--no-textconv"])
 h.run("diff-check",["git","diff","--check"])
 h.run("preflight-before-commit",["bash","scripts/project-preflight.sh","--audit"])
 h.run("stage-exact-report",["git","add","--",path]);assert h.git("diff","--cached","--name-only").decode().splitlines()==[path]
 h.run("normal-document-commit",["git","commit","-m","Correct historical unittest subtest error accounting"])
 head=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip();assert h.git("show","-s","--format=%P",head).decode().strip()==base
 assert h.git("diff-tree","--no-commit-id","--name-only","-r",base,head).decode().splitlines()==[path]
 assert h.run("status-after",["git","status","--porcelain=v1","--untracked-files=all"]).stdout==b""
 s.update(status="COMMITTED_DOCUMENT_CORRECTION",head=head,tree=tree,clean=True,changed_paths=[path],original_log_sha256=hashlib.sha256(log).hexdigest(),top_level_test_methods=58,top_level_ok_lines=54,reported_failures=1,reported_errors=4,subtest_error_lines=2,old_report_sha256=hashlib.sha256(raw).hexdigest(),new_report_bytes=len(updated),new_report_sha256=hashlib.sha256(updated).hexdigest())
except BaseException as ex:s["errors"].append(type(ex).__name__+": "+str(ex))
finally:save()
print(json.dumps({k:v for k,v in s.items() if k!="steps"}),flush=True);raise SystemExit(0 if not s["errors"] else 1)

import pathlib,sys,json,hashlib,ast
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
helper=ROOT/"root_merge_helpers.py"
assert hashlib.sha256(helper.read_bytes()).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
sys.path.insert(0,str(ROOT));import root_merge_helpers as h
h.setup("collector-exact-count-reviewed-component-merge-v1")
old="08c9becab740ab2c375b970f376a7638f44c9e8e";part="f0f6a4192dc3bcda2fca20110322f7cff07e4644"
assert h.git("rev-parse","HEAD").decode().strip()==old
assert h.git("rev-parse","HEAD^{tree}").decode().strip()=="036868dfcc953b6f5574c627e0027c3d4e2d3523"
assert not h.git("status","--porcelain","--untracked-files=all").strip()
cp=h.git("cat-file","commit",part)
assert hashlib.sha1(b"commit "+str(len(cp)).encode()+b"\0"+cp).hexdigest()==part
assert [x[7:].decode() for x in cp.split(b"\n\n",1)[0].splitlines() if x.startswith(b"parent ")]==[old]
assert h.git("rev-parse",part+"^{tree}").decode().strip()=="f2301d62786c8cca73d16c52ae24a2a2dc82e65d"
receipt=pathlib.Path("/private/tmp/chain-owned-process-control-count-evidence-20261114-v1/commit-v1/summary.json")
rb=receipt.read_bytes();assert len(rb)==16309 and hashlib.sha256(rb).hexdigest()=="35bfce3f2fafe0596bcc7a328ab03a947376e2bf825145d31409124c611c13ec"
component=json.loads(rb);assert component["commit"]==part and component["path_count"]==3 and component["clean"] and component["parents"]==[old]
paths={"scripts/ci/ci_job.sh","scripts/ci/check_ci_contract.py","scripts/ci/test_ci_contract.py"}
assert {x["path"] for x in component["paths"]}==paths
assert set(h.git("diff-tree","--no-commit-id","--name-only","-r",old,part).decode().splitlines())==paths
for x in component["paths"]:
 b=h.show(part,x["path"]);assert len(b)==x["bytes"] and hashlib.sha256(b).hexdigest()==x["sha256"] and hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==x["blob_oid"]
patch=h.git("diff","--binary","--full-index",old,part,"--",*sorted(paths))
assert len(patch)==2859 and hashlib.sha256(patch).hexdigest()=="85fd36f54e4c7fa98ccb94a51c4fe4f11bd8e3c6e4c4cbf83ff3f47d21d92ef2"
for p in ("scripts/w1_owned_process_collector_v1.py","scripts/test_w1_owned_process_collector_v1.py"):
 assert h.show(old,p)==h.show(part,p)
h.run("preflight-before",["bash","scripts/project-preflight.sh","--audit"])
h.run("normal-component-merge",["git","merge","--no-ff","--no-commit",part])
report="docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md"
plan_add="""

### 2026-11-14 exact collector count and complete historical-evidence lane

The original full Linux repository-truth lane on 08c9becab740ab2c375b970f376a7638f44c9e8e
ran for 481.260 seconds and failed after all 16 collector controls passed in
2.664 seconds. This includes every original 14 method and both added signal
controls; the previously failing post-fork identity-refusal control passed.
The later shell guard still required exactly 14 and rejected the actual 16.
Preserve original receipt c39d394f383dd88f31544292e3222b8a76f69ebea86377099a6192e8bbba9777
and all 39 original execution files as a failed full lane.

Merge f0f6a4192dc3bcda2fca20110322f7cff07e4644: align the shell and independent
CI contract to exactly 16. Preserve rejection of skips, incomplete/duplicate
counts, failed runs and missing logs. The original four CI methods passed;
negative fixtures retain bad counts 0/13 and additionally reject old 14 and
incomplete 15. Synthetic parser fixtures are not collector execution.
No collector method, runtime, command deadline or native workload changes.

The separate original external-evidence-contract lane on the same 08c9beca
source passed in 225.948 seconds; all 77 readiness tests passed in 36.691
seconds. Both source identities remained 41,671 tracked entries and
3,994,762,924 bytes. Receipt 624efff452b6bd0b2c6ebcf9a47abe3216999a7d051d1e7d0fb9e5ea86fb2ca3
records all 12 driver stages, the original 30-command lane and no source fetch.
The materializer verified all 14 declared historical trees with fetched=[].
These observations bind 08c9beca, not the new integration commit.

Run the original complete repository-truth lane on the new committed source.
Current-source consistency and historical-evidence checks do not repair the
unchanged active Rust four-second/16-worker CONFIRMATION_TARGET failures.
Main integration, protected branch cleanup and a one-branch result remain
pending; no required check, source identity or production acceptance is waived.
"""
report_add="""

## Complete M5 observations and exact-count integration

The full Linux repository-truth lane on 08c9beca exited 1 after 481.260 seconds.
All 16 collector tests passed, including the original post-fork refusal case,
but the later CI parser still required exactly 14. The failed execution and
both unchanged source identities remain preserved; passing the collector
suite does not turn the complete lane into a pass.

Component f0f6a419 updates only the exact collector count in the shell,
its independent CI contract, and their existing mutation controls. It
requires all 16, retains failures for 0/13, and adds refusal of old 14 and
incomplete 15. The original zero-skip, exact-OK, missing-log and failed-process
guards remain. All four original focused CI methods and ten synthetic parser
cases passed; no collector or Rust runtime code changed in this follow-up.

The independent complete external-evidence-contract command on 08c9beca
passed in 225.948 seconds. The previously incomplete readiness suite now
passed all 77 tests in the prepared Linux dependency environment. All 14
declared historical source trees were present, the original materializer
reported fetched=[], and before/after source identities were equal. This
validates the declared historical-evidence contract on that exact source;
it does not grant current system, hosted or production qualification.

The new integration requires its own original full repository-truth result.
The unchanged original C0 head and prospective native confirmation failures,
the original four-second window and 16 pressure workers, and all prior
HOLD_NO_GO / DENY_ALL conditions remain in force. No main merge or branch
deletion has occurred at this checkpoint.
"""
for path,addition in ((h.plan,plan_add),(report,report_add)):
 b=(h.src/path).read_bytes();assert addition.strip().encode() not in b;(h.src/path).write_bytes(b+addition.encode())
mb=json.loads((h.src/h.manifest).read_text())
h.refresh_pins([*sorted(paths),h.plan,report])
ma=json.loads((h.src/h.manifest).read_text())
updates={p:{"old":mb["pinned_blobs"][p],"new":v} for p,v in ma["pinned_blobs"].items() if mb["pinned_blobs"].get(p)!=v}
assert set(updates)<=paths|{h.plan,report}
h.run("stage-root-metadata",["git","add","--",h.manifest,h.plan,report])
index={}
for entry in h.git("ls-files","--stage","-z").split(b"\0"):
 if not entry:continue
 meta,path=entry.split(b"\t",1);mode,oid,stage=meta.split();assert stage==b"0";index[path.decode()]=oid.decode()
assert len(ma["pinned_blobs"])==2600 and all(index[p]==v for p,v in ma["pinned_blobs"].items())
for x in component["paths"]:assert index[x["path"]]==x["blob_oid"]
meta=h.git("diff","--cached",part,"--",h.manifest,h.plan,report)
(h.ev/"root-metadata.patch").write_bytes(meta)
h.run("staged-diff-check",["git","diff","--cached","--check"])
h.run("preflight-staged",["bash","scripts/project-preflight.sh","--audit"])
h.run("normal-commit",["git","commit","-m","Merge exact collector control count and preserve original lane outcomes"])
head=h.git("rev-parse","HEAD").decode().strip();tree=h.git("rev-parse","HEAD^{tree}").decode().strip()
assert h.git("show","-s","--format=%P",head).decode().strip().split()==[old,part]
assert not h.git("status","--porcelain","--untracked-files=all").strip()
for x in component["paths"]:assert hashlib.sha256(h.show(head,x["path"])).hexdigest()==x["sha256"]
r={"schema":"root-reviewed-exact-collector-count-integration-v1","head_before":old,"head_after":head,"tree":tree,"parents":[old,part],"clean":True,"component_paths_preserved":3,"collector_and_16_test_methods_unchanged":True,"prior_M5_full_repository_result":"failed","prior_M5_full_external_result":"passed","new_integration_full_lane_pass_claimed":False,"existing_corpus_updates":updates,"all_indexed_corpus_pins_match":2600,"steps":h.steps,"root_metadata_patch":{"path":str(h.ev/"root-metadata.patch"),"bytes":len(meta),"sha256":hashlib.sha256(meta).hexdigest()}}
b=(json.dumps(r,indent=2)+"\n").encode();(h.ev/"summary.json").write_bytes(b)
print(json.dumps({"head":head,"tree":tree,"summary":str(h.ev/"summary.json"),"summary_bytes":len(b),"summary_sha256":hashlib.sha256(b).hexdigest()}),flush=True)

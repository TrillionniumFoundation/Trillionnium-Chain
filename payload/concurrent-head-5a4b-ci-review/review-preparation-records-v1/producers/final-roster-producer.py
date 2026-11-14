#!/usr/bin/env python3
"""Seal source-review conclusions and a complete53-path external application roster."""
import ast,hashlib,json,os,stat,time
from pathlib import Path
BASE=Path("/private/tmp/chain-ci-new-candidate-5a4b7fe8-review-20261114-v1")
PROPOSAL=BASE/"selected-merge-proposal-v2";OUT=BASE/"final-review-v1"
STORE="trillionnium/crates/trnm-pon-node/src/store.rs"
ARCH=Path("/private/tmp/chain-new-candidate-5a4b7fe8-production-review-20261114-v1")
def sha(b):return hashlib.sha256(b).hexdigest()
def oid(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def read(p,expected=None):
 p=Path(p)
 if p.resolve()!=p:raise ValueError("noncanonical source")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>16*1024*1024:raise ValueError("source type/bound")
  chunks=[];left=st.st_size
  while left:
   b=os.read(fd,min(left,1024*1024))
   if not b:raise ValueError("short source")
   chunks.append(b);left-=len(b)
  if os.read(fd,1):raise ValueError("source grew")
  b=b"".join(chunks);end=os.fstat(fd);at=p.stat(follow_symlinks=False)
  def ident(x):return (x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if ident(st)!=ident(end) or ident(st)!=ident(at):raise ValueError("changed source")
 finally:os.close(fd)
 if expected and sha(b)!=expected:raise ValueError("source SHA")
 return b
artifacts=[]
def put(name,b):
 if isinstance(b,str):b=b.encode()
 p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  v=memoryview(b)
  while v:n=os.write(fd,v);v=v[n:]
 finally:os.close(fd)
 if read(p)!=b:raise ValueError("target readback")
 item={"path":str(p),"bytes":len(b),"sha256":sha(b)};artifacts.append(item);return item
def js(x):return json.dumps(x,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n"
if os.path.lexists(OUT):raise RuntimeError("create-only final directory exists")
OUT.mkdir(mode=0o700)
summary=json.loads(read(PROPOSAL/"summary.json","9b32ef3e370daec33082bd951bbed92c13c9b4b05581ee75f1b2e5e4a7f8b9c0"))
index=json.loads(read(PROPOSAL/"EVIDENCE_INDEX.json","d3f651a11e3576ff5ab3aeade1152e38fbcb89f8d6b3a90bc50de939a63cb640"))
for i in index["files"]:
 b=read(i["path"],i["sha256"])
 if len(b)!=i["bytes"]:raise ValueError("proposal artifact size")
rows=json.loads(read(PROPOSAL/"all-path-dispositions.json"))
capture_rows=json.loads(read(BASE/"three-way-selected-blobs.json"))
steps=json.loads(read(BASE/"steps.json"));bat=next(x["stdout"] for x in steps if x["label"]=="selected-blob-batch");batch=read(bat["path"],bat["sha256"])
blobidx=json.loads(read(BASE/"selected-blob-index.json"));raws={x["oid"]:batch[x["batch_offset"]:x["batch_offset"]+x["bytes"]] for x in blobidx}
originalN={x["path"]:raws[x["versions"]["N"]["oid"]] for x in capture_rows}
for filename in (BASE/"consumer-closure-v2/summary.json",BASE/"final-consumer-edges-v1/summary.json"):
 d=json.loads(read(filename))
 recs=d.get("records",[])
 recs+= [{"path":p,"versions":v} for p,v in d.get("extra_sources",{}).items()]
 for rec in recs:
  n=rec["versions"].get("N")
  if n:
   raw=read(n.get("source_path",n.get("raw_path")),n["sha256"])
   if oid(raw)!=n["oid"] or len(raw)!=n["bytes"]:raise ValueError("N original content address")
   originalN[rec["path"]]=raw
application=[];N_diffs=[]
for row in rows:
 path=row["path"];selection=row["selected"]
 if row["changed_from_M6"]:payload=row["payload"];raw=read(payload["path"],payload["sha256"])
 else:
  m6=row["M6"];raw=raws.get(m6["oid"])
  if raw is None:raise ValueError("missing retained source")
  payload=put("retained-files/"+path,raw)
 if oid(raw)!=selection["oid"] or sha(raw)!=selection["sha256"] or len(raw)!=selection["bytes"]:raise ValueError("application source identity")
 nraw=originalN[path];npayload=put("original-N/"+path,nraw)
 n=row["N"]
 if n and (oid(nraw)!=n["oid"] or sha(nraw)!=n["sha256"]):raise ValueError("N input identity")
 application.append({"path":path,"mode":selection["mode"],"oid":selection["oid"],"bytes":len(raw),"sha256":sha(raw),"payload_path":payload["path"],"disposition":row["selection"],"N_input":{"oid":oid(nraw),"bytes":len(nraw),"sha256":sha(nraw),"path":npayload["path"]}})
sraw=read(ARCH/"source-capture-v1/M6--trillionnium--crates--trnm-pon-node--src--store.rs.stdout","5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c")
if oid(sraw)!="d596dc6bab16698cd18bcc15bcbbe1fafedf603e" or len(sraw)!=391470:raise ValueError("selected full store")
sp=put("retained-files/"+STORE,sraw)
nraw=read(ARCH/"source-capture-v1/N--trillionnium--crates--trnm-pon-node--src--store.rs.stdout","ae54afb15c78e20b5fbb80c89d2a7346aafb2c20e6a1bf665663adc422625da5")
if oid(nraw)!="3bce39ce1aef265a18f304085bc08c0240547065" or len(nraw)!=391556:raise ValueError("N complete store")
np=put("original-N/"+STORE,nraw)
application.append({"path":STORE,"mode":"100644","oid":oid(sraw),"bytes":len(sraw),"sha256":sha(sraw),"payload_path":sp["path"],"disposition":{"disposition":"retain_M6_exact","owner":"architecture_audit/root","reason":"Root explicitly rejects both N check reorderings after static epoch-window/fatal-error-precedence review; no attack execution claimed."},"N_input":{"oid":oid(nraw),"bytes":len(nraw),"sha256":sha(nraw),"path":np["path"]}})
application.sort(key=lambda x:x["path"])
if len(application)!=53 or len({x["path"] for x in application})!=53:raise ValueError("application roster")
manifest=put("complete-selected-53-files.json",js({"schema":"trnm-fixed-concurrent-merge-file-selection-v1","base_head":summary["base_head"],"merge_head":summary["concurrent_head"],"application_is_not_executed":True,"all_other_paths":"Retain M6 exact source/evidence; C0-to-N full49-path inventory is covered by this53-path selection.","files":application}))
continuity=json.loads(read(PROPOSAL/"static-test-and-helper-continuity.json"))
tests=continuity["method_tables"]
matrix={path:{"M6":item["M6_methods"],"selected":item["proposal_methods"],"same_source_methods":len(item["unchanged_source_methods"]),"same_AST_methods":len(item["unchanged_AST_methods"]),"changed_AST_methods":item["changed_AST_methods"],"added_methods":item["added_methods"],"removed_names":item["removed_methods"]} for path,item in tests.items()}
consumers=[
 {"path":"scripts/ci/pq_lifetime_budget.py","selection":"byte-identical C0/M6/N","call_contract":"Original strict evaluate and inspect remain. Synthetic original lock/read controls retained; bare V1 inspect refuses the differing current default sources. No lock regeneration, arithmetic/cap or qualification change."},
 {"path":"scripts/ci/pq_lifetime_current_v2.py","selection":"N plus exactly2 independent SHA literal replacements","call_contract":"Exact frozen raw manifest/lock and21 fixed path set; raw current map plus independent canonical snapshot; all current regular bounded reads; metadata re-read; supplied report recomputed; source revision/qualification false."},
 {"path":"scripts/ci/pq_lifetime_composition.py","selection":"N plus exactly2 reviewed map literal replacements","call_contract":"Explicit current-v3 schema and frozen-v2 hash. Actual current21 and actual root46 inspect, one identical shared release source, union66. All math/helper definitions excluding default_manifest/validate_manifest/inspect remain exact M6 source+AST."},
 {"path":"scripts/ci/pq_chain_claim_guard.py","selection":"N exact","call_contract":"Runs real new current inspect; nested lifetime_budget report carries explicit current-v2 schema/frozen model. Original outer HOLD/noactivation gates retained. The only internal report consumer uses updated explicit nested frozen_model path."},
 {"path":"scripts/ci/pq_proof_profile_binding.py","selection":"unchanged M6/N/C0","call_contract":"validate_declarations calls lifetime.evaluate on frozen model, never legacy.inspect. Native experiment cannot qualify selected RISC Zero profile; exact proof identity and immutable descriptor do not contain system-budget manifest. Actual observed source report includes actual frozen manifest; upstream current-use revocation remains."},
 {"path":"config/pon/pq-proof-profile-binding-v1.json","selection":"unchanged M6/N/C0","call_contract":"System lifetime register pins only path/profile/relationship, not old/new budget raw SHA. Its own current raw SHA797eaa remains bound by M6 H1; N's stale descriptor-only update is not selected."},
 {"path":"scripts/ci/pq_root_dependency_register.py","selection":"unchanged M6/N","call_contract":"Uses budget strict parser helpers; root46 manifest and reader are unchanged. Prior lifetime manifest is only a declared path with prior coverage/query independence both false; legacy reader bytes pinned and unchanged."},
 {"path":"scripts/ci/test_pq_root_dependency_register.py","selection":"unchanged M6/N","call_contract":"Prior model is passed to root validate_manifest only as a wrong-schema negative. No old budget current-source inspect or fixed revision expected."},
 {"path":"scripts/ci/hash_use_contract.py","selection":"retain M6 H1","call_contract":"Uses lifetime parsing/relative-path helpers; does not import frozen lifetime claims. Retains exact current31 source map, independent literal and19 semantic uses."},
 {"path":"scripts/ci/pq_authority_effect_register.py","selection":"retain M6","call_contract":"Only BudgetError/relative_path/strict_json imported. Its actual44 source map remains correct for selected M6 store."},
 {"path":"scripts/ci/pq_root_custody_review_v1.py","selection":"unchanged M6/N","call_contract":"Only BudgetError/strict_json imported; no frozen/current budget execution."},
 {"path":"scripts/ci/pq_root_custody_review_v2.py","selection":"unchanged M6/N","call_contract":"Only BudgetError/strict_json imported; no frozen/current budget execution."},
 {"path":"scripts/ci/pq_root_migration_review_v1.py","selection":"unchanged M6/N","call_contract":"Only BudgetError/natural/relative_path/strict_json imported."},
 {"path":"scripts/ci/w1_upstream_security.py","selection":"unchanged M6/N","call_contract":"Only strict_json, relative_path and BudgetError used; upstream security identity/refusal policy unchanged."},
 {"path":"scripts/ci/ci_job.sh","selection":"N current commands plus M6 collector16","call_contract":"Original58 command remains exactly once, current25 plus reader added; old bare inspectCLI replaced. Composition and claim-guard command names remain; no lane/timeout change."},
 {"path":"scripts/ci/check_ci_contract.py","selection":"N plus M6 exact-count literal","call_contract":"Both exact source block representations and once-only command check updated; distinct10 current-stage workflow controls and31 controls both required."},
 {"path":"scripts/ci/check_pq_research_integration.py","selection":"union","call_contract":"Keeps M6 historical B1 carrier, all prior required paths, and6 added current/QROM paths. Corpus only selected source OIDs change."},
 {"path":"scripts/ci/test_retained_research_ci.py","selection":"unchanged M6/N","call_contract":"Requires unchanged composition command name; explicit current namespace is chosen inside its reader."},
 {"path":".github/workflows/chain-hepta-closure-candidate.yml","selection":"unchanged M6/N","call_contract":"Budget path is an artifact/source-presence declaration, not a hard-coded budget digest or direct legacy inspection."},
 {"path":".github/workflows/pon-legacy-reorg-cost-20261104.yml","selection":"unchanged","call_contract":"Existing claim-guard CLI and test invocation names stay valid; no historical workload is executed in this review."},
 {"path":".github/workflows/pon-pq-system-continuation.yml","selection":"unchanged","call_contract":"Existing claim-guard CLI/test names stay valid; report flags remain HOLD. No consumer found of the former flattened lifetime subfields outside the adapted tests."},
 {"path":"scripts/ci/test_pq_research_integration.py","selection":"unchanged","call_contract":"Imports DescriptorReaderControls from test_pq_chain_claim_guard; that shared helper class remains unchanged."}
]
put("consumer-closure-review.json",js({"schema":"trnm-fixed-source-consumer-closure-review-v1","immutable_revisions":summary["base_head"]+" + "+summary["concurrent_head"],"all_queries_scoped_to":["scripts","config",".github","formal"],"references":["../consumer-closure-v1/raw/N-consumer-references.stdout","../consumer-closure-v1/raw/M6-consumer-references.stdout","../final-consumer-edges-v1/raw/N-downstream-consumers.stdout","../final-consumer-edges-v1/raw/M6-downstream-consumers.stdout"],"consumers":consumers,"tests_or_readers_executed":False,"limitation":"Static in-repository consumer audit; not a deployed dependency closure or new execution result."}))
put("static-control-rosters.json",js(matrix))
readme=f"""# Concurrent N / M6 CI and source-binding review

## Decision and review boundary

The proposed combination retains complete M6 store and existing H1/F1/F2/B1/C5/C6 repairs, adopts the independent N worker artifact tightening, and chooses explicit frozen-model/current-correspondence PQ namespaces. No production qualification follows. This was a read-only immutable-source review; the proposal was materialized outside any working tree. No tests, readers, helpers, native workloads, hosted gates, Git mutations, configuration edits or network requests were performed.

C0 is dc42ce4df5cff79cc61c5addbaf01074b56b06ca; M6 is {summary['base_head']}; N is {summary['concurrent_head']}. The original49-path N delta was classified as2 workflows,6 configs,6 docs,2 fixed expected-observation artifacts,1 formal test,30 script/test paths and2 Rust paths. Architecture owns the2 Rust findings. All original N inputs for the complete53-path decision roster are retained here under original-N/, with their exact content addresses in complete-selected-53-files.json.

The53 selected paths consist of the49 N-changed paths plus the3 exact frozen JSON restorations and the active budget documentation. There are41 changed files relative to M6. Twelve retained outputs, including complete store, are supplied under retained-files/. This is the complete explicit post-merge overwrite/retention roster; the41-file patch alone is a diff against M6 and must not be mistaken for a patch against the unresolved N merge.

## Frozen model and current-source mapping

The three selected JSONs exactly equal C0/N:
- Budget:0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd.
- Lock:094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2.
- Composition-v2:5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052.

The old model retains revision0f9b3054 and unchanged arithmetic. The original V1 reader remains exact20543 bytes, SHAeba31bee86b025a55c45cf8a86ad95bb85db1221af9c1ccd38799666e512555e. It must refuse a current physical source differing from that frozen lock.

The independent current map checks the same21 declared source paths. Twenty N/M6 path blobs are identical by the complete immutable path diff; store alone is explicitly selected as d596dc6b, SHA59182703. The selected raw map SHA is {summary['current_map_sha256']}; its independently fixed canonical map digest is {summary['current_snapshot_sha256']}. The reader and composition each bind both exact new literals. No automatic CI repinning is introduced.

Original58 test method names remain. Fifty-seven methods are byte/AST identical; the sole checked-in-model method now asserts unbound frozen mathematics and separately verified current21 correspondence, with all original unknown/null/noqualification checks retained. The new25 controls separately enforce exact frozen bytes, fixed21 roster, both map identities, all bounded current reads, file/parent symlink refusal, metadata reread, typed false/zero semantics and fresh supplied-report rejection. Both original58 and new25 commands occur once in CI; only the obsolete bare V1 inspectCLI is replaced.

Composition still has60 controls, actual21+46−1=66 paths and the single shared release source. Its numeric/math/helper definitions are exactly unchanged. The child root46 register is still rawSHA2b641a5e with existing5c04 review context; the new current wrapper does not rewrite it. Frozen-v2 input cannot satisfy current-v3 namespace. All bounds remain unknown/null and all qualification fields false.

## Other overlap dispositions

- Keep M6 authority44/current-lifetime20 and recent acceptance store pin. N fc39/store locks describe an unselected body and are not adopted.
- Keep M6 H1 all31 source bindings and independent commitment. N's descriptor-only correction still has six actual mismatches; it cannot overwrite H1.
- Keep B1 carrier required path, exact collector16 and bad0/13/14/15 negatives. N's14 is an inherited C0 snapshot, not evidence that16 controls should be dropped.
- Keep both readiness endpoint methods: static78 total. Preserve M6 selected-body evidence comment and adopt explicit SQLite connection closure; no source-authority fallback.
- Adopt exact SP27 prepared-command/int-zero/false-timeout readback binding; original36 receiver/strata methods remain,4 added.
- Adopt exact JSON type-and-value source-receipt equality; original27 methods remain,3 added.
- Budget observation supports native-completion phases with complete first/second packet accounting. The original CPU/deadline/balance constants remain; this is not a4-second confirmation fix.
- Cell business runner requires the explicit existing21-method CI class rather than stale19 count. Independent10 current-stage workflow methods run in addition to31 prior controls.
- Preserve Nov7/Nov9 QROM originals. The new Nov14 JSON is explicitly a deterministic fixed-input expected observation, not an execution receipt.
- Preserve all M6 plan/source-specific evidence history. Do not import N plan's checkpoint-specific pass/28-head claims as combined facts. Documentation states the selected implementation and pending combined validation.

No CI budget, resource quota, numeric probability, maximum source byte limit, qualification flag, fresh Host requirement,4-second pressure window or16-worker requirement is relaxed. The proposed complete corpus is an explicit union:2504→2510 required paths and2600→2606 pins, with no prior path removed.

## Completion and limitations

All53 selected outputs have exact modes/OIDs/bytes/SHA; the complete application manifest is create-only and immutable. Python files were parsed for static method/source/AST comparisons only. There is no combined Git tree or runtime pass result here. Root's normal merge, final source gates, original full local lanes, worker controls/strict lint and required hosted head/prospective checks remain separate work on the final commit.

Two preparation failures are preserved separately: a read-only lookup used a nonexistent module name before the correct consumer continuation; a proposal builder stopped on a bytes/string concatenation before producing output files. Neither ran a test or changed source. The corrected proposal completed with authoritative PTY exit0.
"""
put("review.md",readme)
state={"schema":"trnm-concurrent-source-ci-final-review-v1","status":"STATIC_REVIEW_AND_EXTERNAL_PROPOSAL_COMPLETE","source_worktree_fence_released":True,"root_source_last_observed":summary["base_head"],"root_now_merge_pending_not_read":True,"application_manifest":manifest,"selected_paths":53,"M6_diff_changed_files":41,"retained_files_supplied":12,"full_M6_patch":summary["full_patch"],"new_current_map":summary["current_map_sha256"],"new_current_snapshot":summary["current_snapshot_sha256"],"tests_executed":False,"runtime_or_hosted_qualification":False,"pending_source_or_Git_mutation_by_agent":False}
put("summary.json",js(state))
meta=put("EVIDENCE_INDEX.json",js({"schema":"trnm-concurrent-final-review-evidence-index-v1","files":artifacts.copy()}))
print(js({"application_manifest":manifest,"summary":str(OUT/"summary.json"),"summary_sha256":sha(read(OUT/"summary.json")),"review":str(OUT/"review.md"),"review_sha256":sha(read(OUT/"review.md")),"index":meta}),flush=True)

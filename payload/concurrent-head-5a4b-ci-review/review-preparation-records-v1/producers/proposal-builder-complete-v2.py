#!/usr/bin/env python3
"""Materialize a static external M6/N source-selection proposal from fixed evidence only."""
import ast,copy,difflib,hashlib,json,os,re,stat,textwrap
from pathlib import Path
BASE=Path("/private/tmp/chain-ci-new-candidate-5a4b7fe8-review-20261114-v1")
OUT=BASE/"selected-merge-proposal-v2"
REVS={"C0":"dc42ce4df5cff79cc61c5addbaf01074b56b06ca","M6":"2a62061177852dc3ebd200fa8d7c66c661a119a1","N":"5a4b7fe8de1adce803184f262fd9f704ead1930c"}
STORE="trillionnium/crates/trnm-pon-node/src/store.rs"
WORKER="trillionnium/crates/trnm-worker-agent/src/audit/artifact.rs"
SELECTED_STORE={"oid":"d596dc6bab16698cd18bcc15bcbbe1fafedf603e","bytes":391470,"sha256":"5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c","mode":"100644"}
def sha(b):return hashlib.sha256(b).hexdigest()
def oid(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def read(p,expected=None,cap=16*1024*1024):
 p=Path(p)
 if p.resolve()!=p:raise ValueError("noncanonical evidence source")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>cap:raise ValueError("not bounded regular evidence")
  chunks=[];left=a.st_size
  while left:
   b=os.read(fd,min(left,1024*1024))
   if not b:raise ValueError("short evidence read")
   chunks.append(b);left-=len(b)
  if os.read(fd,1):raise ValueError("grew")
  b=b"".join(chunks);z=os.fstat(fd);q=p.stat(follow_symlinks=False)
  def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if ident(a)!=ident(z) or ident(a)!=ident(q):raise ValueError("evidence changed")
 finally:os.close(fd)
 if expected is not None and sha(b)!=expected:raise ValueError("evidence SHA differs")
 return b
artifacts=[]
def put(name,b):
 if isinstance(b,str):b=b.encode()
 p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  view=memoryview(b)
  while view:
   n=os.write(fd,view);view=view[n:]
 finally:os.close(fd)
 if read(p)!=b:raise ValueError("proposal readback")
 item={"path":str(p),"bytes":len(b),"sha256":sha(b)};artifacts.append(item);return item
def js(v):return json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n"
def literal_replace(b,a,z,count=1):
 a=a.encode() if isinstance(a,str) else a;z=z.encode() if isinstance(z,str) else z
 if b.count(a)!=count:raise ValueError("literal multiplicity "+repr(a[:80])+": "+str(b.count(a)))
 return b.replace(a,z)
def defs(b):
 text=b.decode();lines=text.splitlines(keepends=True);answer={}
 def walk(nodes,prefix=""):
  for n in nodes:
   if isinstance(n,ast.ClassDef):walk(n.body,prefix+n.name+".")
   elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
    raw="".join(lines[n.lineno-1:n.end_lineno])
    answer[prefix+n.name]={"line":n.lineno,"end":n.end_lineno,"raw":raw,"source_sha256":sha(raw.encode()),"ast_sha256":sha(ast.dump(n,include_attributes=False).encode())}
 walk(ast.parse(text).body)
 return answer
def replace_def(body,name,replacement):
 d=defs(body)
 if name not in d:raise ValueError("missing function "+name)
 return literal_replace(body,d[name]["raw"],replacement)
if os.path.lexists(OUT):raise RuntimeError("create-only proposal exists")
summary=read(BASE/"capture-summary.json","dc0a0601f84574118dbf9939b8a71ce32bac1f5bedf903c03f79dd6b69d9bea4")
capture=json.loads(summary);steps=json.loads(read(BASE/"steps.json"))
batch_info=next(x["stdout"] for x in steps if x["label"]=="selected-blob-batch")
batch=read(batch_info["path"],batch_info["sha256"])
if len(batch)!=batch_info["bytes"]:raise ValueError("batch length")
blobindex=json.loads(read(BASE/"selected-blob-index.json"))
blobs={}
for e in blobindex:
 b=batch[e["batch_offset"]:e["batch_offset"]+e["bytes"]]
 if oid(b)!=e["oid"] or sha(b)!=e["sha256"]:raise ValueError("captured blob identity")
 blobs[e["oid"]]=b
records=json.loads(read(BASE/"three-way-selected-blobs.json"))
lookup={x["path"]:x["versions"] for x in records}
src={}
for row in records:
 for label,item in row["versions"].items():
  if item:src[(label,row["path"])]=blobs[item["oid"]]
c2=json.loads(read(BASE/"consumer-closure-v2/summary.json","254a214451d3f6be70b248167b2fff63e68d8dec67f29c6b0c0eecf19e028c16"))
for rec in c2["records"]:
 lookup[rec["path"]]=rec["versions"]
 for label,e in rec["versions"].items():
  b=read(e["source_path"],e["sha256"])
  if len(b)!=e["bytes"] or oid(b)!=e["oid"]:raise ValueError("extra source identity")
  src[(label,rec["path"])]=b
last=json.loads(read(BASE/"final-consumer-edges-v1/summary.json","4ef9e3fdcf241441310fed61e9f82842c30263880ec582d652bc8a84527475bd"))
for path,versions in last["extra_sources"].items():
 lookup[path]=versions
 for label,e in versions.items():
  b=read(e["raw_path"],e["sha256"])
  if len(b)!=e["bytes"] or oid(b)!=e["oid"]:raise ValueError("last source identity")
  src[(label,path)]=b
arch=json.loads(read(last["arch_source_map_receipt"]["path"],last["arch_source_map_receipt"]["sha256"]))
changed_paths={line.split("\t",1)[1] for line in read(last["arch_M6_N_name_status"]["path"],last["arch_M6_N_name_status"]["sha256"]).decode().splitlines()}
OUT.mkdir(mode=0o700)
chosen={row["path"]:src[("N",row["path"])] for row in records}
decisions={p:{"disposition":"adopt_N_exact","reason":"Independently reviewed C0-to-N delta; unchanged M6 obligations outside this path remain.","owner":"ci_repairs"} for p in chosen}
def choose(p,b,why,mode="compose_reviewed"):
 chosen[p]=b;decisions[p]={"disposition":mode,"reason":why,"owner":"ci_repairs"}
retain={
 ".github/workflows/pon-recent-batch-acceptance.yml":"Keep exact d596 selected store pin; do not bind rejected N store.",
 "config/pon/hash-use-contract-v1.json":"Retain M6 H1 all31 current-correct sources and19 purposes; N still has6 stale pins.",
 "scripts/ci/hash_use_contract.py":"Retain independent M6 H1 map commitment; no historical identity waiver.",
 "config/pon/pq-authority-effects-v1.json":"Selected store equals M6; retain reviewed44-map context, routes and allfalse flags.",
 "scripts/ci/pq_authority_effect_register.py":"Retain exact M6 independent44-source commitment and strict reader.",
 "scripts/ci/test_pq_authority_effect_register.py":"Retain M6 original18 controls and selected-source literals.",
 "docs/security/PQ_AUTHORITY_EFFECT_REGISTER_V1.md":"N context/pin describes unselected store; retain true M6 binding context.",
 "config/pon/w1-lifetime-current-source-v2.json":"Retain exact M6 current20 map; N store variation not selected.",
 "scripts/w1_lifetime_current_observation.py":"Retain current20 independent contract hash and historical7150/1f2b boundaries.",
 "scripts/ci/test_w1_lifetime_current_observation.py":"Retain M6 original14 controls and selected store literal.",
 "docs/security/W1_LIFETIME_CURRENT_SOURCE_OBSERVATION_V2.md":"Retain true M6 current20 binding; no N fc39 relabelling."
}
for p,why in retain.items():choose(p,src[("M6",p)],why,"retain_M6_exact")
# The three frozen inputs are selected explicitly, never inferred from a successful current run.
frozen_paths=["config/pon/pq128-lifetime-budget-v1.json","config/pon/pq128-source-lock-v1.json","config/pon/pq128-lifetime-composition-v2.json"]
for p in frozen_paths:
 if src[("C0",p)]!=src[("N",p)]:raise ValueError("frozen inputs differ between C0/N")
 choose(p,src[("C0",p)],"Restore exact C0/N frozen model/lock/composition bytes; preserve M6 L1 mapping, receipts and source review in Git/evidence.","select_frozen_C0_exact")
# Select only the already reviewed20 equal sources and the root-selected complete store blob.
MAP="config/pon/pq128-source-correspondence-current-v2.json"
CURRENT_READER="scripts/ci/pq_lifetime_current_v2.py"
COMP="scripts/ci/pq_lifetime_composition.py"
CURRENT_COMP="config/pon/pq128-lifetime-composition-current-v3.json"
oldmap=json.loads(src[("N",MAP)]);current_files=dict(oldmap["current_source_files_sha256"])
if len(current_files)!=21 or arch["declared_input_results"]["pq_current21"]!={"count":21,"matches":21,"mismatches":[]}:raise ValueError("21 map baseline")
selected21=[]
for path,digest in sorted(current_files.items()):
 actual=arch["actual_blobs"][path]
 if digest!=actual["sha256"]:raise ValueError("N map actual bytes differ")
 if path==STORE:new=SELECTED_STORE
 else:
  if path in changed_paths:raise ValueError("unexpected current21 M6/N source difference: "+path)
  new=actual
 selected21.append({"path":path,"N":actual,"selected":new,"M6_identity_basis":"root-selected exact complete store" if path==STORE else "exact M6..N full path diff excludes this path; N content-addressed receipt","changed_from_N":new["oid"]!=actual["oid"]})
 current_files[path]=new["sha256"]
new_snapshot=sha(canonical(current_files));old_snapshot=oldmap["current_source_snapshot_sha256"]
newmap=literal_replace(src[("N",MAP)],arch["actual_blobs"][STORE]["sha256"],SELECTED_STORE["sha256"])
newmap=literal_replace(newmap,old_snapshot,new_snapshot)
new_map_sha=sha(newmap);old_map_sha=sha(src[("N",MAP)])
if json.loads(newmap)["current_source_files_sha256"]!=current_files:raise ValueError("new map fields")
choose(MAP,newmap,"Only selected store SHA changes; independent canonical21-map snapshot updated; exact frozen identity/21 roster/caps/qualification unchanged.")
for p in (CURRENT_READER,COMP,CURRENT_COMP):
 b=literal_replace(src[("N",p)],old_map_sha,new_map_sha)
 b=literal_replace(b,old_snapshot,new_snapshot)
 choose(p,b,"Adopt explicit frozen/current namespace with same reviewed21-map bytes and independent snapshot; no reader branch, limit, arithmetic or false qualification change.")
# M6 exact collector count and its independent negative checks survive all N additions.
for p in ("scripts/ci/ci_job.sh","scripts/ci/check_ci_contract.py"):
 b=literal_replace(src[("N",p)],'("owned-process-collector", 14)','("owned-process-collector", 16)')
 choose(p,b,"Union N current-reader/independent10-control wiring with M6 exact16 collector count; no >= matcher, skip/failure/timeout changes.")
p="scripts/ci/test_ci_contract.py"
base_defs=defs(src[("C0",p)]);m6_defs=defs(src[("M6",p)])
changed=[n for n in m6_defs if n in base_defs and m6_defs[n]["raw"]!=base_defs[n]["raw"]]
if len(changed)!=1:raise ValueError("unexpected M6 CI test delta")
if '("owned-process-collector", 14)' not in m6_defs[changed[0]]["raw"] or '("owned-process-collector", 15)' not in m6_defs[changed[0]]["raw"]:raise ValueError("M6 negative roster missing")
choose(p,replace_def(src[("N",p)],changed[0],m6_defs[changed[0]]["raw"]),"Preserve complete M6 exact16/bad0,13,14,15 method; N current-reader omission/duplication/move and10-control workflow negatives also remain.")
p="scripts/ci/check_pq_research_integration.py"
carrier=" 'formal/pon-nakamoto-v1/fixtures/native-collector-e4abb172.py.raw',\n"
anchor=" 'formal/pon-nakamoto-v1/w1_quantum_native_bridge.py',\n"
if src[("M6",p)].count(carrier.encode())!=1 or carrier.encode() in src[("N",p)]:raise ValueError("B1 carrier boundary")
choose(p,literal_replace(src[("N",p)],anchor,anchor+carrier),"Union all6 new N required paths with M6 B1 historical carrier; no required path removed.")
# Keep the M6 evidence comment; adopt only the explicit closing semantics in the reader.
p="scripts/ci/check_public_readiness_evidence.py";b=src[("M6",p)]
b=literal_replace(b,"import sqlite3\n","import sqlite3\nfrom contextlib import closing\n")
b=literal_replace(b,"with sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True) as database:","with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)) as database, database:")
choose(p,b,"M6 selected endpoint body binding/comment retained; N deterministic connection closure is added after the original transaction context.")
p="scripts/ci/test_public_readiness_evidence.py"
extra_name="NativeDurableSchemaTests.test_selected_opener_requires_current_tls_endpoint_witness_guard"
extra=defs(src[("M6",p)])[extra_name]["raw"]
b=src[("N",p)];nd=defs(b)
if extra_name in nd:raise ValueError("duplicate M6 readiness method")
anchor="\nclass PipelineExecutableBindingTests(unittest.TestCase):\n"
b=literal_replace(b,anchor,"\n"+extra+"\n\n"+anchor)
choose(p,b,"Retain all N connection-closing adaptations and additional endpoint mutations, plus complete original M6 endpoint method; static total78, not an execution claim.")
# Selected production delta is included verbatim under architecture/root ownership.
choose(WORKER,src[("N",WORKER)],"Root-selected exact N worker artifact prevalidation/locked-metadata tightening and2 controls; static production review owned by architecture.","adopt_N_exact_root_selected")
decisions[WORKER]["owner"]="architecture_audit/root"
# Preserve the L1 evidence narrative but mark its active-default status as historical.
p="docs/security/PQ128_LIFETIME_BUDGET_V1.md";b=src[("M6",p)]
notice=f"""## Current frozen-model and source-correspondence boundary

The V1 machine register and source lock retain the exact frozen C0 bytes
(SHA-256 `0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd`
and `094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2`),
with the declared historical source revision
`0f9b30549328e5be20f4d3e6e27bd132b42d90de`.
The unchanged V1 reader does not accept different current bytes as that source.

The separate [current correspondence map](../../config/pon/pq128-source-correspondence-current-v2.json)
has raw SHA-256 `{new_map_sha}` and canonical source-map digest
`{new_snapshot}`. Its same21 declared event paths bind the reviewed
current source bytes, including the selected complete store blob
`d596dc6bab16698cd18bcc15bcbbe1fafedf603e`.
The reader independently verifies the exact frozen manifest/lock, raw map,
canonical21-path digest and every bounded regular source read. A supplied
report is accepted only after the same inspection is recomputed.

CI retains the original58-method budget command and adds the25 current
correspondence controls and current reader. The frozen mathematical result is
unbound; the outer record separately records checked current files and
`source_revision_bound=false`. The eight unknown terms, four unknown query
budgets, numeric assumptions, strict refusal limits and null/false qualification
fields are unchanged. Current composition uses its explicit current-v3 namespace.
No original failed or successful source-specific observation transfers to this
combined source without its own validation.

The L1 mapping below is an exact historical integration record. Its reviewed
current-source findings and original receipts remain retained in Git and
evidence; its two JSON identities are no longer the default frozen inputs.

"""
marker="## Current consolidated source binding, 2026-11-14\n"
b=literal_replace(b,marker,notice+"## Historical L1 consolidated source binding, 2026-11-14\n")
b=literal_replace(b,"python3 scripts/ci/test_pq_lifetime_budget.py -v\npython3 scripts/ci/pq_lifetime_budget.py\n","python3 scripts/ci/test_pq_lifetime_budget.py -v\npython3 scripts/ci/test_pq_lifetime_current_v2.py -v\npython3 scripts/ci/pq_lifetime_current_v2.py\n")
choose(p,b,"Retain complete L1 source-review/failure record, label its prior default historical, document explicit current namespace and accurate reproduction commands.")
p="docs/security/PQ128_LIFETIME_COMPOSITION_V2.md"
m6=src[("M6",p)];c0=src[("C0",p)];n=src[("N",p)]
if not n.startswith(c0):raise ValueError("N composition doc is not pure append")
addition=n[len(c0):]
addition=literal_replace(addition,"The v2 machine register and the original observation files remain unchanged.","The selected frozen v2 machine register is byte-identical to C0; its original observation files remain unchanged.")
b=m6+addition+(f"""
### Concurrent-source reconciliation boundary

The earlier L1 section records the then-current default metadata and its actual
source-specific checks. That record and all original evidence are preserved.
The active frozen v2 input now has its true C0 SHA-256
`5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052`.
Current source acceptance belongs to the separate current-v3 manifest and the
current21 map `{new_map_sha}`, with independent snapshot
`{new_snapshot}`. Its selected store is the complete
C0/M6 implementation; the concurrent two store-check reorderings were not
selected. The root46 input keeps its existing manifest identity
`2b641a5e2e1bf66ad924e17d85da21c8cf76d7431fe35c8f448ab921659ba725`.

The original arithmetic helpers and limits are unchanged. The full60-method
composition roster is retained with explicit namespace/fixture assertions.
Frozen V1 is not presented as current-source-bound; actual current21 and root46
reads must agree at their one shared release path and yield exactly66 paths.
This merged correspondence requires its own checks and conveys no native,
lifetime-security, deployment or production qualification.
""").encode()
choose(p,b,"Keep M6 L1 provenance plus N explicit current-v3 explanation; state actual frozen C0 identities and selected map rather than relabelling prior observations.")
p="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
b=src[("M6",p)]
header="### 2026-11-14 complete branch-disposition audit and integration record"
if b.count(header.encode())==1:b=literal_replace(b,header,"### 2026-11-14 frozen branch-disposition audit and integration record")
b+=(f"""
### Concurrent candidate reconciliation — frozen scope and selected source

The concurrent candidate `{REVS['N']}` is reconciled with the reviewed
M6 source `{REVS['M6']}`. The original908-name/892-tip audit and296
terminal dispositions remain the frozen audit scope; their evidence and all
intermediate L1/H1/B1/F1/F2/C5/C6 records are retained. The concurrent plan's
checkpoint-specific claims are not reused as validation of this combination.

Keep the complete C0/M6 Node store blob
`d596dc6bab16698cd18bcc15bcbbe1fafedf603e` (SHA-256
`{SELECTED_STORE['sha256']}`). Static source review rejected the concurrent
store's two check reorderings because they change the epoch window and fatal
error precedence. This is a source-level finding, not a claim of an executed
attack. Adopt the independent worker artifact metadata prevalidation and
locked-baseline strengthening, with its two additional controls.

Retain the exact C0 frozen PQ V1 register/lock and v2 composition JSON bytes.
Current21 acceptance moves to the explicit reviewed correspondence namespace;
its raw map SHA-256 is `{new_map_sha}`, snapshot
`{new_snapshot}`. Only the concurrent store digest changes in that map.
Keep M6's44-authority,20-current-lifetime and31-hash-purpose bindings. The
current composition still joins21 and46 declared paths with one shared release
path and exactly66 unique inputs. All arithmetic, unknown values, limits and
false/null qualification fields remain.

Keep the original58 budget command alongside the25 current-correspondence
controls and reader. Keep the historical B1 collector carrier and its source
guard. Preserve the exact16 owned-process collector count and the independent
bad0/13/14/15 refusals, together with the existing failure, skip and timeout
semantics. Retain both endpoint-witness readback control methods (static78 total),
the explicit SQLite connection closure, exact SP27 child command/status binding,
typed receipt equality, original native-completion phase controls and the
independent10-method W1 current-stage workflow roster.

This reconciliation was prepared from immutable source evidence without running
new tests, native workloads or hosted gates. Existing M6 successes and concurrent
failures remain observations of their respective sources. The combined source
must independently pass the original complete local lanes and required hosted
head/prospective checks. The four-second confirmation budget,16 pressure workers,
fresh Host checks,30-second campaign and protected-main conditions are unchanged.
No waiver, production activation, protected merge, branch deletion or single-branch
remote completion is asserted here. This remains the sole development plan.
""").encode()
choose(p,b,"Preserve M6 history and append only reviewed combined-source selections/pending validation; do not import N checkpoint execution claims or conflicting store/source locks.")
# Keep M6 corpus data and append only the6 explicit N additions, then bind all selected source edits.
CORPUS="config/pon/pq-cross-branch-corpus-v1.json"
mcorpus=json.loads(src[("M6",CORPUS)]);ncorpus=json.loads(src[("N",CORPUS)]);ccorpus=json.loads(src[("C0",CORPUS)])
if set(mcorpus)!=set(ncorpus):raise ValueError("corpus schema keys differ")
new_required=sorted(set(ncorpus["required_paths"])-set(ccorpus["required_paths"]))
new_pins=set(ncorpus["pinned_blobs"])-set(ccorpus["pinned_blobs"])
if len(new_required)!=6 or set(new_required)!=new_pins:raise ValueError("unexpected added corpus scope")
if set(ccorpus["required_paths"])-set(ncorpus["required_paths"]):raise ValueError("N drops prior required path")
combined=copy.deepcopy(mcorpus)
combined["required_paths"]=sorted(set(mcorpus["required_paths"])|set(new_required))
for p in new_required:combined["pinned_blobs"][p]=oid(chosen[p])
pin_updates=[]
for p,b in chosen.items():
 if p==CORPUS:continue
 if p in combined["pinned_blobs"]:
  before=combined["pinned_blobs"][p];after=oid(b)
  if before!=after:pin_updates.append({"path":p,"before":before,"after":after})
  combined["pinned_blobs"][p]=after
if combined["pinned_blobs"].get(STORE)!=SELECTED_STORE["oid"]:raise ValueError("selected store corpus binding differs")
if combined["pinned_blobs"].get(WORKER)!=oid(chosen[WORKER]):raise ValueError("worker corpus pin missing")
# Existing representation is canonical sorted/indent2; preserve all unrelated keys and data.
b=(json.dumps(combined,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
choose(CORPUS,b,"Union M6 required/pinned set plus only6 N additions; rebind exactly the selected source file OIDs including independent worker; no removal, historical evidence rewrite or global regeneration.")
# Static identities and original method preservation; no imports or tests.
static={}
for p,b in chosen.items():
 if p.endswith(".py"):ast.parse(b.decode(),filename=p)
for p in ["scripts/ci/test_pq_lifetime_budget.py","scripts/ci/test_pq_lifetime_current_v2.py","scripts/ci/test_pq_lifetime_composition.py","scripts/ci/test_pq_chain_claim_guard.py","scripts/ci/test_public_readiness_evidence.py","scripts/ci/test_ci_contract.py","scripts/ci/test_pon_budget_controls.py","scripts/ci/test_sp27_receiver_controls.py","scripts/ci/test_sp27_strata_controls.py","scripts/ci/test_throughput_cost_coverage.py","scripts/ci/test_w1_qrom_current_ci.py","scripts/ci/test_w1_qrom_closure_current_controls.py","scripts/ci/test_w1_qrom_semantics_audit.py"]:
 final=defs(chosen[p]);orig=defs(src.get(("M6",p),b""))
 names=lambda d:{n for n in d if n.rsplit(".",1)[-1].startswith("test_")}
 original,selected=names(orig),names(final)
 static[p]={"M6_methods":len(original),"proposal_methods":len(selected),"removed_methods":sorted(original-selected),"added_methods":sorted(selected-original),"unchanged_source_methods":sorted(n for n in original&selected if orig[n]["source_sha256"]==final[n]["source_sha256"]),"unchanged_AST_methods":sorted(n for n in original&selected if orig[n]["ast_sha256"]==final[n]["ast_sha256"]),"changed_AST_methods":sorted(n for n in original&selected if orig[n]["ast_sha256"]!=final[n]["ast_sha256"])}
if static["scripts/ci/test_pq_lifetime_budget.py"]["proposal_methods"]!=58 or len(static["scripts/ci/test_pq_lifetime_budget.py"]["unchanged_AST_methods"])!=57:raise ValueError("58-method continuity")
if static["scripts/ci/test_pq_lifetime_current_v2.py"]["proposal_methods"]!=25 or static["scripts/ci/test_public_readiness_evidence.py"]["proposal_methods"]!=78:raise ValueError("selected roster")
if chosen["scripts/ci/pq_lifetime_current_v2.py"].count(old_map_sha.encode()) or chosen[COMP].count(old_snapshot.encode()):raise ValueError("stale current mapping literal")
# The companion current reader/config only change reviewed SHA literals relative to N.
literal_proofs={}
for p in (CURRENT_READER,COMP):
 original=src[("N",p)]
 expected=literal_replace(literal_replace(original,old_map_sha,new_map_sha),old_snapshot,new_snapshot)
 if chosen[p]!=expected:raise ValueError("current reader code changed")
 literal_proofs[p]={"only_literal_substitutions":[[old_map_sha,new_map_sha],[old_snapshot,new_snapshot]],"N_bytes":len(original),"selected_bytes":len(expected)}
# Ensure current-reader mathematical helpers from composition remain exact.
math_proof={}
md=defs(src[("M6",COMP)]);fd=defs(chosen[COMP])
for name in sorted(set(md)&set(fd)):
 if name not in ("default_manifest","validate_manifest","inspect"):
  if md[name]["raw"]!=fd[name]["raw"]:raise ValueError("arithmetic/helper changed "+name)
  math_proof[name]={"source_sha256":fd[name]["source_sha256"],"AST_sha256":fd[name]["ast_sha256"]}
for command in ("    python3 scripts/ci/test_pq_lifetime_budget.py\n","    python3 scripts/ci/test_pq_lifetime_current_v2.py\n","    python3 scripts/ci/pq_lifetime_current_v2.py\n"):
 if chosen["scripts/ci/ci_job.sh"].count(command.encode())!=1:raise ValueError("mandatory command count")
# Save full selected files and exact diff relative to M6, excluding unchanged retained files.
path_records=[];patches=[]
for p in sorted(chosen):
 b=chosen[p];before=src.get(("M6",p),b"")
 entry={"path":p,"M6":lookup.get(p,{}).get("M6"),"N":lookup.get(p,{}).get("N"),"selected":{"oid":oid(b),"bytes":len(b),"sha256":sha(b),"mode":(lookup.get(p,{}).get("M6") or lookup.get(p,{}).get("N") or {}).get("mode","100644")},"selection":decisions[p],"changed_from_M6":b!=before}
 if b!=before:
  entry["payload"]=put("files/"+p,b)
  oldoid=oid(before) if ("M6",p) in src else "0"*40
  newoid=oid(b);newfile=("M6",p) not in src
  mode=entry["selected"]["mode"]
  h=f"diff --git a/{p} b/{p}\n"
  if newfile:h+=f"new file mode {mode}\n"
  h+=f"index {oldoid}..{newoid}"+("" if newfile else " "+mode)+"\n"
  diff="".join(difflib.unified_diff(before.decode().splitlines(keepends=True),b.decode().splitlines(keepends=True),fromfile="/dev/null" if newfile else "a/"+p,tofile="b/"+p,n=3))
  raw=(h+diff).encode();patches.append(raw)
  entry["patch"]=put("patches/"+p.replace("/","--")+".patch",raw)
 path_records.append(entry)
fullpatch=put("M6-to-selected-proposal.patch",b"".join(patches))
put("all-path-dispositions.json",js(path_records))
put("selected-current21-provenance.json",js({"source_map_sha256":new_map_sha,"canonical_snapshot_sha256":new_snapshot,"N_source_map_sha256":old_map_sha,"N_canonical_snapshot_sha256":old_snapshot,"paths":selected21,"source_checks":"immutable Git blob evidence and exact M6..N full path-diff join; no reader executed"}))
put("static-test-and-helper-continuity.json",js({"tests_executed":False,"method_tables":static,"literal_only_current_readers":literal_proofs,"composition_unchanged_math_and_helpers":math_proof,"original_budget_reader":lookup["scripts/ci/pq_lifetime_budget.py"],"collector_C6_method":changed[0],"collector_C6_method_sha256":m6_defs[changed[0]]["source_sha256"],"ci_original58_once":True,"ci_new25_once":True,"corpus_added_required_paths":new_required,"corpus_pin_updates":pin_updates}))
fingerprint=sha(canonical([{"path":x["path"],**x["selected"]} for x in path_records]))
state={"schema":"trnm-concurrent-ci-selected-proposal-v2","status":"STATIC_PROPOSAL_NOT_APPLIED_OR_EXECUTED","base_head":REVS["M6"],"concurrent_head":REVS["N"],"common_source":REVS["C0"],"source_or_Git_or_refs_or_stage_or_network_access":False,"tests_executed":False,"native_qualification_granted":False,"full_combined_tree_not_yet_created":True,"selection_file_count":len(path_records),"changed_file_count":sum(x["changed_from_M6"] for x in path_records),"changed_payload_bytes":sum(x["selected"]["bytes"] for x in path_records if x["changed_from_M6"]),"selected_files_manifest_sha256":fingerprint,"full_patch":fullpatch,"current_map_sha256":new_map_sha,"current_snapshot_sha256":new_snapshot,"selected_store":SELECTED_STORE,"worker_selected":lookup[WORKER]["N"],"required_paths_before":len(mcorpus["required_paths"]),"required_paths_after":len(combined["required_paths"]),"pinned_paths_before":len(mcorpus["pinned_blobs"]),"pinned_paths_after":len(combined["pinned_blobs"]),"pending":"Root review/application as normal merge; independent final source gates, full original local lanes and required hosted checks."}
put("summary.json",js(state))
put("README.md",f"""# Static selected-source proposal for M6 and concurrent N

Status: **prepared only**. No working tree, Git object/ref, stage, configuration or network operation is performed by this producer. No suite, reader, helper, native workload or hosted gate is executed.

Apply scope, if approved by root, is the full files/ tree or the exact M6-to-selected-proposal.patch after the normal ancestry merge. Original N input blobs are retained in the parent content-addressed capture; all-path-dispositions.json names both immutable inputs and each selected output. Other M6 source/evidence paths remain untouched.

- M6 base: {REVS['M6']}.
- Concurrent N: {REVS['N']}.
- Shared C0: {REVS['C0']}.
- Selected complete store: {SELECTED_STORE['oid']}.
- Current21 raw map: {new_map_sha}; independent snapshot: {new_snapshot}.
- Three exact C0 frozen inputs remain separate from actual current correspondence.
- Original58 budget controls remain;25 new correspondence controls are independent.
- Exact collector16 and bad0/13/14/15 negative controls, B1 historical carrier, H1/F1/F2 repairs remain.
- Both endpoint-witness methods remain (static78 total). This count is not a test result.
- N worker artifact tightening is verbatim and owned by architecture/root review.

The legacy inspection CLI intentionally cannot relabel different current sources as the frozen V1. Mandatory current acceptance uses the explicitly bound new reader. The proof-profile descriptor and root register retain their existing semantics; their helpers do not silently waive current-source checks.

The current source maps, test rosters, arithmetic-helper AST/source identities and full path dispositions are supplied for review. Existing M6 successes and N failures remain tied to their original sources. Final combined tests, source gates and hosted required checks remain pending; no limits or qualification flags are relaxed.
""")
index=put("EVIDENCE_INDEX.json",js({"schema":"trnm-static-proposal-evidence-index-v1","files":artifacts.copy()}))
print(js({"status":state["status"],"summary":str(OUT/"summary.json"),"summary_sha256":sha(read(OUT/"summary.json")),"patch":fullpatch,"changed_files":state["changed_file_count"],"index":index,"selected_files_manifest_sha256":fingerprint}),flush=True)

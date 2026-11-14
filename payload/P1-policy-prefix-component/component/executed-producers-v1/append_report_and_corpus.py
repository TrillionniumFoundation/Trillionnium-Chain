import pathlib,os,subprocess,json,hashlib,sys,traceback
S=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-20261114');E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');O=E/'final-document-and-corpus-v1'
assert not O.exists();O.mkdir()
env=os.environ.copy();env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1')
def sha(b):return hashlib.sha256(b).hexdigest()
def oid(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def put(n,b):
 if isinstance(b,str):b=b.encode()
 (O/n).write_bytes(b);return {'path':str(O/n),'bytes':len(b),'sha256':sha(b)}
def run(n,a):
 r=subprocess.run(a,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);put(n+'.stdout',r.stdout);put(n+'.stderr',r.stderr);assert r.returncode==0,(n,r.returncode,r.stderr[-2000:]);return r.stdout
state={'schema':'trnm-policy-prefix-document-corpus-closure-v1','status':'HOLD','errors':[],'prior_dispatch_syntax_error':'First JavaScript preparation failed before any PTY or filesystem operation; this execution is the first document mutation.'}
try:
 summary_raw=(E/'current-consumer-validation-v2/summary.json').read_bytes();assert sha(summary_raw)=='ec1a745291e4ec3f4cda2eb9769d7196490edabc49e92587a17f2dca43b0f9be'
 suite=json.loads(summary_raw);assert suite['status']=='PASS' and suite['total_passed']==200
 meta=json.loads((E/'current-metadata-update-v1/summary.json').read_bytes());assert meta['status']=='CURRENT_METADATA_APPLIED_PENDING_ORIGINAL_CONTROLS'
 run('preflight',['bash','scripts/project-preflight.sh'])
 plan='docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md';report='docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md'
 heading='### 2026-11-14: PublicPolicy ID prefix-equivalence successor of M8'
 plan_add="""
### 2026-11-14: PublicPolicy ID prefix-equivalence successor of M8

The isolated successor starts from M8 ed0d35487f2a67239e4d646fd41c2c7acb5cc740
and changes only the existing PublicPolicy::id computation in
trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs. A private OnceLock
retains the unfinalized SHA-256 state after the immutable 5,105-byte framed
prefix. Each call clones it and appends all six original framed suffix fields.
The original resource literal, domain, encoding, returned bytes, fresh Host
checks, nonce order, deadline cadence, 4-second window and 16 pressure workers
are unchanged. The 84 original tests in that file remain byte-identical; three
oracle/suffix/clone-independence controls are added. No nonce optimization is
included.

The Mac libtest build remains HOLD with 11 existing Darwin fixture errors
before any test ran. On the independent Linux M8-plus-Rust-proposal worktree,
the first run used serial RUST_TEST_THREADS=1 and passed three new controls
plus the original golden. A separate run removed every RUST_TEST_* environment
variable and passed the same 3 + 1 with the default harness. Strict all-target,
all-feature Clippy passed and was not repeated. Its SQLite I/O boundary warning
about nonabsolute RUSTC remains in the raw evidence; these results grant no
SQLite/native or hosted-performance qualification.

The current correspondence/composition digests change only for the reviewed
source bytes. All three frozen model/lock/composition JSON files, historical
identities, mathematical controls, caps and false qualification fields remain
unchanged. After preserving the Mac temporary-directory symlink refusal, the
same original 58 + 25 + 60 + 57 consumer controls passed with a canonical
temporary directory. Seven policy-vector and 33 Hash-use controls also passed.
The Hash-use reader still covers only its 19 declared purposes and 31 sources,
not this entire call graph. The normal merged-source and hosted gates remain
required; no 4-second completion or latency improvement has been measured.
"""
 report_add="""
### 2026-11-14: PublicPolicy ID prefix-equivalence successor of M8

This local component starts from M8 ed0d35487f2a67239e4d646fd41c2c7acb5cc740
(tree 1aa9c21812489080980bdc3c1c2bb43611e88354). The reviewed Rust patch is
16,945 bytes, SHA-256
519f7b6950743386f53e655edf5e31d3f198de581c7125461a08b28d81211a37.
The original public_v3.rs is 433,736 bytes, SHA-256
1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70;
the candidate is 438,782 bytes, SHA-256
0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a.
Reversing the four declared transformations recovers the original file byte
for byte, including all 84 preexisting test bodies and all Host, authorization,
nonce and deadline code.

The private cache retains the unfinalized state of the existing pon_wire::hash
framing after its immutable 5,105-byte prefix: 79 complete SHA-256 blocks plus
49 buffered bytes. The six original framed dynamic fields add 61 bytes; warm
calls finalize two blocks from a cloned state. These are encoding counts, not
measurements or a latency bound. Cold initialization still performs the prefix
work. The four-thread control checks independent clone results, but does not
guarantee that the harness scheduled simultaneous cold initialization.

Actual observations remain distinct:

- Mac libtest compilation: HOLD, 11 existing Darwin fixture errors and zero
  executed Rust tests; summary SHA-256
  2447c1d7d7300e3a1b8d0d2591ad362c294b261510ef493511496d0a8bfcdcdf.
- Independent Linux M8 plus the exact single-file Rust proposal: serial
  RUST_TEST_THREADS=1 passed the three new controls and original full-qualified
  golden. Strict all-target/all-feature Clippy with -D warnings passed.
  Summary SHA-256
  bf16496bd43d61e935e84748177d8add0ef5cc661be35f77ddb2ec11f94448f4.
- Default-harness follow-up: all RUST_TEST_* environment variables were removed;
  unchanged 3-prefix and 1 --exact commands passed with no ignored tests.
  Summary SHA-256
  0be788fea02aa1a59869c7610f42002c39954f52a63b4f4a76bfdf78f038780a.
  Clippy was not repeated. Both Linux records verify that the root M8 worktree
  stayed clean and the independent uncommitted proposal did not change.
- Original Python policy-vector 7/7 and Hash-use 33/33 controls, the actual
  Hash-use inspector and workspace formatting passed; summary SHA-256
  6464a84fa41517c4d41b0ff4a03032009347c079a904e363a291ed7c4ad8a27a.
- The first budget suite encountered the Mac system temporary directory's
  symlink ancestor: 53 passed, one failed and four errored. That failure is
  preserved. With only a canonical temporary directory selected, unchanged
  budget58, current-correspondence25, composition60 and chain-claim57 all
  passed. The three actual inspectors retained HOLD/HOLD_NO_GO and
  activation=false. Summary SHA-256
  ec1a745291e4ec3f4cda2eb9769d7196490edabc49e92587a17f2dca43b0f9be.

The Linux compilation warning "SQLite I/O boundary UNQUALIFIED: RUSTC must be
absolute" is retained. The hash controls grant no SQLite/native acceptance;
Clippy applies to the exact isolated Rust-proposal source. These are not
hosted 4-second results.

For one reviewed successful paid RPC, the server computes the base policy ID
once for cookie construction, once for Solution validation, once for body
validation and once for response construction; the client computes it once
and reuses it. WaitGrant polling does not repeat it. This is a per-RPC static
count, with no proven global invocation bound. Two historical numbers are
different: the W1 trace's 1,099 fresh Host observations are
3 + 256 + 128 + 512 + 200; the separate x64 policy-stage lower bound is
370 issued + 369 spent + 360 delivered = 1,099 (ARM:
524 + 519 + 510 = 1,553). The latter uses distinct server counters, not direct
id() instrumentation, an exact 4-second interval or a Host count.

This successor's current 21-path map changes only the public_v3.rs digest.
Its new raw-map SHA-256 is
4f234fbff89fdf5693b4d7b82676a46574f92e297fdd535101110a76b9abb3e0,
and canonical source-map digest is
e8b0d9ceb227e95a045cee1b9224719c8b9ac9c416f8f503218bfee0160d57dc.
The current reader and composition independently bind this pair. These
successor metadata bytes are not claimed to exist at the M8 commit. Frozen
V1 budget, source lock and V2 composition remain respectively SHA-256
0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd,
094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2 and
5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052.
Path sets, mathematics, caps, flags and source-revision limitations are
unchanged. H1's 19-use/31-source inventory is not expanded: the helper retains
the existing PublicPolicy SHA-256 purpose, reviewed by framing/oracle evidence,
without claiming full-callgraph coverage. No nonce optimization, Host-check
reduction, limit increase or qualification waiver is included.
"""
 for path,addition in [(plan,plan_add),(report,report_add)]:
  raw=(S/path).read_bytes();assert heading.encode()not in raw
  put(path.replace('/','--')+'.before',raw)
  new=raw.rstrip(b'\n')+b'\n\n'+addition.strip().encode()+b'\n'
  (S/path).write_bytes(new);assert(S/path).read_bytes()==new
 changed=run('changed-before-corpus',['git','diff','--name-only']).decode().splitlines()
 expected={'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs','config/pon/pq128-source-correspondence-current-v2.json','scripts/ci/pq_lifetime_current_v2.py','config/pon/pq128-lifetime-composition-current-v3.json','scripts/ci/pq_lifetime_composition.py','docs/security/PQ128_LIFETIME_BUDGET_V1.md','docs/security/PQ128_LIFETIME_COMPOSITION_V2.md',plan,report}
 assert set(changed)==expected,changed
 corpus='config/pon/pq-cross-branch-corpus-v1.json';old=(S/corpus).read_bytes();data=json.loads(old)
 assert corpus not in data['pinned_blobs']
 before_roster=set(data['pinned_blobs']);pairs=[];outside=[]
 for path in sorted(expected):
  raw=(S/path).read_bytes()
  if path in data['pinned_blobs']:
   baseline=run('baseline-oid-'+path.replace('/','--'),['git','rev-parse','HEAD:'+path]).decode().strip()
   assert data['pinned_blobs'][path]==baseline,(path,'old corpus pin mismatch')
   pairs.append({'path':path,'old_oid':baseline,'new_oid':oid(raw),'bytes':len(raw),'sha256':sha(raw)})
   data['pinned_blobs'][path]=oid(raw)
  else:outside.append(path)
 assert set(data['pinned_blobs'])==before_roster
 (S/corpus).write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
 assert json.loads((S/corpus).read_bytes())==data
 put('corpus-pin-deltas.json',json.dumps({'changes':pairs,'changed_files_outside_existing_corpus':outside,'roster_unchanged':True},indent=2)+'\n')
 finalpaths=run('changed-paths',['git','diff','--name-only']).decode().splitlines();assert set(finalpaths)==expected|{corpus}
 patch=run('working-diff',['git','diff','--no-ext-diff','--no-textconv']);run('diff-check',['git','diff','--check'])
 helptext=run('corpus-cli-help',['/opt/homebrew/bin/python3','-B','scripts/ci/pq_cross_branch_corpus.py','--help'])
 state.update(status='DOCS_AND_EXISTING_CORPUS_PINS_CLOSED',changed_paths=finalpaths,changed_path_count=len(finalpaths),corpus_changed_pins=len(pairs),corpus_roster_unchanged=True,corpus_unselected_paths=outside,patch={'bytes':len(patch),'sha256':sha(patch)})
except BaseException as exc:state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
put('summary.json',json.dumps(state,indent=2)+'\n')
print(json.dumps(state,indent=2),flush=True)
sys.exit(0 if state['status']=='DOCS_AND_EXISTING_CORPUS_PINS_CLOSED'else 1)

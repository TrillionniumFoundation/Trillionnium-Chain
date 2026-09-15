# `trnm-native-execution-v0`

Active zero-foreign deterministic application and durable execution-artifact-P
owner for the frozen PoCO-BFT v0 profile.

For ordinary, non-empty successor blocks, the application:

- opens one exact authenticated parent JMT snapshot containing committed
  parameters, signer policy, replay indices, validator lifecycle, PoCO state,
  and runtime objects;
- verifies exact signed outer bytes and executes the body in order, so later
  transactions observe earlier in-block writes;
- applies runtime, validator-lifecycle, PoCO/cutoff, and mandatory system
  writes to one collision-checked state plan;
- independently derives the payload, complete post-state, receipts, and
  empty-evidence roots;
- exposes an independent immutable preview request with no block ID or
  caller-supplied roots, returning only the four derived roots, exact receipts,
  and request/write-plan fingerprints; final execution recomputes everything;
- atomically records the canonical `NativeExecutedBlockV0` artifact, complete
  target snapshot/overlay, replay sets, lifecycle record, store identity, and
  monotonic local sequence in SQLite; and
- performs an immutable fresh-connection readback and recomputes the complete
  target JMT/root before it can return `Valid`.

Prepared P records form a BlockId-keyed overlay DAG rather than a height-keyed
single slot. Sibling forks can coexist, and a child can execute from the exact
fresh-confirmed snapshot of a prepared parent. The application commit ID is
derived when P is created, so a child's parent commitment remains stable when
that parent is later finalized. Committing is permitted only for the exact
child of the current committed head; it atomically promotes that finalized
prefix, retains its prepared descendants, and prunes losing siblings.
A QC is never interpreted as an application commit or finality instruction.
An explicit `commit_finalized_block_v0` adapter is available for integration
tests: it requires a complete `FinalityProofV0`, verifies that proof with the
strict Ed25519 verifier, binds its finalized header (BlockId, height, state
root, parent, timestamp, and committed roots) to the exact executed block, and
then delegates to the existing atomic commit. This adapter is not a Core
callback, does not mint Safety/signer authority, and does not enable
`qc_as_application_commit` or production activation.

The schema-v3 journal also contains one separate fresh-genesis state-sync
import path. Given an exact h1 execution request and a nonzero proof identifier,
it independently recomputes the full transition from the initialized genesis
snapshot, atomically installs the h1 application TrustedBase, and records a
checksummed proof/request/artifact/snapshot binding. It deliberately creates no
local durable-P row, validation job, completion, terminal fact, or speculative
overlay. Retry and reopen require byte-exact proof/request readback; a foreign
proof, a previously used store, row tampering, or schema-v2 store is rejected.
The proof identifier remains comparison input: this crate does not verify BFT
finality, so only the Node's consuming Core/Safety/signer commissioning join may
use the confirmed import.

`DurableNativeApplicationV0` implements `NativeApplicationV0`. Its public owner
is non-`Clone`, the durable-P record is private, a second process is excluded by
an owner lock, and reopen validates the complete committed-prefix/overlay DAG.
Store substitution,
sequence rollback, artifact/snapshot/lifecycle/replay substitution, schema
drift, malformed/WAL SQLite sidecars, broken ancestry, duplicate sequences,
and non-exact commit requests fail closed. A regular hot rollback journal left
by a killed writer is repaired only through SQLite's own write-transaction
rollback path, followed by database-and-directory fsync and immutable
readback; WAL/SHM or unverifiable sidecars remain fail-closed.
An applied-but-acknowledgment-lost commit is recovered by exact idempotent
readback; either metadata-only or P-only partial-commit third states are
permanently fenced. Unresolved prepared P records yield
`ValidationReplayRequired` with their exact count.

## Authority boundary

This is a durable application boundary, not a complete validator safety path.
It has no Core permit or Valid callback, no SafetyStore authority, no whole-node
checkpoint/CAS, no signer watermark, no `RequestSignature`, and no signing,
network, or broadcast capability. It is not wired into the default Node
process host and is not a production candidate.

The current tranche is also intentionally narrower than the whole frozen-v0
protocol:

- evidence must be empty;
- the committed validator set/epoch supplied at store creation remains the
  execution authority; validator-set activation and a returned validator-set
  update are not implemented;
- a local SQLite sequence detects in-file rollback but is not an external
  whole-machine anti-rollback authority;
- a three-boundary SIGKILL matrix (before SQLite commit, after commit, and
  after directory fsync) plus critical-page short-write tests now prove the
  local commit coordinator's atomic/replay behavior; this is not a full
  power-loss, filesystem, or multi-process takeover campaign;
- database and containing-directory fsyncs are attempted after genesis, H1
  TrustedBase, and finalized application commits (and during hot-journal
  recovery), but no external anti-rollback, file-descriptor pinning, remote
  signer, or whole-node checkpoint evidence is claimed; and
- canonical runtime attempts preserve typed deterministic rejection codes and
  authenticated-state unavailability; runtime/mutation/PoCO/lifecycle invariant
  faults fail closed. Non-runtime outer/body/schema failures still use the
  existing closed fallback rejection code; exhaustive classification of those
  helpers remains future work.

Accordingly, `durable_artifact_p=true` and
`native_application_v0_implementation=true` do not imply Core/Safety authority
or production activation. The finalized-commit adapter is an integration seam
only; `qc_as_application_commit`, `core_application_seal_eligible`, and
`production_candidate` remain false in package and project status metadata.

## Bounded execution and inventory read optimizations

`native_parallel.rs` retains a private one-use cache only after the existing
strict envelope verifier succeeds. The ordered owner may reuse that work only
for byte-for-byte identical input under the same chain and timestamp. It still
checks the original decoded envelope, the commissioned signer policy, block
and committed replay, nonce, runtime dependencies, fees and atomic mutations.
An invalid envelope cannot construct this cache. A mismatch consumes it; a
missing cache always runs the original verifier.

Retention is at most 64 KiB of original bytes per attempt, at most 32 attempts
per batch, plus the already bounded context. A larger valid envelope or failed
buffer reservation disables reuse, not transaction validity. There are no new
wire fields, signature domains, fee rules, public constructors or activation
flags. The six added tests in `native_parallel_tests.rs` cover exact-byte and
context binding, single use, all worker counts, replay, invalid signatures,
oversize fallback and the signer-policy boundary. These tests require Rust
execution; their presence alone supplies neither acceptance nor speed figures.

`durable.rs::map_p_inventory_v0` retains a key-only cursor while consuming each
complete row. `load_p_by_block_v0` reuses a prepared statement, never cached row
bytes. This removes repeated statement preparation and the temporary Rust
collection of all IDs. It does **not** remove N point lookups, history auditing,
full snapshots, JMT verification or serial commit. It does not add an index or
sort full historical snapshot BLOBs. The mapper must not write on its own
connection or publish a prefix before every row has passed validation.

The normal-connection WAL regression tests SQLite cursor snapshot behavior;
WAL is **not** commissioned for the native immutable-read owner. Its namespace,
lock, close/readback and full integrity requirements remain unchanged. The
Python test `scripts/ci/test_native_inventory_sql_v0.py` executes the actual
schema and key/lookup query strings with synthetic SQL payloads and reproduces
the old mixed-read pattern. It is SQL-only evidence, not Rust recovery or a
physical-fault campaign. Three additional Rust inventory tests must run through
the actual application fixtures before adoption.

## Authenticated snapshot recovery

Primary module: M07. Consumers: M06 execution and M08 finalized recovery.
Snapshot admission checks every retained root against its indexed JMT root
node, including historical versions below a healthy latest head. A missing
root node, substituted root node or mismatched retained root rejects recovery.
This replaces the per-version scan of the full node map with JMT's indexed
root lookup; it does not prune history or change snapshot codec bytes.

Latest-state admission still verifies every live value and key preimage against
the latest root. The shared verifier passes one proven value at a time to its
consumer and detects duplicate keys using borrowed key references. Recovery
discards these values after verification; callers that request the full live
map explicitly collect it. This removes an additional full live-value map from
recovery's peak memory, not the decoded snapshot itself. Complete historical
leaf audits, incremental persistence, retention/GC and measured finalized
throughput remain separate obligations. Local corruption regressions do not
establish an external rollback anchor or independent storage acceptance.

## Native complete-execution vector

The maintained corpus contains only native PoCO inputs and outputs.
`native-complete-durable-p-v0.json` pins the full four-root ordinary-body
result, transaction-byte digests, durable sequence transitions, recovery
dispositions, and authority-false boundary. Its raw file digest is checked by
the boundary gate, while the Rust test recomputes every value from the native
inputs. No removed application, node harness, adapter, archive, or differential
oracle is built or executed.

## Test-only sync fault ownership

Primary module: M06. Consumer: M17 exact-source qualification.
The `cfg(test)` fault registry is scoped by the exact store path. Different
store paths may be armed concurrently; two outstanding faults for one path
are rejected before changing the registry. Matching path and boundary consume
one fault exactly once. A wrong path or boundary consumes nothing.

Each guard owns an independent allocation identity. Its destructor removes only
that registration, even after consumption and rearming the same path/boundary.
Panic unwinding must release only the unwinding test's fault. Registration
rejection releases the mutex before panicking, so it cannot poison unrelated
store tests. This is fixture isolation, not a production filesystem identity,
canonical-path, crash-durability or consensus guarantee. Test callers use the
same application path at arm and consume; aliases are not normalized here.

The retained direct registry regressions supplement, not replace, the existing
SQLite initialization, H1 import and finalized-commit sync-failure regressions.
Parallel tests remain enabled and their failure assertions remain unchanged.

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-native-execution-v0 --lib --locked
```

The registry and new tests compile only under `cfg(test)`. Production sync calls,
commit/recovery logic, public APIs, hashes and database schema are unchanged.

The unwind test first proves that registration succeeded and then checks the
exact injected panic payload. A panic in registration itself must not satisfy
an unwind-cleanup test. The same-path race uses two workers, bounded start and
release channels, and overlapping guard lifetimes to require exactly one
successful registration. The winning fault is consumed from another thread,
then the same path is rearmed before the old worker guard is dropped; the new
registration must survive that drop. All five direct registry tests retain
parallel execution. These tests supplement the existing SQLite initialization,
H1 import and finalized-commit uncertainty tests; they do not replace them.


## Native checkpoint authorization

Primary module: M06. The native owner now produces the application-side
checkpoint authority chain in `poco_checkpoint`, `poco_authenticated_candidate`,
`poco_epoch_commitment`, `poco_checkpoint_header`, `poco_joint_handoff`, and
`poco_preparation_journal`. The private constructors accept no generic verifier,
caller-normalized candidate transcript, or inert-kernel conversion.

`prepare_native_poco_checkpoint_v0` reconstructs the exact committed cutoff JMT
and lifecycle, audits the complete kind-16 projection, computes B2-G with strict
Ed25519 verification, and joins the raw H1 finality chain and generated H2
namespace membership proofs. It derives native execution from the live owner's
preview and freezes the exact parent ID, timestamp, body, receipts and state.
The returned opaque `PreparedNativePocoCheckpointV0` requires a successful
independent preparation-journal reservation and exact header binding.

`confirm_poco_checkpoint_v0` revalidates that existing journal reservation,
requires the exact checkpoint execution to be COMMITTED in the same native
owner, compares the complete body and receipts, reconstructs the post-execution
candidate/commitment, and strictly verifies the checkpoint/two-seal and handoff
proofs. `ConfirmedNativePocoCheckpointV0` retains the owner-affine durable row;
it has no public constructor or conversion from naked roots or proof kernels.
After reopening, the same raw proof inputs reconstruct preparation using the
exact committed P readback instead of pretending an old parent is a live head.

`confirm_poco_checkpoint_for_handoff_v0` is a separate pre-certificate
readback candidate. It first bounds and strictly verifies the checkpoint and
two seals using M01's `decode_verify_checkpoint_finality_strict_v0`, then repeats
the original COMMITTED-row, preparation-owner, body/receipt and recomputed
cutoff/next-set provenance checks. It requires no joint handoff certificate.
The returned `CommittedNativePocoCheckpointForHandoffV0` has private fields and
no Clone or deserializer; it exposes only readback facts and the existing frozen
handoff descriptor. Neither this receipt nor its descriptor authorizes a seal or
old/new-role signature. The supplied admission budget is for this checkpoint
proof pass; cutoff/native provenance work retains separate existing bounds.

`complete_poco_checkpoint_handoff_v0` consumes the receipt and subsequently
supplied joint-certificate bytes, reopening/rechecking the same native and
preparation authority through the original confirmation path. A held receipt
cannot bypass journal halt, missing/replaced records, another owner or stale
native state. The six new native regression functions cover pre-certificate
readback, PREPARED-state refusal, corrupted-proof work charging, zero budget,
held-receipt invalidation and reopening the actual application stores. Six M01
regressions cover strict verification and exact budget edges. These Rust
regressions are authored verification targets, not an assertion of local compiler
or test execution. The independent Node corpus test is signature/byte evidence
only, not native runtime, state or epoch acceptance.

The preparation journal publishes a reservation or binding only after SQLite
commit and a fresh connection read back the exact transition, preparation,
bound record and phase, with database path/inode identity checked again. A
missing row is not recreated by this confirmation. Commit or readback
uncertainty sets the process-shared sticky halt; the capability is withheld.

Local admission limits are 64 transitions, 1,024 preparation records and
256 MiB of aggregate encoded records to audit. New records must fit before
insertion; exact retries and binding an existing reservation remain possible
at the record-count limit. SQLite also has a 512 MiB database page ceiling,
with database and sidecar physical bytes checked before connections and after
commit readback. These checks are not an OS disk quota and do not isolate
transient WAL space during a transaction. Ordinary capacity exhaustion returns
an embedded `std::io::ErrorKind::StorageFull` as local unavailability; it does
not mark a peer block invalid, halt a healthy journal, or erase earlier rows.
There is no automatic journal garbage collection and no independent external
rollback anchor: coherently restoring the application and sidecar together
still requires the separate whole-node recovery authority.

Four native database regressions cover committed-cutoff enforcement, exact
preparation/reopen, a signed checkpoint/two-seal/handoff with committed P and
restart recovery, and held-token rejection after sidecar halt, row deletion,
file replacement or owner substitution. The historical raw protocol corpora
and all source privacy/durable-preparation checks remain enabled. These are
local implementation tests, not independent module or production acceptance.
The 20 journal regressions additionally cover publication-time replacement,
halt and missing-row faults, exact retries at the real record limit, oversized
database rejection and scan/transition admission budgets.

This application authority does not advance Core's epoch fence or mint a
signing permit. The separate consensus checkpoint-applied/seal/activation state
and the native JMT/version progression through the seal heights remain required
before a live first block of the next epoch can execute.

## Frozen operation-sequence profile boundary

The retained `poco-application-operation-sequences-v0.json` corpus contains nine
sequences, 18 positive steps and nine negative cases. Its five full-store
sequences share eight initial physical writes whose JMT root is exactly
reproducible by the current native store. Their historical signer-policy hash
uses a different domain profile, so the current native application constructor
rejects that genesis with `bootstrap lifecycle signer-policy mismatch`. A Rust
negative regression locks both the exact initial root and this refusal.

This does not provide a current-profile durable replay of the nine sequences.
The original signed operations bind their decision IDs to the historical
source root and authority commitment; rewriting the initial policy and signing
new operations would produce a different corpus. A reviewed profile mapping
and complete native submission, commit and recovery evidence remain required.
The historical operation-sequence gate is not restored or declared complete
by this negative test.

The same test module now also replays the unchanged corpus through the actual
private PoCO transition kernel. Nine named cases cover all 18 positive steps
and nine typed rejections, including the four explicitly isolated prune
sequences. They compare frozen operation IDs/counts/roots, complete namespace
writes, mutation roots, manifest/projection bytes and historical JMT roots;
negative cases require unchanged overlay and snapshot bytes. The corpus SHA-256
is pinned in the test, and no expected root is regenerated from the kernel.

This seam supplies historical context directly inside `cfg(test)`. It does not
admit that context through the current application owner, authenticate outer
signatures, call ProcessProposal/FinalizeBlock, persist a durable P artifact or
qualify restart. The separate owner-profile rejection above remains required.


### Pre-certificate checkpoint commit

`commit_poco_checkpoint_for_handoff_v1` joins the existing native preparation
and exact executed P to actual old-set checkpoint/two-seal finality before
calling the existing atomic application commit. It needs no joint handoff
certificate and creates no seal application rows. The independently commissioned
old configuration must equal the preparation context. One bounded strict
Ed25519 proof pass verifies the exact prepared header/parent/commitment and all
required shares before storage commit; header/body/receipt equality, the original
preparation namespace and a freshly authenticated exact durable execution row
must also pass. An exact already-COMMITTED replay is allowed only through the
existing current-head/idempotency checks, never by inventing a row or artifact.

After commit, fresh native/preparation readback reconstructs cutoff/next-set
provenance and the exact committed receipt. Only then does the operation return
`CommittedNativePocoCheckpointForHandoffV0` to the later, separately authorized
role-signing path. The immutable strict proof is retained across that operation;
there is no late second proof pass whose work budget could fail after commit.
Existing native/cutoff audits retain their separate bounds. No signature,
checkpoint CAS, publication or epoch activation is performed by this method.

`NativeCheckpointCommitErrorV1::BeforeCommit` means the native commit call was
not reached. It is a local preflight result, not a consensus transaction error.
Every error at or after commit is `Uncertain`; callers must fence dependent
participation and perform fresh readback or retry the identical checkpoint.
Reconstruction uses the original preview request and raw cutoff evidence, not a
new request based on an advanced head. Post-commit sidecar failure cannot be
reported as "nothing happened". This does not establish atomicity between the
native database and preparation journal or independent rollback resistance.

The real SQLite/Ed25519 tests in
`poco_checkpoint/native_authorization_tests/checkpoint_commit_tests_v1.rs` cover
strict commit before handoff, unchanged application state on invalid signatures,
byte/work limits, substituted execution, missing/halted/replaced/foreign
preparation, and database/directory synchronization failures after commit.
Reopen and repeated exact commit must recover one sequence and one application
effect; neither seal height may acquire a dummy application row. This closes
this bounded commit-producer gap, not live seal voting, Safety14, new-epoch
ancestry, consensus/JMT coordinate progression or two continuous epochs.


### Native finalized snapshot read/export

Primary implementation owner: M06; consumers M07/M08/M13. This is an additive
read boundary over the unchanged native Borsh/JMT and native manifest domains,
not the generic M13 `TRNMSM01` storage format and not an installation capability.

`DurableNativeApplicationV0::begin_finalized_snapshot_export_v1` first verifies
actual strict PoCO finality for an already COMMITTED application row. It then
freshly audits the native source and binds the exact current head, durable
sequence, store identity and SHA-256 snapshot digest to a private owner-affined
`NativeSnapshotExportV1`. Historical targets and PREPARED rows cannot export.
The manifest producer checks its 4,096-descriptor bound before allocating the
array. `read_snapshot_chunk_v1` accepts that original live owner's token and one
index, freshly validates source identity/head/sequence/snapshot again, and
returns only the exact indexed bytes under the existing native chunk domain.
Reopen, another owner or intervening source movement invalidates the token; the
caller must re-prove/export the current target rather than mixing generations.

`verify_native_snapshot_stream_v1` consumes an independently trusted
`StrictFinalityProofV0`, the local immutable native configuration, exact native
manifest, fallible chunk iterator and local read limits. Manifest metadata never
chooses the trust anchor or validator set. The oldest certified header must
match chain, genesis, profile, epoch, validator/parameter commitments and exact
height/block/root before input is read. Each chunk must match its indexed
length/digest; one look-ahead item detects extra input. Short, reordered,
corrupt or over-budget input cannot yield a result. Original transport errors
are retained separately from local resource exhaustion and invalid snapshots.
These are local read dispositions, not transaction-invalidity codes.

The reader parses the actual native Borsh snapshot field order: node map,
versioned values, preimages, stale-node set and retained roots. It limits
aggregate entries before insertion, checks sorted unique keys, validates length
prefixes before application-value allocation and compares each re-encoded entry
to its exact input. JMT NodeKey nibble lengths/padding are validated in at most
52 stack bytes before the dependency's derived decoder can bypass constructor
invariants. Shared validation in both the original slice decoder and this reader
checks node path/type/count/version invariants, actual child references/hashes,
leaf counts and retained leaf/value hashes at the leaf's own version. It then
runs the existing retained-root, preimage and latest live-value proof audit.
These internal historical checks do not independently finalize old roots.

Before returning, the latest actual JMT version/root and authenticated validator
lifecycle must match the strict target, chain, local signer policy and active
validator projection. The native snapshot manifest digest is recomputed from
the exact streamed SHA-256 and native chunk digests. The private non-Clone
`VerifiedNativeSnapshotReadV1` exposes height/block/root/snapshot/proof digests
and byte count, but deliberately not the local manifest commit ID: that ID is
not independently authenticated by consensus. Decoded replay sets are empty,
the temporary store is discarded, and no Core, signer, install or replay-floor
authority is issued.

Local limits are positive byte/entry/record budgets, with hard admission caps
of 4 GiB encoded bytes, 2,000,000 aggregate entries and 16 MiB encoded record
size; operators must choose budgets appropriate for their actual memory. Only
one transport chunk and one record copy are retained in addition to the decoded
JMT collections. A transport must bound allocations/deadlines before yielding
chunks. The complete decoded JMT remains resident, every source chunk request
still audits full native history/snapshot, and historical roots remain retained.
This is not native incremental persistence, bounded-history recovery, pruning,
a network downloader or an end-to-end throughput improvement.

`pcc1_finality/snapshot_stream_tests.rs` uses actual SQLite native execution and
strict Ed25519 finality to test export/read, owner replacement, PREPARED refusal,
root substitution, corruption, short/extra streams, typed transport errors and
pre-read resource limits. `snapshot_reader_v1.rs` covers bounded/noncanonical
Borsh and malformed JMT metadata, including corruption below a healthy latest
root. Source-bound execution logs are separate from these required properties;
independent acceptance and whole-node state-sync installation remain open.

## Candidate framed recovery transfer

The real finalized catch-up owner now consumes bounded byte streams through
`receive_framed_stream_v1`. Source records come from
`read_finalized_catchup_block_v1`; snapshot bytes come from the existing immutable
pinned export. Exact framing, preverified target, real execution/commit, final
JMT equality and trailer/EOF all precede owner release. Failed transfers retain
only independently finalized prefix work and require fresh database recovery.

See [the operation contract](../../../docs/modules/TRNM_NATIVE_CATCHUP_STREAM_V1.md)
for every field, resource ceiling, error/retry rule, Node TCP absolute-deadline
consumer and regression scope. This is candidate application recovery, not
Core/Safety rejoin, live epoch transitions, incremental persistence or activation.

# M07 State / JMT / Storage technical specification v1

Status: **candidate sparse-epoch computation and bounded schema-4 persistence implemented;
ordinary schema-5 incremental owner and conservative node-only GC implemented; sparse
migration, multiple-epoch recovery and production acceptance pending**.
Primary module: M07. Producers: M06/M08/M13. Consumers: M02/M06/M08/M13/M14.

## Authority

Frozen v0 state roots, checkpoint/cutoff equality and seal semantics remain
unchanged. `trnm-native-execution-v0/src/{store,durable,complete,poco_checkpoint}.rs`
and application snapshot/SQLite implementations define current source behavior.
`NativeExecutionStoreV0` is presently an externally implementable candidate read
boundary; internally consistent values are not proof of a lifecycle-pinned
production snapshot. The target creates that authenticated immutable ownership.

Schema3/4 durable execution encodes complete historical JMT snapshots in P records
and audits retained history. Explicit ordinary schema3→5 migration now changes
actual preparation/commit persistence to incremental nodes, values and replay
state; it preserves key/value codecs, state roots and receipts. Opening a database
never automatically changes its backend.

### Implemented candidate and remaining persistence boundary

`trnm-native-execution-v0/src/epoch_store.rs::CarriedRootReaderV1` now implements
the root-only adapter specified below. `complete.rs::compute_complete_epoch_native_block_v1`
uses it with the opaque M08 edge, computes the authenticated configuration/usage
prefix and user operations into one C+3 plan, and preserves ordinary +1 checks.
The read-only `preview_epoch_block_v1` and durable `execute_epoch_block_v1`
require owner affinity, a fresh committed checkpoint P digest/sequence and exact
current head C. The latter produces a separately encoded dual-parent P through
M08's explicit schema-4 bridge. `preview_epoch_descendant_v1` and
`execute_epoch_descendant_v1` use an owner-affine prepared P to compute/store
C+4/C+5 before the first-new finality arrives. They do not publish those roots.

The plan's private epoch tag permits exact C to C+3 application to an in-memory
copy. Empty, leaf and internal JMT tests retain real child versions, reject
physical seal rows and compare roots against ordinary contiguous computation.
The real signed fixture persists C=8 to P11/P12/P13, closes/reopens the store,
strictly verifies real new-set three-chain signatures, and commits11 once.

Sparse snapshot **local codec 2** is enabled only through the schema-4 epoch
bridge in `epoch_store.rs` / `epoch_durable.rs`. It retains the existing Borsh
snapshot field order and node/value encodings, changing the local version to2.
Every root gap must be exact C to C+3; the checkpoint root must match, all gap
rows must be absent, and active parameters must match retained strict evidence.
Codec1 rejects sparse root histories and its decoder rejects codec2. The local
checksum alone cannot create an edge: prepared-capability recovery reconstructs
native checkpoint/cutoff, original bound preparation and strict joint evidence.
The bridge retains complete snapshots and audits retained history; it does not
close storage growth or per-block cumulative audit cost.

The current bridge admits the first transition from a legacy-v0 committed
checkpoint and ordinary descendants. A later epoch checkpoint from P familyv1,
full sparse-history proof/RPC adapters, state-sync installation and schema4→5
incremental migration remain pending. These limitations are fail-closed.

## Interfaces

### Implemented incremental transaction kernel and ordinary owner

`store::incremental_store_v1` now contains a real SQLite JMT delta kernel using
`incremental_schema_v1.sql`. It borrows the native owner's transaction; it opens
no file, creates no signing owner and returns no native commit/finality receipt.
The explicit ordinary schema-5 owner below joins these operations to actual
P, replay, lifecycle and commit state in the same transaction. Schema3/4 retain
their snapshot paths. There is no automatic backend switch.

- `install_incremental_schema_v1` creates the exact new tables inside the
  owner's explicit migration transaction. `check_incremental_schema_v1` is the
  open/migration inventory check and rejects altered definitions, extra indexes
  and triggers. It is not rerun as a per-block historical audit.
- `import_incremental_snapshot_v1` currently admits only a fully checked
  canonical genesis snapshot with one real root and sequence0. Multi-root or
  positive-height imports use the separate explicit history importer below.
- `import_incremental_history_v1` accepts a fully audited ordinary snapshot and
  an owner-authenticated exact root/block/epoch list. It checks every contiguous
  real root, imports physical history once and records `ni_imported_root`
  bindings under a source-anchor digest; the native owner must bind that anchor
  in its explicit migration record. This is a storage primitive, not an owner
  migration API or downloaded-snapshot authority. Sparse imports remain fenced.
- `retire_incremental_prepared_v1` retires a selected uncommitted subtree in
  child-first order and releases exact anchor pins/references. The owner must
  retire native P rows in the same transaction and roll back on any error.
  `ni_sequence` retains the prepare watermark after pruning, preventing reuse
  of a retired last preparation's sequence.
- `open_incremental_reader_v1` resolves an exact committed block or prepared
  state-delta artifact. It borrows the owner's SQLite transaction, overlays only
  the bounded prepared suffix, checks immutable ancestry/record bindings and
  rebases through an ancestor's exact committed root without changing descendants.
  `prove` verifies inclusion/noninclusion and key preimages against the pinned
  root. The restore-only rightmost-leaf API rejects multi-version use.
- `stage_incremental_plan_v1` consumes the existing complete execution plan,
  checks its real parent, root and every planned write proof, then inserts only
  changed nodes/values/preimages into the prepared delta. Same-height siblings
  never share speculative NodeKey rows. Exact retries return the original
  persisted reference; a changed plan for the same block rejects.
- `apply_incremental_delta_v1` requires the entire expected storage head and
  exact prepared reference, rechecks its parent, and writes selected nodes,
  values, root, references, commit result, phase and head atomically in that
  transaction. Exact operation retries compare all bound fields. The application
  owner must first verify finality, bind the returned storage artifact into P,
  abort on error and complete its existing SQLite/file/readback durability
  barriers. Calling this storage operation alone supplies none of that authority.

The local delta codec is u16-be1, u32 node count, then bounded u32-framed pinned
JMT Borsh NodeKey and Node bytes; u32 value count followed by version u64-be,
key hash32, presence u8 and framed value; then u32 preimage count followed by
key hash32 and framed preimage. All maps have strict canonical order; trailing,
duplicate, oversized and wrong-version data rejects before use. Node paths,
padding, child versions/hashes/types and redundant leaf/child counts are checked.
Tombstones retain explicit presence=0 with no bytes. Existing root/key/value
hash algorithms are unchanged.

The prepared storage artifact is distinct from `NativeExecutedBlockV0`'s
artifact ID. Its local digest binds namespace/profile, parent kind/id/height/root,
anchor height/root, target height/block/root, delta hash and persist sequence.
M08 must include this reference in its own immutable P; neither ID substitutes
for the other. Head/namespace/record domains are local storage metadata only.
The storage commit sequence counts applied deltas, independently of schema4's
durable sequence that also counts preparation operations.
The migration-support tables are `ni_imported_root(version U64 PRIMARY KEY,
source_anchor H32, result BYTES[144], checksum H32)` and
`ni_sequence(id INTEGER PRIMARY KEY CHECK(id=1), persist_sequence U64)`, both
STRICT. Imported result is exact height8/block32/root32/sequence8/intent32/
head-checksum32. Its domain `trnm.native-incremental.imported-root.v1` binds the
namespace digest, source anchor and result using the kernel's framed hash helper.
These are local schema additions; existing exact-schema databases are rejected
unless explicitly migrated, never silently relabelled.

`collect_incremental_nodes_v1` performs a bounded, writer-transaction node-only
collection pass. It first audits every immutable node, child hash/path and
`refs` count against all `ni_roots`/`ni_pin` rows and phase-0 `ni_prepared`
anchors, then validates each `ni_gc_queue` item. It queues only zero-reference
nodes and deletes with an expected-hash/zero-ref CAS; each deleted internal
node decrements and, when necessary, queues its children in the same
transaction. A malformed counter, child, pin, anchor or queue row aborts the
transaction. The pass never deletes `ni_values`, `ni_preimages`, historical
roots or prepared records, because this owner cannot prove a value/replay
retention floor. SQLite rollback therefore leaves both queue and nodes intact.

This kernel implements only ordinary +1 updates in one epoch; epoch-tagged plans
and changed-epoch commits reject until persisted edge reconstruction is joined.
It retains all historical roots/value floors. Current pins
are only retained-root and speculative-parent pins; their count derives from
commit sequence plus bounded pending rows, avoiding a history scan per prepare.
Before enabling additional pin reasons or value pruning, replace this closed
accounting with the corresponding atomic counters and audited release authority;
node-only collection remains conservative and cannot claim production retention
qualification.

Bounds are 128 live prepared records, depth8, 2 GiB live prepared bytes,
64 MiB reader suffix, 16,384 pins, 1,024 writes/preimages, 65,537 nodes, 4,096
bytes per node, 128 per NodeKey, 65,536 per preimage and 16 MiB aggregate values
and preimages separately. Preparation reserves capacity for two descendants
before opening a new branch. Enabled deployment profiles must still prove that
their largest admissible three-block suffix fits these limits; no production
profile is enabled by constants alone. Pending-capacity queries use the phase
index and never read committed delta bodies.

The storage tests compare 96 successive real JMT roots with the existing store,
check that fixed-size updates retain constant delta bytes, and exercise fork
isolation/rebase, exact retry, tombstones/empty roots, bounded depth, every delta
truncation, corrupt state/records, schema changes and SQLite transaction abort/
file reopen. Additional regressions import twelve historical updates and verify
all roots before continuing with a delta, retire a fork without reusing sequence,
reject oversized SQL blobs without treating them as absence, and reject a fourth
16 MiB delta when its suffix would exceed the reader cap. These establish
storage behavior, not an end-to-end node performance
result, physical power-loss qualification or completion of S1.

### Implemented ordinary native owner (explicit schema 5)

The implemented compatible owner interface is a fresh, affine confirmation of a
prepared capability: `confirm_prepared_incremental_execution_v1(&prepared)`.
Its private receipt binds the same live owner/path, exact P digest/prepare
sequence, header/artifact, application parent, state delta/root and replay
ancestry. It exposes comparison fields only; a Core adapter must consume the
receipt together with its actual application owner. A committed receipt matcher
must additionally re-read the exact COMMITTED P digest and commit sequence,
not merely compare the current application head. The schema4 epoch counterpart
uses the same rule with its retained strict edge and snapshot digest.

Ordinary execution uses authenticated point reads within the pinned parent
transaction. Worker input must distinguish an unrequested key from a proved
absent key: missing prefetch data requests an owner-side proof, never a negative
membership result. Bounded read-discovery rounds retain real parallel runtime
attempts; exhausting a scheduling budget drops the attempt and runs the normal
ordered execution. PoCO mutations, scheduled cutoff refresh and epoch activation
still require the complete bounded frozen namespace projection. These changes
do not alter frozen transaction, receipt, JMT key or finality encodings.

Primary M07, consumer M08. `durable::incremental_owner_v1` installs `ni_*`
inside the existing application's SQLite transaction and retains the same file
and operation owner. `upgrade_incremental_schema_v1(expected_head, source_header)`
requires a completely audited source schema3, no unresolved preparations, exact
head/header/block/root/chain/genesis, and imports all retained ordinary real roots
once. The source header's ID is the existing committed block ID; it supplies the
parent timestamp for strict finality verification. Schema4 sparse import rejects.
Opening schema3/4 does not migrate; opening schema5 never reconstructs a snapshot.

The transaction installs the tables below, imports state and replay baseline,
clears metadata's `authenticated_snapshot` to empty with SHA256(empty), replaces
legacy metadata replay sets with canonical empty Borsh sets, and changes selector
to5 without changing native head/sequence. Old committed P rows remain archival;
new prepares/commits do not read, clone, re-encode or update their snapshots.
Migration retry requires the same retained source header and exact expected
current head, synchronizes the file and performs the source audit again.

`U64` below means exactly eight big-endian bytes; `H32` exactly32 bytes; `Head104`
means height U64, block H32, state-root H32, application-commit-ID H32. Tables are
STRICT; P and replay-node tables use WITHOUT ROWID. Unknown tables/triggers/views
or schema/index drift fail closed.

| Table | Exact fields and bounds |
|---|---|
| `native_incremental_owner_v1` singleton id1 | `source_head` Head104, `source_sequence` U64, `source_snapshot/source_commands/source_nonces` H32, canonical `source_header` ≤4096, `source_replay_root/source_anchor` H32, `head_commit_sequence` U64, `storage_checksum` H32, `replay_version` U64, `replay_root/owner_checksum` H32. |
| `native_incremental_p_v1` block H32 PK | Native `sequence` U64 UNIQUE, `status` INTEGER 0 Prepared/1 Committed, application `parent` Head104, optional `parent_p` H32, exact artifact-v0 ≤16MiB, canonical header ≤4096, `storage_artifact` H32/`storage_sequence` U64, `replay_parent_version` U64/root H32, `replay_delta` ≤16MiB, lifecycle JSON ≤1MiB, P `digest` H32, optional native `commit_sequence` U64 present iff Committed. Index status. No snapshot or cumulative identity sets. |
| `native_incremental_replay_node_v1` | Canonical Borsh `node_key` ≤128 PK and `node` ≤4096. Only changed immutable nodes are inserted at commit. This local replay JMT is separate from consensus state. |

The immutable migration-anchor domain is
`trnm.native-application.incremental-migration.v1`, binding in order store ID,
descriptor hash, signer-policy commitment, source Head104, source durable sequence,
source snapshot/command-set/nonce-set digests, source-header SHA256 and baseline
replay root. The current owner checksum domain
`trnm.native-application.incremental-owner.v1` binds anchor, current Head104,
head's native commit sequence, exact `ni_*` head checksum, replay version/root.

The P digest domain `trnm.native-application.incremental-p.v1` binds store ID,
native prepare sequence, parent Head104, optional parent-P encoded byte0 or byte1
plus H32, artifact SHA256, header SHA256, storage artifact and persist sequence,
replay-parent version/root, replay-delta SHA256 and lifecycle SHA256. Prospective
application commit ID uses `trnm.native-application.incremental-commit.v1` over
P digest, block ID, target state root and target replay root. Storage commit intent
uses this exact prospective native commit ID. Storage commit sequence counts
applied blocks independently from native sequence, which also counts preparations.

Replay membership is authenticated, not inferred from an ordinary SQL identity
index. Every present leaf's value is exactly byte1. Keys use domains
`trnm.native-incremental.replay-command.v1` over UTF8 command ID, and
`trnm.native-incremental.replay-nonce.v1` over UTF8 signer ID and nonce U64. Strings
are nonempty and ≤4096 bytes. The local replay version starts0 at migration and
advances once per executed application block, independent of consensus height.
Its delta is u16-be1, version U64, root H32, node-count u32-be, then strictly
ordered framed canonical Borsh NodeKey/Node pairs, each length u32-be. Require
exact EOF/re-encoding, ≤65537 nodes and ≤16MiB. Node path padding, depth, leaf
prefix, internal cached counts and child versions are checked before JMT use.

Cold open verifies baseline membership against the original source P commitment:
canonical source replay sets, old P digest/derived commit ID, exact root0 cardinality
and membership proofs. It pins the audited source anchor inside the live owner;
warm operations require the same anchor. Missing nodes or oversized values fail;
they cannot mean an identity is absent. Prepared branches read at most8 exact
replay deltas plus committed tree, with ≤64MiB aggregate suffix. Commit recomputes
the exact replay delta from the retained signed transaction envelopes before
applying it, preventing an unrelated replay update from riding with a state P.

`preview_incremental_block_v1`, `execute_incremental_block_v1` and
`reopen_prepared_incremental_execution_v1` use a fixed transaction and an audited
parent/P ancestry. The execution receipt is private-constructor, non-Clone and
owner-affine. `commit_incremental_finality_bytes_v1` strictly verifies actual
Ed25519 ordinary three-chain proof, exact retained target header and authenticated
parent timestamp. One transaction applies state/replay deltas, updates native
head/sequence and owner checksums, marks P Committed and retires only unrelated
uncommitted forks with their exact storage pins. Exact retry synchronizes and
freshly revalidates without allocating another sequence. Foreign/stale/substituted
P, missing parent, bad proof, wrong expected predecessor or unreadable suffix fails.

Native speculative workers receive only an immutable map of proved requested
objects, including explicit absent entries. Signature/decode admission runs once
per candidate batch, in workers. Actual runtime read discovery requests missing
keys; the owner proves sorted keys in the same pinned SQLite transaction and
retries workers for at most65 rounds (64 bounded dependencies plus the complete
attempt). No SQLite connection crosses threads. Each attempt retains at most64
reads/256KiB; the batch prefetch map and owner object cache retain at most2048
keys/8MiB. These are scheduling limits: exhausted cache capacity bypasses caching,
while prefetch/worker failure discards speculation and the ordered path executes
using authenticated point reads. Cache misses are never proof of absence.

The lifecycle is a separate exact point proof. Ordinary runtime, empty blocks
and legacy validator transitions outside a scheduled cutoff do not enumerate
live state. A PoCO operation, cutoff refresh or epoch rollover lazily requests
the frozen complete namespace once; that path still traverses the current tree,
bounded by65536 entries,64MiB key/value bytes and1048576 visited nodes. Eliminating
that remaining scan requires a separately authenticated namespace enumeration
contract; no general constant-cost execution or throughput claim is made.
Native pending rows are ≤128 and their artifact/header/replay/
lifecycle bytes total ≤2GiB; state/replay suffix budgets may reject earlier.
Historical roots are retained; GC and sustained large-history qualification are
pending. Legacy snapshot/state-proof/preview APIs explicitly reject schema5 until
versioned adapters exist. Recovery reports actual new pending P count.

The real test migrates committed heights1–4 including a signed CreditAccount,
prepares5/6/7 plus a sibling5, rejects replay of baseline and prepared identities,
commits5 using real signatures, removes only the sibling/pin, and reopens the
retained6/7. Source snapshot byte totals remain unchanged and current snapshot
metadata remains empty. Three SIGKILL cuts (before SQLite commit, after commit,
after fsync) reopen as exactly source4 or target5 and retry with the same native
sequence14. This proves the ordinary slice, not sparse migration or node activation.

The fresh-P receipts reject foreign/reopened owners and old phase readbacks after
commit. A test rewrites the local native commit sequence and recomputes the owner
checksum while preserving the same valid head; the prior committed receipt still
rejects because it binds the exact sequence. A 10000-unrelated-account differential
uses an adapter that refuses whole-tree reads: runtime results match0/1/2/4/8
workers and the same fewer-than32 proved keys are read in both small/large states.

### Owned storage packages and schema separation

These existing packages are distinct from the planned incremental native
schema below. Do not silently migrate their bytes or treat a shared root width
as evidence that their state models are interchangeable.

| Package / current APIs | State, producer and consumer contract | Errors, invariants and acceptance |
| --- | --- | --- |
| `trnm-state`: `StateStore::{get_ref,put_task_new,update_task,set_gov_param_with_action,debit_balance,credit_balance,state_root}`, consumption snapshots, `verify_wal_and_find_checkpoint_node_recovery` | In-memory compatibility state owns versioned numeric objects, balances, staged governance, consumption records/nonces and monetary policy; root cache is invalidated by mutations. `CheckpointMeta`/`WalMeta` and WAL verification are evidence/recovery surfaces, not the native JMT format. Legacy runtime/RPC consumers must retain this explicit model binding. | Existing mutation APIs often return `Result<_, String>`; planned adapters map them to typed invalid-input, conflict, insufficient-funds, overflow or corrupt-recovery outcomes without accepting message text as authority. Preserve exact object version checks, debit/credit conservation and complete rollback snapshots. Tests must restore objects, balances, governance and consumption together and compare roots; corrupt/reordered WAL must not yield ready state. Migrating to native JMT requires M13 authenticated conversion/replay, not a renamed root. |
| `trnm-native-application-sqlite`: `SqliteProposalValidationStoreV0::{reserve_v0,deliver_core_accepted_v0,acknowledge_v0}` and replay-session APIs; `SqliteNativeFinalizationHistoryV0::{append,audit,read_sequence}` | Stores exact `NativeExecutedBlockV0` artifacts and proposal binding. A reservation capability is released only after atomic persistence and fresh-connection exact readback; normal P→D→K acknowledgment and replay P→D→C→K/checkpoint closure bind actual Core/Safety/history readback. Finalization history records the application-produced result; it neither executes nor advances the application head. M08/M15 own the ordering. | Preserve `ValidationStoreErrorCodeV0` distinctions: foreign token/binding/transition reject, `CommitUncertain` fences pending recovery, `RollbackDetected`/`ReplacedStore`/`CorruptStore` stop the owner. Test mismatched artifact bytes, cross-store token, lost reservation/delivery/ACK response, substituted source history and incomplete replay activation. Bound finalization history by `MAX_FINALIZATION_HISTORY_ENTRIES_V0` and deployment retention; never prune a pending replay source. |
| `trnm-poco-order-state-v1`: `PocoOrderStateStoreV1::{open_existing_pinned,materialize_global_execution_binding_v1,prove_membership_v1}` and `PocoCanonicalOrderStateStoreV1::{recover_order_application_parent_v1,issue_finalized_prepared_order_apply_v1,apply_finalized_prepared_order_block_v1}` | Candidate SQLite tag-50 writer and separately commissioned canonical Order state. Private linear permits consume M15 finalization ownership, M08 prepared Order plan and verified exact parent/finality; fresh pins authenticate reopen. The canonical store can recover committed prepared blocks/applied owners; materialization alone is not later Order finality. | `OrderStateErrorCodeV1` distinguishes stale parent/fork/permit/plan/finality mismatch from unavailable store, tamper/rollback and uncertain commit. Test compile-fail permit cloning/forging, stale pin, foreign prepared plan, failed transaction with retained retry permit, exact postcommit recovery and membership at the committed root. Preserve tag/schema and CEV1 context; planned v0 carried-root alias must not be grafted onto this v1 store. |

Each persistent owner keeps its existing schema/codec and pin validation during
the incremental migration. The new `ni_*` tables are a separate local version
with an explicit M13 migration boundary; opening an old database must never
implicitly create them or reinterpret existing validation/replay stages.

### Existing authenticated object representation

`store.rs::stored_object_key_v0` uses domain bytes `trnm/authenticated-state/v4`,
zero separator, object namespace byte 1, u16-be namespace version 1, u32-be
component length and exact component bytes. `authenticated_key_hash_v0` hashes
that key with SHA-256. This layout must not be replaced by a convenient string.

`AuthenticatedObjectRecordV0` uses its existing Borsh encoding in declared order:
schema_version u16, object_type String, object_version u64, value_hash [u8;32],
value Vec<u8>. Borsh's encoding is distinct from CEV0; do not change its scalar
endianness to match consensus headers. Decode validates schema/type and exact
SHA-256(value). `CompleteStateWriteV0` binds key and optional value; `None` is a
namespace-authorized tombstone, not general permission to delete PoCO kinds.

The source snapshot codec and JMT node bytes remain exact inputs. State-object
versions, JMT root version labels and consensus heights are distinct concepts
even when ordinary execution currently equates the last two.

### Planned owned APIs

```text
open_authenticated_read(expected: CommittedApplicationHead, pin: NamespaceOwner)
  -> Result<AuthenticatedReadSnapshotV1, StoreFailure>
open_prepared_parent(parent_artifact: Hash32,
                     expected: PreparedParentExpectationV1, pin: NamespaceOwner)
  -> Result<AuthenticatedPreparedSnapshotV1, StoreFailure>
prepare_incremental(parent: AuthenticatedApplicationParentV1,
                    writes: SealedCanonicalWrites, target: ApplicationCoordinate)
  -> Result<PreparedStateDeltaV1, StoreFailure>
commit_incremental(intent: VerifiedApplicationCommitIntent,
                   delta: PreparedStateDeltaV1, expected: StoreHeadCAS)
  -> Result<CommittedApplicationReadbackV1, StoreFailure>
open_epoch_parent(edge: AuthenticatedEpochApplicationEdgeV1,
                  checkpoint: AuthenticatedReadSnapshotV1)
  -> Result<CarriedRootReaderV1, StoreFailure>
```

These owned APIs are planned; the internal `CarriedRootReaderV1` candidate now
exists but does not implement their durable snapshot/namespace lifecycle.
M08 owns finality/commit intent; M06 owns
canonical writes; M07 independently verifies parent/root/namespace and applies
one transaction. No API takes a caller boolean `is_finalized` or untrusted root
as authority. M13 can stage bytes but cannot call commit without admitted proof.

`CommittedApplicationHead` binds chain/genesis, execution height/block ID,
JMT label/root, commit_sequence, schema/profile and owner generation.
The namespace owner pins canonical root-directory descriptor and store identity.
A read snapshot pins the same database transaction/root/preimage/value view for
its lifetime; all reads, including absence and policy/replay lookups, use it.

`AuthenticatedApplicationParentV1` is a private-construction sum of committed
`AuthenticatedReadSnapshotV1`, prepared `AuthenticatedPreparedSnapshotV1` and
the first-new-block `CarriedRootReaderV1`; callers cannot manufacture a variant
from a root. `PreparedParentExpectationV1` contains chain/genesis, block ID,
execution height, JMT label/root, execution-profile digest and owner generation.
These are expected facts, not credentials. `open_prepared_parent` reads the
immutable P artifact and exact delta, verifies both digests and every parent
link back to a retained committed root, then recomputes/validates each overlay
root and value/preimage binding. A cycle, missing ancestor, stale owner, fork
substitution or inconsistent height/version rejects before returning a handle.

The prepared snapshot pins that committed anchor plus all ancestry artifacts.
Reads consult the newest exact node/value delta in that one ancestor chain,
then earlier deltas and the immutable committed snapshot; sibling deltas never
participate. Tombstones stop lookup and NodeKey versions remain unchanged.
Store fork-local nodes only inside artifact-keyed deltas until commit, because
two sibling candidates may have the same NodeKey but different node bytes.
The snapshot can prepare a child, but cannot prove canonical membership, issue
an execution receipt or move the committed head. Public proofs use committed
snapshots only. Reopen reconstructs this capability from artifacts and roots;
persisting a boolean `prepared_verified` is insufficient.

## State machine

### Ordinary incremental storage target

`VerifiedParent -> DeltaPrepared -> CommitIntentObserved -> Applied -> FreshReadback`.
Prepared deltas remain speculative and may have sibling forks. Only M08's exact
oldest-target finality permits application apply; readback never promotes a fork.

1. Open one immutable authenticated committed or prepared parent. Validate
   actual root and exact chain/parameter/policy/replay namespace relation.
2. Admit sorted unique complete writes, exact expected object versions and
   namespace-authorized create/update/delete rules. A tombstone may not bypass
   application retention, permanent replay nullifiers or a legal hold.
3. Feed those writes to pinned JMT `put_value_set` at the selected target label.
   Verify output root, new node/value batch and stale references against M06's
   sealed plan. Stale metadata does not itself authorize physical deletion.
4. Under `BEGIN IMMEDIATE`, compare exact current committed head/sequence,
   prepared artifact digest and M08 intent. Insert immutable nodes/value versions,
   preimages, root descriptor, replay/domain changes and commit record atomically.
5. Update metadata head and sequence once. Exact duplicate with identical result
   returns readback; same identity with different bytes/root is corruption/conflict.
6. Close, synchronize and freshly reopen according to the storage durability
   profile; recheck descriptor/sidecar identity and target root before return.

This speculative-parent path is mandatory for three-chain progress: prepare
C+3 over the authenticated epoch edge, then C+4 over C+3's immutable prepared
delta and C+5 over C+4 before C+3 is finalized. The same rule applies to ordinary
blocks. Commit still advances only the oldest finalized target with its exact
committed application predecessor; it cannot skip an uncommitted ancestor.
After an ancestor commits, descendants may reopen against the identical new
committed root and remaining deltas without changing their artifact identity.
Discarded forks release pins only after all dependent children/commit intents
are gone; capacity pressure rejects new local preparation as unavailable.

Planned incremental tables retain composite keys `(node_version,node_path)`,
`(key_hash,value_version)` including tombstones, `key_hash->exact preimage`,
actual executed-root descriptors, immutable P artifacts/deltas, committed head,
commit intent/result, retention pins and epoch-edge metadata. Primary keys are
unique; canonical byte encodings and fixed-width ordering are explicit schema
inputs. Do not store one complete historical snapshot in each new P row.
Legacy snapshot imports must reconstruct this index and compare every retained
root before switching the head; the old database stays recoverable until CAS.

### Planned local SQLite schema 1

The new backend uses separate `native_incremental_schema=1`; it does not rename
an existing schema or reinterpret old snapshot rows. Tables are STRICT,
WITHOUT ROWID except the singleton head, with no unlisted triggers/views.
`U64` below is a BLOB of exactly eight big-endian bytes, `H32` is length-32 BLOB,
`BYTES` is bounded BLOB and `TAG` is INTEGER with the listed CHECK set. All
columns are NOT NULL except explicitly marked optional. These SQL types are
local storage representation, not replacements for existing Borsh value bytes.

| Table / primary key | Required columns and constraints |
|---|---|
| `ni_meta` / singleton id=1 | schema TAG=1; chain BYTES; genesis H32; namespace H32; owner_generation U64; head_height U64; head_block H32; head_version U64; head_root H32; commit_sequence U64; head_intent H32; head_checksum H32. |
| `ni_nodes` / node_key BYTES | node_version U64; node_bytes BYTES; node_hash H32; refs U64. node_key and node_bytes are exact pinned-JMT Borsh; version equals decoded NodeKey version; hash equals decoded node hash. |
| `ni_values` / (key_hash H32, version U64) | present TAG in {0,1}; value BYTES. present=0 requires zero value bytes and means tombstone, not missing database row. |
| `ni_preimages` / key_hash H32 | preimage BYTES; SHA-256 matches key_hash; a different preimage at the same hash rejects. |
| `ni_roots` / version U64 | epoch U64; consensus_height U64; block_id H32; root H32; root_node_key BYTES; commit_sequence U64 UNIQUE; intent H32 UNIQUE. Only actually applied blocks enter this table; version=consensus_height. |
| `ni_prepared` / artifact H32 | parent_kind TAG in {0 committed,1 prepared}; parent_id H32 (committed block ID or prepared artifact); parent_height U64; parent_version U64; parent_root H32; anchor_version U64; anchor_root H32; owner_generation U64; profile H32; target_height U64; block_id H32; delta BYTES; delta_hash H32; expected_root H32; persist_sequence U64 UNIQUE; phase TAG in {0 prepared,1 committed}; optional edge H32. A prepared parent has smaller persist_sequence; a committed parent resolves an exact ni_roots row. Target JMT version equals target_height; parent/target +1 or exact authenticated edge is checked. |
| `ni_commit` / operation H32 | predecessor_checksum H32; expected_sequence U64; artifact H32; target_block H32; target_root H32; successor_sequence U64 UNIQUE; result BYTES. Successor equals checked expected+1. Immutable after insert. |
| `ni_pin` / (owner H32, reason TAG, version U64) | reason in {0 retained-history,1 speculative-parent,2 checkpoint,3 epoch-edge,4 sync-export,5 unresolved-commit}; root H32; reference_count U64 positive; optional release_authority H32. |
| `ni_epoch_edge` / strict_binding H32 | edge BYTES; checksum H32; checkpoint_version U64; first_height U64; phase TAG in {0 Installed,1 Consumed}; optional committed_block H32. Tag1 requires committed_block and exact corresponding ni_roots row. |
| `ni_gc_queue` / node_key BYTES | enqueued_generation U64; expected_hash H32; zero-reference check repeated under transaction before delete. |

Every head CAS compares namespace, generation, predecessor checksum, root,
version and commit_sequence, not sequence alone. A single SQLite transaction
inserts ni_commit/ni_roots and related state, changes P phase and optional edge,
adjusts pins/references, and updates ni_meta. Zero matching head rows means
conflict; more than one is corruption. Exact retry reads ni_commit and compares
every bound field. Real seal-label rows in any application table are forbidden.
Indexes on node_version, value version, prepared parent and pin version are
listed schema objects; migration/restore validates this closed schema and
canonical row encodings before opening an authoritative handle.

### Selected epoch design: sparse JMT labels and one carried predecessor root

This design chooses **actual application JMT label = executed consensus height**.
Checkpoint C has real application label C. Seals C+1/C+2 execute no application,
produce no P application row, receipt, state mutation or application sequence
increment. The first new block executes once and has real label C+3. Subsequent
ordinary blocks again advance by one, preserving frozen cutoff equal-height checks.

M08's `AuthenticatedEpochApplicationEdgeV1` binds the committed checkpoint
(C, block ID, root, commit_sequence), old terminal seal2 (C+2, header/ID), first
new height C+3, exact old/new configurations, joint descriptor and strict proof
binding. M07 accepts it only with fresh checkpoint readback and verified M08
edge authority. It is not derived from caller heights or matching roots alone.

Pinned JMT 0.12.0 `tree_cache.rs::TreeCache::new(next_version)` uses
`NodeKey::new_empty_path(next_version-1)` for non-genesis. Its TreeReader fetches
that root; internal child entries carry their own possibly much older versions.
`reader.rs::get_value_option` means latest value at or below the requested version.
These facts select the following narrowly scoped adapter:

1. `CarriedRootReaderV1` borrows the immutable checkpoint snapshot and retains
   exact edge coordinates; its owner holds the authenticated edge alive.
   It is constructed only for a single first-new target `next_version=C+3`.
2. For the exact key `NodeKey(C+2, empty nibble path)` only, return the checkpoint
   root node read at `NodeKey(C, empty nibble path)` and independently verify
   its hash against the committed checkpoint root before use.
3. For every other NodeKey, perform exact normal lookup. **Never rewrite
   `(C+2,path)` to `(C,path)` for arbitrary paths**: descendants may originate
   at older versions or have no node at C. Preserve child version references.
4. Parent value lookups at virtual predecessor C+2 resolve under the same
   checkpoint snapshot at C. Verify no real node/value/application rows exist
   in the two seal labels. Other requested versions retain normal exact rules;
   unsupported future versions fail rather than returning a latest value.
5. Normal JMT update produces the real C+3 node/value batch/root. Require every
   new write label be C+3 and complete dependency/root equality with canonical
   execution. No two dummy empty `put_value_set` calls are permitted for seals.
6. If JMT marks virtual root `(C+2,empty)` stale, consume it as retirement of
   local alias metadata only; do not delete or relabel real checkpoint root C.
   All nonvirtual stale-node keys keep their exact physical identity.
7. A no-op application write set still produces the real C+3 root through JMT's
   normal freeze logic. Empty-tree, leaf-root and internal-root cases obey the
   same rule; no restoration API assuming all nodes have one version is used.

The alias is an internal read view, never an entry in the public executed-root
index. It has no proof class, application receipt or monetary effect. Proof/cache
APIs must refuse to present C+1/C+2 as executed application versions. A client
querying a seal may return its carried checkpoint root plus the consensus seal
proof, explicitly identifying application coordinate C. It cannot relabel a
checkpoint membership proof as an execution receipt at seal height.

This requires a dedicated first-new execution path in M06; ordinary parent
height/version checks remain unchanged. The request explicitly binds consensus
parent seal2 and application parent checkpoint. M02 validates the handoff
ancestry edge; M07 supplies storage ancestry. Merely installing an alias does
not authorize a consensus height jump or change active application configuration.

## Persistence and recovery

### Implemented schema-4 bridge before incremental migration

M08's `native_durable_execution_p_v1` and `native_epoch_edge_v1` provide
an explicit bounded full-snapshot bridge. Schema 3 retains codec1 and ordinary
P semantics. Explicit migration to schema 4 adds the epoch evidence/context
tables; the first-new and later sparse-history preparations use P family v1,
even when a later ordinary block retains artifact v0. Metadata selects codec2
only with a freshly reconstructed authenticated lineage. No existing v0 P bytes
or state-value/JMT codecs change. This bridge is a runtime prerequisite, not
the incremental backend or a storage-performance result.

To migrate schema 4 into `ni_*`, restore every retained real root under its
verified edge lineage, materialize exact physical nodes/values/preimages and
artifact ancestry, and compare all root/replay/lifecycle/configuration digests.
Virtual seal roots are never emitted into `ni_roots` or `ni_nodes`. Convert
prepared snapshots to ancestor-relative deltas only after verifying the exact
parent P and all differences; fork-local collisions stay inside their own delta.
Persist edge evidence and retention pins before switching the owner/head by CAS.
The source remains readable until the complete target audit and fresh readback
succeed. Interrupted migration chooses the exact source or exact target from
its journal; it never merges two partly populated namespaces.

Store epoch-edge metadata in the same authoritative namespace as its checkpoint
pin and eventual C+3 commit. It contains exact edge bytes/checksum, predecessor
application head, expected first target, owner generation and state
`Installed | Consumed`. This is planned local metadata, outside the state root.
`Installed` permits repeated identical speculative reads; it is not consumed
until canonical application commit. Different first-new proposals may be prepared
under normal consensus rules, but at most one finality-authorized target commits.

On crash before commit, reconstruct the reader only after M08 re-verifies the
edge and current checkpoint head. On crash after commit, fresh head/commit row
must match the exact target, consumed edge and sequence+1; return the same result.
Alias metadata without proof/head/pin or real state without its commit record
fences dependent operations. M13 restores real checkpoint nodes plus evidence,
then installs an alias through this API; it must not import a peer's alias flag.

### Retention and garbage collection target

Keep roots required by active/retained checkpoints, speculative parents,
first-new edges, state-sync exports, light-client/accountability horizons and
unacknowledged commits. An edge pins checkpoint root C and its complete reachable
physical node/value closure; the virtual root itself owns no data to prune.

Incremental node-only GC is implemented by the explicit
`DurableNativeApplicationV0::collect_incremental_nodes_v1(max_nodes)` owner
maintenance API. The underlying transaction primitive is crate-private and
cannot be invoked by a caller that supplies an arbitrary SQLite transaction or
namespace. The API holds the durable owner's operation lock, confirms the
process-pinned namespace identity, opens an immediate SQLite writer transaction,
audits the schema-5 `native_incremental_owner_v1` anchor and head binding, and
only then invokes the collector. Its report carries the validated owner anchor;
a report with no owner anchor is storage-primitive output and is not an owner
maintenance result. A successful pass is committed, database/directory synced,
and reopened through the normal owner audit. GC is never called automatically
from block preparation or commit, so the scheduler remains an explicit owner
decision.

`max_nodes = 0` is an audit-only probe: it validates the complete node/edge/root/
pin/prepared/queue graph and returns the current queue depth without enqueueing
or deleting anything. This keeps health checks from becoming durable GC work.

The collector uses immutable node child-reference counts plus explicit root pins. Insert
each physical node once and increment its exact child edges once; shared nodes
are not rewritten. Root-pin changes are transactional with head/edge changes.
The collector first audits all node records, child hashes, roots, pins,
phase-0 prepared anchors and queue hashes, then queues only zero-reference
nodes. Each bounded batch rechecks zero references and the expected hash under
the writer transaction before deletion and decrements child counts atomically.
Never delete from a stale-list alone. A malformed count/edge/root/pin/queue
fences the transaction. Historical roots, values, preimages and prepared rows
are never deleted by this pass.

MVCC values need a separate retention floor: for each key retain all versions at
or above the oldest required real root and the latest predecessor value/tombstone
needed by that floor. Replay/nullifier/key-history retention may demand more.
A node reference count cannot by itself prove a value, receipt or nullifier is
collectable. Compaction journals its scan cursor/generation and exact deleted
batch so restart neither repeats an effect nor skips a live dependency.

## Resource bounds

Use existing block/message limits, complete execution write/transaction limits,
namespace constraints and JMT key depth. Current native snapshot/PoCO history
checks include an 8,192-version authenticated history window; configured
`snapshot_lead_blocks` must not exceed the production retained cutoff capacity.
Sparse labels require retention measured in consensus labels and actual retained
roots explicitly; do not count two seals as two application snapshots.

Planned signed storage-profile fields: maximum prepared forks/bytes/depth/records, delta nodes,
value/preimage bytes, pinned roots/edge records, pending GC bytes, scan work per
batch, snapshot export bytes/chunks and minimum free durable space. Validate all
checked products and capacity for one largest enabled transition before admission.
Missing values disable the new backend; they are not silently replaced by RAM size.
GC/backpressure is local unavailable, never proof that a peer block is invalid.

### Explicit bounded development profile (planned fixture, never fallback)

All byte/count fields below are unsigned checked u64, except schema u16=1.
Profile `native-incremental-dev-v1` is an opt-in fixture input to implementation
qualification, not a mainnet parameter or permission to weaken accepted limits.

| Field | Development value |
|---|---:|
| max_prepared_forks / max_prepared_bytes | 16 / 2147483648 |
| max_prepared_depth / max_prepared_records | 8 / 128 |
| max_distinct_writes / max_delta_nodes | 1024 / 65537 |
| max_value_preimage_bytes / max_delta_bytes | 16777216 / 335544320 |
| max_pinned_roots / max_epoch_edges | 16384 / 32 |
| max_gc_queue_bytes / gc_batch_nodes / gc_batch_bytes | 268435456 / 4096 / 8388608 |
| max_export_bytes / export_chunk_bytes | 2147483648 / 1048576 |
| recovery_batch_bytes / minimum_free_durable_bytes | 67108864 / 4294967296 |

Loading checks `delta_nodes >= 1+64*max_distinct_writes` for JMT's nibble-depth
upper bound, `delta_bytes >= delta_nodes*max_encoded_node_bytes +
value_preimage_bytes + exact_schema_overhead`, and
`prepared_bytes >= 3*delta_bytes + maximum_commit_and_edge_overhead`, using the
pinned implementation's proven maximum node bytes, not an unchecked constant.
Require depth and record capacity at least three for the active three-chain;
cap every ancestor walk by max_prepared_depth and total retained records/bytes
before taking new pins. Reserve capacity for the active three-chain before
admitting sibling forks; do not let adversarial siblings starve its next child.
Check pin capacity against history roots plus active forks/exports/edge roots;
edge retention must cover `1+max(evidence_window,unbonding_delay,trusting_period)`.
Check one export chunk fits transport and byte counters, and enough free space
remains for the largest admitted transaction/WAL/sidecars. If any computed bound
exceeds this example profile, reject that profile or reduce its explicitly
selected test workload; never silently truncate an enabled valid transition.
Deployment values require separately authenticated profile selection.

## Security

Planned typed errors distinguish `ParentMismatch`, `RootMismatch`,
`NamespaceViolation`, `VersionConflict`, `UnauthorizedEpochEdge`,
`VirtualVersionExposure`, `CorruptStore`, `CapacityUnavailable`, `CommitUncertain`
and `RecoveryConflict`. Input mismatches reject without writes; unavailable has
no durable effect; uncertain requires fresh readback; corruption/conflicting
committed roots halt. A lost write reply is never assumed to mean rollback.

Validate symlink/path/descriptor/sidecar identity around authoritative I/O and
reopen. Local hash chains/checksums do not defeat whole-namespace rollback;
M03/M08 reconcile independent monotonic state. No cache hit may bypass exact
root/owner binding, especially at unchanged version with modified node bytes.

## Observability and SLO

Measure bytes/nodes read and written per committed block, prepared bytes,
retained/pinned roots, replay scan work, GC backlog, fsync tails and restart time.
Keep application commits, consensus heights and virtual alias lookups separate.
Report cost against state/history size as well as transaction count. Numeric
latency/capacity acceptance comes from the signed qualified storage profile.

## Verification and evidence

Existing storage/root, durable execution, snapshot restore and PCC1 tests remain
required. New `M07-INCREMENTAL` vectors compare exact roots/receipts/replay state
with the existing independent serial semantics over create/update/delete/no-op.
`M07-PIN` races immutable reads, head advance, prune, namespace replacement and
sidecar replacement. `M07-GC` proves shared child/value retention and restart-safe
bounded deletion, including permanent nullifiers and all active pin reasons.
`M07-SPECULATIVE` prepares three blocks before the first commit, with divergent
sibling nodes at the same NodeKey, overwritten values/tombstones and crash
reopen at every ancestor depth. Compare serial roots, reject cycles/missing or
substituted ancestors, prove no speculative public proof/receipt and commit the
oldest block exactly once while later plans retain valid pinned ancestry.

`M07-EPOCH` must run pinned JMT 0.12.0 through actual root-only adapter: C to C+3,
then second epoch, empty tree/leaf/internal/no-op, older child versions, physical
gap rows, fake edge, wrong terminal seal/root, virtual stale-root handling,
GC while edge pinned, restart before/after C+3 apply and snapshot install. Reject
all virtual-version proof/cache publication. Compare every real cutoff version
and root to frozen semantics; do not relax `ensure_exact_cutoff` to pass a test.

M06 produces exact writes/expected roots; M08 owns commit/edge evidence; M13
independently rebuilds from exported nodes and evidence. Publish exact planned
local schema/edge bytes and positive/negative vectors before accepting readers.

## Activation boundary

The candidate root adapter, real first-new persistence/strict commit and local
reopen tests pass. The incremental transaction kernel has separate storage tests;
its ordinary schema3→5 owner has real signed/replay/fork/SIGKILL tests, while
sparse finality commit, GC, complete proof adapters and two-epoch matrix must land
and pass before removing any remaining fence or full-audit protection.
If pinned JMT behavior cannot satisfy the root-only design, stop and revise this
local storage contract under producer/consumer review; never alter frozen
consensus bytes or publish seal application effects as a workaround.

### Explicit schema6 first-new incremental candidate

Primary M07, consumers M06/M08. Feature `incremental-epoch-candidate` is default
closed. Schema5 retains its ordinary +1 and old configuration checks. The
schema6 transition requires an already imported schema5 head exactly at the
original COMMITTED checkpoint C, zero ordinary incremental preparations, and
an owner-affine, freshly confirmed `AuthenticatedEpochApplicationEdgeV1`.
Schema4 remains a separate snapshot bridge; schema4-to6 migration is rejected.
The schema3-to5 import can precede this transition; neither open nor preview
migrates a file. Schema6 keeps the immutable migration anchor and original
legacy P/history for checkpoint/cutoff reconstruction, and stores no new full
snapshot or cumulative replay sets.

The schema6 owner row contains source-anchor H32, edge-binding H32, original
checkpoint P digest H32 and actual commit sequence U64, exact encoded recovery
evidence (at most 64MiB), and a framed owner checksum. The evidence includes
checkpoint artifact/header, cutoff proof/parent, preparation ID, strict old
checkpoint/two-seal proof, joint authorization and both exact configurations.
Its single-entry lineage is the edge binding. Only artifactkind=1 is accepted
in this first slice: frozen epoch-artifact-v1, actual application parent Head104
at C, consensus parent C+2/BlockId in the artifact, target C+3, old/new config
hashes and edge binding must agree with strict evidence. P includes exact
header, native persist sequence, state storage artifact/sequence, replay parent
version/root, replay delta (16MiB), lifecycle (1MiB), and digest; native artifact
is bounded to 16MiB and header to 4096 bytes. Prepared row limits are 128 rows
and 2GiB aggregate, shared with the underlying ni storage reservation bounds.

The ni first-new stage is a distinct typed-edge entry. It requires a COMMITTED
parent C and plan coordinates C/C+2/C+3. Only NodeKey(C+2, empty path) aliases
NodeKey(C, empty path); other paths retain real versions and all value reads
are capped at C. No roots, physical nodes or values may occur in either seal
version. The delta contains only target C+3 nodes/values, pins the real C root,
and hashes the exact edge coordinates in a distinct storage-artifact domain.
Ordinary stage still rejects every epoch plan and requires parent+1; ordinary
apply also rejects an epoch delta. No virtual root is inserted into ni_roots.

First-new execution performs the existing authenticated config/usage rollover
before user transactions in one complete plan. State delta, replay delta,
exact native P and sequence CAS persist in the same owner transaction followed
by file/directory sync and fresh confirmation. Reopen reconstructs the strict
edge from retained native cutoff/checkpoint/preparation and signed evidence;
matching hashes alone do not issue the receipt. A receipt is non-Clone,
owner-affine, and rechecks exact P digest/sequence and storage/replay roots.
Until the dedicated strict commit consumer lands, schema6 retains committed
head C; descendants, finality commit, public state-sync/proof adapters and GC
remain unsupported. PREPARED C+3 is never exposed as a committed application
head or as a Core ACK.


Implemented candidate source is `incremental_epoch_owner_v1.rs` plus the private
`incremental_epoch_storage_v1.rs` adapter. Live schema6 ownership pins the exact
edge-row checksum, while the row separately retains the immutable schema5 source
anchor. Cold open checks the closed SQL schema and bounded row inventory; only
`recover_incremental_epoch_edge_v1` and
`reopen_prepared_incremental_epoch_v1(block, expected_p_digest)` reconstruct
native authority from the actual preparation journal and committed source P.
The latter also matches state storage block, target height, both parent/root
coordinates, edge binding and storage sequence to the native P. No caller-built
edge or low-level `ni_*` artifact is an application receipt. The existing v0
recovery inventory explicitly rejects schema6 instead of reporting an empty
ordinary table as an exact recovery result.

Three candidate tests cover the real signed C8→C11 path, unchanged root/receipts
against schema4 execution, owner mismatch, exact retries, cold reopen, altered
edge/checkpoint/P sequence and missing preparation journal; separate storage
cases cover empty, leaf and internal roots with unchanged physical child
versions and rejection of seal values/future nodes. Process SIGKILL cuts before
SQL commit, after commit before sync and after sync before readback leave either
zero or one complete native-P/state-delta/edge transaction. Every reopened
committed head stays C8. These checks establish bounded preparation/recovery,
not finality commit, storage-device crash certification or production activation.

### Explicit schema6-to7 commit and descendant owner

The default-off `incremental-epoch-candidate` feature implements schema7 in
`incremental_epoch_commit_v1.rs` and `incremental_epoch_descendant_v1.rs`.
`upgrade_incremental_epoch_commit_v1(&actual_edge)` freshly confirms the original
COMMITTED checkpoint C, then installs two closed SQL tables and CASes the
version from6 to7 in one transaction. Open never migrates. Schema6's codec and
prepare-only behavior remain unchanged; schema5's ordinary +1 guards continue
to reject either epoch schema. The empty revision grants no finality authority.

The resumable owner entry point is
`DurableNativeApplicationV0::ensure_incremental_epoch_commit_owner_v1(&edge)`;
the older `upgrade_...` name delegates to it for compatibility. It takes the
native operation lock, reaudits the immutable edge-owner checksum and migration
pin, creates schema7 only from schema6, and on retry strictly decodes any
retained commit row before syncing and fresh-validating the file. A malformed
retained row rejects the owner operation. It returns no prepared or committed receipt, so
strict finality remains the only path that moves the application head. The
candidate node adapter invokes this method only after its complete owner join;
it is outside the default feature closure.

| Schema7 record | Exact persisted fields and validation |
| --- | --- |
| `native_incremental_epoch_commit_v1` | Singleton id=1, revision=1; block H32 unique, native P digest H32, actual commit sequence U64 unique, target Head104, full first-new proof BYTES (1..64MiB), checksum H32. Domain `trnm.native-application.incremental-epoch-commit-record.v1` binds store ID, immutable edge-owner checksum, block, P digest, sequence, target head and SHA256(proof). |
| `native_incremental_epoch_descendant_commit_v1` | Block H32 primary key; native P digest H32, actual commit sequence U64 unique, target Head104, full ordinary new-set proof BYTES (1..64MiB), checksum H32. Domain `trnm.native-application.incremental-epoch-descendant-commit.v1` binds the same fields. Aggregate retained descendant proof bytes must not exceed64MiB. |

The actual first-new commit consumer revalidates the owner-affine P, rebuilds
its native edge from original checkpoint/preparation/evidence, and verifies the
strict epoch-first three-chain proof using terminal seal C+2 and the exact full
signed C+3 header. One owner transaction applies the sparse JMT delta, exact
command/nonce replay delta, first commit record, ni edge phase0→1 and selected
block, native head/sequence CAS, and fork retirement. No seal root/value/P is
created. Sync and fresh readback precede the committed receipt. Exact retries
return the original native commit sequence; another valid proof for the same
full header/edge does not replace the retained first evidence.

`IncrementalEpochParentV1::{First,Descendant}` borrows an actual non-Clone native
P capability. Ordinary C+4/C+5 and later pre-checkpoint preparations bind its
real application target Head104 and P digest, inherit the authenticated new
validator/parameter set, and compose pending state/replay deltas. They use the
ordinary artifact codec and `native_incremental_p_v1` table with explicit new-set
context validation; merely constructing a low-level ni reference is insufficient.
The complete pending chain is bounded to8 deltas and64MiB replay bytes. Each
native P table bounds inventory to128 rows/2GiB; the underlying ni reservation
limits also apply. A full capacity error does not prune arbitrary safety data.

Descendant commit requires the first block already committed, exact current
application parent, exact replay predecessor, and a strict ordinary three-chain
proof under the retained new set/parameters. State, replay, P status and commit
sequence, proof record and owner head update atomically. Losing branches are
removed child first; winning pending descendants remain readable. The next
checkpoint height is an explicit fence: this version does not implement a
second handoff, retained-history GC, public historical proof adapters or M13
schema7 transfer. Internal retained proofs serve cold auditing only.

Cold audit verifies the original checkpoint/source P and strict joint evidence,
then binds first-new artifact request, exact signed header and all four roots,
actual payload/receipts, checkpoint application parent, edge, native P sequence,
ni block/parent/root/storage sequence and replay identities. It verifies every
committed descendant's bounded ancestry, retained strict proof, exact native/ni
parent and persist identity, replay key delta and P/head sequence linkage. A rehashed local checksum cannot substitute for these joins.
The live edge pin stays the original immutable edge-owner checksum; every
operation compares it again after recovering the edge and acquiring its native
operation lock. Historical reconstruction may recover ancestry evidence, but
cannot issue the fresh activation-at-C receipt after the application head advances.

#### Schema7 implementation checklist and crash cuts

The implementation review for this block is intentionally byte-specific:

| Cut | Durable source/target that may be observed after reopen | Required action |
| --- | --- | --- |
| before schema7 transaction | schema6 edge only | retry the CAS; do not infer a migration from a directory name |
| after table creation, before metadata CAS | schema6 metadata plus uncommitted tables | roll back the SQLite transaction and retry |
| after metadata CAS, before sync | schema7 metadata and both tables | sync/read back exact descriptors, or fence on any third state |
| retained first-new P/commit row | exact block/P/sequence/head/proof/checksum tuple | decode and re-audit the strict edge before returning the same receipt |
| descendant row conflict | existing row is accepted only if every field is byte-equal | conflicting payload/proof is a halt, never replacement |

The candidate implementation symbols are
`trnm-native-execution-v0/src/incremental_epoch_commit_v1.rs::ensure_incremental_epoch_commit_owner_v1`,
`...::commit_incremental_epoch_finality_bytes_v1`, and
`trnm-native-execution-v0/src/incremental_epoch_descendant_v1.rs`.
The node-side join is
`trnm-poco-node/src/epoch_runtime_candidate_v1.rs::ensure_incremental_epoch_commit_owner_v1`.
These APIs are feature-gated and candidate-only: they do not enable the
default node, create a signer intent, or make an unfinalized P a committed
application head. Acceptance still requires measured growing-history bytes,
SIGKILL/device-fault evidence, pruning-reference replay and a complete M13
multi-epoch import path.

### Live native namespace continuity

On Unix, `DurableNativeApplicationV0` retains open descriptors for its database,
canonical parent directory and actual lock file; it pins the preparation sidecar
once present. Fresh checks compare path metadata with held-FD dev/inode, uid,
gid and mode; reject symlinks and non-single-linked regular files; and reject
parent-path aliasing. Directory link counts may change as unrelated files are
created, so directory identity uses the descriptor rather than a fixed link count.
An observed mismatch permanently fences that live owner, including after an
attacker restores the old file. Ordinary SQLite transactions and explicit schema
migrations must preserve the pinned database identity.

Operation entry, direct durable receipt matching and the at-C epoch confirmation
check this owner state; the latter repeats it after its content/proof readback.
Preparation open also checks before/after and binds the new sidecar to this owner.
A new explicit cold open independently audits the durable contents and obtains
new pins; these local descriptors are not an external anti-rollback service or a
claim of arbitrary hostile-filesystem atomicity. Unix identity validation is a
requirement of the current custody receipt path; other platforms cannot silently
substitute pathname equality for it.

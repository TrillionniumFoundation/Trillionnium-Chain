# M07 State / JMT / Storage technical specification v1

Status: **native sparse-epoch computation implemented as a candidate;
durable epoch persistence, incremental storage and production acceptance pending**.
Primary module: M07. Producers: M06/M08/M13. Consumers: M02/M06/M08/M13/M14.

## Authority

Frozen v0 state roots, checkpoint/cutoff equality and seal semantics remain
unchanged. `trnm-native-execution-v0/src/{store,durable,complete,poco_checkpoint}.rs`
and application snapshot/SQLite implementations define current source behavior.
`NativeExecutionStoreV0` is presently an externally implementable candidate read
boundary; internally consistent values are not proof of a lifecycle-pinned
production snapshot. The target creates that authenticated immutable ownership.

Current durable execution encodes complete historical JMT snapshots in P records
and audits retained history. The compact-inventory/borrowed-reader optimizations
remove copies, not this growth. The planned incremental backend below changes
local persistence while preserving key/value codecs, state roots and receipts.

### Implemented candidate and remaining persistence boundary

`trnm-native-execution-v0/src/epoch_store.rs::CarriedRootReaderV1` now implements
the root-only adapter specified below. `complete.rs::compute_complete_epoch_native_block_v1`
uses it with the opaque M08 edge, computes the authenticated configuration/usage
prefix and user operations into one C+3 plan, and preserves ordinary +1 checks.
The public owner entry point is read-only `preview_epoch_block_v1`; it does not
persist an epoch P or advance the application head. Owner affinity and fresh
checkpoint P digest/commit sequence are rechecked before opening the snapshot.

The candidate plan's private epoch tag permits exact C to C+3 application to an
in-memory copy. Tests then compute C+4/C+5 over that copy. This is not yet the
durable speculative-parent API below. Empty, leaf and internal JMT tests retain
real child versions, reject physical seal rows and compare roots against ordinary
contiguous computation. The real signed checkpoint fixture covers C=8 to 11,
raw request substitution rejection and an old owner capability after reopen.

Sparse snapshot **local codec 2** is presently compiled only for tests in
`epoch_store.rs`. It retains the existing Borsh snapshot field order and node/
value encodings, changing the local codec version to 2. Its constructor requires
the retained verified edges; every root gap must be exact C to C+3, checkpoint
root must match, all gap rows must be absent, and active parameters must match
the latest edge. Codec 1 explicitly rejects sparse root histories and its decoder
rejects codec 2. The test decoder does not recover authority from a checksum.
Production durable open does not call it; persisted edge evidence, fresh edge
reconstruction and the schema-4 bridge in M08 are prerequisites to enabling it.
Incremental `ni_*` storage, bounded GC, two-epoch durable recovery and state-sync
installation remain planned; the candidate does not close snapshot growth.

## Interfaces

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
| `ni_nodes` / node_key BYTES | node_version U64; node_bytes BYTES; node_hash H32; references U64. node_key and node_bytes are exact pinned-JMT Borsh; version equals decoded NodeKey version; hash equals decoded node hash. |
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

### Planned schema-4 bridge before incremental migration

M08's planned `native_durable_execution_p_v1` and `native_epoch_edge_v1` provide
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

Planned incremental GC uses immutable node child-reference counts plus explicit
root pins. Insert each physical node once and increment its exact child edges
once; shared nodes are not rewritten. Root-pin changes are transactional with
head/edge changes. Removing a pin queues only zero-reference nodes; bounded
background batches recheck zero references under the writer lock before deletion
and decrement child counts atomically. Never delete from a stale-list alone.
Counters are derived indexes: a malformed count/edge or inconsistent root audit
fences GC; independently audit them against retained roots before qualifying GC.

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

The candidate root adapter and real first-new computation have passing local
tests. The schema-4 durable bridge, incremental schema/migration, GC and two-epoch
matrix must land and pass before removing any old fence or full-audit protection.
If pinned JMT behavior cannot satisfy the root-only design, stop and revise this
local storage contract under producer/consumer review; never alter frozen
consensus bytes or publish seal application effects as a workaround.

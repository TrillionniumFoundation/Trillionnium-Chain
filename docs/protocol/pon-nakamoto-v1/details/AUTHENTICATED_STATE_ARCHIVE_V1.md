# Durable authenticated-state research archive v1

This contract continues the [sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the [account-archive execution relation](ACCOUNT_ARCHIVE_PROTOTYPE_V1.md).
It defines a separate, reference-backed research store. It changes no installed
consensus profile, native state root, Node database schema or capacity limit.

Source ownership is the native composition candidate:
[public archive](../../../../trillionnium/crates/trnm-pon-node/src/authenticated_state_archive.rs),
[transactional storage](../../../../trillionnium/crates/trnm-pon-node/src/store/authenticated_state.rs),
and [native tests](../../../../trillionnium/crates/trnm-pon-node/src/authenticated_state_archive_tests.rs).
The ordinary Node and the existing account archive remain separate read-only
sources during every operation of this new API.

## 1. Actual sources and publication authority

`AuthenticatedStateArchive::import_genesis` accepts the actual Node and an existing
account-archive checkpoint. It obtains the complete native genesis state from
`Node::state_at`, checks the account checkpoint's actual branch, height and full
source root, and prepares the existing authenticated-state witness. It independently
recomputes the complete account/non-account commitments and all funds/count
aggregates before constructing its private initial record. Caller-selected synthetic
accounts or a supplied JSON commitment cannot initialize this namespace.

`publish` accepts a stored parent checkpoint, an actual child block identifier already
retained by the supplied Node, the parent's account-archive checkpoint and the two
witness inputs used by the existing authenticated execution relation. It performs:

1. Complete, checked reconstruction of the stored parent, including equality with
   the actual native parent state and the exact installed context.
2. Native packet retrieval and exact parent, height, network and parameter binding.
   The child must be readable under the configured ancestor bound after publication.
3. Actual execution through `execute_with_state_witness_and_progress`, using the
   native packet's transactions, height and miner. Missing, extra, malformed or
   foreign witnesses retain that relation's refusals.
4. Equality of the returned parent commitment with the stored parent; equality of
   the complete executed successor with `Node::state_at(child)`; and exact header
   state-root and receipt-root agreement. Complete-state recomputation independently
   checks the successor account root, account count/balance, non-account root/count,
   escrow, reward balance and issued supply.
5. Conversion of the actual original-parent account and non-account changes into
   one ordered delta list. Applying that list to the checked parent must reproduce
   the complete executed successor exactly.
6. One atomic publication of the delta rows, immutable checkpoint and optional
   compare-and-swap active selection.

The public interface never accepts a `StateExecutionObservation` as publication
authority. Serialized checkpoint data is decoded only as an internal untrusted
record and rechecked before returning a public `Checkpoint`. The resulting record
binds the actual retained packet's digest, transaction root, miner and receipt
bytes, as well as its exact account-archive parent checkpoint identifier.

Native admission provenance comes from the supplied Node's retained block and
checked state APIs; the sidecar does not implement another work verifier or fork
choice. An admitted inactive fork can be imported deliberately. This is neither
consensus activation nor a claim that the selected sidecar branch has greatest work.

## 2. Namespace, tables and encodings

The database schema namespace is `pon-authenticated-state-archive-v1`; the record
schema is `pon-authenticated-state-checkpoint-v1`. Opening a nonempty database with
a different table set, schema or network/parameters/genesis tuple is refused. The
native Node database and `pon-account-archive-prototype-v1` database are not upgraded,
attached or imported implicitly.

| Table | Exact role |
| --- | --- |
| `authenticated_meta(key, value)` | Exactly `schema` and the 96-byte network/parameters/genesis concatenation. |
| `authenticated_checkpoints(id, branch, parent, height, data)` | Immutable checkpoint; unique native branch id; parent is the preceding checkpoint id; indexed columns must equal the encoded record. |
| `authenticated_deltas(checkpoint, ordinal, data)` | Exact ordered per-block changes; ordinals start at zero and are contiguous; no delta may be missing or added. |
| `authenticated_snapshots(checkpoint, data)` | One complete native genesis snapshot. Successors retain deltas instead of full snapshots. |
| `authenticated_active(singleton, checkpoint, generation)` | At most one row, singleton 1, positive generation, existing checkpoint. |

Stored JSON uses compact `serde_json` serialization of the declared Rust structures.
The decoder rejects unknown fields and requires byte-for-byte equality with a fresh
serialization of the decoded value. Record field order is therefore part of this
stored encoding, rather than a caller-selected JSON representation.

`Record` field order is `schema`, `id`, `branch`, `parent`, `height`, `commitment`,
`delta_root`, `delta_count`, `snapshot_digest`, `execution`. Its identifier uses
the existing protocol `hash` framing and domain `authenticated-state-checkpoint-v1`
over one compact JSON tuple in that same order with `id` omitted. The commitment
retains the separately versioned authenticated-state commitment schema and digest;
this storage namespace does not redefine any existing account or native state hash.

The delta root is `sequence_root("authenticated-state-deltas-v1", delta_bytes)`,
including the exact canonical byte representation at each ordinal. Snapshot bytes
use domain `authenticated-state-snapshot-v1`. Native packet bytes use domain
`authenticated-state-native-packet-v1`. Changing any of these stored relationships
requires another explicit namespace, without silently reinterpreting this one.

Each delta encodes `key`, `before` and `after`. Optional values use a wrapper:
an absent value is `null`, whereas a present JSON null is `{"value":null}`. Thus
deleting a present null and inserting a new present null remain distinct operations.
Keys are strictly increasing; unchanged records are refused; each `before` value
must equal the exact current value during replay.

## 3. Atomicity, cancellation and branch selection

Publication uses an immediate SQLite transaction with WAL journaling and
`synchronous=FULL`. The writer checks schema/context, the expected parent seal and
optional active generation before inserting anything. It inserts actual delta rows
and the checkpoint, reloads the stored payload to check its exact row count and
digest, optionally updates the active pointer, checks logical quotas, and commits.

After the last write, the transaction rechecks its context plus availability and
exact payload digests along the target's complete sealed ancestor path. This covers
both new publication and explicit selection. A missing snapshot or corrupted delta
introduced between the earlier complete read and the transaction, or by the final
selection write's trigger, cannot publish an unreadable child or advance the selected
generation. The final check includes genesis and occurs before COMMIT.

Any returned failure before commit drops the transaction. Progress callbacks are
cooperative boolean cancellation boundaries, including execution, individual delta
writes, checkpoint write, selection write and immediately before commit. They do
not preempt a native hash, signature check, SQLite statement or complete-state scan.
There is no cancellation callback after commit that could report a rollback of an
already committed operation. A successful public checkpoint is returned only after
the storage commit succeeds.

`Selection::Inactive` records a branch without changing the active pointer.
`Selection::Activate { expected }` selects within the same publication transaction;
an explicit later `activate` also uses compare-and-swap. Each successful selection
increments the local generation. Selecting genesis or an older branch never restores
an earlier generation, removes another branch, rewinds Node's active head, or changes
local task/revocation/operation history. Stale generations and duplicate native branch
publications are explicit errors.

Selection must affect exactly one row, and an immediate readback must equal the
requested checkpoint and new generation. A SQLite trigger that ignores or changes
the write cannot produce a successful selection result; publication rolls back its
earlier checkpoint and delta writes as well. Native regressions also install an
`AFTER UPDATE` trigger that deletes the genesis snapshot: both selected publication
and a separate branch switch refuse and restore the exact original rows.

The existing account archive is read-only in these transactions. Producing and
retaining its successor account nodes remains its own explicit operation; the new
store does not pretend that two independent database commits are atomic. Availability
and ownership of future account witnesses remain separate obligations.

## 4. Read and reopen checks

Read operations use a consistent SQLite read transaction. Every operation checks
the namespace and logical quotas; orphan checkpoint references, deltas, snapshots
or active pointers are refused. The active table must contain zero or one valid row.
`active()` returns selection metadata; obtaining an authenticated complete state
requires `read` or `read_active`.

Reopen checks every stored checkpoint's canonical payloads, delta/snapshot digests,
parent relationship and actual native packet binding. If a selected checkpoint
exists, it reconstructs that complete state before returning. Inactive checkpoints
receive the same complete reconstruction when read or selected.

Reconstruction walks to the genesis snapshot, retains only ancestor identifiers,
then replays one block's ordered deltas at a time. Every intermediate checkpoint is
checked against the preceding native parent/header, the complete reconstructed
state commitment and all aggregates. The final complete state must also equal the
actual native state. A self-consistent local record hash alone cannot establish an
account sum, count, source root or execution result.

## 5. Resource boundaries and remaining work

| Limit or observation | Current meaning |
| --- | --- |
| `max_checkpoints` | Default 2,048 immutable checkpoints, including genesis. |
| `max_delta_rows` | Default 1,000,000 rows across the entire store. |
| `max_payload_bytes` | Default 256 MiB, summed checkpoint/delta/snapshot payload lengths. |
| `max_history` | Default 2,048 records including the genesis anchor; a new child is refused before publication if it would be unreadable under this bound. |
| Per-record payload | At most 32 MiB per encoded checkpoint, delta or genesis snapshot. |
| Complete state | The existing 65,536-key bound remains unchanged. |
| `Observation` | Actual checkpoint, delta and snapshot row counts plus summed payload bytes. |

These are logical quotas. They do not bound SQLite pages, indexes, fragmentation,
WAL retention or physical disk growth. The quota/orphan queries themselves scan
retained tables. Full-state reconstruction and account/root rebuilding still scale
with state and ancestor depth; the full native comparison remains necessary. The
store retains a complete state, one block's decoded changes and bounded ancestor
identifiers while replaying. Reopen additionally checks all retained payloads.

There is no persistent incremental authenticated-root authority replacing Node,
no efficient non-account range proof, no global disk pruning, no priced growth rule
and no independent witness availability service. Those remain concrete subsequent
work under the same plan. This implementation does not promote public-testnet,
production, independent-operator or scientific work-qualification flags.

## 6. Native and independent verification

The native `authenticated_state_archive` tests exercise actual signed transfers
and admitted native blocks, competing sibling branches, continuation, inactive
publication, selection back to genesis, monotonic generation and reopen. They
compare the exact retained state with ordinary Node execution and retain native
receipts. Negative cases cover unavailable/tampered rows, incoherent and forged
aggregates, wrong schema/context, stale selection, missing witnesses, exact null
encoding, quota failures, cancelled writes and an injected SQLite write failure.
An additional subprocess exits immediately before commit without running Rust or
SQLite destructors; reopening retains the original rows and selection and exposes
no child checkpoint. This is process-loss recovery, not a simulated hardware power
failure or a filesystem durability certification.

The successful branch test can export a fresh SQLite snapshot and complete actual
native sources when `TRNM_AUTHENTICATED_STATE_VECTORS` names a fresh JSON path. The
SQLite file is its `.sqlite` sibling, produced with `VACUUM INTO` only after the
successful fixture and reopen checks. The manifest schema is
`pon-authenticated-state-archive-native-observation-v1`; it retains the exact native
states and packets, source account checkpoints, all seven publication/selection
operations, final selection, quotas and actual row/payload counts. Failed corruption
fixtures cannot overwrite this successful artifact.

Native test source, an exported observation and an independently executed comparison
are separate evidence. None establishes power-loss behavior on unspecified storage
hardware, public proof availability or a production backend migration.

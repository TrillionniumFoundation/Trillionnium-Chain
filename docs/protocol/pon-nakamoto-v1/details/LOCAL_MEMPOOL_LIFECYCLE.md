# Native local queued PNX1 lifecycle

The existing Node M07/M08 SQLite/lock owner retains a bounded local queue using
M05 TypedAdmissionGate and the exact M06 executor. This is the explicit local
profile `native-local-queued-pnx1-v2`, not a second execution engine, task ledger,
external-effect supervisor or consensus mechanism. Public-development-v2 still exposes
only block Submit/Head/History; this module adds no transport operation.

## Identity, limits and persistent facts

`Node::enable_local_mempool(PoolLimits)` explicitly selects a context committed to
network, parameters, genesis and the deterministic serialized limits. The local DDL
hash includes its four tables. Older store schema/context is refused; no table import,
silent migration, fallback or change to existing chain transaction signatures is added.
Existing blocks can be validated into a fresh owner normally; the local queue is not a
consensus state key. Reopening alone supplies no new checked mining batch.

Limits are1..256 retained raw transactions,1..524288 raw bytes,1..16 members per local
group, a critical reserve below total record capacity,1..4096 retained removal digests
and an explicitly selected nonzero preview-miner identity. Pending, sequence-consumed,
expired and blocked archives **all** consume the same row/byte budgets. Each raw PNX1
is at most2048 bytes. If new admission needs capacity, V2 may evict whole branch-relative terminal cache
groups as specified below; queued/blocked or partly terminal groups stay protected. A
full protected queue rejects explicitly. Each group preserves original order/bytes/digest/signer/nonce/expiry/fee-limit;
fixed eight-byte nonce/expiry/fee columns preserve the full wire u64 range.

The M05 adapter is private and immutable. It re-encodes canonical PNX1, checks the
exact H(tx-id, complete signed bytes) and signer, and invokes the existing M06 main
preparation for the selected tag, network, expiry and strict Ed25519 signature.
M05 signer-scoped replay/recheck operates against the exact pending sequence prefix.
Its `max_gas` bridge is the configured command base-fee plus encoded-byte fee, and
`max_bytes` is measured canonical envelope length. These are derived local admission
bounds; PNX1 has no signed gas field and this is not arbitrary-program gas metering,
a measured CPU lower bound or a computational-hardness certificate.

After typed checks, M06 executes the whole candidate prefix against one immutable
parent using the configured preview miner. This handles actual funds/fees, nonce
sequences, funding dependencies, profile gates and control semantics. Success is a
local execution preview; its proposed state, fees, nonce, subsidy and receipts are
never installed into chain state by queue admission. Actual block creation/admission
must run the existing authoritative work and execution path again.

## Admission-triggered terminal cache eviction V2

V2 has a fresh profile/context/group hash domain and metadata DDL; opening a V1
owner refuses before database mutation. V1 source and evidence retain their original
finite-cache behavior. This is a fresh local storage continuation, not a consensus or
transaction signature change. See the exact algorithm and diagnostics in
[LOCAL_MEMPOOL_CACHE_V2](LOCAL_MEMPOOL_CACHE_V2.md).

Only a new, validated admission that needs row/byte space triggers cache eviction.
The owner selects oldest whole SequenceConsumed/Expired groups only when **every**
member is expired or its nonce has been consumed in the actual active branch.
Queued, Blocked and partly terminal groups are protected. Capacity reclaim, fixed-size
GC counters/hash head and insertion of the new complete group commit atomically.
Invalid native/M05/M06 admission or a failed SQL insertion leaves evicted raw groups
and counters intact. Reads, reconciliation, duplicate receipts and unsuccessful
protected-full submissions do not evict cache.

Cache eviction makes no local revocation or exact-inclusion/finality claim. It creates
no removal tombstone and promises no automatic requeue. After a heavier fork a valid
original raw may be resubmitted and fully checked again. Explicit operator pruning
below remains monotonic, independently capped and irreversible locally across reorg.

## Atomic local groups and exact mining batches

`pool_submit(raw)` and `pool_submit_bundle(raws)` perform resource/capacity, canonical,
strict signature/replay and complete M06 prefix checks before one SQLite transaction
writes the group and all members. A failed second row rolls back the first row and
group header. Rebuilding the real TypedAdmissionGate yields actual admission/ready
metadata counts for the full reconstructed pending prefix, not only new submitted
members; no fake PendingNonceReservation token or committed-chain fact is
created. SQLite owns durable local reservations. Owner group order is retained; M05
lane pop order is not permitted to split a group or reorder signed account sequences.

This protects **local queue and batch assembly only**. A block producer may separately
include signed transactions. Consensus renewal atomicity requires the single
[V3 tag22](QUALIFIED_TASK_LIFECYCLE_V3.md); a V2 tag19/tag21 local bundle cannot fix its
sole-task liveness gap.

`pool_mining_batch(parent,generation,max_records,max_bytes)` requires the actual active
parent and generation, selects an intact prefix of complete queued groups, rechecks
M05/M06 and returns original raws plus group IDs and local context. A group exceeding
the batch budget is not partially returned. `pool_validate_batch(&batch)` checks exact
retained group order/raw bytes, current status, preview miner and parent/generation,
then executes the current checks again. `pool_batch_is_current` is only a cheap context/
generation fence and grants no authenticity or chain activation. A miner must recheck
before use; actual Node validation still decides admission, activation and confirmation.

## Reopen, branch changes, statuses and local pruning

`pool_reconcile` replays complete original groups against the actual active parent in
insertion order. `pool_status` explicitly performs this reconciliation. A valid pending
group is Queued; expired groups are Expired; an active ledger sequence already consumed
is SequenceConsumed; temporarily invalid application/sequence prefixes are Blocked.
SequenceConsumed does **not** assert this exact transaction was mined. Exact inclusion
and confirmation remain normal chain observations. New groups cannot replace a queued
signer/nonce conflict. A matching retained group returns a bounded duplicate receipt
with its current state, not a new reservation or an execution guarantee.

Retained raw groups can become Queued again after a heavier fork restores their
unexpired account sequence and application state. They undergo strict typed and whole
M06 checks before reuse, including after restart. Branch-relative classification may
change; its local insertion/removal facts do not roll back with a chain reorganization.

`pool_status_snapshot` is bounded read-only and never invokes M06. It reports actual
active parent/generation, last checked parent/generation and `classification_current`.
A chain change makes its old classification visibly stale. A public status adapter
must preserve this scope instead of quietly triggering whole-prefix execution or
promoting stale Queued/SequenceConsumed to inclusion or confirmation.

`pool_prune_terminal(group)` is explicit local pruning only. It cannot prune Queued
facts. One atomic SQLite transaction records each original signed transaction digest
and removes its terminal group; regrouping, replay or a chain reorg cannot silently
resurrect locally removed signed members. Raw-digest removal history has its own
finite budget; full removal history refuses further prune. These logical row/byte
budgets are not a physical SQLite/WAL, chain archive or whole-disk quota. No global duplicate filter,
infinite physical retention, source fairness or chain-external permission is inferred.

## Native tests and remaining scope

`trnm-pon-node/tests/local_mempool.rs` exercises actual Node/M05/M06/SQLite behavior:
queued funding across groups and sequential sender nonces, exact restart and policy
mismatch, real signed fee/profile/expiry/conflict rejection, row/byte limits, failed
source control bundle without partial admission, intact two-control batch and actual
block execution, mutable-batch binding rejection, stale read-only snapshot, actual
heavier-fork raw restoration, per-raw removal monotonicity/regrouping rejection, finite
archives/removal history, admission-triggered terminal-cache eviction and its rollback,
partly terminal protection, real second-SQLite-row fault rollback and previous DDL shape
rejection. An explicitly invoked ignored selector also executes4500 signed nonce-bearing
raws in563 actual native packets with an eight-record retained pool and one restart;
its logical chain timestamps do not measure sustained wall-clock or public service.
These are scoped tests, not independent public-security or economics acceptance.

Reconciliation reconstructs bounded queues and validates prefixes conservatively;
its work can grow with configured queue size. It is local synchronous work, not a
cheap public resource-protection proof. Continuous mining, wall-clock/task-material
renewal, public transaction RPC, operator custody and WAN/service qualification require
their own exact owner integration and observations. No automatic source re-signature,
legacy/random mining fallback, transaction execution outside the chain, ML value or
hard-work acceptance is introduced by these queued facts.

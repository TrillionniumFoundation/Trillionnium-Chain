# TRNM PoCO-BFT production contracts v0

Status: **P0 implementation-contract freeze; production activation remains false**

Date: 2026-08-08

This document freezes the host/Core contracts that must exist before the
PoCO-BFT prototype can be called a durable node. It does not activate PoCO
weights, replace the protocol specification, or claim a production node.
Changing a consensus-visible rule requires a protocol-version transition.
Changing a local resource limit must never change block validity.

## 1. SafetyState durable record

`SafetyStateRecordV0` is the only restart authority for Core safety state.
The in-memory `SafetyState` value is not a persistence format.

The record must:

- use one versioned, canonical, bounded codec with strict EOF checking;
- bind the codec version, chain ID, protocol version, epoch, validator-set ID,
  genesis block ID and monotonic safety revision;
- encode every field required by `Core::recover`, including vote and timeout
  watermarks, high/locked QC references, finalized tip, payload terminal facts,
  validation obligations/completions, pending syncs, the complete pending sign
  intent, the ordered finalization queue and any safety halt;
- preserve canonical ordering for every collection and reject duplicates,
  disorder, unknown required variants, non-minimal integers, trailing bytes and
  records above the configured hard byte bound;
- carry a domain-separated checksum over the complete header and payload;
- be written with write-new-record -> fsync(record) -> fsync(journal/index) ->
  atomic active-pointer update -> fsync(parent directory), or an equivalent
  single-database WAL transaction with `synchronous=FULL`;
- retain at least the previous confirmed revision and reject rollback, gaps,
  chain/profile mismatch, checksum failure or a state that `Core::recover`
  cannot authenticate.

No signature request, broadcast or finalization effect may escape before the
exact revision which authorizes it has passed the durable storage barrier.
Peer snapshots can restore public Core state but can never restore or lower a
local signer watermark.

## 2. Complete canonical SignIntent

`Effect::RequestSignature` must carry one complete
`CanonicalSignIntentV0`, not an opaque root plus a caller-selected kind.
The envelope is immutable and contains:

- chain ID, protocol version, epoch and validator-set ID;
- author validator ID and the authorizing SafetyState revision;
- a closed intent variant: vote `(view, height, block_id, complete canonical
  vote preimage)` or timeout `(view, high_qc reference, complete canonical
  timeout preimage)`;
- the Core-computed signing root and an intent fingerprint covering every
  field above.

The signer must canonical-encode the supplied preimage, recompute the signing
root and fingerprint, compare both in constant time where applicable, and
persist its own anti-equivocation journal before producing a signature.
Exact intent replay returns the same signature or an idempotent success.
A same-epoch conflicting intent at or below a persisted watermark, a lower
safety revision, chain/profile drift, or root/preimage mismatch fails closed.
Signer state is local, monotonic and never reconstructed from application,
Core or peer snapshot data.

Current G1f evidence closes only the local-timeout subset of this contract. A
non-cloneable ordinary host owns Core, SafetyStore, signer journal, and one
injected exact-idempotent producer; confirms the exact Ordinary SafetyState
write before `StorageAck`; completes the journal and external watermark before
`SignatureReady`; and releases a private-field typed timeout outbound bound to
the canonical intent fingerprint. Exact reopen replays the persisted signature
without another producer call, while signer revision ahead of the authenticated
SafetyStore and Vote signing fail closed. Non-retryable runtime failures latch
the live host; only producer or external-watermark `Unavailable` may retry the
same durable intent. This is not a production producer or
complete SafetyRules/locked-QC rollback boundary. The host binary, pacemaker,
network transport, and Vote path remain unimplemented. A required-feature
local Linux matrix now covers six direct-child SIGKILL/reap boundaries from
authenticated Safety readback through verified typed Broadcast and requires
two fresh official-host exact replays. It authenticates the `0/0/0`, `1/1/1`,
or `1/2/2` signer stage and compares the complete typed outbound identity. The
producer-generation checkpoint occurs before the helper producer returns to
the signer; it is not evidence for the narrower post-trait-return window. This
is not power-loss/hardware-fsync, production HSM/KMS, network wire-byte, or
whole-namespace rollback evidence.

## 3. Durable validation job and callback outbox

The authoritative application database owns one
`validation_jobs_v0` row per `(route, full ValidationId)`. The immutable part
stores:

- request fingerprint and route/full `ValidationId`;
- exact signed-header/body reference and body checksum;
- exact parent block/state/JMT version and authenticated parent root;
- exact validator-set, consensus-parameter, runtime/configuration and protocol
  references used by evaluation;
- creation revision and a row checksum.

The logical monotonic state machine is:

`reserved -> evaluated -> callback_pending -> delivered -> acked -> applied`

`evaluated` is a logical authority boundary, not necessarily a separately
committed row. A schema may atomically seal the evaluated artifact and create
`callback_pending` in one transaction; it must never expose a durable
half-evaluated image between those two facts.

Rules:

- evaluation may start only after `reserved` is durable;
- `evaluated` seals the typed terminal result. A valid result also stores all
  four computed roots, receipts, a sealed domain delta, the canonical write
  recipe, and a domain-separated commitment to every exact physical JMT-plan
  field. Recovery replans against the authenticated exact parent and must match
  both the committed root and plan commitment;
  deterministic invalidity stores its closed reason code. Retryable
  `Unavailable` is an attempt fact, not a terminal callback, and must be
  retried under a Core-authorized generation;
- creation of `callback_pending` and its outbox payload is the same durable
  transaction as sealing the evaluated artifact;
- the outbox idempotency key is the route, full `ValidationId`, result and
  artifact checksum. Delivery can repeat after a crash; acknowledgement is
  idempotent and cannot acknowledge a different payload;
- `applied` is written only by the atomic Finalize transaction. Invalid jobs
  may be terminally acknowledged but never mutate application state;
- reopening an existing congruent row returns its durable state for replay or
  takeover. It must not silently coalesce and abandon unfinished work;
- any immutable-field mismatch, state regression, checksum failure or missing
  referenced body/config is a fail-stop invariant, never a new validity
  decision.

Snapshot export excludes node-local jobs/outbox rows. Restart recovery reads
them before accepting new work and deterministically resumes evaluation,
delivery, acknowledgement or apply from the last durable state.

## 4. Ordered finalization queue

Core and the host use a durable, strictly ordered ancestor queue rather than a
single latest-proof slot. Each entry binds proof ID, finalized block ID,
height/view, authenticated direct parent, proof bytes/checksum and Core safety
revision.

- enqueue is idempotent by proof ID and rejects conflicting height/block data;
- entries are contiguous from the durable applied tip and are applied only in
  ascending height order;
- no descendant may be acknowledged while an earlier ancestor is absent or
  unapplied;
- the host sends `FinalizationApplied` only after the application transaction
  and queue acknowledgement are durable;
- recovery reissues the oldest unacknowledged entry. Pruning cannot remove
  data needed by any queued entry.

## 5. BlockId-keyed speculative overlay

Every unfinalized executable block owns a sealed overlay keyed by its native
`BlockId`. An overlay binds its exact parent `BlockId`, parent state/JMT
version and root, body/config fingerprints, receipts, all four computed roots,
domain delta, canonical write recipe, exact physical-plan commitment and
artifact checksum.

- height-one execution uses an explicit synthetic-genesis authority;
- a child executes only from its exact parent overlay (or the committed tip
  when that parent is finalized); it may never reopen an unrelated committed
  head and splice the result;
- evaluation never mutates committed application state;
- Finalize revalidates the job, overlay lineage, parent/head and roots, replans
  the canonical writes against that exact parent, requires the resulting root
  and every physical-plan field to match the sealed commitment, then atomically
  promotes the sealed delta/replanned JMT update, receipts, native block/head,
  job state and finalization acknowledgement;
- promotion is idempotent. Conflicting forks and descendants of a discarded
  parent are reclaimed only after they are no longer needed by Core recovery,
  sync or evidence retention.

## 6. Consensus parameters versus local backpressure

`ConsensusParametersV0` is epoch-committed and is the sole source of
consensus-visible validity limits. Host-local resource controls belong to a
separate `NodeResourceLimitsV0` and are never hashed into a block or validator
set.

Consensus parameters may determine deterministic validity. Local limits may
only:

- delay admission, return typed `Unavailable`, bound queues/concurrency and
  request retry/fetch;
- apply peer scoring or transport backpressure without fabricating a block
  result; and
- trigger a local fail-stop when a promised durable invariant cannot be kept.

Local capacity, disk pressure, thread availability, timeouts or queue fullness
must never become `DeterministicallyInvalid`, alter execution order, change a
root, advance a cursor, or influence proposer/voter consensus semantics.
Admission must reserve capacity before accepting ownership, and release it
only at a documented durable transition.

## Required crash matrix

Before the durable single-node milestone can close, tests must kill the
process immediately after reservation, execution, JMT planning, callback
outbox commit, callback delivery, signer-journal fsync, signature production,
broadcast enqueue, Finalize commit and directory/database fsync. Every restart
must demonstrate no double-sign, no duplicate apply, no root drift, no lost
ancestor finalization and no permanently coalesced validation job.

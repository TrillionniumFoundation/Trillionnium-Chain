# M08 Finality / Node Commit / Recovery technical specification v1

Status: **implementation contract; candidate only**

## Authority

M08 owns ordered application finalization, the Node Commit Ledger, projection
coordination, publication eligibility and restart convergence. It consumes
authenticated decisions from M02/M03/M06/M07/M13. It cannot choose a fork,
create a signature, reinterpret application validity or override a safety halt.

## Interfaces

`NodeCommitRecordV1` binds node generation, chain and validator identity,
height/view/block/parent, proposal and proof digests, pre/post state roots,
receipt/event roots, Safety revision, sign intent, signer watermark, finality
proof, checkpoint predecessor, durable sequence and previous-record digest.

Ports are typed by stage:

- `PrepareCommitV1`;
- `SealApplicationV1`;
- `PersistSafetyV1`;
- `PersistSignIntentV1`;
- `ConfirmSignatureV1`;
- `ApplyFinalityV1`;
- `ConfirmCheckpointV1`;
- `PublishOutboundV1`;
- `RecoverNodeV1`;
- `ReadProjectionV1`.

A later-stage capability cannot be constructed from an opaque caller digest or
telemetry event.

## State machine

```text
Prepared
 -> ApplicationSealed
 -> SafetyPersisted
 -> SignIntentPersisted
 -> SignatureConfirmed
 -> FinalityApplied
 -> CheckpointConfirmed
 -> OutboundPublished
```

The sequence is append-only and monotonic. Each step verifies the exact previous
record and all cross-module roots. Replaying the same transition is idempotent.
Skipping, reordering, changing generation or changing any bound digest is a
stop condition.

Finality is applied in exact ancestor order. A child cannot become durable
finality while an unacknowledged ancestor remains at the queue front. A
publication failure never authorizes re-signing.

## Persistence and recovery

The ledger is the coordinator authority; subordinate stores are either named
independent authorities or idempotent projections. Recovery compares every
store with the last complete ledger record and classifies each as exact source,
exact target, safely replayable, rebuildable projection or ambiguous. Ambiguous
states stop before networking or signing.

Required crash boundaries exist before and after every stage, including an HSM
operation that succeeded with its response lost, checkpoint CAS success with
lost reply, finality write with lost reply, disk full, fsync error, WAL/SHM
partial persistence, process takeover and whole-store rollback. Fresh readback,
not cached success, resolves uncertainty.

## Resource bounds

The ledger bounds record bytes, retained ancestry, pending commits, recovery
scan length, projection retries, proof bytes, signature work and rebuild work.
Compaction may checkpoint only finalized, independently verifiable history and
must retain the evidence/slashing and weak-subjectivity horizons. Recovery work
has an explicit operator-visible ceiling and never silently truncates history.

## Security

A clone, lower generation, regressed watermark, mismatched chain/application
identity, conflicting finality proof, replaced database, stale checkpoint or
same-height different root fails closed. The external monotonic anchor is
independent of the rollback domain it protects. Local hash chains and file
watermarks do not claim resistance to coherent disk-image rollback.

## Observability and SLO

The `authority-hot-path-v1` profile reports per-stage p50/p95/p99, fsync and HSM
latency, pending depth, oldest pending age, replay count, ambiguous-stop count,
restart convergence time, projection lag and finalized committed goodput.
Telemetry is derived from ledger facts but cannot recreate stage authority.

## Verification and evidence

Tests exhaust every crash cut and lost-response combination, duplicate replay,
projection reorder, corrupted record, rollback, clone, disk pressure,
controller-cache loss, process takeover, partition/heal and state-sync rejoin.
Evidence proves no double sign, no conflicting finality, no skipped ancestor and
exact post-restart root convergence. Physical power-loss and hardware signer
tests require independent execution records.

## Activation boundary

M08 remains candidate until the default node uses the full stage sequence for
arbitrary proposals and transactions, the external anchor/HSM boundary is real,
physical recovery is accepted, state sync rejoins the same finality history and
independent reviewers replay the fault matrix on the exact release artifact.

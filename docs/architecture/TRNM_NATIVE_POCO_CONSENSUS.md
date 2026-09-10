# TRNM Native PoCO Consensus Architecture

Status: **binding development architecture**  
Updated: 2026-09-11

## Decision

Trillionnium Chain uses its self-developed Proof of Consumption protocol for
consensus coordination, execution, economic settlement and finality evidence.

The canonical path is:

`network ingress -> trnm-node -> trnm-mempool -> trnm-executor -> trnm-pouw/trnm-state -> committed state root and finality receipt`

No third-party consensus engine or adapter may become a production dependency.

## Responsibilities

### `trnm-node`

Owns authenticated peer communication, proposal construction, validator votes,
round/view change, quorum assembly, durable anti-equivocation state, block
commit, restart recovery and finality receipt publication.

### `trnm-mempool`

Owns bounded admission, duplicate rejection, traffic classes, reserved
critical capacity, fairness, backpressure and proposal-ready transaction
selection.

### `trnm-executor`

Owns deterministic access-set conflict detection, execution grouping,
parallel-work planning and conservative serial fallback. Execution results are
merged only by a deterministic commit order.

### `trnm-pouw`

Owns the PoCO lifecycle: task creation, worker acceptance, commit, reveal,
consumption evidence, challenge, resolution, timeout and settlement. Historical
crate naming is retained for source compatibility; PoCO is the active protocol.

### `trnm-state`

Owns versioned objects, balances, governance state, replay protection,
checkpoints, write-ahead recovery and the committed state root.

### Finality libraries

`trnm-finality-types` defines portable block, vote, quorum, inclusion-proof and
receipt types. `trnm-finality-verifier` verifies them without depending on the
full node.

## Native consensus flow

1. Ingress authenticates and canonicalizes a transaction before admission.
2. The mempool applies duplicate, resource, QoS and anti-spam policy.
3. A native proposer selects an ordered candidate set for a height and round.
4. Validators independently authenticate, execute and derive transaction and
   state roots.
5. Validators vote only for the exact canonical header they executed.
6. A quorum certificate requires at least two-thirds plus one of configured
   voting power.
7. The node atomically commits the block, state root, anti-replay data and
   anti-equivocation evidence.
8. A finality receipt binds the committed header, quorum evidence and inclusion
   proof material for external verification.
9. A timeout or partition without quorum advances the round/view or stalls; it
   must not produce conflicting finalized heights.

## Core safety invariants

1. Every proposal, vote and command is bound to chain ID, height/round, signer
   identity and canonical bytes.
2. A validator must not sign conflicting blocks at the same safety boundary;
   anti-equivocation state must survive restart.
3. A commit requires at least two-thirds plus one of configured voting power.
4. Every validator executes the same ordered commands and derives the same
   transaction root, state root and block hash.
5. Replayed command IDs, invalid nonces, expired envelopes and altered payloads
   fail closed.
6. Failed transactions do not mutate committed state.
7. Economic settlement conserves value except for explicitly governed issuance
   or burn operations.
8. Recovery starts only from authenticated checkpoints and verified logs.
9. Network partitions without quorum must stall rather than finalize conflicting
   heights.
10. Performance claims require end-to-end multi-host evidence, not scheduler-only
    microbenchmarks.

## Development scope

The current native implementation contains local multi-validator tests,
round-change and recovery paths, authenticated messages, state-root checks,
conflict grouping, PoCO settlement tests and finality receipts.

The following remain release blockers until demonstrated by reproducible gates:

- authenticated multi-host peer formation and state synchronization;
- secure remote signing, HSM/KMS integration and key-compromise recovery;
- validator staking, unbonding, jail and slashing policy;
- threshold governance, timelocks and emergency authority separation;
- sustained adversarial load, disk-full and long-duration soak evidence;
- durable indexer, explorer, archive and public read-model;
- independent security audit, long fuzz campaigns and build provenance.

## Acceptance rule

A feature is implemented only when it executes through the native path on every
validator, produces deterministic committed roots and has replayable evidence
bound to an exact commit. The project must remain marked not release-ready
until the blockers in `../../RELEASE_READINESS.md` are closed.

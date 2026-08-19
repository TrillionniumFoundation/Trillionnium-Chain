# 10 — Invariants, formal obligations, and conformance

Status: **draft normative target; design-only, not implemented, not frozen, not activated**

This document is the cross-plane proof and release contract. Passing prose
review is not normative freeze. Every invariant must be represented by exact
schemas/vectors, executable checks, formal or mathematical evidence where
appropriate, and independent review.

## 1. Cross-context and encoding invariants

- Every consensus-affecting object binds chain/genesis, protocol version,
  stack profile, object kind/schema, canonical ID, authority, and predecessor
  or version where applicable.
- Canonical encoding is total only for recognized bounded values; unknown
  enums/versions, non-minimal representations, duplicate fields/items,
  alternate order, trailing bytes, overflow, and excessive allocation fail
  closed.
- Every object ID, signing root, certificate, state-root kind, and proof
  statement has a distinct domain. Generic Merkle leaf/node/list domains bind
  the closed `RootKindV1` discriminant in every preimage, so two destination
  roots remain cryptographically distinct. V0 and v1 bytes cannot cross-decode
  or cross-verify.
- Logical object IDs exclude mutable transport/signature layout; certificate
  IDs bind the canonical unique signer set where signer identity is semantic.

## 2. Agent and capability invariants

- Capabilities bind delegate, issuer generation, task/model/tool/endpoint
  scope, operations, budget, rate, validity window, revocation generation,
  session key, and allowed nonce lanes.
- Authority can only narrow through delegation. Revocation is monotonic and
  takes effect under an explicit height rule.
- Nonces are monotonic per `(agent_id, authorizing_key_id, capability_id,
  session_generation, lane:u16)`; one lane, key, session, capability, agent,
  chain, or profile cannot replay into another.
- Spending across concurrent lanes cannot exceed one shared authorized budget;
  reservation and release are deterministic and crash-idempotent.

## 3. Market/task invariants

- Offer, acceptance, lease, escrow, start, checkpoint, resume, migrate, cancel,
  timeout, result, challenge, resolution, refund, and settlement transitions
  are explicit, authorized, and monotonic.
- One task attempt has at most one Offered or Active lease. Redundant compute
  is represented by distinct tasks/attempts with distinct escrow and results,
  never multiple active leases under one attempt.
- Every checkpoint/result binds exact task/lease/input/profile/artifact roots.
  Migration extends an accepted checkpoint and cannot erase an obligation.
- Escrow remains conserved and cannot be paid, refunded, or slashed twice.

## 4. Data-availability invariants

- TransactionBatch and ArtifactEvidence are different namespaces with
  different vote, verification, retention, and light-client meanings.
- An attestation signature escapes only after exact bytes, manifest, capacity,
  retention obligation, and anti-equivocation journal are durable and read
  back.
- A valid AC is threshold attestation to durable storage, not correctness,
  usefulness, privacy, payment, or perpetual availability.
- Every voting validator retrieves and deterministically validates the complete
  TransactionBatch before voting. Missing data never produces a vote.
- Repair preserves the obligation; GC occurs only after expiry and all task,
  challenge, settlement, sync, and evidence holds close.

## 5. Order and signing invariants

- Less than one-third Byzantine weight cannot cause conflicting finalized
  blocks within one valid activation history.
- An honest validator emits at most one Vote and one exact Timeout per allowed
  epoch/view rule; duplicate signer weight is rejected before summation.
- Safe voting respects the durable locked QC. A TC only advances view and
  never unlocks or finalizes. Finality requires the exact three-chain rule.
- SafetyState, complete sign intent, signer journal/watermark, application/DA
  facts, and whole-node checkpoint persist and reconcile before signature
  release. Rollback or ambiguous commit fails closed.
- Epoch changes and protocol activation require exact old/new dual quorum and
  finalized descriptors; no fallback history exists.

## 6. Deterministic execution invariants

- Object-aware MVCC is observationally equal to canonical serial execution,
  independent of scheduler interleaving, cache, thread count, or retries.
- Committed object versions, receipt/event order, usage, fees, and roots follow
  canonical block order. Undeclared writes and stale reads cannot commit.
- Every accepted transaction has exactly one explicit outcome receipt;
  statically invalid transactions are never included.
- Nonce/fee effects for reverted/out-of-resource outcomes follow one exact
  deterministic rule; host failure cannot be encoded as successful execution.
- Block finalization and exact replay are idempotent, while a different body or
  source under one ID fails closed.

## 7. Verification, rollup, and dual-finality invariants

- `(verification_profile_id: Bytes, verification_profile_version: u32,
  verification_profile_hash: Hash32)` defines exact statements, bindings, evidence,
  authority, challenge/appeal, resolution, maturity, settlement, and PoCO
  eligibility. Unknown profiles fail closed.
- Order finality, result finality, and settlement finality are distinct. Later
  challenge success only creates forward transitions and never reorgs order.
- Consumption rollups bind both parties, contiguous unique sequence ranges,
  task/result/meter/evidence roots, totals, settlement, DA, policy, and window.
  No entry appears in two rollups or settlements.
- Only mature, settled, challenge-closed, related-party-compliant consumption
  affects a later epoch's PoCO weight. Current/shadow consumption cannot alter
  the epoch already validating it.

## 8. Accounting invariants

- Value is conserved across balances, escrow, provider payment, refund, DA and
  execution fees, challenge bonds/rewards, slashes, burns, and protocol reward.
- AI compute payment, protocol fee, storage/DA payment, verifier reward, and
  slash are separately accounted and cannot be relabelled.
- All arithmetic is checked integer/fixed-point with explicit rounding and
  remainder destination. Supply changes require explicit authorized rules.
- Block-end fee aggregation is equal to the sum of canonical per-transaction
  deltas and avoids a shared per-transaction collector write.

## 9. Light-client and sync invariants

- Clients distinguish OrderFinality, ApplicationState, ArtifactAvailability,
  and ResultSettlementFinality proofs and expose their limited meanings.
- Trusted state advances only from a valid proof chain, exact epoch handoff,
  and profile/version rules. A TC, untrusted snapshot, or adapter response
  cannot advance it.
- State sync reconstructs the exact authenticated state and all live DA/legal
  holds; it never imports or lowers local signer/Safety/attestation journals or
  external watermarks.
- V0-to-v1 activation has one terminal v0 checkpoint, one migration output,
  one dual-quorum statement, one successor history, and no downgrade/fallback.

## 10. Required formal models

Before freeze, the repository must contain bounded but traceable models for:

1. weighted HotStuff locks, QC/TC, three-chain finality, partition/heal;
2. persist-before-sign across Safety/App/Signer/DA/whole-node checkpoints;
3. DA durable-before-attest, withholding, repair, retention, holds, and GC;
4. BatchRef availability/retrieval and execute-before-vote;
5. capabilities, revocation, shared budgets, and parallel nonce lanes;
6. task/lease/escrow/checkpoint/migration/cancel/timeout lifecycle;
7. verification profiles, challenges, dual result/order finality;
8. deterministic MVCC serial equivalence and finalization replay;
9. ConsumptionRollup uniqueness, maturity, and PoCO eligibility;
10. multi-resource fee/value conservation;
11. epoch dual quorum and v0-to-v1 activation/no-fallback; and
12. multi-hop light-client/state-sync proof acceptance.

Every model states assumptions, bounds, correspondence to spec fields, checked
properties, known limits, and retained failing mutants. Model checking is
evidence, not a proof beyond its bounds.

## 11. Required schemas and vectors

Normative freeze requires:

- assigned canonical wire schemas for every object and closed enum;
- byte, ID, signing-root, certificate, Merkle/root, state-transition, proof,
  migration, and fee vectors generated independently from the implementation;
- boundary values for zero/max lengths, weights, quorum thresholds, epochs,
  heights, nonces, time windows, resource counters, and checked arithmetic;
- negative vectors for wrong chain/genesis/version/profile/domain/root kind,
  unknown enum, duplicates, reordering, trailing bytes, truncation, overflow,
  invalid signatures, stale generations, expired capability/retention, and
  v0/v1 cross-decode;
- exact task/verification/challenge/rollup/settlement histories; and
- an independent parser and light client that consume the same vectors.

## 12. Fault, fuzz, and interoperability evidence

Required campaigns include:

- structured/property fuzzing of every decoder, root builder, state transition,
  proof verifier, scheduler, and migration parser;
- differential execution under varied thread counts, conflicts, restarts, and
  two independent implementations;
- SIGKILL, power-loss, fsync/rename, disk-full, short-write, corruption,
  rollback, commit-uncertain, HSM unavailable/rollback, and DA-loss injection
  at every durable boundary;
- authenticated network partitions, equivocation, Byzantine input, slow/refuse
  leaders, withholding, repair, catch-up, epoch close, and handoff;
- 4/7-node minimal safety baseline, then 7/31/100-validator controlled WAN
  profiling once v1 is implemented; and
- independent schema/parser/light-client interoperability.

A 15-second fuzzer startup, simulator TPS, loopback ingress, v0 tests, or one
implementation is not v1 conformance evidence.

## 13. Freeze and activation gates

`specification_status` may become `frozen` only when all numbered normative
documents agree; schemas and vectors are complete; formal models and retained
mutants pass; light-client, state-sync, upgrade, and economics contracts close;
and independent review finds no open Critical/High contradiction.

Implementation completion additionally requires two interoperable critical
parsers/verifiers, full node integration, crash/fault campaigns, WAN evidence,
reproducible artifacts, SBOM/provenance, operational runbooks, external review,
and all machine truth fields updated atomically. Freeze does not imply
implementation; implementation does not imply activation; activation does not
imply production readiness.

Creating a new BFT theorem/decision rule is permitted only after Certified DA
and parallel execution are implemented and profiling still proves Order is the
dominant bottleneck or a formal hard requirement remains unmet; existing
HotStuff/Jolteon/DAG alternatives are shown insufficient; the new safety/liveness
model is independently reviewed; retained mutants pass; at least two
implementations interoperate; and WAN, epoch, recovery, state-sync, and light
client evidence closes.

Performance claims use committed goodput, finality tail latency, and measured
unit cost under identical hardware, application, durability, and fault models.
Ingress TPS is never consensus throughput.

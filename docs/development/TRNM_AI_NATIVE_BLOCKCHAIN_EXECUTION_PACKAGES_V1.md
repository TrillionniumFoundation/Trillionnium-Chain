# TRNM AI-native Blockchain execution-package map v1

Status: **subordinate execution decomposition; not a second development plan**

Authority:

- Canonical plan: [`TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
- Evidence contract: [`TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md`](TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)
- Machine truth: [`../../config/consensus-mainline.json`](../../config/consensus-mainline.json)
- Release truth: [`../../RELEASE_READINESS.md`](../../RELEASE_READINESS.md)

This file converts the canonical G0–G5 route into review-sized engineering
packages. It does not change any protocol validity rule, machine flag, gate
status, release conclusion, or activation decision. A package may be developed
before its promotion prerequisite is accepted, but it remains
`candidate-non-normative` and cannot satisfy a later gate.

## 1. Package discipline

Every package obeys the following rules:

1. One pull request closes one named capability slice.
2. A package has one owner, one source/tree tuple, one test/evidence index and
   one rollback boundary.
3. Source, schema, vectors, negative tests, documentation and truth metadata
   for a capability land together.
4. A package does not set `production_candidate`, protocol activation, public
   testnet, validator-run, performance or release flags.
5. Safety and recoverability packages precede throughput or AI feature work.
6. A local carrier, unit test, fixture, simulator or SQLite root does not become
   Node, network or production authority by naming.
7. Every accepted package records which downstream evidence must be rerun when
   its inputs change.
8. Open Critical/High findings, unknown crash outcomes, root divergence,
   double-sign, lost obligation, ambiguous rollback or truth drift stop
   promotion immediately.

## 2. Current source split

As of 2026-08-28, the canonical development ref is
`refs/heads/docs/chain-poco-bft-mainline-20260825`. The branch documentation tip
may be newer than its tested code. Package evidence must therefore bind these
separately:

```text
branch_tip
code_source_commit
code_source_tree
plan_assessed_commit
plan_assessed_tree
evidence_source_commit
evidence_source_tree
```

A documentation-only descendant cannot upgrade a code result, and an older
plan assessment cannot silently cover newer source. Each package manifest must
make every relation explicit.

## 3. Critical path

The strict promotion path remains:

```text
G0
 -> G1-R1 replay recovery/status authority
 -> G1-R2 replay-to-Core durable acknowledgement
 -> G1-R3 authoritative ordinary Proposal execution and Vote
 -> G1-R4 ordered finality, apply and restart recovery
 -> G1-R5 4/7-node native consensus campaign
 -> G1.5 v1 normative freeze and v0 baseline
 -> G2.0 complete CEV1 transaction/wire traceability
 -> G2A certified DA
 -> G2B Agent/Market/Task
 -> G2D deterministic execution/MVCC/fees
 -> G2C verification/challenge
 -> G2E settlement
 -> G2F whole-node authority/state sync/light client
 -> G3 WAN performance and Order decision
 -> G4 adversarial public-testnet readiness
 -> G5 economic/governance/mainnet activation
```

The order deliberately places G2D before G2C and G2E: execution produces the
canonical resource/result intent; verification decides result maturity;
settlement alone changes economic state.

## 4. G0 packages — one reproducible native truth

### G0-P1 — source and authority normalization

Objective: one unambiguous branch/source/evidence identity.

Deliverables:

- protected canonical default branch or an explicit temporary exception record;
- generated `CURRENT_SNAPSHOT.json` with branch, code, tested, assessed and
  release-candidate identities;
- removal of repository clone/path ambiguity from active documentation;
- branch protection, required checks and CODEOWNERS policy;
- clean-clone truth check on worktree, staged index, pushed commit and source
  archive.

Exit evidence: two clean clones independently reproduce the same snapshot
manifest and dependency graph.

### G0-P2 — native release and SBOM closure

Objective: reproducible active-Cargo artifacts with no production Comet/ABCI
edge.

Deliverables:

- default/all-features Cargo tree and lockfile scans;
- deterministic native binary/library build;
- signed SBOM/provenance;
- negative startup contract for legacy data directories;
- explicit archival allowlist for migration-only source.

Non-claim: this does not prove a working validator or migration ceremony.

## 5. G1 packages — frozen-v0 authority

### G1-R1 — external payload replay recovery and Core-ack ledger

Objective: remove the state in which an authenticated payload is durably
admitted but an operator cannot determine or repair its publication state.

Scope:

- independent full WAL/hash-chain verification;
- exact target binding;
- exact one-record head-lag repair only;
- retained temporary quarantine;
- immutable Core acknowledgement record supplied after an externally proven
  durable Core acknowledgement;
- stable status/recovery CLI;
- no production Node/Core activation.

Detailed contract:
[`packages/TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md`](packages/TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md)

### G1-R2 — replay-to-Core acknowledgement owner

Objective: replace the manually supplied Core acknowledgement with one
Node-owned durable transition.

Required state machine:

```text
AuthenticatedFrame
 -> PayloadWalAdmitted
 -> CoreDeliveryPending
 -> CoreInputAccepted
 -> CoreSafetyRevisionDurable
 -> ReplayCoreAckDurable
 -> DeliveryCompleted
```

Deliverables:

- one non-cloneable Node owner for the payload receipt and Core input;
- Core result/revision digest generated by Core, not caller input;
- payload breadcrumb and Core acknowledgement committed in one predecessor-
  bound whole-node checkpoint or recoverably coordinated transaction;
- exact idempotent replay after response loss;
- no fresh-generation admission while an earlier target is unresolved;
- process kill matrix at every transition.

Exit: no possible recovered state reports “new” for a frame already accepted by
Core, and no state reports “acknowledged” without the exact durable Core
revision.

### G1-R3 — ordinary Proposal → execution → AuthorityVote

Objective: generalize the bounded synced-proposal fixture into the real ordinary
proposal route.

Deliverables:

- complete canonical body and evidence retrieval;
- exact parent header/state/JMT authority;
- active validator-set, parameter and runtime-profile binding;
- native execution and four-root comparison;
- deterministic `Valid | Unavailable | DeterministicallyInvalid` mapping;
- SafetyRules safe-vote decision and persist-before-sign;
- remote signer intent generated only from the Core-owned authority;
- no raw key in the default node.

Exit: a real non-empty ordinary proposal reaches a signed Vote under process
restart tests; every root/context mutation fails closed.

### G1-R4 — ordered finality and durable application apply

Objective: close the complete ancestor-ordered finalization contract.

Deliverables:

- contiguous durable finalization queue;
- exact proof/body/overlay lineage;
- application apply and JMT promotion in ascending ancestor order;
- atomic queue acknowledgement and committed-head readback;
- response-loss recovery, duplicate apply rejection and losing-fork reclamation;
- restart recovery from every queue/apply boundary.

Exit: zero lost ancestor, duplicate apply or state-root drift across the crash
matrix.

### G1-R5 — native 4/7-node evidence

Objective: prove the preceding single-node authority in a real network.

Campaigns:

- normal finality;
- offline minority and rejoin;
- leader crash and timeout certificate;
- 2+2 and 4+3 partition/heal profiles as applicable;
- validator restart and catch-up;
- state sync from a trusted finalized checkpoint;
- epoch/key rotation;
- signer and disk fault injection.

Exit: signed process/network evidence with zero conflicting finality,
double-sign or root divergence. Transport-only smoke is not an exit.

## 6. G1.5 packages — v1 specification freeze

### G1.5-S1 — CEV1 normative inventory

- exact `ConsensusParametersV1`;
- exact `StackProfileV1`;
- complete verification registry entries;
- object/operation/error registries;
- closed lengths, counts, nesting and cost budgets;
- version/domain mapping and old-byte rejection.

### G1.5-S2 — independent conformance

- two independent parsers;
- exact encode/decode round trips;
- positive, negative, differential, mutation and fuzz corpora;
- retained formal mutants;
- independent light-client and upgrade review.

Exit: `normative_freeze=true` only after independent review; candidate kernels
cannot substitute.

## 7. G2.0 packages — complete W0–W7 traceability

Each operation kind `0..29` receives one generated row containing:

```text
kind
status(enabled|disabled)
schema_hash
domain
maximum_bytes
maximum_nested_items
maximum_signature_work
static_authority
nonce_lane
access_set
DA_binding
Order_binding
execution_receipt
result_or_challenge_binding
settlement_binding
RPC/SDK projection
positive_vectors
negative_vectors
implementation_owner
evidence_id
```

Disabled kinds terminate in a canonical rejection. Enabled kinds must traverse
all applicable W1–W7 links. No local kernel API is accepted when the same bytes
cannot be decoded through `AgentTransactionV1`.

## 8. G2 plane packages

### G2A — certified DA

First activation profile: `DA-FULLREP-V1` only.

Required closure:

- authenticated author and attestor journals;
- durable-before-attest;
- exact `TransactionBatch` and `ArtifactEvidence` namespaces;
- full retrieval, repair, withholding evidence and retention holds;
- proposal retrieval-before-vote binding;
- Node-owned GC authority after finality/challenge retention;
- restart and multi-host fault matrix.

DAS/erasure sampling remains a separately versioned future profile.

### G2B — Agent/Market/Task

Required closure:

- root/controller/session key lifecycle;
- attenuated capability and shared budget;
- parallel nonce lanes and payer nonce;
- Task, Bid, Lease, Escrow, Checkpoint, pause/resume/migrate/cancel/timeout/refund;
- profile immutability and scope enforcement;
- authenticated global state/JMT integration.

### G2D — deterministic execution/MVCC/fees

Required closure:

- declared object access and exact versions;
- parallel speculative execution;
- canonical-index validation and deterministic retry;
- serial-equivalent state/receipts/events/fees;
- multi-resource meter and block-end fee reduction;
- fork-aware overlays and finality promotion;
- identical roots across worker counts and conflict schedules.

### G2C — verification/challenge

Initial production candidate profile should be one narrow objective profile,
preferably deterministic re-execution. Every profile has an independent
assurance case covering statement, trust root, parser, cost, expiry, revocation,
challenge, display label and failure semantics. No automatic profile fallback
is allowed.

### G2E — settlement

Required closure:

- chain-derived settlement intent;
- escrow/account/bond/treasury conservation;
- one-shot exactly-once apply;
- payment/refund/reward/slash policy roots;
- challenge maturity and no premature PoCO eligibility;
- duplicate, stale price, wrong asset and insolvency negatives.

### G2F — whole-node authority

Hard exit requirements:

- one authenticated snapshot or explicit atomic multi-store transaction;
- canonical application JMT root, never a candidate composite-root substitute;
- external monotonic anti-rollback anchor;
- process-owned signer, broadcast, restart and state sync;
- two independent light clients covering Order, DA, execution, result,
  settlement and upgrade proofs;
- complete W0–W7 real transaction trace.

## 9. G3 packages — measurement before consensus novelty

### G3-M1 — benchmark contract

Freeze `benchmark-manifest-v1`, workload bytes, topology, faults, clocks,
percentile denominator, raw traces, cost normalization and independent replay.
Submitted TPS is never reported as committed goodput.

### G3-M2 — 7/31/100 process matrix

Report process, host, operator, custody and region counts separately. Multiple
processes on one machine do not become multiple failure domains.

### G3-M3 — retain/amend/replace Order ADR

Only measured bottlenecks may trigger an Order change. Any replacement requires
a new protocol version, formal safety/liveness model, two interoperable
implementations, migration and light-client rules.

## 10. G4 packages — adversarial public testnet

- 7–30 day soak;
- multi-region partition, DDoS, disk, OOM, state-sync and signer campaigns;
- public RPC/WS/indexer and SDK conformance;
- external consensus, cryptography, security and economic audits;
- incident, upgrade, key rotation and disaster-recovery exercises;
- independent operator onboarding.

## 11. G5 packages — economics and activation

- PoCO wash-consumption/Sybil/cartel model;
- bond, unbond, jail, slash and evidence windows;
- parameter/governance authority and emergency powers;
- migration/export/import ceremony;
- fresh genesis and cross-peer GenesisQC;
- signed release, SBOM, provenance and rollback authority;
- explicit activation vote and machine-flag change.

PoCO voting weight remains shadow-only until economic and consensus audits are
accepted.

## 12. Parallel work that is allowed

The following work may proceed in parallel as candidate-only preparation:

- v1 schema authoring and independent parser implementation;
- deterministic execution benchmark harness;
- DA full-replication local kernels;
- SDK/error-registry generation;
- economic simulations;
- external audit preparation.

It may not bypass G1 authority or change global completion flags.

## 13. Package evidence minimum

Every package evidence record contains:

```text
package_id
canonical_plan_id
source_commit
source_tree
branch_tip
dirty_paths
toolchain
Cargo.lock hash
binary/library hashes
SBOM hash
exact commands
positive tests
negative tests
crash points
retained mutants
known gaps
reviewers
independent replay
scope
authority
data_scope
expires_at
machine flags proposed for change
```

No package in this map is accepted merely because this document exists.

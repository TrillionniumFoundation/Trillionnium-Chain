# TRNM Cross-Chain Crate Blueprint (2026-03-19)

## Purpose

This document translates the high-level question

> “What should TRNM borrow from Conflux, Algorand, Sui, and Solana?”

into a **crate-level execution blueprint** for the current TRNM Rust workspace.

It is intentionally pragmatic:
- focus on **what to borrow**,
- **what not to borrow**,
- and **what to implement in the next 1-3 months**.

The goal is **not** to make TRNM look like any one reference chain.
The goal is to make TRNM:
- more modular,
- easier to reason about,
- more scalable under worker/verification load,
- and more rigorous in governance / checkpoint / proof semantics,

while preserving **TRNM-native worker verification, challenge/resolve, and migration-era audit evidence surfaces**, without treating retained PoUW naming as ongoing payout authority.

---

## Executive Summary

### Recommended composite direction

TRNM should evolve as a layered hybrid:

- **State / execution kernel → Sui-like**
  - object/version discipline
  - deterministic parallel execution
  - explicit shared-vs-owned state distinctions
  - checkpoint/effects-first thinking

- **Ingress / mempool / RPC data plane → Solana-like**
  - high-throughput ingress engineering
  - QoS and hot-spot isolation
  - transport discipline (QUIC-like patterns, bounded queues, backpressure)
  - explicit read/write conflict hints for fast admission decisions

- **Economics / sponsor / optional finality overlay → Conflux-like**
  - sponsored interactions / free-ingress support
  - storage pricing / collateral concepts
  - separation of ordering/processing from stronger finality guarantees

- **Proof discipline / state proofs / governance schema rigor → Algorand-like**
  - state-proof mentality
  - lightweight, explicit verification surfaces
  - formal governance key schema and timelock classes
  - smaller trusted execution surfaces

- **Worker accounting / challenge-resolve / PoUW-compatibility surfaces → TRNM-native**
  - do not flatten this into a copy of any reference chain
  - keep the task lifecycle, metering, challenge/resolve semantics, and worker accounting as protocol-native differentiators during migration
  - BL09 retirement-prep note: retained PoUW naming or receipts here should be read as migration-era compatibility or provenance / audit evidence, not as the default payout authority once PoCO is primary

---

## Current TRNM Mapping

### Workspace crates

- `trnm-types`
- `trnm-state`
- `trnm-executor`
- `trnm-pouw`
- `trnm-mempool`
- `trnm-rpc`
- `trnm-node`
- `trnm-worker-agent`
- `trnm-cli`
- `trnm-bridge-poc`
- `trnm-oracle`
- `trnm-bench`

### High-level role mapping

| TRNM crate | Primary reference | Why |
|---|---|---|
| `trnm-types` | Sui | object/version-oriented schema discipline |
| `trnm-state` | Sui + Algorand | state model, checkpoint/state-root rigor, governance schema |
| `trnm-executor` | Sui + Solana | deterministic parallel execution + contention-aware scheduling |
| `trnm-pouw` | TRNM-native (+ methods from Sui/Solana/Algorand) | protocol core must stay proprietary/native |
| `trnm-mempool` | Solana | admission, QoS, backpressure, hot-path data plane |
| `trnm-rpc` | Solana + Algorand | efficient ingress + explicit query/verification surfaces |
| `trnm-node` | Solana + Conflux | high-throughput node data plane + stronger finality/economic overlays |
| `trnm-worker-agent` | Solana-like runtime patterns | external worker I/O, bounded execution, adapter discipline |
| `trnm-bridge-poc` | Algorand + Conflux | state-proof orientation + finality-aware bridge discipline |
| `trnm-oracle` | Algorand + Conflux | proof/attestation discipline + settlement-aware externalization |
| `trnm-cli` | none specifically | operational tooling, thin integration surface |
| `trnm-bench` | none specifically | benchmarking and scenario validation |

---

## Reference Chain Lessons: What to Borrow / Not Borrow

## 1. Sui

### Borrow

#### A. Object-centric state boundaries
Apply strongly to:
- `trnm-types`
- `trnm-state`
- `trnm-executor`
- parts of `trnm-pouw`

Concrete TRNM translation:
- make stateful entities more explicitly object-scoped:
  - task objects
  - governance parameter objects
  - authority-set objects
  - pending resolve approval objects
  - escrow and treasury state objects
  - verification receipts / snapshots / checkpoint summaries

#### B. Version-first semantics
TRNM already leans this way. Push it harder:
- every mutable protocol-critical object should have a clear version / snapshot / restore story
- state-root-sensitive objects must define deterministic serialization and mutation ordering

#### C. Owned vs shared execution paths
This is one of the best Sui ideas for TRNM.

TRNM should distinguish:
- **owned / single-writer objects**
  - task-local state
  - worker-local receipts
  - some metering artifacts
- **shared / governance-sensitive objects**
  - authority sets
  - parameter tables
  - escrow/treasury state
  - global approval sets / registries

This should directly inform:
- `trnm-executor` conflict grouping
- `trnm-state` mutation APIs
- `trnm-node` pre-exec gating

#### D. Effects/checkpoint mentality
Use Sui’s “effects/checkpoints are first-class” mindset.
TRNM should lean further into:
- post-execution effect bundles
- checkpoint summaries
- state-root-certified snapshots
- replay/restore equivalence guarantees

### Do NOT borrow
- Sui’s full user/programming model
- shared object complexity for its own sake
- generic DeFi-oriented transaction abstraction that would blur PoUW semantics

---

## 2. Solana

### Borrow

#### A. Sealevel-style data plane thinking
Apply to:
- `trnm-mempool`
- `trnm-rpc`
- `trnm-node`
- parts of `trnm-executor`

TRNM should not copy the account model, but should copy the idea that:
- transactions/messages should expose enough dependency information
- non-conflicting work should be admitted and scheduled cheaply
- hot-path routing should optimize around parallelizable workloads

#### B. Gulf Stream-like forwarding intuition
Especially for:
- worker task pickup / receipt submission
- challenge / reveal / resolve traffic
- bridge/oracle ingress

TRNM can benefit from:
- expected downstream target awareness
- bounded forwarding queues
- less “shared waiting room” behavior

#### C. QUIC / bounded transport / backpressure discipline
Apply to:
- `trnm-rpc`
- `trnm-node`
- `trnm-worker-agent`

Not necessarily by copying Solana stack exactly, but by adopting its mindset:
- defend the ingress path
- shape traffic early
- localize congestion
- don’t let global queues become protocol bottlenecks

#### D. Local fee-market style hotspot isolation
TRNM can adapt this into:
- local priority domains for hot challenge/reveal flows
- per-domain backpressure
- preventing one noisy task family or bridge/oracle domain from degrading the rest of the system

### Do NOT borrow
- the Solana account model wholesale
- PoH-specific assumptions
- Solana’s entire runtime/program surface

TRNM is not an account-list-first chain. It should borrow Solana’s **data-plane engineering**, not its whole mental model.

---

## 3. Conflux

### Borrow

#### A. Sponsorship / subsidized interaction model
Apply to:
- `trnm-node`
- `trnm-rpc`
- `trnm-pouw`
- `trnm-bridge-poc`

TRNM-specific uses:
- free-ingress or subsidized task creation
- sponsored bridge/oracle actions
- worker onboarding or platform-sponsored system flows

#### B. Storage collateral / storage pricing ideas
Apply to:
- `trnm-state`
- `trnm-pouw`
- `trnm-bridge-poc`
- `trnm-oracle`

TRNM will likely accumulate:
- proofs
- evidence
- snapshots
- bridge records
- oracle observations

A clear storage collateral / storage pricing model will matter earlier than it does on simple transfer chains.

#### C. Separation of ordering and stronger finality
TRNM does not need Conflux Tree-Graph itself, but should learn from the split:
- fast processing / ordering path
- stronger confidence/finality layer for bridge/oracle/settlement-critical consumers

Useful for:
- `trnm-node`
- `trnm-bridge-poc`
- `trnm-oracle`

### Do NOT borrow
- Tree-Graph / GHAST as a wholesale replacement
- a full consensus pivot away from the current TRNM path

That would be too invasive and would discard too much of the current Rust L1 evolution.

---

## 4. Algorand

### Borrow

#### A. State proof mentality
Apply strongly to:
- `trnm-state`
- `trnm-bridge-poc`
- `trnm-oracle`
- `trnm-node`

TRNM should move toward:
- state-proof-friendly checkpoint summaries
- verifier-friendly compact proof material
- light-client-oriented outputs for bridge/oracle consumers

#### B. Governance schema explicitness
Apply immediately to:
- `trnm-state`
- `trnm-pouw`

Each governance key should eventually carry explicit metadata:
- type
- sensitivity class
- timelock class
- merge policy
- restore/checkpoint behavior
- case/canonicalization rules

This is especially important because current `trnm-state` failures already point at governance merge-gate drift.

#### C. Small, explicit verification surfaces
Apply to:
- `trnm-pouw`
- `trnm-bridge-poc`
- `trnm-oracle`
- `trnm-rpc`

Prefer explicit, auditable verification paths over convenience layers or implicit fallback behavior.

### Do NOT borrow
- AVM/TEAL itself
- Algorand’s whole smart contract execution model

Borrow the **discipline**, not the VM.

---

## Crate-by-Crate Blueprint

## `trnm-types`

### Borrow from
- **Sui**: object/version schema discipline
- **Algorand**: explicit schema metadata mindset

### Near-term actions
1. Audit all protocol-critical structs for:
   - explicit version fields
   - deterministic serialization expectations
   - canonical field ordering assumptions
2. Introduce stronger type-level separation for:
   - authority-set identifiers
   - governance-key descriptors
   - checkpoint summary references

### Avoid
- over-generalization that obscures protocol semantics

---

## `trnm-state`

### Borrow from
- **Sui**: object/version + shared/owned discipline
- **Algorand**: governance schema + state-proof mindset

### Near-term actions
1. Build a typed governance-key registry:
   - canonical key
   - key class
   - timelock class
   - case policy
   - merge/restore rules
2. Formalize checkpoint summary objects and state proof surfaces.
3. Make restore/checkpoint equivalence more explicit in core APIs, not just tests.
4. Continue large test-tree decomposition (`state_root_regression`, `m1_pause_resolve_escrow_invariant`).

### Avoid
- silently encoded governance behavior in scattered helper logic

---

## `trnm-executor`

### Borrow from
- **Sui**: deterministic parallel execution
- **Solana**: practical contention-aware routing/scheduling

### Near-term actions
1. Make conflict metadata more explicit in executor interfaces.
2. Distinguish owned-object fast path vs shared-state serialized path.
3. Add metrics for contention domains, not just total throughput.

### Avoid
- pure account-list mimicry

---

## `trnm-pouw`

### Borrow from
- **Sui**: version/restore/checkpoint discipline
- **Solana**: throughput-oriented ingress/verification path engineering
- **Algorand**: explicit proof/governance discipline
- **Conflux**: economics ideas around sponsorship/storage only where useful

### Keep TRNM-native
- task lifecycle
- metering
- challenge/resolve
- worker accounting
- proof adjudication semantics

### Near-term actions
1. Keep decomposing medium blocks, but with a mandatory `--list` baseline.
2. Introduce more formal proof/checkpoint/state-summary outputs for bridge/oracle consumers.
3. Reduce governance-sensitive implicit behavior inside challenge/resolve paths.
4. Continue splitting large verification and apply-path subtrees, but do not allow “green tests with shrinking test count.”

### Avoid
- borrowing another chain’s protocol semantics wholesale

---

## `trnm-mempool`

### Borrow from
- **Solana** primarily

### Near-term actions
1. Audit queueing and hot-path admission around:
   - worker ingress
   - challenge/reveal bursts
   - bridge/oracle traffic
2. Add local-priority domains / hotspot isolation concepts.
3. Bound queue growth more aggressively.

### Avoid
- global one-size-fits-all priority handling

---

## `trnm-rpc`

### Borrow from
- **Solana**: ingress/data-plane rigor
- **Algorand**: explicit proof/query surfaces

### Near-term actions
1. Do a churn audit before more structure splitting.
2. Separate user-facing query surfaces from proof/verification surfaces.
3. Design APIs that can eventually export checkpoint/state proof artifacts cleanly.

### Avoid
- further large-scale reshuffling before consistency review

---

## `trnm-node`

### Borrow from
- **Solana**: high-throughput runtime/data plane
- **Conflux**: finality layering concepts

### Near-term actions
1. Distinguish fast processing path from stronger settlement/finality path.
2. Add clearer checkpoint/finality outputs for downstream bridge/oracle use.
3. Keep node data plane lean; don’t let governance or bridge semantics overcouple into the hot path.

---

## `trnm-worker-agent`

### Borrow from
- **Solana-like** runtime discipline

### Near-term actions
1. Bounded ingress and retry shaping.
2. Stronger separation of execution adapters vs transport/retry logic.
3. Worker-side proof/result packaging should expose conflict and resource hints more explicitly.

---

## `trnm-bridge-poc`

### Borrow from
- **Algorand**: state proof / light client mentality
- **Conflux**: finality-aware settlement layering

### Near-term actions
1. Continue decomposing large bridge test trees.
2. Move from “logic works” to “logic is backed by verifiable state evidence.”
3. Formalize what bridge consumers need from TRNM checkpoint/finality outputs.

### Avoid
- bridge logic that assumes full-node trust forever

---

## `trnm-oracle`

### Borrow from
- **Algorand**: proof discipline
- **Conflux**: finality-aware external event settlement

### Near-term actions
1. Standardize oracle observation/attestation schema.
2. Tie oracle settlement to explicit checkpoint/finality confidence classes.
3. Keep oracle evidence minimal and externally verifiable.

---

# Concrete 1-3 Month Action Plan

## Month 1

### P0
1. `trnm-state`: implement typed governance-key registry.
2. `trnm-pouw`: enforce `cargo test -- --list` baselines for every medium/large split.
3. `trnm-state`: continue test-tree decomposition (`unpause`, `governance.rs`, remaining large test files).
4. `trnm-bridge-poc`: continue decomposition of `integration_tests` and remaining large test matrices.

## Month 2

### P1
1. `trnm-state` + `trnm-node`: define checkpoint summary / state-proof-facing data model.
2. `trnm-rpc`: split proof/query APIs from generic client APIs.
3. `trnm-mempool`: prototype local-priority domains / hotspot isolation.
4. `trnm-pouw`: surface more explicit proof/checkpoint outputs for downstream consumers.

## Month 3

### P2
1. `trnm-bridge-poc`: prototype trust-minimized verification path over checkpoint/state summaries.
2. `trnm-oracle`: align observation/settlement flow with checkpoint/finality classes.
3. `trnm-node`: prototype optional stronger finality overlay outputs for bridge/oracle consumers.
4. `trnm-pouw`: formalize storage-heavy proof/evidence retention policy and pricing assumptions.

---

# Non-Goals

TRNM should **not**:
- become a Sui clone,
- become a Solana clone,
- replace its protocol core with Conflux DAG mechanics,
- or absorb Algorand’s VM model.

The right move is **selective borrowing by layer**, not chain cosplay.

---

# Final Recommendation

The strongest architectural trajectory for TRNM is:

> **Sui-like state/execution kernel + Solana-like data plane + Conflux-inspired economics/finality layer + Algorand-like proof/governance discipline, while preserving TRNM-native worker verification and migration-era PoUW compatibility surfaces.**

This is the highest-leverage path because it improves:
- scalability,
- modularity,
- verification rigor,
- bridge/oracle trust surfaces,
- and governance safety,

without erasing the protocol’s unique value.

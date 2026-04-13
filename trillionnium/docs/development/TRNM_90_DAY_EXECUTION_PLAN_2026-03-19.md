# TRNM 90-Day Execution Plan (2026-03-19)

## Purpose

This document turns the cross-chain blueprint into a **90-day execution plan**.

It assumes the following architectural direction:
- state/execution kernel becomes more **Sui-like**
- ingress/data plane becomes more **Solana-like**
- economics/finality support selectively borrow from **Conflux**
- proof/governance discipline borrows from **Algorand**
- **PoUW verification and audit evidence remain TRNM-native during migration, but not as payout authority**

This plan is intentionally execution-oriented.
It prioritizes:
1. correctness and test stability,
2. structure and maintainability,
3. performance/data-plane improvements,
4. stronger bridge/oracle trust surfaces.

---

# Success Criteria for the Next 90 Days

By the end of this plan, TRNM should have:

1. **A stable split discipline**
   - large-file decomposition no longer causes silent test drop-offs
   - test-list baselines become standard for sensitive crates

2. **A typed governance registry in `trnm-state`**
   - governance keys are explicit, typed, classified, and auditable

3. **A clearer object/version execution story**
   - owned/shared state distinctions are clearer in `trnm-state` and `trnm-executor`

4. **A cleaner high-throughput ingress/data-plane design**
   - `trnm-mempool` / `trnm-rpc` / `trnm-node` have a documented and partially implemented QoS / hotspot-isolation strategy

5. **A checkpoint / state-proof roadmap**
   - `trnm-state`, `trnm-node`, `trnm-bridge-poc`, and `trnm-oracle` align around checkpoint summaries and proof-facing outputs

6. **A much flatter test topology across the heaviest crates**
   - especially `trnm-state`, `trnm-bridge-poc`, and remaining `trnm-pouw` medium blocks

---

# Phase 0 (Immediate Rule Change) — Day 0 to Day 3

## Objective
Stop test-topology regression while continuing decomposition.

## Required rule changes

### 1. Decomposition acceptance must become 3-part
Every medium/large split in sensitive crates must record:
- `cargo test ...`
- `cargo test ... -- --list`
- a file-structure proof (`wc -l`, generated submodules, `git status --short`)

### 2. Sensitive crates that must use this rule
- `trnm-pouw`
- `trnm-state`
- `trnm-bridge-poc`

### 3. Strong-success contract for subagents
A split is only “success” if:
- parent file becomes thin,
- child directory exists,
- relevant git status exists,
- verification was actually executed,
- and for `trnm-pouw`, compiled tests do not go below baseline.

## Deliverables
- baseline discipline documented in workflow notes
- test-list artifact location decided (suggestion below)

## Suggested artifact paths
- `artifacts/testlists/trnm-pouw-lib-current.txt`
- `artifacts/testlists/trnm-state-current.txt`
- `artifacts/testlists/trnm-bridge-poc-current.txt`

---

# Phase 1 — Day 1 to Day 21

## Theme
Flatten structure debt in the new main battlefields while stabilizing `trnm-pouw`.

## A. `trnm-state` — highest structural priority

### Why now
`trnm-state` is now the largest remaining structural debt center, especially in test trees.

### Target areas
1. `tests/state_root_regression/*`
2. `tests/m1_pause_resolve_escrow_invariant/*`
3. `src/tests/governance/*`
4. `src/tests/resolve_approval.rs`
5. `src/tests/wal_checkpoint.rs`

### Concrete goals
- finish flattening the remaining 800+ / 900+ test files
- isolate the 4 known failing tests into cleaner domains
- make governance-sensitive behavior easier to audit

### Execution sequence
1. `m1_pause_resolve_escrow_invariant/unpause.rs`
2. `state_root_regression/regression/governance.rs`
3. remaining `m1_pause_resolve_escrow_invariant/*` large files
4. remaining `state_root_regression/*` medium files
5. targeted work on the 4 existing failures:
   - `governance::params::*`
   - `governance::emergency_pause::*`
   - `resolve_approval::*`
   - `wal_checkpoint::*`

### Success criteria
- all major test trees split into parent entry + children
- known failures isolated by clearer ownership/domain
- no new test-count regressions in `trnm-state`

---

## B. `trnm-bridge-poc` — second structural priority

### Why now
The crate is structurally heavy but responds very cleanly to decomposition.

### Target areas
1. `tests/integration_tests.rs`
2. remaining `x2_*` / `x3_*` large test trees
3. bridge settlement / replay / compensation groupings

### Concrete goals
- flatten remaining 800+ / 900+ blocks
- make bridge test domains legible by scenario
- prepare the crate for proof-oriented redesign later

### Execution sequence
1. `tests/integration_tests.rs`
2. next largest x2/x3 scenario files
3. cleanup of overlapping helper/setup/test-support structure

### Success criteria
- bridge-poc test files are consistently modular
- bridge paths are grouped by domain rather than one giant matrix file
- crate remains green on full `cargo test -p trnm-bridge-poc -q`

---

## C. `trnm-pouw` — continue, but under guardrails

### Why now
Still strategically important, but no longer the only battlefield.

### Target areas
1. remaining 700–850 line files
2. `verification/tests.rs` and verification subtrees already in flight
3. remaining medium apply-path / verifier test blocks
4. `common/metrics.rs` follow-up integration check

### Concrete goals
- continue flattening medium blocks
- hold `cargo test -p trnm-pouw --lib -q` at or above current stable baseline
- avoid another fraud/tee-style test topology regression

### Execution sequence
1. remaining 800-ish verification/apply-path files
2. `verifiers/zk/tests/*` remaining heavy files
3. `resolve_auth/*` medium blocks
4. remaining `create_accept_parts/*` medium blocks

### Success criteria
- stable baseline maintained (`--list` tracked)
- no split accepted without test-list proof
- remaining large test areas continue to shrink without hidden regressions

---

# Phase 2 — Day 22 to Day 45

## Theme
Convert architecture intuition into enforceable core interfaces.

## A. `trnm-state` typed governance registry

### Goal
Replace scattered governance-key assumptions with one explicit registry.

### Registry fields
Each governance key should define:
- canonical key string
- value type
- sensitivity class
- timelock class
- merge/update policy
- restore/checkpoint behavior
- canonicalization/case rules

### Why this matters
Current failures already show that key schema and timelock classification drift are real risks.

### Deliverables
- governance registry type(s)
- migration of key classification logic to registry-driven flows
- tests asserting registry completeness and explicitness

---

## B. `trnm-state` / `trnm-executor` owned-vs-shared execution model audit

### Goal
Make execution categories explicit enough to support clearer deterministic concurrency.

### Actions
- classify hot objects into owned/single-writer vs shared/governance-sensitive
- audit executor grouping rules against that classification
- add metrics for contention classes / shared-state bottlenecks

### Deliverables
- object-category design note
- executor grouping adjustments or at least explicit TODO map
- metrics for contention class visibility

---

## C. `trnm-pouw` proof/checkpoint output discipline

### Goal
Move toward more explicit proof/checkpoint/state-summary outputs.

### Actions
- identify proof-facing outputs required by bridge/oracle consumers
- define minimal receipt/checkpoint summary shape that can be externally verified later
- reduce ad hoc proof/result interpretation spread across modules

### Deliverables
- protocol note or schema draft
- first implementation slices in verification/reporting paths

---

# Phase 3 — Day 46 to Day 70

## Theme
Improve the data plane.

## A. `trnm-mempool` / `trnm-rpc` / `trnm-node` Solana-style ingress audit

### Goal
Adopt Solana-like engineering where it matters, without copying the account model.

### Topics
- QoS domains
- hotspot isolation
- bounded ingress queues
- backpressure discipline
- explicit dependency hints
- transport modernization (QUIC-like patterns if justified)

### Deliverables
- short architecture note: current bottlenecks + proposed queueing model
- explicit list of traffic classes:
  - worker flows
  - reveal/challenge/resolve
  - bridge/oracle ingress
  - admin/governance traffic
- first implementation changes in mempool or node ingress where low-risk

---

## B. `trnm-node` finality layering note

### Goal
Separate fast processing from stronger confidence/finality outputs.

### Why
This is where Conflux-inspired ideas help most:
- not a DAG rewrite,
- but a cleaner distinction between processing path and stronger finality signals.

### Deliverables
- node-facing finality tier proposal
- candidate outputs for bridge/oracle consumers
- checkpoint/finality metadata requirements

---

# Phase 4 — Day 71 to Day 90

## Theme
Turn TRNM into a more proof-aware, bridge-aware system.

## A. `trnm-bridge-poc` proof-oriented redesign slice

### Goal
Move from “bridge logic works” to “bridge logic can be backed by chain-verifiable evidence.”

### Actions
- define what checkpoint summary / state proof material a bridge consumer actually needs
- map current bridge settlement tests to those proof surfaces
- prototype a trust-minimized verification path, even if partial

---

## B. `trnm-oracle` attestation / observation discipline

### Goal
Align oracle settlement with checkpoint/finality classes and explicit observation schema.

### Actions
- standardize observation record shape
- define attestation confidence classes
- connect oracle settlement semantics to checkpoint/finality outputs

---

## C. `trnm-pouw` economics follow-up

### Goal
Translate Conflux-like ideas into TRNM-native economics.

### Topics
- sponsor/free-ingress model boundaries
- storage-heavy proof/evidence retention pricing
- which actions may be subsidized safely
- which states should impose collateral/storage burden

### Deliverables
- economics note (sponsor/storage/collateral candidates)
- candidate implementation map touching node/rpc/pouw/state

---

# Risk Register

## 1. Test-count regressions in `trnm-pouw`
Mitigation:
- no split accepted without `--list` baseline proof
- keep baseline artifact files

## 2. `trnm-state` hidden governance drift
Mitigation:
- typed governance registry before more policy complexity is added

## 3. `trnm-rpc` churn causing consistency loss
Mitigation:
- do not over-split before a churn review
- review interfaces first

## 4. Over-borrowing from reference chains
Mitigation:
- borrow by layer, not by branding
- keep PoUW and task lifecycle strictly TRNM-native

---

# Suggested Weekly Cadence

## Week 1-3
- heavy structural decomposition (`state`, `bridge-poc`, guarded `pouw`)

## Week 4-6
- typed governance registry + owned/shared execution audit

## Week 7-10
- ingress/QoS/finality architecture work

## Week 11-13
- checkpoint/state-proof / bridge/oracle / economics integration planning

---

# Concrete Immediate Next Actions

If execution starts today, the best next moves are:

1. continue flattening `trnm-state` large test trees
2. continue flattening `trnm-bridge-poc` large integration/matrix trees
3. continue `trnm-pouw` medium-file decomposition only under test-list guardrails
4. create baseline artifact files for `trnm-pouw`
5. draft typed governance registry for `trnm-state`

---

# Final Note

This plan assumes a key principle:

> TRNM should borrow **execution shape** from Sui, **data-plane engineering** from Solana, **economics/finality support** from Conflux, and **proof/governance discipline** from Algorand — but keep PoUW itself unmistakably TRNM-native.

That is the highest-leverage path for the next 90 days.

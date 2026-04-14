# TRNM 4-Week Sprint Plan (2026-03-19)

BL09 retirement-prep note: any retained `trnm-pouw` crate, lane, or test-guardrail references in this sprint plan should be read as migration-era compatibility, decomposition guardrails, or provenance / audit evidence coverage only. If PoCO is the primary settlement path, these retained references are not the default payout authority and do not re-authorize default work-unit payout paths.

## Goal

Translate the 90-day execution plan into a **4-week sprint plan** that can be executed immediately.

This plan assumes:
- structural decomposition remains active,
- `trnm-pouw` must stay under test-list guardrails,
- `trnm-state` and `trnm-bridge-poc` are now co-primary structural battlefields,
- and architectural cleanup should begin in parallel, not only after all decomposition ends.

---

# Sprint Themes

## Theme A — Structural debt reduction
Primary targets:
- `trnm-state`
- `trnm-bridge-poc`
- guarded `trnm-pouw`

## Theme B — Test-topology stabilization
Primary targets:
- `trnm-pouw`
- decomposition workflow itself

## Theme C — Architecture hardening prep
Primary targets:
- `trnm-state` governance schema
- checkpoint / proof-oriented interfaces
- `trnm-rpc` / `trnm-node` data-plane review inputs

---

# Week 1 — Finish current heavy structural front

## Objective
Close the currently visible top structural blocks while the split momentum is high.

## Priority A: `trnm-state`

### Targets
1. `tests/m1_pause_resolve_escrow_invariant/unpause.rs`
2. `tests/state_root_regression/regression/governance.rs`
3. remaining medium files in:
   - `tests/m1_pause_resolve_escrow_invariant/*`
   - `tests/state_root_regression/*`

### Expected output
- parent-entry + child-module decomposition pattern normalized across both test trees
- remaining major blocks in these trees reduced below ~400–500 lines where feasible

### Notes
- full crate still has 4 known failures; sprint does **not** require solving those immediately, but does require keeping the failure set stable and isolated

---

## Priority B: `trnm-bridge-poc`

### Targets
1. `tests/integration_tests.rs`
2. remaining bridge scenario trees adjacent to `x2_*` / `x3_*`

### Expected output
- bridge test topology grouped by scenario families instead of giant all-in-one files
- crate remains green on `cargo test -p trnm-bridge-poc -q`

---

## Priority C: `trnm-pouw`

### Targets
1. `src/common/apply_path/tests/create_accept_parts/resolve_pause_paths.rs`
2. `src/verification/verifiers/zk/tests/backend_id_hints.rs`
3. next 700–800 line candidates from the current top list

### Guardrail
Every accepted split must include:
- `cargo test -p trnm-pouw --lib -q`
- `cargo test -p trnm-pouw --lib -- --list`
- compiled tests must stay **>= current stable baseline**

### Expected output
- no further silent regression in `trnm-pouw` test topology
- medium-file shrinkage continues safely

---

# Week 2 — Governance and state discipline

## Objective
Stop governance drift from remaining scattered across tests and helpers.

## Priority A: typed governance registry in `trnm-state`

### Deliverable
First implementation draft for a typed governance-key registry with:
- canonical key
- value type
- sensitivity class
- timelock class
- merge policy
- restore/checkpoint behavior
- canonicalization/case policy

### Why in Week 2
Current crate-level failures already point at governance schema drift and timelock classification drift.

---

## Priority B: failure isolation clean-up in `trnm-state`

### Focus failures
1. `governance::params::*`
2. `governance::emergency_pause::*`
3. `resolve_approval::*`
4. `wal_checkpoint::*`

### Deliverable
Not necessarily fixes yet, but:
- clearer ownership
- cleaner test grouping
- explicit notes on whether each failure is schema drift, logic drift, or restore/checkpoint drift

---

## Priority C: `trnm-pouw` test baseline discipline

### Deliverable
A small baseline system for `trnm-pouw`:
- canonical `--list` output file
- one update procedure
- one comparison procedure

### Suggested location
- `artifacts/testlists/trnm-pouw-lib-current.txt`
- or another agreed path under workspace control

---

# Week 3 — Data-plane and execution review sprint

## Objective
Turn cross-chain borrowing into concrete engineering notes and first implementation hooks.

## Priority A: `trnm-mempool` / `trnm-rpc` / `trnm-node` review

### Questions to answer
1. Which traffic classes deserve separate QoS buckets?
2. Which hotspots should be isolated locally rather than globally?
3. Which flows should become bounded / prioritized / forwarded differently?
4. Where can dependency metadata improve admission or scheduling?

### Deliverable
A short design note with:
- traffic classes
- bottleneck map
- proposed local-priority or hotspot-isolation model
- first low-risk implementation candidates

---

## Priority B: `trnm-executor` owned/shared state audit

### Goal
Map current execution paths to a clearer owned-vs-shared state classification.

### Deliverable
A concrete object-category table:
- task-local objects
- authority/governance objects
- escrow/treasury objects
- pending resolve / approval objects
- checkpoint-related objects

And a note on how executor grouping should use it.

---

## Priority C: `trnm-pouw` verification/reporting outputs

### Goal
Start narrowing the gap between “internal protocol effects” and “externally verifiable summaries.”

### Deliverable
A short schema or draft interface for:
- checkpoint-facing proof summaries
- verification receipts usable by bridge/oracle paths
- state-root-sensitive verification artifacts

---

# Week 4 — Bridge/oracle proof path preparation

## Objective
Use the cleaned structure to prepare proof-aware externalization.

## Priority A: `trnm-bridge-poc`

### Deliverable
A draft of what a bridge consumer minimally needs from TRNM:
- checkpoint summary
- state root reference
- effect summary
- finality/confidence class
- proof material expectations

### Optional execution slice
Prototype one trust-minimized verification stub in bridge tests or support code.

---

## Priority B: `trnm-oracle`

### Deliverable
A standardized observation/attestation shape:
- what is observed
- what is signed/attested
- how confidence/finality class is attached
- how downstream consumers verify it

---

## Priority C: economics scoping note

### Deliverable
A short note on where to selectively borrow Conflux-like ideas:
- sponsor/free-ingress support
- storage-heavy proof/evidence retention pricing
- optional settlement/finality classes for bridge/oracle consumers

This should stay a scoped economics note, not an immediate protocol rewrite.

---

# Weekly Subagent Allocation Guidance

## Week 1
Best for parallel structural work:
- 2x `trnm-state`
- 1x `trnm-bridge-poc`
- 2x guarded `trnm-pouw`

## Week 2
Best for mixed decomposition + design:
- 1x governance registry design
- 1x `trnm-state` failure isolation
- 1x guarded `trnm-pouw`
- 1x bridge continuation

## Week 3
Best for audit/design threads:
- 1x mempool/rpc/node data-plane audit
- 1x executor owned/shared audit
- 1x pouw verification-summary draft
- 1x ongoing structural split if safe

## Week 4
Best for proof-path prep:
- 1x bridge proof requirement mapping
- 1x oracle observation/attestation schema
- 1x economics/finality scoping note
- 1x cleanup/follow-up structural thread

---

# Stop Conditions / Guardrails

## Do not continue blind decomposition if:
- `trnm-pouw` compiled test count drops below baseline
- a split reports success without thin parent + child directory + git status proof
- the same subtree repeatedly “runs” without actual landing

## Pause and audit if:
- `trnm-rpc` churn continues to rise without interface stabilization
- `trnm-state` governance failures expand beyond the known 4
- bridge/oracle semantics start spreading across unrelated crates without a checkpoint/finality contract

---

# Expected End-of-4-Week State

By the end of 4 weeks, success should look like:

1. `trnm-state`
- major large test trees mostly flattened
- governance registry design in place or partially implemented
- known failures isolated more cleanly

2. `trnm-bridge-poc`
- major x2/x3/integration test matrices flattened
- bridge tests grouped by real domain boundaries

3. `trnm-pouw`
- several more 700–800 line blocks flattened
- no new silent test regressions
- baseline discipline normalized

4. `trnm-rpc` / `trnm-node` / `trnm-mempool`
- first explicit data-plane review completed

5. `bridge` / `oracle`
- proof- and checkpoint-oriented interface planning started

---

# Final Recommendation

If immediate execution continues, the best next sprint pattern is:

> **keep structural momentum on `trnm-state` and `trnm-bridge-poc`, continue `trnm-pouw` under strict baseline guardrails, and begin governance/checkpoint/data-plane design work in parallel rather than waiting for the decomposition phase to fully end.**

That is the highest-leverage 4-week path.

# TRNM Hotspot Review Checklist (2026-03-24)

BL09 retirement-prep note: any retained `trnm-pouw` file-path, hotspot, or settlement-adjacent references in this checklist should be read as migration-era compatibility review scope or provenance / audit evidence coverage only. If PoCO is the primary settlement path, these retained references are not the default payout authority and do not re-authorize default work-unit payout paths.

## Purpose

This checklist is for reviewing the current highest-risk / highest-leverage files in the TRNM Rust workspace.

The goal is **not** generic style review.
The goal is to answer, for each hotspot:

1. Is the protocol / runtime behavior correct?
2. Is the trust boundary explicit?
3. Is the file carrying too many responsibilities?
4. What is the safest next split or cleanup action?

---

# Global Review Questions

Apply these to every hotspot file before diving into file-specific checks.

## A. Protocol correctness
- Does the file encode consensus- or settlement-relevant behavior?
- Are fail-closed paths explicit and consistent?
- Are canonicalization rules single-sourced, or duplicated?
- Are restore / replay / reentry semantics deterministic?

## B. Trust boundary clarity
- Does the file verify external inputs, or assume trusted upstream data?
- Are attestation / proof / signature checks colocated with policy decisions?
- Are proof-facing outputs explicit and auditable?

## C. State / mutation discipline
- Are side effects clearly staged, applied, or scrubbed?
- Are error paths side-effect free when they should be?
- Does the file mutate shared/global state in too many places?
- Are version / slot / identity collisions fail-closed?

## D. Structural health
- Can the file be explained as 1-2 responsibilities, or is it acting as a dump site?
- Are helper layers real boundaries, or just naming wrappers?
- Is the parent file thin enough, or still acting as the real implementation hub?

## E. Testability
- Does the file have obvious test domains?
- Would splitting it risk silent test drop-off?
- Is there a stable `cargo test ... -- --list` baseline for this surface?

---

# Review Priority Tiers

## P0 — Review first
1. `crates/trnm-pouw/src/verification/real_tee_backend.rs`
2. `crates/trnm-pouw/src/lib.rs`
3. `crates/trnm-state/src/lib.rs`
4. `crates/trnm-node/src/main.rs`
5. `crates/trnm-rpc/src/main.rs`
6. `crates/trnm-state/tests/m1_pause_resolve_escrow_invariant.rs`
7. `crates/trnm-state/tests/state_root_regression.rs`
8. `crates/trnm-pouw/src/verification/verifiers/mod.rs`

## P1 — Review next
9. `crates/trnm-executor/src/lib.rs`
10. `crates/trnm-worker-agent/src/tests.rs`
11. `crates/trnm-state/src/tests.rs`
12. `crates/trnm-rpc/src/tests.rs`
13. `crates/trnm-rpc/src/reliability.rs`
14. `crates/trnm-cli/src/main.rs`

## P2 — Review after that
15. `crates/trnm-rpc/src/relay.rs`
16. `crates/trnm-pouw/src/verification/backend.rs`
17. `crates/trnm-bridge-poc/tests/x2_settlement_loop.rs`
18. `crates/trnm-mempool/src/lib.rs`
19. `crates/trnm-pouw/src/verification/verifiers/zk.rs`
20. `crates/trnm-worker-agent/src/proof_adapter.rs`

---

# File-Specific Checklists

## 1) `crates/trnm-pouw/src/verification/real_tee_backend.rs`

### What to review
- Transport / session lifecycle / attestation / payload validation / retry / error mapping boundaries
- Whether backend-specific policy is mixed with generic TEE plumbing
- Whether receipt-hash / attested payload binding is single-sourced

### Red flags
- One function both parsing transport noise and making settlement-policy decisions
- Error mapping duplicated across many branches
- Implicit normalization of proof/receipt fields before trust decisions
- TEE attestation verification spread across unrelated helpers

### Desired next action
- Split into:
  - `transport`
  - `session`
  - `attestation`
  - `payload_validation`
  - `error_mapping`

---

## 2) `crates/trnm-pouw/src/lib.rs`

### What to review
- Whether create / commit / reveal / challenge / resolve / timeout logic is still too entangled
- Whether metering, challenge accounting, and governance-sensitive checks are colocated too tightly
- Whether protocol transitions remain explicit and auditable

### Red flags
- Hidden coupling between reveal and resolve via shared helper state
- Phase transitions encoded via ad hoc field checks rather than clear transition helpers
- Policy reads repeated in multiple lifecycle branches

### Desired next action
- Split into lifecycle modules:
  - `create`
  - `commit`
  - `reveal`
  - `challenge`
  - `resolve`
  - `timeout`

---

## 3) `crates/trnm-state/src/lib.rs`

### What to review
- Restore / replay / reentry entrypoints
- Governance key / key-id / registry rules
- Canonical state-root input surfaces
- Whether governance policy is still scattered instead of registry-driven

### Red flags
- Same governance key semantics enforced in multiple unrelated helpers
- Different restore paths encoding slightly different collision rules
- Canonicalization and validation happening in inconsistent order

### Desired next action
- Introduce a stronger typed governance registry
- Continue extracting restore/governance/state_root submodules without changing semantics

---

## 4) `crates/trnm-node/src/main.rs`

### What to review
- Whether runtime orchestration, recovery, rollback, metrics, and node entry are too tightly coupled
- Whether hot-path logic is mixed with administrative/recovery logic
- Whether finality/checkpoint output logic is explicit enough

### Red flags
- `main.rs` still acting as the real implementation body
- Recovery and live runtime branching tangled together
- Metrics and event emission logic mixed with control flow

### Desired next action
- Thin shim `main.rs`
- Push runtime/recover/rollback/metrics into dedicated modules

---

## 5) `crates/trnm-rpc/src/main.rs`

### What to review
- Query / relay / market / transfer / audit boundaries
- Whether proof-facing surfaces are explicit or mixed into generic client API logic
- Whether env/config parsing still leaks into business logic

### Red flags
- Main entry still contains substantial route logic
- Audit/query helpers duplicated across handlers
- Too many responsibilities hidden behind top-level command dispatch

### Desired next action
- Further split into `query/`, `relay/`, `market/`, `transfer/`, `audit/`

---

## 6) `crates/trnm-state/tests/m1_pause_resolve_escrow_invariant.rs`

### What to review
- Are paused/unpause/toggle/members/lifecycle concerns separable?
- Is there too much repeated fixture setup?
- Are there implicit invariants that should become named helpers?

### Red flags
- Huge clusters of nearly identical paused resolve approval tests
- Repeated escrow setup obscuring semantic differences

### Desired next action
- Split by domain:
  - `lifecycle`
  - `toggle`
  - `unpause`
  - `members`

---

## 7) `crates/trnm-state/tests/state_root_regression.rs`

### What to review
- Are object/governance/pending-resolve/restore domains clearly separable?
- Are there repeated state-root collision fixtures that should be shared?
- Is the file still carrying too many unrelated determinism concerns?

### Red flags
- Large repeated setup blocks for pending governance and task restore roots
- Restore/noop/fail-closed cases mixed with field-boundary tests

### Desired next action
- Split into:
  - `governance`
  - `restore`
  - `object_updates`
  - `pending_resolve`
  - `boundaries`

---

## 8) `crates/trnm-pouw/src/verification/verifiers/mod.rs`

### What to review
- Fraud / tee / zk / payload routing boundaries
- Whether backend selection and verifier policy are duplicated
- Whether verifier family routing is explicit and single-sourced

### Red flags
- Backend-family parsing duplicated in multiple verifier paths
- Fallback logic that is not obviously fail-closed

### Desired next action
- Push family-specific routing deeper into dedicated verifier modules

---

## 9) `crates/trnm-executor/src/lib.rs`

### What to review
- Conflict grouping semantics
- Shared vs owned object classification
- Scheduling behavior and contention visibility

### Red flags
- Implicit concurrency assumptions not reflected in types or metrics
- Shared-state slow path not clearly separated from owned fast path

### Desired next action
- Make object class / contention class explicit in executor-facing APIs

---

## 10) `crates/trnm-worker-agent/src/tests.rs`

### What to review
- Whether adapter / dispatch / audit / flush / runtime tests should be separate domains
- Whether test structure mirrors actual module boundaries

### Desired next action
- Break test entry into runtime-specific subtrees matching source structure

---

## 11) `crates/trnm-state/src/tests.rs`

### What to review
- Whether governance / restore / wal / resolve approval tests can be further isolated

### Desired next action
- Continue flattening toward domain-owned files

---

## 12) `crates/trnm-rpc/src/tests.rs`

### What to review
- Whether relay/query/audit/oracle/transfer tests are still coupled by shared monolithic entry

### Desired next action
- Split remaining high-density mixed test entrypoints

---

## 13) `crates/trnm-rpc/src/reliability.rs`

### What to review
- Dedup / retry / cleanup / store config / circuit-breaker boundaries
- Persistence vs policy separation

### Desired next action
- Consider slicing into:
  - `dedup`
  - `retry`
  - `cleanup`
  - `store`
  - `config`

---

## 14) `crates/trnm-cli/src/main.rs`

### What to review
- Handler boundaries for query / tx / wallet / templates
- Whether CLI parsing and business logic are still too coupled

### Desired next action
- Keep main as CLI router, push implementations to handlers

---

## 15) `crates/trnm-rpc/src/relay.rs`

### What to review
- Session / ack / quota / proof-query boundaries
- Whether relay proof logic is over-coupled to queue management

### Desired next action
- Split queue/session management from proof-query surfaces

---

## 16) `crates/trnm-pouw/src/verification/backend.rs`

### What to review
- Backend trait design and abstraction health
- Whether generic backend contract is cleanly separated from concrete TEE/runtime details

### Desired next action
- Keep backend contract thin and proof-oriented

---

## 17) `crates/trnm-bridge-poc/tests/x2_settlement_loop.rs`

### What to review
- Whether compensation / replay / timeout / happy path domains are separable
- Whether bridge settlement assumptions are explicit enough for future proof-oriented redesign

### Desired next action
- Split by settlement scenario family

---

## 18) `crates/trnm-mempool/src/lib.rs`

### What to review
- Lane admit / fairness / quota / spillover / recovery boundaries
- Whether hotspot isolation logic is explicit or just emergent from tests

### Desired next action
- Further separate queueing model components into explicit modules

---

## 19) `crates/trnm-pouw/src/verification/verifiers/zk.rs`

### What to review
- Selected backend / backend-family / system-hint / VK metadata consistency
- Whether zk backend routing is overly entangled with generic verifier plumbing

### Desired next action
- Tighten zk backend routing into smaller submodules if drift risk remains high

---

## 20) `crates/trnm-worker-agent/src/proof_adapter.rs`

### What to review
- Proof/result packaging boundaries
- Transport normalization vs proof semantics vs adapter-side validation

### Desired next action
- Keep adapter-side proof shaping thin and auditable

---

# Review Output Template

For each file, record:

## File
- Path:
- Current size / complexity signal:
- Risk tier: P0 / P1 / P2

## Findings
- Correctness risks:
- Trust-boundary risks:
- Structural risks:
- Testability risks:

## Decision
- Leave as-is
- Split now
- Split later after guardrails
- Add tests first
- Refactor behind behavior lock

## Next patch candidate
- Smallest safe follow-up change:
- Required verification command(s):
- Need `--list` baseline? yes/no

---

# Final Note

This checklist should be used to produce **small, path-scoped, behavior-locked review patches**.
Do not combine hotspot review with broad workspace cleanup.

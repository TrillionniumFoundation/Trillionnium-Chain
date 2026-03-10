# TRNM ZKP Backend Stage Closeout — 2026-03-10

## Scope

This document summarizes the current **ZKP backend hardening wave** already absorbed into the local mainline candidate as of `2026-03-10`.

It is **not** a release sign-off document.
For release/readiness truth-source, see `RELEASE_READINESS.md`.
For 80% acceptance criteria, see `docs/reports/TRNM_ZKP_80_ACCEPTANCE_DOD_2026-03-10.md`.

## Mainline Snapshot

- Local `main`: `8fd5ae96`
- Remote `origin/main`: `b39597e3`
- Delta: local `main` is ahead by **6 commits**

## Absorbed ZKP / Verification Commits

### 1. `93d63d17` — `fix(zk): guard backend and zk_system contract`

**What landed**
- Bound `backend_id` selection to explicit `zk_system` expectations.
- Known backend/system mismatches now fail closed instead of slipping through router ambiguity.

**Why it matters**
- Prevents backend routing from drifting away from proving-system semantics.
- Turns `backend_id ↔ zk_system` into a code-level contract.

**Evidence**
- `cargo test -p trnm-pouw zk_verifier_rejects_backend_id_and_zk_system_mismatch_fail_closed -- --nocapture`
- `cargo test -p trnm-pouw zk_verifier_accepts_known_backend_and_matching_zk_system -- --nocapture`

---

### 2. `c84a1948` — `fix(verification): tighten tee backend parity semantics`

**What landed**
- Tightened TEE parity with the shared verification platform.
- Aligned TEE backend routing / registry expectations with current platform semantics.

**Why it matters**
- Keeps TEE from diverging into a separate ad-hoc verification path.
- Reduces semantic drift between ZK and TEE verifier outcomes.

**Touched areas**
- `trillionnium-rust/crates/trnm-pouw/src/verification/registry.rs`
- `trillionnium-rust/crates/trnm-pouw/src/verification/verifiers/tee.rs`

---

### 3. `03965384` — `refactor(zk): tighten backend error taxonomy`

**What landed**
- Tightened ZK backend verdict mapping into explicit taxonomy:
  - `invalid`
  - `malformed`
  - `unavailable`
  - `backend_error`
- Added direct tests for unknown backend selection, internal backend failure, malformed backend payload, and invalid proof path behavior.

**Why it matters**
- Moves the system away from fragile string-based “best effort” error interpretation.
- Makes backend verdicts auditable and testable.

**Evidence**
- `cargo test -p trnm-pouw -q`
- `./scripts/v2/v1_proof_backend_ci_gate.sh`
- `./scripts/v2/v1_proof_backend_ci_gate_regression_test.sh`

---

### 4. `5e2e89d3` — `fix(zk): add minimal vk_ref resolver guard`

**What landed**
- Promoted `vk_ref` from “must be non-empty” to a minimal resolver guard.
- Accepted current dev/mock-groth16 and demo groth16 routes.
- Unknown `vk_ref` now fails closed.
- `vk_ref ↔ zk_system` inconsistency also fails closed.

**Why it matters**
- Makes `vk_ref` part of actual verifier semantics rather than passive metadata.
- Creates a safe stepping stone toward a fuller vk/key registry later.

**Evidence**
- `cargo test -p trnm-pouw zk_verifier_rejects_unknown_vk_ref_fail_closed -- --nocapture`
- `cargo test -p trnm-pouw zk_verifier_rejects_vk_ref_and_zk_system_mismatch -- --nocapture`
- `cargo test -p trnm-pouw -q`

---

### 5. `2a2888e6` — `fix(zk): guard backend fallback by system`

**What landed**
- Enforced `zk_allow_backend_fallback` as a real router policy instead of a documentation-only flag.
- Fallback disabled: no silent retry.
- Fallback enabled: only same-system fallback is allowed.
- Cross-system fallback remains fail-closed.

**Why it matters**
- Implements one of the most important “80% DoD” requirements in code.
- Prevents silent backend hopping across proving systems.

**Evidence**
- `cargo test -p trnm-pouw -q`
- `./scripts/v2/v1_proof_backend_ci_gate.sh`
- `./scripts/v2/v1_proof_backend_ci_gate_regression_test.sh`

---

### 6. `8fd5ae96` — `fix(zk): enforce canonical public_inputs ordering`

**What landed**
- Enforced canonical `public_inputs` ordering in code:
  1. `task_id`
  2. `proof_type`
  3. `worker`
  4. `result_hash`
- Rejected payloads that omit the `proof_type` slot or shuffle canonical ordering.
- Updated registry/backend path tests to the new canonical layout.

**Why it matters**
- Aligns implementation with the frozen payload/public-input protocol.
- Removes one of the last “looks valid but semantically ambiguous” payload classes.

**Evidence**
- `cargo test -p trnm-pouw -q`
- `./scripts/v2/v1_proof_backend_ci_gate.sh`
- `./scripts/v2/v1_proof_backend_ci_gate_regression_test.sh`

## What This Wave Achieved

Taken together, this wave moved TRNM ZKP backend work from:

- feature-gated demo path
- router skeleton
- CI gate skeleton
- protocol/docs-only constraints

into a state with real code-level hardening across:

- `backend_id ↔ zk_system`
- `vk_ref`
- backend fallback policy
- explicit error taxonomy
- canonical `public_inputs`
- TEE/ZK platform parity

## What Still Does **Not** Mean

This wave **does not** mean:

- multi-backend production support is complete
- production key / vk lifecycle is complete
- multi proving-system support is complete
- release readiness is achieved
- TRNM is “100% ZKP complete”

## Remaining Gaps to Watch

The next highest-value remaining gaps are:

1. **Richer `vk_ref` / key registry lifecycle**
   - current resolver is intentionally minimal and scoped to active dev/demo routes.

2. **More real-backend verdict coverage**
   - especially finer invalid-proof distinction under the real backend path.

3. **Second proving-system scout**
   - to test whether the platform can host a second backend/system without collapsing into ambiguity.

4. **Evidence rollup / reporting cleanup**
   - current evidence exists across tests and commits, but can still be packaged more cleanly.

## Practical Read on Progress

A reasonable interpretation after these 6 commits is:

- TRNM ZKP backend is now materially beyond “docs + noop + mock”.
- The platform has begun turning protocol rules into enforceable verifier behavior.
- The project is closer to the “80% engineering-acceptable” bar defined in
  `docs/reports/TRNM_ZKP_80_ACCEPTANCE_DOD_2026-03-10.md`, but is not yet at full closeout.

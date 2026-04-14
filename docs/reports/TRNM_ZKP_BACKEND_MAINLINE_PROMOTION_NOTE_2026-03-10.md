# TRNM ZKP Backend Mainline Promotion Note — 2026-03-10

> Scope note: this document summarizes a historical ZKP backend promotion wave for local mainline review on 2026-03-10. It is **not** the current release-readiness truth source and must not be read as current release sign-off. For current release/readiness status, see `RELEASE_READINESS.md`.
>
> BL09 retirement-prep note: retained `trnm-pouw`, PoUW, or verification-backend wording in this historical promotion note is migration-era compatibility and provenance / audit evidence only. It must not be read as current default payout authority or as re-authorizing the default work-unit payout path once PoCO settlement is primary.

## Snapshot

- Local `main`: `ac9caf9e`
- Remote `origin/main`: `b39597e3`
- Delta: local `main` is ahead by **8 commits**

This note summarizes the current ZKP/verification hardening wave already absorbed into local `main` and ready for final review before any remote push.

## Commits in Scope

### Platform Semantics / Routing
1. `93d63d17` — `fix(zk): guard backend and zk_system contract`
2. `c84a1948` — `fix(verification): tighten tee backend parity semantics`
3. `03965384` — `refactor(zk): tighten backend error taxonomy`
4. `5e2e89d3` — `fix(zk): add minimal vk_ref resolver guard`
5. `2a2888e6` — `fix(zk): guard backend fallback by system`
6. `8fd5ae96` — `fix(zk): enforce canonical public_inputs ordering`

### Evidence / Review / Real-backend Verdict Split
7. `0d0ef484` — `docs: add zkp backend stage closeout`
8. `ac9caf9e` — `test(zk): split malformed and invalid real backend proofs`

## What This Wave Changed

### 1. Backend selection is no longer loose
- `backend_id` now has an enforceable relationship with `zk_system`.
- known mismatches fail closed instead of relying on implicit router behavior.

### 2. TEE and ZK now sit closer to one platform contract
- TEE parity was tightened so TEE does not drift into a separate ad-hoc verifier world.
- outcome semantics are now closer across TEE/ZK.

### 3. ZK backend error classes are sharper
The system now distinguishes and tests:
- `invalid`
- `malformed`
- `unavailable`
- `backend_error`

### 4. `vk_ref` is now part of actual verifier semantics
- unknown `vk_ref` fails closed
- `vk_ref ↔ zk_system` mismatches fail closed
- current implementation is intentionally minimal and scoped to active dev/demo routes

### 5. Fallback is now an actual policy, not just a doc string
- `zk_allow_backend_fallback=false` => no silent retry
- `zk_allow_backend_fallback=true` => only same-system fallback is allowed
- cross-system fallback remains fail-closed

### 6. Canonical `public_inputs` ordering is now enforced
Canonical order is locked to:
1. `task_id`
2. `proof_type`
3. `worker`
4. `result_hash`

This closes a remaining ambiguity class where payloads could look structurally valid but semantically drift from the frozen protocol.

### 7. Real-backend invalid verdicts are now more precise
The real backend path now distinguishes:
- malformed proof encoding
- cryptographically invalid proof

instead of leaving both under one blurry invalid bucket.

## Validation Evidence

### Shared verification / gate coverage
- `cargo test -p trnm-pouw -q`
- `./scripts/v2/v1_proof_backend_ci_gate.sh`
- `./scripts/v2/v1_proof_backend_ci_gate_regression_test.sh`

### Targeted ZK route / contract checks
- `cargo test -p trnm-pouw zk_verifier_rejects_backend_id_and_zk_system_mismatch_fail_closed -- --nocapture`
- `cargo test -p trnm-pouw zk_verifier_accepts_known_backend_and_matching_zk_system -- --nocapture`
- `cargo test -p trnm-pouw zk_verifier_rejects_unknown_vk_ref_fail_closed -- --nocapture`
- `cargo test -p trnm-pouw zk_verifier_rejects_vk_ref_and_zk_system_mismatch -- --nocapture`

### Targeted real-backend checks
- `cargo test -p trnm-pouw --features real-zk-backend zk_verifier_rejects_malformed_real_groth16_proof_encoding -- --nocapture`
- `cargo test -p trnm-pouw --features real-zk-backend zk_verifier_rejects_cryptographically_invalid_real_groth16_proof -- --nocapture`
- `cargo test -p trnm-pouw --features real-zk-backend -q`

## Practical Read

This wave moved TRNM ZKP backend work from:
- demo/backend feature gate + platform skeleton

into a more defensible state with code-level constraints over:
- backend/system binding
- fallback policy
- key reference semantics
- canonical public inputs
- error taxonomy
- real backend invalid verdict separation

## What This Still Does NOT Mean

This does **not** mean:
- multi-backend production support is done
- multi proving-system support is done
- production VK lifecycle / rotation is done
- release readiness is signed off
- the ZKP backend is “100% complete”

## Remaining Highest-Value Gaps

1. second proving-system scout / containment test
2. richer `vk_ref` / key registry lifecycle
3. broader real-backend coverage beyond current demo route
4. final remote promotion / push decision

## Recommendation

Current local `main` is coherent enough for a **push/readiness review decision**, but the remote move should still be explicit and human-approved.

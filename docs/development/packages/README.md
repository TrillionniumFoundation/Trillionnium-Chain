# Chain execution packages

These files are subordinate work packages for the single canonical Chain Plan.
They cannot override protocol, machine, release or evidence truth.

## Exact source split

- Continuation candidate source: `feature/chain-g1-external-blocker-closure-20260830@c0e309743f9696c8ee8bc035ff4c427df4d0eb25` (tree `3b46b2e72879afb4750aab61ebab955ef2c375d1` at code-closure verification)
- Synced base: `origin/feature/chain-a18-repository-truth-ci-hardening-v1-20260830@1663abd8935be4e5819f5ff0c7ded250a3664097`
- Latest inspected A20 remote tip: `feature/chain-a20-p2-tx-tombstone-gc-v1-20260830@9bf9ef2f0cf18183f5a5b0ec459e8affae4d8df5` (tree `43b00a053971405a8eeb4e4c581d04eaee9ade59`; unsafe/write-capable workflow excluded; exact A20 workflow failed and payload job was runner-policy blocked)
- Latest inspected A21 remote tip: `feature/chain-a21-p1-seal-native-commit-verifier-v1-20260830@b58665a783c0e1bcceb33455acde65ee6ada4034` (verified source `c05364e7324fe3ff2c4a8b22322698a0cddd5dc1`; exact baseline/payload checks passed, PR jobs skipped by policy)
- Latest inspected A22 remote tip: `feature/chain-a22-p1-capability-authority-audit-v1-20260830@8e6c2fb5b9f2dd6d60f2b7fb00ac8382b95ba18d` (safe scanner parent `7a9c1bc85dd190a8cbf13da53020b86e6e676092` ported; divergent branch tree changes excluded)
- Latest candidate classification: `draft / unaccepted`
- Assessed Plan source: `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md` (SHA-256 `aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd`; assessed snapshot `8198fea0307eb368df34ff77ffc272a6b0e655ec`)
- Machine stage: `G1-native-host-incomplete`
- Production candidate/activation: `false / false`

The code-closure candidate also carries recovery client-transport isolation,
bounded replay-WAL/temporary scans, A20 parent/child identity and inventory
fences, a sealed native commit/replay-floor verifier boundary, deterministic
A22 capability inventory, and a G1 process-host checked generation plus
three-block proof-horizon fence.  These are repository checks only; they do not
close the independent review, real campaign, custody, physical power-loss,
audit or soak gates.

A branch tip, tested source, assessed source and accepted source are separate
identities.

## Current promotion-critical package stack

### Recovery/Core acknowledgement

- [`TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md`](TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md)
- [`TRNM_G1_R1_SOCKET_OWNER_BOUNDARY_V1.md`](TRNM_G1_R1_SOCKET_OWNER_BOUNDARY_V1.md)
- G1-R2 package and crash/evidence companions
- Draft PRs #2 and #3 remain candidate inputs, not accepted exits

### External recovery/status owner

- [`TRNM_G1_R1_SOCKET_OWNER_BOUNDARY_V1.md`](TRNM_G1_R1_SOCKET_OWNER_BOUNDARY_V1.md)
- Candidate one-shot Unix owner, endpoint identity pinning, bounded I/O and
  explicit Core-acknowledgement seam; production owner and atomic replay-to-Core
  acknowledgement remain open.

### Ordinary Proposal

- [`TRNM_G1_R3_ORDINARY_PROPOSAL_EXECUTION_TARGET_V1.md`](TRNM_G1_R3_ORDINARY_PROPOSAL_EXECUTION_TARGET_V1.md)

### Ordered finalization/recovery

- [`TRNM_G1_R4_FINALIZATION_RECOVERY_TARGET_V1.md`](TRNM_G1_R4_FINALIZATION_RECOVERY_TARGET_V1.md)
- [`TRNM_G1_R4A_FINALIZATION_INTENT_PROCESS_MATRIX_V1.md`](TRNM_G1_R4A_FINALIZATION_INTENT_PROCESS_MATRIX_V1.md)
- [`TRNM_G1_R4_FULL_CLOSURE_DOCUMENTATION_V1.md`](TRNM_G1_R4_FULL_CLOSURE_DOCUMENTATION_V1.md)
- [`trnm-g1-r4a-manifest-v1.toml`](trnm-g1-r4a-manifest-v1.toml)

R4A covers the intent-publication fence only. Application, Safety, checkpoint,
multi-block, anti-rollback, fork reclamation and independent process evidence
remain open.

The current continuation also carries the repository-owned durable history and
transaction-admission retention slices:

- [`TRNM_A19_P1_EXEC_TERMINAL_HISTORY_V1.md`](TRNM_A19_P1_EXEC_TERMINAL_HISTORY_V1.md)
- [`TRNM_A20_P2_TX_TOMBSTONE_GC_V1.md`](TRNM_A20_P2_TX_TOMBSTONE_GC_V1.md)

Both are candidate-only.  A19 still needs an accepted Core/cross-store owner
and independent replacement/power-loss replay; A20 still needs production
application nonce-floor integration and the same external evidence gates.

The sealed native receipt capability boundary is documented in
[`TRNM_A21_P1_SEAL_NATIVE_COMMIT_VERIFIER_V1.md`](TRNM_A21_P1_SEAL_NATIVE_COMMIT_VERIFIER_V1.md).
The deterministic capability inventory is a review aid only; its findings do
not substitute for the independent review and audit gates.

### Native network and future-gate documentation

- [`TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md`](TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md)

This matrix includes the R5 4/7-node campaign, G1.5 normative inventory,
G2.0 W0-W7 traceability, G2A–G2F contracts, and G3–G5 benchmark/security/
operations/economics/governance documentation.

Package ordering and the complete G0–G5 decomposition remain in
[`../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md).

The Workspace Agent registry and copy-ready prompts are under
[`../agents/`](../agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md).

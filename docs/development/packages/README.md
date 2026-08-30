# Chain execution packages

These files are subordinate work packages for the single canonical Chain Plan.
They cannot override protocol, machine, release or evidence truth.

## Exact source split

- Continuation candidate source: `feature/chain-g1-external-blocker-closure-20260830` (commit/tree are derived at verification time)
- Synced base: `origin/feature/chain-a18-repository-truth-ci-hardening-v1-20260830@1663abd8935be4e5819f5ff0c7ded250a3664097`
- Latest inspected A20 remote tip: `feature/chain-a20-p2-tx-tombstone-gc-v1-20260830@7bc87e153a3d4c6426ff9e0a22e8469923d7ffe4` (unsafe self-modifying workflow excluded; exact remote fixtures run failed)
- Latest candidate classification: `draft / unaccepted`
- Assessed Plan source: `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md` (SHA-256 `aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd`; assessed snapshot `8198fea0307eb368df34ff77ffc272a6b0e655ec`)
- Machine stage: `G1-native-host-incomplete`
- Production candidate/activation: `false / false`

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

### Native network and future-gate documentation

- [`TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md`](TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md)

This matrix includes the R5 4/7-node campaign, G1.5 normative inventory,
G2.0 W0-W7 traceability, G2A–G2F contracts, and G3–G5 benchmark/security/
operations/economics/governance documentation.

Package ordering and the complete G0–G5 decomposition remain in
[`../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md).

The Workspace Agent registry and copy-ready prompts are under
[`../agents/`](../agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md).

# Chain execution packages

These files are subordinate work packages for the single canonical Chain Plan.
They cannot override protocol, machine, release or evidence truth.

## Exact source split

- Latest candidate integration source: `feature/chain-g1-r4c-full-gap-closure-20260829@6e0189e351015ef3230f217ca7ff86149baedcf0`
- Latest candidate classification: `draft / unaccepted`
- Assessed Plan source: `docs/chain-poco-bft-mainline-20260825@8198fea0307eb368df34ff77ffc272a6b0e655ec`
- Machine stage: `G1-native-host-incomplete`
- Production candidate/activation: `false / false`

A branch tip, tested source, assessed source and accepted source are separate
identities.

## Current promotion-critical package stack

### Recovery/Core acknowledgement

- [`TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md`](TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md)
- G1-R2 package and crash/evidence companions
- Draft PRs #2 and #3 remain candidate inputs, not accepted exits

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

### Native network and future-gate documentation

- [`TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md`](TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md)

This matrix includes the R5 4/7-node campaign, G1.5 normative inventory,
G2.0 W0-W7 traceability, G2A–G2F contracts, and G3–G5 benchmark/security/
operations/economics/governance documentation.

Package ordering and the complete G0–G5 decomposition remain in
[`../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md).

The Workspace Agent registry and copy-ready prompts are under
[`../agents/`](../agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md).

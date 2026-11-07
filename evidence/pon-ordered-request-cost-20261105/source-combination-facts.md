# Chain/runtime source-combination facts

Source inspection recorded 2026-11-05, 09:13:34 UTC; validation receipts read back 2026-11-05T10:26:11Z. This record combines source inspection with the completed validation outcomes for the current continuation. It is not an execution-source manifest, a new development plan, or an activation receipt. The accompanying JSON provides exact file references and selected-file hashes; those hashes do not replace complete raw-source verification.

## Current sources and execution status

The local Chain HEAD is 657bf2a462ff13a6101ebcb4fbe0fb91c515c972, with tree 7ce7ac50f788dd421e7cc0c9ddb957ade3e8df73. HEAD, tree and a clean worktree were checked read-only. The completed validation receipts identify this source/tree before and after execution, and their retained log hashes were verified. The Node build passed with the explicit Node-only `profile.test.package.trnm-pon-node.debug=0` override. The full Node run retained **1,083 passed, 5 failed and 28 ignored**; its exit code is 101. The owner-epoch and witness-deadline tests each passed once in separate diagnostic runs of the same binary. Those two passes do not replace or cancel the full-suite failures. The earlier original-profile `59546d6` SIGKILL remains a failed build. See the [exact Chain source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/657bf2a462ff13a6101ebcb4fbe0fb91c515c972). Its URL is an exact-source locator; remote publication was not checked.

The **13 new Rust feature tests all passed**: multiproof 3, timestamp 2, canonical dependencies 1, read epochs 6, and CPU observation 1. Public-v3 reader 51, from-zero reader 140, source-integrity 43 and CI roster 9 tests passed. M06 all-targets retained **253 passed and 8 ignored**. Strict workspace/all-targets/all-features Clippy and the repository gates passed. Receipt basenames and the five full-suite failure names are retained in the accompanying JSON.

The original F0 runner executed all **5 planned named tests successfully**, then failed business confirmation acceptance with `CONFIRMATION_TARGET`. All three raw reports exist. The reports retain **644 receiver records** (95 baseline, 549 pressure), and explicitly record **0/1 independently confirmed business transactions in each phase**. Execution and inclusion counts were not separately observed and remain null. The CPU extension covers 449 records; 195 missing extensions remain unknown. These outcomes do not establish confirmation TPS or whole-request CPU.

The **original scale run** completed **2 of 9** planned cohorts and exited 101. The third, 64 accounts with 128 warmup blocks, stopped after the retained `warmup_started` event at index 104; its stderr JSON output is truncated and the root cause remains unknown. The six later cohorts were not started. Its formal reader exited 1 with `REFUSED / exact cohort file set`. This original failure remains retained.

One **diagnostic retry**, using the same frozen source, native binary and original nine-cohort grid, exited 0 and recorded `run_completed`. Its formal reader also exited 0 with `COMPLETE_LOCAL_OBSERVATION`: **9/9 cohorts, 72 measured native blocks, 153 returned stage records, 9 cancelled admissions and 9 cold reopens**. The 153 records contain 144 accepted and 9 rejected stage outcomes; they are not counts of independently confirmed transactions. This retry does not replace the original failure. Both attempts keep p99 and confirmation TPS null; the completed local observation does not qualify throughput, public-network readiness or production activation.

The observed runtime candidate is hepta-private-ci 7530e4bc7aa61a0c23a5933fef4a65d86a586cf8, tree 253d7584783cf658b9d5192d1106aa4c08fe031f. Exact-ref files were inspected, but this runtime was not materialized or executed for this continuation. Runtime executed is **false**. These two source identities therefore do not constitute a newly executed Chain/runtime pair. See the [runtime source](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8).

## Preserved historical V10 identity

The historical tested V10 pair remains Chain 04be5f02c84cf5cb626a53f34bc03a5bd6ff5137, tree d4f4a85c439982d8decec9265c1993408f3577cf, and runtime d7c32f38ae1c3890e73ff48ef8ee725ba4e80c58, tree b79a4a4677b672a89cce53c9abe6f6c71810ee88. Its profile is hepta-integrated-chain-execution-v10. Its manifest SHA256 remains 97e5311a86a0dc6fcd62a29ca9cd8a323c9b34a6991790ae347cfbb57bf796ed. The manifest's 51 entries count files, not tests.

The [historical report](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8/qualification/learning-generations/hepta-pair-v10-source-20261105/README.md) retains all nine gates as HOLD and distinguishes separate Growth and PQ configurations. Neither the historical manifest nor its results are rewritten here. No old success, failure, resource profile or qualification is reassigned to the current sources.

## Actual workflow defaults

The [workflow at the observed runtime commit](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8/.github/workflows/hepta-neural-study-v1.yml) still selects hepta-integrated-chain-execution-v4. Its three checkout roles are:

| Role | Variable | Commit |
| --- | --- | --- |
| chain | CHAIN_SHA | c16507147b65285ea94dead22d3b93c5db7295af |
| chain-answer-eos | RESEARCH_CHAIN_SHA | c16507147b65285ea94dead22d3b93c5db7295af |
| chain-observed | OBSERVATION_CHAIN_SHA | c16507147b65285ea94dead22d3b93c5db7295af |

The [closed source registry](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8/scripts/hepta_smollm_execution_source_v1.py) also registers V10, pointing to the historical Chain commit. Registration does not change the workflow default. Several source-integrity branches explicitly recognize V10 or V9/V10, including native inputs, raw-byte checks and merge verification; adding a registry entry alone does not extend all those guards.

## Combination interfaces in the frozen Chain source

The shared [Growth execution helper](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/store/growth.rs) now passes Some(header.ledger.timestamp) into M06. Construction, admission, retained replay and cold replay use this projection. The dedicated tests exercise real PQ expiry at the M06 input boundary and classical Growth output/admission/replay behavior. Both dedicated tests passed in `new-timestamp-tests.json`; their scope does not establish PQ Growth wire or public admission.

Five composition boundaries remain in the source:

- **Configuration:** the Growth builder changes parameters and chain context, while the PQ Profile seals both through its configuration digest. Directly mutating that sealed profile is rejected as PQ2_CONFIG_CHANGED.
- **Transaction decoding:** PNP2 requires the classical Envelope and 159–2048 bytes per transaction. Account-witness selection also uses the classical decoder. Accepting larger bytes alone would not supply profile-aware owner discovery.
- **Authority state:** Growth combines touched account leaves with the complete working partition. PQ validation requires complete account-to-authority and retained-generation coverage, rejecting orphan pq-* rows. Permanent leaves contain balance and nonce only. A canonical SPKI JSON value alone occupies 3,950 bytes, while all working state is capped at 262,144 bytes. Keeping every account's authority history there does not provide scalable PQ account storage.
- **Backend ownership:** PermanentAccountGrowthV2 remains separate from the PQ network, continuous and witness backends. PQ account settings require the PQ network owner; the Growth opener does not supply that owner. A combined recovery and activation contract is consequently absent.
- **Public profile:** NativeGrowthV1 requires a classical identity and allows operations 6/7/8. PQ identity selects PqHistoryV4 and operations 2/3; the client enforces that pairing too. The [Growth public resource identity](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/growth.rs) expressly excludes a pool, history walker and automatic parent recovery. Removing one guard would not integrate these interfaces.

## Complete-state and qualification boundaries

The [Node migration inventory](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/store/pq_migration_inventory.rs) still refuses Growth with GROWTH_COMPLETE_STATE_UNAVAILABLE. Its legacy material expects the original Header identity, a full-State root and at most 65,536 rows; trusted imports additionally cap accounts at 64. Growth uses PGH2 identity, partition commitments and up to one million permanent accounts. Working state cannot substitute for that complete ledger. Any complete inspection must retain zero-balance accounts, nonce floors and all working rows; exporting them alone would not make the old migration type compatible.

Unified PQ/Growth/public/ordinary/recovery execution remains unestablished. This record makes no new confirmed-TPS claim and grants no production or installation authorization. Final source-bound execution receipts remain the evidence owners for current validation results.

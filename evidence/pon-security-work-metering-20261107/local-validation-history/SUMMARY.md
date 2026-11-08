# Final local validation

Status: **INCOMPLETE**. All requested Python discovery commands ran; native skips and staging Git errors remain outstanding. No skipped test is counted as passed.

## Suite outcomes

| Suite | Total | Passed | Failures | Errors | Skipped | Exit |
|---|---:|---:|---:|---:|---:|---:|
| grouped | 210 | 205 | 0 | 3 | 2 | 1 |
| fresh-query-floor | 27 | 27 | 0 | 0 | 0 | 0 |
| fresh-resource-transfer | 15 | 15 | 0 | 0 | 0 | 0 |

## Module outcomes

| Module | Total | Passed | Failures | Errors | Skipped |
|---|---:|---:|---:|---:|---:|
| test_grouped_cell_operator_v0 | 11 | 9 | 0 | 0 | 2 |
| test_grouped_challenge_shortcuts_v0 | 9 | 8 | 0 | 1 | 0 |
| test_grouped_fanout_reanalysis_v1 | 18 | 18 | 0 | 0 | 0 |
| test_grouped_fresh_admission_wire_v0 | 12 | 12 | 0 | 0 | 0 |
| test_grouped_fresh_deployment_cost_v0 | 41 | 41 | 0 | 0 | 0 |
| test_grouped_fresh_work_v0 | 11 | 11 | 0 | 0 | 0 |
| test_grouped_legal_strategy_v0 | 19 | 17 | 0 | 2 | 0 |
| test_grouped_low_rank_v0 | 6 | 6 | 0 | 0 | 0 |
| test_grouped_request_batch_v0 | 15 | 15 | 0 | 0 | 0 |
| test_grouped_work_lottery_adversarial_v0 | 27 | 27 | 0 | 0 | 0 |
| test_grouped_work_profile_v1 | 41 | 41 | 0 | 0 | 0 |
| test_fresh_work_query_floor_v0 | 27 | 27 | 0 | 0 | 0 |
| test_fresh_work_resource_transfer_v0 | 15 | 15 | 0 | 0 | 0 |

## Outstanding tests

- **SKIP** `test_grouped_cell_operator_v0.GroupedNativeIntegrationTests.test_one_real_process_init_all_shapes_full_scalar_and_numpy_differential`: skipped 'TRNM_GROUPED_NATIVE is unset: actual native integration not executed'.
- **SKIP** `test_grouped_cell_operator_v0.GroupedNativeIntegrationTests.test_real_process_hostile_frames_reject_without_success_fallback`: skipped 'TRNM_GROUPED_NATIVE is unset: actual native integration not executed'.
- **ERROR** `test_grouped_challenge_shortcuts_v0.ChallengeShortcutTests.test_plan_exists_before_failed_load_and_keeps_complete_denominator`: git rev-parse HEAD exited 128: candidate staging has no Git metadata.
- **ERROR** `test_grouped_legal_strategy_v0.CampaignIntegrityTests.test_load_failure_retains_unstarted_real_arms_and_preregistered_schedule`: git rev-parse HEAD exited 128: candidate staging has no Git metadata.
- **ERROR** `test_grouped_legal_strategy_v0.CampaignIntegrityTests.test_source_gate_failure_prevents_observations_but_retains_full_plan`: git rev-parse HEAD exited 128: candidate staging has no Git metadata.

## Syntax, whitespace and source integrity

All seven changed Python files passed AST parsing and compilation in memory, with no pyc output requested. Whitespace checks emitted no diagnostics. Raw `git diff --no-index --check` exit status was 1 for each changed file, indicating differences rather than a whitespace error. Candidate source hashes were unchanged across the checks.

| Source | SHA256 |
|---|---|
| formal/pon-nakamoto-v1/experiments/reanalyze_grouped_fanout_v1.py | `3ac9a625421addd573aba827da1830ab6579af17fff82cf24dcf35222d1208a9` |
| formal/pon-nakamoto-v1/grouped_fresh_deployment_cost_v0.py | `eeec2e1cc1fa5b269635d3dfa1fcf800325b5d3a6ebe5dba2c935638d4bf3773` |
| formal/pon-nakamoto-v1/grouped_work_profile_v1.py | `8e63a160cc639ea77a3b122f982bc5a885ba1c926bb92531270897fd80164b66` |
| formal/pon-nakamoto-v1/test_grouped_fanout_reanalysis_v1.py | `03f24af7ba0db3d05ef87220803b6511fbb678df108b96677f00950c0576ca56` |
| formal/pon-nakamoto-v1/test_grouped_fresh_deployment_cost_v0.py | `9ce117792b57c2ee6656f2141094404b2eb829d0272910fe3481980b89c90dab` |
| formal/pon-nakamoto-v1/test_grouped_work_profile_v1.py | `c54730920ff28a77f3125333314b88e0bfdf8fbbce04fd9ad3e8e799d4c82120` |
| evidence/pon-security-work-metering-20261107/replay_retained_query_trace.py | `71b6c30bfe78b910b075126279e30165d021ae4df47b44455f05d47ce8625c3e` |

## Scope

CI entry points were inspected in `scripts/ci/ci_job.sh`, `scripts/ci/check_ci_contract.py`, and `experiments/validate_grouped_fresh_work_v0.py`. Local invocations used the same three discovery patterns, with bytecode writes disabled. Native executables were not supplied or built; native exact-commit validation remains with the parent workflow. No dependency installation, remote operation, source modification, production qualification or chainwork claim is made.

# Ordered request and read-epoch evidence scope

The frozen source is `657bf2a462ff13a6101ebcb4fbe0fb91c515c972`, tree `7ce7ac50f788dd421e7cc0c9ddb957ade3e8df73`. Compared with `6ee529046d295e3175f09112492abee373f1f54c`, the requested feature scope adds **20 test functions: 13 Rust and 7 Python**. These are function counts, not counts of loop iterations, fault injections, transactions, or confirmed business requests. The complete merged diff adds 35 functions: the other 15 are two catalog tests, four History spool tests, and nine CI roster tests.

## Exact new feature-test inventory

Multiproof, three:

- `native_constructed_query_retains_one_full_verification_and_identical_facts`
- `native_constructed_query_preserves_every_cancellation_boundary_without_writes`
- `native_constructed_query_rechecks_context_and_storage_on_each_operation`

Header timestamp, two:

- `growth_header_timestamp_controls_real_pq_m06_expiry_at_the_input_boundary`
- `growth_header_timestamp_preserves_classic_outputs_admission_and_retained_replay`

Canonical dependencies, one:

- `growth_parallel_preparation_keeps_dependent_task_settlement_spends_and_reward_canonical`

Read epochs, six:

- `native_growth_v2_read_snapshot_hides_foreign_epoch_until_release`
- `native_growth_v2_account_queries_refuse_foreign_commit_inside_read_snapshot`
- `native_growth_v2_working_queries_refuse_foreign_commit_inside_read_snapshot`
- `native_growth_v2_head_and_exact_observations_refuse_foreign_commit_at_ready`
- `native_growth_v2_autocommit_queries_recheck_foreign_epoch_after_read`
- `native_growth_v2_successful_payment_rechecks_epoch_after_read_snapshot`

Native CPU observation, one:

- `cancelled_owner_retains_actual_scoped_work_until_join_and_original_settlement`

Reader validation, seven:

- `test_original_settlement_values_keep_all_costs_outcomes_and_unknown_denominators`
- `test_original_settlement_values_refuse_missing_negative_overflow_bool_and_forged_sums`
- `test_unknown_original_total_is_not_reconstructed_from_readable_component_clocks`
- `test_v2_original_residual_cannot_be_missing_with_known_nonnegative_subtraction`
- `test_v2_budget_success_requires_a_known_original_residual`
- `test_request_owner_clocks_keep_post_disconnect_tail_and_unfinished_costs`
- `test_request_owner_clocks_reject_early_terminal_and_invalid_unknown_claims`

Existing TCP-disconnection and signed-success/clock-failure tests also gained assertions; they are not additional test functions. The new cancellation fixture joins real scoped worker CPU after cancellation, including a failed-clock branch. Its integer workload tests metering, not W1 validity or business confirmation.

## What the observation measures

`public-v3-cpu-settlement-observation-v2` retains the original `owner_cpu_ns`, `scoped_worker_cpu_ns`, `total_cpu_ns`, `live_paid_cpu_ns`, and `residual_cpu_ns`. Known total equals owner plus joined scoped workers. Residual is exactly the original checked subtraction of live-paid from total; unavailable operands or underflow remain unknown. Successful budget settlement requires a known residual. These facts create no additional debit or authority.

The reader preserves accepted, rejected, unknown, missing-extension, legacy-v1, failed-clock, and unfinished denominators. It reports known counts, unknown counts, known sums, empirical p50/p95, extrema, and a mean with an explicit known-sample denominator. An unknown original total is not reconstructed from readable components. A null journal field means no continuous-journal scope. Historical v1-only derivations remain compatible.

Lifecycle observations separately describe accept-to-owner-closure wall time and task ownership after connection closure. An unclosed task has unknown terminal latency. Connection closure does not timestamp the cancellation signal; task ownership includes buffered completion. CPU associated with a completed post-disconnect owner includes work performed before disconnect.

Original CPU samples exclude reactor CPU and budget/journal work after the original owner sample. The overlapping `cpu_settle` phase cannot be added to those samples. Neither whole-request CPU nor CPU consumed exclusively during the post-disconnect tail is established.

## Evidence acceptance and reporting limits

Receipts identify the same source/tree before and after execution, verify tracked bytes, and match retained log hashes. A pass claim also requires successful exit and the named-test transcript; failed receipts remain evidence. Compilation alone does not execute tests. All **13 new Rust tests passed**. Reader **51**, from-zero reader **140**, source-integrity **43**, CI roster **9**, and M06 **253 passed / 8 ignored** completed successfully. Strict workspace/all-targets/all-features Clippy and repository gates passed.

The Node-only `debug=0` build passed. The full Node run retained **1,083 passed / 5 failed / 28 ignored**. Owner-epoch and witness-deadline isolated runs of the same binary each passed once; they do not cancel those five failures. The earlier original-profile `59546d6` SIGKILL remains a failed build. Functional passes establish their exercised behavior, not capacity.

Original F0 retained **5 named-test passes**, but business acceptance failed with `CONFIRMATION_TARGET`. All **644 receiver records** remain: 95 baseline and 549 pressure. Original CPU fields are known for 449 records and unknown for 195 missing extensions; these are scoped costs, not whole-request CPU. The raw reports record **0/1 independently confirmed transactions per phase**; separate execution and inclusion counts remain null. All owners closed, but no positive post-disconnect cohort occurred. Closure does not imply business success.

Original scale retained **2/9 completed cohorts**, exit 101, and reader refusal. Third-cohort stderr JSON stops at warmup index 104; the root cause remains unknown. One diagnostic retry used the same source, binary and original grid, completed **9/9 cohorts**, and passed its formal reader (`COMPLETE_LOCAL_OBSERVATION`): **72 measured blocks, 153 returned stage records, 9 cancelled admissions and 9 cold reopens**. It does not replace the original failure. Returned stages are not confirmed business requests.

Report stage p99 only for its explicitly retained terminal cohort with known outcomes and durations. These scale reports retain p99 null and do not qualify throughput. Whole-population request p99, successful independent-confirmation latency, confirmation TPS and exclusive CPU tail remain unestablished. ACK, execution, inclusion, independent confirmation and owner closure remain distinct.

# Node coverage diagnostic on frozen 690f710c

**Qualification remains false.** This report counts complete target summaries across two independent Cargo invocations. The original failures and timeout remain retained.

Source commit: 690f710c1b6808787996e86aa4c36bd53e1f3939. Tree: b9ff2e5c4ca6e465b86cb4b2bd466ad831147899.

## Actual counts

| Scope | Passed | Failed | Ignored | Measured | Filtered |
|---|---:|---:|---:|---:|---:|
| Original complete targets | 1254 | 8 | 40 | 0 | 0 |
| Remainder complete targets | 294 | 7 | 15 | 0 | 0 |
| Cross-run complete targets | 1548 | 15 | 55 | 0 | 0 |

Completed targets: 91 / 91. Missing or ambiguous targets: 0. Ignored tests are excluded from passed counts. No nested harness or partial test-case count is included.

The original process ended by native timeout 124 and has no source-after snapshot. A later snapshot does not repair that missing provenance. The remainder native Cargo exit was 101; its host terminal state was failed.

## Five native targets

| # | Kind | Target | Run | Status | Passed | Failed | Ignored | Measured | Filtered |
|---:|---|---|---|---|---:|---:|---:|---:|---:|
| 1 | test | no_gain_fees | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 2 | test | funded_service_contract | original | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 3 | test | native_demand_evidence | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 4 | test | native_task_operation_v2 | remainder | completed_passed | 3 | 0 | 0 | 0 | 0 |
| 5 | test | native_active_anchor | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |

These rows retain their source run and raw-log provenance. Passing these five targets does not change any original failure or qualify the whole Node suite.

## Failed targets

| # | Kind | Target | Run | Status | Passed | Failed | Ignored | Measured | Filtered |
|---:|---|---|---|---|---:|---:|---:|---:|---:|
| 1 | lib | trnm_pon_node | original | completed_with_failures | 1139 | 5 | 31 | 0 | 0 |
| 2 | test | architecture_delivery_compare | original | completed_with_failures | 12 | 1 | 0 | 0 | 0 |
| 3 | test | evaluation_sync_observation | original | completed_with_failures | 2 | 1 | 0 | 0 | 0 |
| 4 | test | mining_service_budget | original | completed_with_failures | 1 | 1 | 0 | 0 | 0 |
| 5 | test | native_node | remainder | completed_with_failures | 28 | 2 | 1 | 0 | 0 |
| 6 | test | public_cli | remainder | completed_with_failures | 2 | 1 | 0 | 0 | 0 |
| 7 | test | public_intake_v2 | remainder | completed_with_failures | 0 | 2 | 0 | 0 | 0 |
| 8 | test | public_pool_cli | remainder | completed_with_failures | 3 | 2 | 0 | 0 | 0 |

Failure causes require retained per-test evidence. Diagnostic files supplied with this report are listed by exact hash in its manifest; they are not inferred from target names.

## All 91 targets

| # | Kind | Target | Run | Status | Passed | Failed | Ignored | Measured | Filtered |
|---:|---|---|---|---|---:|---:|---:|---:|---:|
| 1 | lib | trnm_pon_node | original | completed_with_failures | 1139 | 5 | 31 | 0 | 0 |
| 2 | bin | trnm-pon-node | original | completed_passed | 14 | 0 | 0 | 0 | 0 |
| 3 | example | account_archive_vectors | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 4 | example | account_execution_vectors | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 5 | example | continuous_pipeline | remainder | completed_passed | 13 | 0 | 0 | 0 | 0 |
| 6 | example | distributed_pipeline | remainder | completed_passed | 9 | 0 | 0 | 0 | 0 |
| 7 | example | hepta_task_fixture | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 8 | example | history_state_cost | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 9 | example | lifecycle_atomic_continuity | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 10 | example | lifecycle_continuity | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 11 | example | llm_zero_gain_round | remainder | completed_passed | 8 | 0 | 0 | 0 | 0 |
| 12 | example | native_reorg_query_cost | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 13 | example | operator_owned_finite_mining | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 14 | example | operator_pool_fixture | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 15 | example | pon_w1_budget_report | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 16 | example | pon_w1_cost_matrix_v2 | remainder | completed_passed | 5 | 0 | 0 | 0 | 0 |
| 17 | example | pon_w1_false_trace_reuse_v1 | remainder | completed_passed | 5 | 0 | 0 | 0 | 0 |
| 18 | example | pon_w1_legal_strategy_v1 | remainder | completed_passed | 8 | 0 | 0 | 0 | 0 |
| 19 | example | pon_w1_legal_strategy_v3 | remainder | completed_passed | 6 | 0 | 0 | 0 | 0 |
| 20 | example | pon_w1_preparation_strategy_v4 | remainder | completed_passed | 9 | 0 | 0 | 0 | 0 |
| 21 | example | pon_w1_reused_cost_v3 | remainder | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 22 | example | public_pool_fixture | remainder | completed_passed | 0 | 0 | 0 | 0 | 0 |
| 23 | test | accepted_task_observation | original | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 24 | test | account_archive_execution | original | completed_passed | 12 | 0 | 0 | 0 | 0 |
| 25 | test | account_archive_projection | original | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 26 | test | account_archive_prototype | original | completed_passed | 8 | 0 | 1 | 0 | 0 |
| 27 | test | account_obligation_ranges | original | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 28 | test | ancestry_long_sync | original | completed_passed | 0 | 0 | 1 | 0 | 0 |
| 29 | test | architecture_delivery_compare | original | completed_with_failures | 12 | 1 | 0 | 0 | 0 |
| 30 | test | authenticated_storage_cli | original | completed_passed | 7 | 0 | 0 | 0 | 0 |
| 31 | test | checkpoint_tile_operator | original | completed_passed | 3 | 0 | 1 | 0 | 0 |
| 32 | test | cli_secret_canary | original | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 33 | test | continuity_authenticated | original | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 34 | test | continuity_cli | original | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 35 | test | daa_adversarial_schedule | original | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 36 | test | derived_commitment | original | completed_passed | 5 | 0 | 0 | 0 | 0 |
| 37 | test | distributed_roles | original | completed_passed | 0 | 0 | 4 | 0 | 0 |
| 38 | test | evaluation_observation | original | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 39 | test | evaluation_observation_cli | original | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 40 | test | evaluation_quorum_cli | original | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 41 | test | evaluation_round_observation | original | completed_passed | 1 | 0 | 1 | 0 | 0 |
| 42 | test | evaluation_round_observation_cli | original | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 43 | test | evaluation_sync_observation | original | completed_with_failures | 2 | 1 | 0 | 0 | 0 |
| 44 | test | evolution_cli | original | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 45 | test | funded_service_contract | original | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 46 | test | growth_persistence_cancellation | original | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 47 | test | integer_factor_candidate_v2 | original | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 48 | test | local_mempool | original | completed_passed | 14 | 0 | 1 | 0 | 0 |
| 49 | test | maintenance_paired_conformance | original | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 50 | test | mining_service_budget | original | completed_with_failures | 1 | 1 | 0 | 0 | 0 |
| 51 | test | model_composition_v4 | remainder | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 52 | test | model_evidence_v3 | remainder | completed_passed | 6 | 0 | 0 | 0 | 0 |
| 53 | test | native_active_anchor | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 54 | test | native_compact_execution | remainder | completed_passed | 5 | 0 | 0 | 0 | 0 |
| 55 | test | native_demand_evidence | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 56 | test | native_growth_cli | remainder | completed_passed | 5 | 0 | 0 | 0 | 0 |
| 57 | test | native_growth_public_cli | remainder | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 58 | test | native_node | remainder | completed_with_failures | 28 | 2 | 1 | 0 | 0 |
| 59 | test | native_task_operation_v2 | remainder | completed_passed | 3 | 0 | 0 | 0 | 0 |
| 60 | test | no_gain_fees | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 61 | test | nonce_speculation_cost | remainder | completed_passed | 0 | 0 | 1 | 0 | 0 |
| 62 | test | one_zero_task_preparation_lifecycle | remainder | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 63 | test | operation_local_parent | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 64 | test | operator_actors | remainder | completed_passed | 12 | 0 | 0 | 0 | 0 |
| 65 | test | pinned_peer_polling | remainder | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 66 | test | pool_mining | remainder | completed_passed | 10 | 0 | 0 | 0 | 0 |
| 67 | test | pq_account_native | remainder | completed_passed | 11 | 0 | 0 | 0 | 0 |
| 68 | test | pq_migration_inventory | remainder | completed_passed | 5 | 0 | 0 | 0 | 0 |
| 69 | test | protected_ingress | remainder | completed_passed | 12 | 0 | 1 | 0 | 0 |
| 70 | test | public_cache_modes | remainder | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 71 | test | public_cli | remainder | completed_with_failures | 2 | 1 | 0 | 0 | 0 |
| 72 | test | public_evaluation | remainder | completed_passed | 8 | 0 | 0 | 0 | 0 |
| 73 | test | public_intake_v2 | remainder | completed_with_failures | 0 | 2 | 0 | 0 | 0 |
| 74 | test | public_pool_cli | remainder | completed_with_failures | 3 | 2 | 0 | 0 | 0 |
| 75 | test | public_pool_v3 | remainder | completed_passed | 3 | 0 | 0 | 0 | 0 |
| 76 | test | public_submit_recovery | remainder | completed_passed | 24 | 0 | 0 | 0 | 0 |
| 77 | test | public_v3_from_zero | remainder | completed_passed | 5 | 0 | 1 | 0 | 0 |
| 78 | test | public_v3_multiprocess | remainder | completed_passed | 17 | 0 | 8 | 0 | 0 |
| 79 | test | public_v3_observation_cli | remainder | completed_passed | 6 | 0 | 0 | 0 | 0 |
| 80 | test | public_v3_observer | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 81 | test | public_v3_request_accounting | remainder | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 82 | test | public_v3_service_campaign | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 83 | test | qualified_tasks | remainder | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 84 | test | release_finality_v2 | remainder | completed_passed | 2 | 0 | 2 | 0 | 0 |
| 85 | test | task_lifecycle | remainder | completed_passed | 4 | 0 | 0 | 0 | 0 |
| 86 | test | task_lifecycle_v3 | remainder | completed_passed | 3 | 0 | 0 | 0 | 0 |
| 87 | test | task_lifecycle_v4 | remainder | completed_passed | 3 | 0 | 1 | 0 | 0 |
| 88 | test | task_output_root_parity | remainder | completed_passed | 2 | 0 | 0 | 0 | 0 |
| 89 | test | work_fuzz_semantics | remainder | completed_passed | 6 | 0 | 0 | 0 | 0 |
| 90 | test | work_header_binding | remainder | completed_passed | 1 | 0 | 0 | 0 | 0 |
| 91 | test | zero_task_preparation_lifecycle | remainder | completed_passed | 1 | 0 | 0 | 0 | 0 |

The CSV and JSON retain canonical source paths and raw-log byte intervals. The original partial model_composition_v4 observation is preserved in the union and excluded from sums; only its preassigned remainder invocation can contribute a complete summary.

This report establishes controlled execution observations and counting coverage only. It is not independent customer demand, external-funding independence, physical model gain, production installation, or a single successful Cargo gate.

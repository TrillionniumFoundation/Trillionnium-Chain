# Documentation and implementation authority

The sole plan is `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.
The selected target is `pon-nakamoto-v1`. The portability inventory binds each actual
Cargo package to exactly one M00-M17 owner; absent implementation is stated explicitly.

Old consensus code, protocol directories, byte registries, launchers and legacy appendices
are deleted. Git is the archive; no old decoder or automatic fallback remains in the
active build. New domains/schemas require fresh namespaces, not in-place database reuse.

Retained task/MVCC/settlement stores have LOCAL monotonic commit semantics. They are not
an implemented branch/undo layer. Storage and evaluator trust thresholds are application
contracts, not ledger quorum or fork choice. No source rename grants new proof authority.

Source integrity, retained component tests, work hardness, actual node operation, model
future-window efficacy and deployment are separate facts. Activation remains false.
Do not modify protected-main requirements, self-approve, or replace a missing domain with
a default-success stub. Required CI retains the five existing check names and tests only
actual portable source, native development owners and clearly scoped reference models. No old fixture is relabelled
as new consensus/security/efficacy evidence.


## Current applicability and evidence classes

The [applicability registry](../../config/pon/applicability-v1.json) joins the existing
module contract, maturity and source inventories; it is not a second plan. Its canonical
procedure table is derived from those owners, rather than maintained as another copy:

```bash
python3 scripts/ci/check_applicability.py --format markdown
python3 scripts/ci/check_applicability.py --format json
```

Each of the 39 procedure rows identifies its module document, actual source symbols,
controlled entrypoint, exact tests and source-binding evidence class. Product entrypoints
remain separate and null where not integrated. The checker checks links, callable/test
bindings, all eighteen modules, profile revisions and snapshot package count. It does not
run those tests. Use the existing module evidence reporter to derive historical receipt
applicability against the actual checkout; no declaration here promotes old measurements.

<!-- applicability-table:start -->
| Boundary / modules | Configuration / revision | Contract | Entrypoint | Exact test selector |
|---|---|---|---|---|
| evaluation-v1 / M06, M11, M15 | [public-evaluation-native-v1.json](../../config/pon/public-evaluation-native-v1.json), revision6 | [PUBLIC_EVALUATION_LIFECYCLE](../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_EVALUATION_LIFECYCLE.md) | [run](../../trillionnium/crates/trnm-pon-node/src/main.rs) | trillionnium/crates/trnm-pon-node/tests/public_evaluation.rs::every_arrival_order_closes_identically_and_missing_is_abort |
| lifecycle-v2 / M01, M05, M06, M15 | [qualified-task-lifecycle-v2.json](../../config/pon/qualified-task-lifecycle-v2.json), revision7 | [QUALIFIED_TASK_LIFECYCLE_V2](../../docs/protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V2.md) | [run](../../trillionnium/crates/trnm-pon-node/src/main.rs) | trillionnium/crates/trnm-pon-node/tests/task_lifecycle.rs::renew_keeps_one_output_revoke_stops_new_work_and_reopen_reorg_are_real |
| lifecycle-v3 / M01, M05, M06, M15 | [qualified-task-lifecycle-v3.json](../../config/pon/qualified-task-lifecycle-v3.json), revision8 | [QUALIFIED_TASK_LIFECYCLE_V3](../../docs/protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md) | [run](../../trillionnium/crates/trnm-pon-node/src/main.rs) | trillionnium/crates/trnm-pon-node/tests/task_lifecycle_v3.rs::sole_task_atomic_renew_rejects_partial_legacy_bad_signature_window_sequence_without_mutation |
| lifecycle-v4 / M01, M05, M06, M15 | [qualified-task-lifecycle-v4.json](../../config/pon/qualified-task-lifecycle-v4.json), revision9 | [QUALIFIED_TASK_LIFECYCLE_V4](../../docs/protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md) | [run](../../trillionnium/crates/trnm-pon-node/src/main.rs) | trillionnium/crates/trnm-pon-node/tests/task_lifecycle_v4.rs::delayed_atomic_renew_preserves_used_output_meter_and_revoke_reorg_state |
| checkpoint-tile-v1 / M01, M05, M06, M15 | [checkpoint-tile-task-v1.json](../../config/pon/checkpoint-tile-task-v1.json), revision10 | [CHECKPOINT_TILE_TASK_V1](../../docs/protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_TASK_V1.md) | [run](../../trillionnium/crates/trnm-pon-node/src/main.rs) | trillionnium/crates/trnm-pon-node/tests/checkpoint_tile_operator.rs::native_revision10_replay_renew_reorg_reopen_and_original_profiles_are_distinct |
| local-pool-reconciliation / M05, M06, M07, M08, M15 | Local/transport policy; no consensus revision | [LOCAL_MEMPOOL_LIFECYCLE](../../docs/protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md) | [Node::pool_reconcile](../../trillionnium/crates/trnm-pon-node/src/store/mempool.rs) | trillionnium/crates/trnm-pon-node/tests/local_mempool.rs::retained_groups_restore_after_real_heavier_fork_and_terminal_prune_is_monotonic |
| protected-hello-handoff / M04, M15 | Local/transport policy; no consensus revision | [ADMISSION_SECURITY](../../docs/protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) | [try_handoff_hello](../../trillionnium/crates/trnm-pon-node/src/ingress.rs) | trillionnium/crates/trnm-pon-node/src/ingress.rs::protected_hello_additional_opportunities_never_refresh_expired_original_deadlines |
| integer-factor-v2 / M00, M06, M10, M11, M15 | [integer-factor-candidate-v2.json](../../config/pon/integer-factor-candidate-v2.json), revision11 | [NATIVE_INTEGER_FACTOR_CANDIDATE_V2](../../docs/protocol/pon-nakamoto-v1/details/NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md) | [run](../../trillionnium/crates/trnm-pon-node/src/main.rs) | trillionnium/crates/trnm-pon-node/tests/integer_factor_candidate_v2.rs::exact_variants_refuse_and_real_fork_restores_duplicate_window<br>trillionnium/crates/trnm-pon-node/tests/integer_factor_candidate_v2.rs::missing_score_abort_keeps_same_round_marker_and_new_round_allows_update<br>trillionnium/crates/trnm-pon-node/tests/integer_factor_candidate_v2.rs::loaded_release_parent_full_range_and_new_round_are_native<br>trillionnium/crates/trnm-pon-node/tests/integer_factor_candidate_v2.rs::cli_selects_fresh_profile_and_genesis_before_any_candidate |
| public-intake-v3-r3 / M04, M15 | Local/transport policy; no consensus revision | [PUBLIC_POOL_INTAKE_V3](../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md) | [serve_public_protected_v3_with_metrics](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs) | trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs::eight_paid_submits_wait_for_full_queue_without_losing_body_or_absolute_deadline<br>trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs::resource_revision_r3_rejects_signed_old_cookies_and_preserves_control_output_reserve |
<!-- applicability-table:end -->

These rows are source-binding navigation, not fresh execution receipts. Source checks,
local execution, historical receipts, exact hosted-head checks, prospective-merge checks
and independent external acceptance are distinct evidence classes in the registry.
An author report or passing source check cannot replace any other class. Exact hosted
head/base/merge outcomes must be fetched from CI at verification time; this registry
asserts none. Tests executed on an uncommitted candidate must retain that fact and their
actual command/environment, and do not certify a later commit or merge tree.

M05 reconciliation is implemented for the explicitly enabled local pool, including
original signed-group replay after a heavier fork and stale read-only classifications.
That does not imply an automatic external event consumer or physical-effect rollback.
The protected Hello uses zero-capacity rendezvous with bounded repeated opportunities,
original deadlines and three socket owners. Historical Busy/failure observations remain
historical; changed scheduling, cache budgets or documentation do not rerun them.

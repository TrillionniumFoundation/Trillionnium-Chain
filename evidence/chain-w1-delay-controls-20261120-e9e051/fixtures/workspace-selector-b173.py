import json, os, re
from pathlib import Path
root = Path(os.environ["TRNM_CI_RECEIPT_DIR"]) / "semantic-controls"
registries = {}
for crate in ("m06", "node"):
    names = []
    for line in (root / f"{crate}-registry.log").read_text().splitlines():
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_:]*): test", line)
        if match:
            names.append(match[1])
    assert names and len(names) == len(set(names)), "empty or duplicate libtest registry: " + crate
    registries[crate] = set(names)
selected = []
groups = []
def prefix(crate, group, name, count):
    names = sorted(test for test in registries[crate] if test.startswith(name))
    assert len(names) == count, f"{group}: expected {count} actual registered controls, got {len(names)}"
    groups.append({"crate": crate, "group": group, "prefix": name, "expected_count": count, "tests": names})
    selected.extend((crate, group, test) for test in names)
def exact(crate, group, names):
    assert names and len(names) == len(set(names))
    assert all(test in registries[crate] for test in names), "missing exact control: " + group
    groups.append({"crate": crate, "group": group, "expected_count": len(names), "tests": names})
    selected.extend((crate, group, test) for test in names)
prefix("m06", "full-root-arithmetic", "pon_commitment::full_root_arithmetic_tests::", 5)
exact("m06", "unchanged-canonical-map", [
    "pon_commitment::unchanged_snapshot_tests::unchanged_snapshot_shares_only_after_full_actual_bytes_match",
    "pon_commitment::unchanged_snapshot_tests::unchanged_snapshot_retains_exact_capacity_charges_and_all_budget_boundaries",
    "pon_commitment::unchanged_snapshot_tests::unchanged_snapshot_misleading_root_and_changed_bytes_take_original_repair_path",
    "pon_commitment::unchanged_snapshot_tests::unchanged_snapshot_keeps_late_canonical_errors_before_wire_and_cache_limits",
    "pon_commitment::unchanged_snapshot_tests::unchanged_candidate_early_miss_retains_complete_late_validation",
    "pon_commitment::unchanged_snapshot_tests::unchanged_snapshot_empty_delta_still_checks_the_original_tree_root",
])
exact("node", "account-root-digest", [
    "account_archive_prototype::native_root_digest::tests::native_root_digest_matches_record_and_sparse_references_after_exact_input_changes",
    "account_archive_prototype::native_root_digest::tests::native_root_digest_keeps_original_traversal_cancellation_and_collision_order",
    "account_archive_prototype::native_root_digest::tests::native_root_digest_keeps_fork_shape_and_all_lift_input_relations",
])
exact("node", "growth-return-observations", [
    "store::growth::tests::scale_observation::native_growth_scale_retains_rejected_and_cancelled_admission_returns",
    "store::growth::tests::scale_observation::native_growth_scale_retains_admission_when_activation_returns_error",
])
exact("m06", "canonical-ascii", [
    "pon_executor::root_arithmetic_tests::canonical_ascii_guard_matches_exhaustive_bytes_pairs_and_borrow_chains",
    "pon_executor::root_arithmetic_tests::canonical_ascii_keeps_original_serde_bytes_and_vec_capacities",
    "pon_executor::root_arithmetic_tests::canonical_ascii_into_keeps_reused_capacity_and_failed_input_untouched",
    "pon_executor::root_arithmetic_tests::canonical_ascii_commitment_keeps_late_grammar_before_wire_and_cache_errors",
    "pon_executor::root_arithmetic_tests::arithmetic_root_ascii_encoding_matches_independent_serde_reference",
    "pon_executor::root_arithmetic_tests::arithmetic_root_preserves_complete_grammar_before_all_wire_limits",
    "pon_commitment::bounded_encoding_tests::canonical_ascii_fast_encoding_keeps_direct_serde_budget_decisions_and_charges",
])
prefix("node", "reorg-tail", "store::reorg_readback_tests::", 6)
exact("node", "direct-append-readback", [
    "store::append_readback_tests::direct_append_keeps_complete_rows_events_state_and_cold_reopen",
    "store::append_readback_tests::direct_append_cancellation_at_each_callback_leaves_no_partial_publication",
])
exact("node", "current-sql-root", [
    "store::detached_admission::tests::large_parent_root_arithmetic_keeps_current_sql_and_original_read_checkpoints",
])
exact("node", "prepared-current-history", [
    "store::historical_commitment_tests::legacy_prepared_history_reads_observe_current_rows_writes_and_rollback",
    "store::historical_commitment_tests::legacy_prepared_history_reads_reprepare_after_schema_and_authorizer_changes",
    "store::historical_commitment_tests::actual_foreign_snapshot_delta_and_root_damage_preserve_original_failures",
])
prefix("node", "postwrite-readback", "store::native_authenticated::post_write_readback::tests::", 23)
assert len({(crate, test) for crate, group, test in selected}) == len(selected)
(root / "selected-tests.tsv").write_text("".join(f"{crate}\t{group}\t{test}\n" for crate, group, test in selected))
print(json.dumps({"result": "PASS", "scope": "exact libtest registry selection only; no execution verdict and not the complete runtime suite",
                  "registry_counts": {crate: len(names) for crate, names in registries.items()},
                  "selected_count": len(selected), "groups": groups}, indent=2))

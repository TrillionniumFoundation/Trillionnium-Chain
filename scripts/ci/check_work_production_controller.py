"""Run exactly the non-provisioning production Work controller unit controls."""

import argparse
import json
from pathlib import Path
import unittest


# Preserve the original 22 IDs (621393a091d), adding exactly the two ESRCH
# observation controls (38783ebe9e5). Do not derive the admitted roster from
# the checkout's discovery result or let a changed test replace a known one.
_ORIGINAL = (
    "test_01_service_names_are_exact_owned_names",
    "test_02_service_profile_never_changes_the_fixed_budget",
    "test_03_public_entry_rejects_local_and_optimized_before_any_output",
    "test_04_source_and_build_shapes_reject_before_execution",
    "test_05_prior_lease_must_be_exact_same_root_seal",
    "test_06_previous_and_final_leases_cannot_diverge",
    "test_07_synthetic_full_frame_accepts_only_as_validation_fixture",
    "test_08_actual_lifetime_and_fresh_boundaries_cannot_be_removed",
    "test_09_budget_parent_and_whole_product_are_not_metadata_only",
    "test_10_challenge_task_ticket_and_every_progress_point_are_bound",
    "test_11_observations_must_name_exact_live_roster",
    "test_12_namespace_and_actual_executable_are_bound_per_thread",
    "test_13_resource_samples_and_clone_baseline_are_complete",
    "test_14_resource_delta_preserves_all_four_checked_fields",
    "test_15_inside_failure_still_collects_both_final_fences",
    "test_16_prior_success_refusal_precedes_any_service_command",
    "test_17_complete_boot_extent_is_mandatory",
    "test_18_complete_capture_reader_accepts_only_as_synthetic_control",
    "test_19_raw_cannot_be_omitted_or_coherently_replaced",
    "test_20_scope_and_exact_observation_types_are_not_promoted",
    "test_21_cache_and_actual_task_roster_are_reread",
    "test_22_capture_aliases_and_duplicate_fields_are_refused",
)
_ESRCH = (
    "test_23_disappearing_worker_never_supplies_missing_proof",
    "test_24_observer_service_and_attribution_failures_remain_fatal",
)
_OWNER = "hia.platform.work_owner.test_production.ProductionControls."
REQUIRED = tuple(_OWNER + name for name in (*_ORIGINAL, *_ESRCH))
SCHEMA = "trnm.production-work-controller-ci.v1"
KEYS = frozenset(("schema", "status", "required", "started", "executed", "skipped",
                  "failures", "errors", "actual_production_positive"))


def suite_ids(node):
    if isinstance(node, unittest.TestSuite):
        return [name for child in node for name in suite_ids(child)]
    return [node.id()]


def require_roster(discovered):
    if (type(discovered) is not list or discovered != list(REQUIRED)
            or len(REQUIRED) != 24 or len(set(REQUIRED)) != 24):
        raise ValueError("Complete production controller discovery is required")


def run_controls(suite):
    require_roster(suite_ids(suite))
    started = []

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)

    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    report = {"schema": SCHEMA, "status": "FAIL", "required": list(REQUIRED),
              "started": started, "executed": result.testsRun, "skipped": len(result.skipped),
              "failures": len(result.failures), "errors": len(result.errors),
              "actual_production_positive": False}
    if (result.wasSuccessful() and not result.expectedFailures and not result.unexpectedSuccesses
            and report_is_exact_pass({**report, "status": "PASS"})):
        report["status"] = "PASS"
    return report


def report_is_exact_pass(report):
    if type(report) is not dict or set(report) != KEYS:
        return False
    fixed = list(REQUIRED)
    return (report["schema"] == SCHEMA and report["status"] == "PASS"
            and type(report["required"]) is list and report["required"] == fixed
            and type(report["started"]) is list and report["started"] == fixed
            and report["actual_production_positive"] is False
            and all(type(report[name]) is int and report[name] == wanted
                    for name, wanted in (("executed", len(REQUIRED)), ("skipped", 0),
                                         ("failures", 0), ("errors", 0))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not __debug__:
        raise SystemExit("Optimized Python is not admitted")
    from hia.platform.work_owner import test_production
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_production)
    try:
        report = run_controls(suite)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    if not report_is_exact_pass(report):
        raise SystemExit("A production controller group failed or was omitted")


if __name__ == "__main__":
    main()

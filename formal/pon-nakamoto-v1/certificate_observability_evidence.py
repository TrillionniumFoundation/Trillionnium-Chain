"""Bind exact observability/countermodel results to an actual native export.

This reader requires a complete native-run input and every referenced packet.
It never synthesizes, builds, invokes, or silently substitutes a native run.
Exported arithmetic is checked; process authenticity and world coverage are
not inferred from JSON, source hashes, local clocks, or equal commitments.
"""
from __future__ import annotations

import argparse
from fractions import Fraction as F
import hashlib
import json
from pathlib import Path

import certificate_observability_models as model
from mandatory_units_query import QueryBudget
import native_owner_score_bridge as bridge


SCHEMA = "pon-certificate-observability-evidence-v1"
SOURCE_PATHS = (
    "formal/pon-nakamoto-v1/certificate_observability_models.py",
    "formal/pon-nakamoto-v1/certificate_observability_tests.py",
    "formal/pon-nakamoto-v1/certificate_observability_evidence.py",
    "formal/pon-nakamoto-v1/CERTIFICATE_OBSERVABILITY_V1.md",
    "formal/pon-nakamoto-v1/mandatory_units_query.py",
    "formal/pon-nakamoto-v1/native_owner_score_bridge.py",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_owner_observation.rs",
    "trillionnium/crates/trnm-pon-node/examples/support/native_owner_scenario.rs",
)


def native_counterpair_binding(document: dict) -> dict:
    """Additional experiment predicates AFTER bridge.check_run has succeeded."""
    refs = document.get("references")
    model.require(type(refs) is dict, "NATIVE_SCENARIO_REFERENCES")
    snapshots = {row["name"]: row for row in document["snapshots"]}
    before_name, after_name = refs.get("hidden_before_snapshot"), refs.get("hidden_after_snapshot")
    model.require(before_name in snapshots and after_name in snapshots, "HIDDEN_VIEW_REFERENCES")
    before, after = snapshots[before_name], snapshots[after_name]
    b, a = bridge.check_census(before["census"]), bridge.check_census(after["census"])
    model.require(before["node"] == after["node"], "HIDDEN_VIEW_OWNER")
    model.require(b.raw["local_view_commitment"] == a.raw["local_view_commitment"]
                  and b.rows == a.rows and b.raw["active_tip"] == a.raw["active_tip"],
                  "HIDDEN_VIEW_CHANGED")
    model.require(b.raw["owner_attempt"] < a.raw["owner_attempt"]
                  and b.raw["ended_ns"] <= a.raw["started_ns"], "HIDDEN_ATTEMPT_ORDER")
    target, hidden = refs.get("target_block"), refs.get("hidden_competing_tip")
    model.require(target in b.paths[b.raw["active_tip"]] and hidden not in b.rows,
                  "HIDDEN_BRANCH_NOT_HIDDEN")
    other = [row for row in document["snapshots"] if row["node"] != before["node"]
             and row["census"]["active_tip"] == hidden]
    model.require(len(other) == 1, "HIDDEN_OWNER_WITNESS")
    h = bridge.check_census(other[0]["census"])
    model.require(target not in h.paths[hidden] and hidden in h.eligible,
                  "HIDDEN_BRANCH_NOT_COMPETING")
    private_rows = tuple(block for block in h.paths[hidden] if block != h.raw["genesis"])
    model.require(all(block not in b.rows for block in private_rows), "HIDDEN_ANCESTOR_ALREADY_VISIBLE")
    model.require(h.scores[hidden] > b.scores[b.raw["active_tip"]], "HIDDEN_SCORE_NOT_STRICTLY_GREATER")
    confirmations = document["confirmations"]
    initial_index, post_index = refs.get("initial_confirmation_index"), refs.get("post_reorg_confirmation_index")
    for index in (initial_index, post_index):
        model.require(type(index) is int and 0 <= index < len(confirmations), "CONFIRMATION_REFERENCE")
    initial, post = confirmations[initial_index], confirmations[post_index]
    model.require(initial["confirmed"] is True and initial["reorged"] is False
                  and initial["included_block"] == target and initial["observed_tip"] == b.raw["active_tip"],
                  "INITIAL_CONFIRMATION_MISSING")
    model.require(post["confirmed"] is False and post["reorged"] is True
                  and post["included_block"] == target and post["observed_tip"] == hidden,
                  "ACTUAL_REORG_MISSING")
    after_reorg = [row for row in document["snapshots"] if row["node"] == before["node"]
                   and row["census"]["active_tip"] == hidden
                   and row["census"]["observed_now"] == post["observed_now"]
                   and row["census"]["active_generation"] == post["active_generation"]]
    model.require(len(after_reorg) == 1, "REORG_LOCAL_CENSUS")
    r = bridge.check_census(after_reorg[0]["census"])
    return {
        "before_snapshot": before_name, "after_snapshot": after_name,
        "hidden_owner_snapshot": other[0]["name"], "post_reorg_snapshot": after_reorg[0]["name"],
        "same_local_view_projection_commitment": b.raw["local_view_commitment"],
        "equal_retained_rows_checked": True,
        "before_owner_attempt": b.raw["owner_attempt"], "after_owner_attempt": a.raw["owner_attempt"],
        "before_process_interval_ns": [b.raw["started_ns"], b.raw["ended_ns"]],
        "after_process_interval_ns": [a.raw["started_ns"], a.raw["ended_ns"]],
        "entire_os_timing_observation_identical": False,
        "theorem_same_public_schedule_coupling_established_by_this_run": False,
        "target_block": target, "initial_confirmed_depth": initial["depth"],
        "initial_native_required_work_delta": bridge.work(initial["work_delta"]),
        "initial_selected_score": b.scores[b.raw["active_tip"]],
        "unseen_competing_score": h.scores[hidden],
        "unseen_competing_non_genesis_rows": len(private_rows),
        "strict_score_inequality_checked": True,
        "post_reorg_selected_score": r.scores[hidden],
        "post_reorg_eligible_max_score": bridge.work(r.raw["eligible_max_score_hex"]),
        "post_reorg_selection_deficit": bridge.work(r.raw["raw_selection_deficit_hex"]),
        "native_confirmation_then_reorg_predicates_in_export_checked": True,
        "probability_of_this_native_failure_estimated": False,
        "global_hidden_inventory_upper_bound": None,
        "physical_first_ready_times_authenticated": False,
    }


def exact_model_evidence() -> dict:
    ledger = model.UniqueReadyLedger(tuple(model.ReadyDelivery(str(i), i, 128) for i in range(1, 33)))
    windows = tuple(model.Window(str(i), 0, 32, F(4096)) for i in range(32))
    packing = model.check_window_witness(ledger, windows, (F(1, 32),) * 32, F(4096))
    law = model.ProbabilityTree((
        model.Leaf("left_bad", ("left", "bad"), F(1, 100)),
        model.Leaf("left_safe", ("left", "safe"), F(49, 100)),
        model.Leaf("right_bad", ("right", "bad"), F(1, 200)),
        model.Leaf("right_safe", ("right", "safe"), F(99, 200)),
    ))
    attempts = (
        model.Attempt("root", (), ("left_bad", "right_bad"), F(3, 200)),
        model.Attempt("after_left", ("left",), ("left_bad",), F(1, 50)),
        model.Attempt("after_right", ("right",), ("right_bad",), F(1, 100)),
    )
    return {
        "all_results_are_declared_exact_models": True,
        "overlapping_window_witness": packing,
        "one_global_mu1_tail_for_any_checked_witness": model.global_mu1_event_bound(
            QueryBudget(1, 32, True, True), F(4096)),
        "predictable_risk_bank": model.check_predictable_risk_bank(law, attempts, F(7, 200)),
        "postselected_restart_counterexample": model.first_success_restart_counterexample(),
        "finite_full_table_advice_counterexample": model.full_table_advice_countermodel(),
        "two_world_impossibility_model": model.synthetic_counterpair(),
        "model_values_are_actual_native_risk": False,
    }


def build_evidence(native_path: Path) -> dict:
    native_path = native_path.resolve(strict=True)
    before = hashlib.sha256(native_path.read_bytes()).hexdigest()
    document = bridge.read_run(native_path)
    checked = bridge.check_run(document, native_path.parent)
    binding = native_counterpair_binding(document)
    model.require(hashlib.sha256(native_path.read_bytes()).hexdigest() == before, "NATIVE_INPUT_CHANGED")
    root = Path(__file__).resolve().parents[2]
    manifest = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_PATHS}
    return {
        "schema": SCHEMA, "starting_source_commit": model.BASE_COMMIT,
        "base_commit_contains_new_files_claimed": False,
        "exact_source_manifest_sha256": manifest,
        "native_input_path": str(native_path), "native_input_sha256": before,
        "native_packet_artifacts_checked": True, "native_score_bridge": checked,
        "actual_native_counterpair_binding": binding,
        "exact_models": exact_model_evidence(),
        "claim_boundary": {
            "local_current_admitted_view_predicates_checked": True,
            "all_ever_admitted_history_complete": False,
            "unadmitted_or_remote_inventory_complete": False,
            "native_executable_or_os_attested": False,
            "global_resource_coverage_attested": False,
            "actual_joint_initial_state_attested": False,
            "actual_conditional_restart_law_attested": False,
            "mu1_credit_equals_native_required_work": False,
            "physical_resource_tail_proved": False,
            "native_six_successor_failure_probability": None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-owner-json", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = build_evidence(args.native_owner_json)
    with args.out.open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(model.public_json(result), indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"schema": SCHEMA, "status": "checked", "output": str(args.out),
                      "native_input_sha256": result["native_input_sha256"],
                      "physical_resource_tail_proved": False,
                      "native_six_successor_failure_probability": None}, sort_keys=True))


if __name__ == "__main__":
    main()

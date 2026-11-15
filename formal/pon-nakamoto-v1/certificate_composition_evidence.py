"""Required raw-journal / real-signature composition evidence, with no fallback.

The native input must be the complete durable-owner scenario's run.json and
packet directories. This program never manufactures a substitute native run.
It creates real ML-DSA signatures over those exact retained bytes, then checks
which claims survive composition. A separate false producer statement uses an
old, fully valid W1 proof and deliberately makes no native producer call.
"""
from __future__ import annotations

import argparse
from fractions import Fraction as F
import json
from pathlib import Path
import sys
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

import certificate_composition as cc
import certificate_observability_models as co
import lifecycle_query_bound as lqc
from native_execution_certificate import CertificateError, strict_json
from native_owner_journal import MAX_BYTES, read_journal
import work_lifecycle_certificate as wlc
from work_lifecycle_help import HelpPolicy


REPO = Path(__file__).resolve().parents[2]
P = F(1, 16)
SOURCES = (
    "formal/pon-nakamoto-v1/certificate_composition.py",
    "formal/pon-nakamoto-v1/certificate_composition_tests.py",
    "formal/pon-nakamoto-v1/certificate_composition_evidence.py",
    "formal/pon-nakamoto-v1/CERTIFICATE_COMPOSITION_V1.md",
    "formal/pon-nakamoto-v1/lifecycle_query_bound.py",
    "formal/pon-nakamoto-v1/lifecycle_query_runtime.py",
    "formal/pon-nakamoto-v1/lifecycle_query_charging_v1.md",
    "formal/pon-nakamoto-v1/native_owner_journal.py",
    "formal/pon-nakamoto-v1/native_owner_score_bridge.py",
    "formal/pon-nakamoto-v1/certificate_observability_models.py",
    "formal/pon-nakamoto-v1/work_lifecycle_certificate.py",
    "formal/pon-nakamoto-v1/work_lifecycle_help.py",
    "formal/pon-nakamoto-v1/mandatory_units_relation.py",
    "formal/pon-nakamoto-v1/mandatory_units_query.py",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "trillionnium/crates/trnm-pon-node/src/native_owner_journal.rs",
    "trillionnium/crates/trnm-pon-node/examples/native_owner_journal_v1.rs",
    "trillionnium/crates/trnm-pon-node/examples/support/native_journal_scenario.rs",
)


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(cc.public_json(value), output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")


def source_manifest() -> dict[str, str]:
    return {name: cc.digest((REPO / name).read_bytes()) for name in SOURCES}


def refusal(call, expected: str) -> dict:
    try:
        call()
    except (cc.CompositionError, co.ObservabilityError, wlc.LifecycleError, CertificateError) as error:
        cc.need(expected in str(error), "WRONG_REFUSAL:" + str(error))
        return {"rejected": True, "error_type": type(error).__name__, "error": str(error)}
    raise cc.CompositionError("REQUIRED_NEGATIVE_CONTROL_ACCEPTED:" + expected)


def model_evidence() -> dict:
    law = co.ProbabilityTree((
        co.Leaf("hit_hit", ("hit", "hit"), P ** 2),
        co.Leaf("hit_miss", ("hit", "miss"), P * (1 - P)),
        co.Leaf("miss_hit", ("miss", "hit"), (1 - P) * P),
        co.Leaf("miss_miss", ("miss", "miss"), (1 - P) ** 2),
    ))
    global_report = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(1, 0, 1), 128)
    prefix_report = lqc.continuation_given_complete_prefix(
        distinct_seen=1, marked_seen=1, post_queries=0, output_slots=1, credit=128)
    cc.need(global_report["bound"] == F(31, 256) and prefix_report["bound"] == 1,
            "PREFIX_COUNTEREXAMPLE_CHANGED")
    root = cc.ModelRiskUse("whole_lifetime", (), ("hit_hit", "hit_miss", "miss_hit"), global_report)
    reused = cc.ModelRiskUse("selected_paid_hit", ("hit",), ("hit_hit", "hit_miss"), global_report)
    correct = cc.ModelRiskUse("selected_paid_hit", ("hit",), ("hit_hit", "hit_miss"), prefix_report)
    fresh = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(0, 0, 1), 128)
    attempts = (cc.ModelRiskUse("one", (), ("hit_hit", "hit_miss"), fresh),
                cc.ModelRiskUse("two", (), ("hit_hit", "miss_hit"), fresh))
    return {"schema": "pon-composition-exact-model-counterexamples-v1",
        "paid_prefix": {"global_report": global_report, "observed_hit_report": prefix_report,
            "global_bank": cc.check_model_risk_bank(law, (root,), F(31, 256)),
            "conditional_bank": cc.check_model_risk_bank(law, (correct,), F(1)),
            "illegal_global_reuse": refusal(lambda: cc.check_model_risk_bank(law, (reused,), F(31, 256)),
                                            "GLOBAL_BOUND_IS_NOT_CONDITIONAL")},
        "repeated_allowance": {
            "single_budget_reuse": refusal(lambda: cc.check_model_risk_bank(law, attempts, P),
                                            "PREDICTABLE_RISK_BUDGET_OVERSPENT"),
            "proper_shared_budget": cc.check_model_risk_bank(law, attempts, 2 * P)},
        "post_coherent_classical_reveal": cc.post_quantum_classical_reveal_counterexample(),
        "omitted_empty_payload_timing": cc.empty_payload_timing_counterexample(),
        "actual_network_or_quantum_experiment": False,
        "native_six_successor_probability": None}


def save_signed(directory: Path, control: dict) -> None:
    directory.mkdir()
    artifact_directory = directory / "artifacts"
    artifact_directory.mkdir()
    write_json(directory / "signed_observations.json", control["documents"])
    write_json(directory / "public_expected_pins.json",
               {name: wlc.pin_wire(pin) for name, pin in control["pins"].items()})
    for sha, raw in control["artifacts"].items():
        cc.need(cc.digest(raw) == sha, "SIGNED_ARTIFACT_HASH")
        with (artifact_directory / (sha + ".bin")).open("xb") as output:
            output.write(raw)


def signed_packets(packets: dict[str, bytes], manifest: dict[str, str]) -> dict:
    """Attest possession/publication only, never claim a PNP1/MU1 equivalence."""
    key = MLDSA65PrivateKey.generate()
    writer = wlc.ObservationWriter(key,
        session=cc.digest(b"CC1 exact packet publication " + wlc.public_spki(key)),
        source_commit=cc.BASE_COMMIT, source_manifest=manifest, help_policy=HelpPolicy(()))
    exports = {}
    for digest, raw in packets.items():
        cc.need(cc.digest(raw) == digest, "PACKET_PUBLICATION_HASH")
        exports[digest] = writer.append("publish_artifact", {
            "artifact_sha256": digest, "artifact_bytes": len(raw), "role": "classical_help"})
    document, pin = writer.close()
    return {"documents": {"packet-holder": document}, "pins": {"packet-holder": pin},
            "artifacts": packets, "root": "packet-holder", "publish_events": exports}


def confined_directory(base: Path, relative: str) -> Path:
    cc.need(type(relative) is str and relative and not Path(relative).is_absolute()
            and all(part not in (".", "..") for part in Path(relative).parts), "NATIVE_JOURNAL_RELATIVE_PATH")
    path = base / relative
    cc.need(not path.is_symlink(), "NATIVE_JOURNAL_SYMLINK")
    resolved = path.resolve(strict=True)
    cc.need(resolved.parent == base, "NATIVE_JOURNAL_PATH_ESCAPE")
    return resolved


def run(native_run: Path, retained_wlc: Path, output: Path, state: dict) -> dict:
    before_sources = source_manifest()
    write_json(output / "source_manifest_before.json", before_sources)
    cc.need(native_run.is_file() and not native_run.is_symlink()
            and native_run.stat().st_size <= 64 * 1024 * 1024, "RAW_NATIVE_RUN_REQUIRED")
    native_run = native_run.resolve(strict=True)
    raw_run = cc.raw_file(native_run, 64 * 1024 * 1024, "RAW_NATIVE_RUN_REQUIRED")
    report = strict_json(raw_run.decode("utf-8"))
    cc.need(report.get("schema") == "pon-native-owner-journal-run-v1", "NATIVE_RUN_NAMESPACE")
    cc.need(report.get("native_execution_exercised") is True
            and report.get("starting_source_commit") == cc.BASE_COMMIT, "NATIVE_SCENARIO_SOURCE")
    entries = report.get("journals")
    cc.need(type(entries) is list and 6 <= len(entries) <= 16, "COMPLETE_NATIVE_SCENARIO_REQUIRED")
    directories, summaries, journal_hashes = {}, {}, {}
    for entry in entries:
        cc.need(type(entry) is dict and set(entry) == {"name", "path", "checkpoint"}, "JOURNAL_MANIFEST_FIELDS")
        name = entry["name"]
        cc.need(type(name) is str and name not in directories, "JOURNAL_MANIFEST_IDENTITY")
        path = confined_directory(native_run.parent, entry["path"])
        directories[name] = path
        journal_hashes[name] = cc.digest(cc.raw_file(path / "journal.pnoj1", MAX_BYTES, "RAW_NATIVE_JOURNAL_REQUIRED"))
        summaries[name] = read_journal(path, expected_checkpoint=entry["checkpoint"])
    cc.need({"alice", "bob", "crash_recovered", "old_snapshot", "restored_without_pin", "orphan_recovered"}
            <= set(directories),
            "COMPLETE_NATIVE_SCENARIO_NAMES")
    state["raw_journals_checked"] = len(summaries)
    write_json(output / "native_reader_results.json", summaries)

    alice, recovered = summaries["alice"], summaries["crash_recovered"]
    invalid = report["invalid_same_id_packet"]
    valid_sha, invalid_sha, block = (cc.hex32(invalid[name]) for name in
                                   ("valid_packet_sha256", "sha256", "id"))
    cc.need(valid_sha != invalid_sha and valid_sha in alice["valid_packet_bindings"]
            and invalid_sha in alice["raw_artifacts"] and invalid_sha not in alice["valid_packet_bindings"],
            "ACTUAL_SAME_ID_VALID_INVALID_CONTROL_REQUIRED")
    cc.need(alice["valid_packet_bindings"][valid_sha]["block_id"] == block
            == alice["raw_artifacts"][invalid_sha]["block_id"], "SAME_BLOCK_ID_REQUIRED")
    packet_bytes = {sha: (directories["alice"] / "packets" / (sha + ".pnp1")).read_bytes()
                    for sha in (valid_sha, invalid_sha)}
    signed = signed_packets(packet_bytes, {
        "certificate_composition.py": before_sources[SOURCES[0]],
        "native_owner_journal.py": before_sources["formal/pon-nakamoto-v1/native_owner_journal.py"],
        "journal.pnoj1": journal_hashes["alice"]})
    save_signed(output / "native_packet_publications", signed)
    common = {"journal_directory": directories["alice"], "expected_checkpoint": alice["checkpoint"],
              "documents": signed["documents"], "pins": signed["pins"], "artifacts": signed["artifacts"],
              "signed_root": signed["root"]}
    valid_link = cc.PacketJoin(signed["root"], signed["publish_events"][valid_sha], valid_sha, block)
    invalid_link = cc.PacketJoin(signed["root"], signed["publish_events"][invalid_sha], invalid_sha, block)
    joined = cc.join_local_evidence(**common, links=(valid_link, valid_link))
    cc.need(joined["distinct_native_packet_ids"] == 1
            and joined["repeated_publications_add_no_distinct_native_work"] == 1,
            "DUPLICATE_PUBLICATION_DOUBLE_COUNTED")
    rejected_invalid = refusal(lambda: cc.join_local_evidence(**common, links=(invalid_link,)),
                               "EXACT_SIGNED_PACKET_NOT_NATIVE_VALIDATED")
    write_json(output / "exact_packet_join.json", joined)
    state["exact_native_packet_join_checked"] = True

    a8 = cc.hex32(report["references"]["a8_before_restart"])
    first_seen = alice["registry"][a8]
    cc.need(first_seen["origin_class"] == "recorded_local_production"
            and first_seen["first_seen_epoch"] == 1
            and first_seen["native_relation_rechecked_by_census"] is True,
            "RESTART_RELABELED_OR_LOST_OLD_OUTPUT")
    cc.need(alice["rollback_witnesses"] and alice["outside_lease_intervals"] and alice["clock_regressions"],
            "NATIVE_REORG_RESTART_CLOCK_CONTROLS_MISSING")
    cc.need(any(item["operation"] == "activate_observed" and item["prepared"] is True
                for item in recovered["unresolved_intents"])
            and recovered["outside_lease_intervals"]
            and recovered["last_census"]["active_tip"] == report["references"]["b8"],
            "ACTUAL_COMMITTED_ACTIVATION_GAP_NOT_RETAINED")
    cc.need(any(item["eligible_local_deficit_witness"] is not None
                for item in recovered["confirmation_failures"]), "RECOVERY_FAILURE_NOT_REMAPPED")
    rejected_old = refusal(lambda: read_journal(directories["old_snapshot"],
                                                expected_checkpoint=recovered["checkpoint"]),
                           "J_CHECKPOINT_MISMATCH")
    old_unpinned = read_journal(directories["old_snapshot"])
    cc.need(old_unpinned["trusted_history_anchor"] is False
            and old_unpinned["fresh_resource_state_attested"] is False, "OLD_PREFIX_PROMOTED_TO_FRESH")
    orphan = summaries["orphan_recovered"]
    cc.need(any(item["operation"] == "make" and item["prepared"] is True
                for item in orphan["unresolved_intents"])
            and len(orphan["orphan_artifact_observations"]) == 1
            and len(orphan["valid_packet_bindings"]) == 1, "ACTUAL_ORPHAN_RECOVERY_CONTROL_REQUIRED")
    orphan_binding = next(iter(orphan["valid_packet_bindings"].values()))
    orphan_origin = orphan["registry"][orphan_binding["block_id"]]
    cc.need(orphan_origin["origin_class"] == "gap_or_recovery_discovery"
            and orphan_origin["native_relation_rechecked_by_census"] is True
            and report["orphan_production_terminal_refusal"] == "OWNER_JOURNAL_RECORD_BUDGET",
            "ORPHAN_ADMISSION_ERASED_INCOMPLETE_PRODUCTION")
    native_controls = {"invalid_same_id_signed_publication": rejected_invalid,
        "duplicate_valid_publication_count": joined["distinct_native_packet_ids"],
        "old_produced_output_after_restart": first_seen,
        "actual_strict_rollback_witnesses": alice["rollback_witnesses"],
        "after_native_commit_crash_unresolved_intents": recovered["unresolved_intents"],
        "first_observed_confirmation_failures": recovered["confirmation_failures"],
        "old_snapshot_with_new_external_expectation": rejected_old,
        "old_snapshot_without_expectation_is_parseable": True,
        "old_snapshot_without_expectation_is_fresh": False,
        "orphan_recovery_observations": orphan["orphan_artifact_observations"],
        "orphan_validated_later_keeps_unknown_production_origin": orphan_origin,
        "orphan_original_production_remains_unresolved": orphan["unresolved_intents"],
        "checkpoint_from_report_is_independently_trusted": False,
        "native_risk_promotion": refusal(lambda: cc.native_risk_from_join(joined),
                                         "NATIVE_RELATION_RESOURCE_STATE_AND_WORLD_BRIDGES_UNPROVED")}
    write_json(output / "native_composition_negative_controls.json", native_controls)

    verify_input, program_sha = cc.retained_unit_verify_input(retained_wlc)
    with patch("subprocess.Popen", side_effect=AssertionError("native producer must not run in attribution counterexample")):
        false_producer = cc.signed_valid_proof_without_producer(verify_input, program_sha)
        verified_false = wlc.verify_collection(false_producer["documents"], false_producer["pins"],
                                               false_producer["artifacts"], false_producer["root"])
    save_signed(output / "signed_false_producer_statement", false_producer)
    counters = verified_false["root"]["counters"]
    cc.need(counters["reported_native_calls"] == 1
            and counters["full_W1_artifact_predicates_rechecked"] == 1
            and verified_false["root"]["recorder_execution_attested"] is False,
            "FALSE_PRODUCER_CONTROL_NOT_REPRODUCED")
    attribution = {"signed_statement_verified": verified_false,
        "native_producer_invocations_while_constructing_and_verifying_statement": 0,
        "full_W1_predicate_recomputed_by_verifier": True,
        "signer_owned_old_valid_bytes_before_statement": True,
        "signed_statement_claimed_new_producer_call_is_false_by_construction": True,
        "signer_execution_attribution_proved": False,
        "query_budget_promotion": refusal(lambda: wlc.query_budget_from_observation(verified_false),
                                          "LIFECYCLE_COVERAGE_AND_INITIAL_STATE_UNATTESTED")}
    write_json(output / "producer_attribution_counterexample.json", attribution)
    state["real_signature_and_full_W1_attribution_counterexample_checked"] = True
    write_json(output / "exact_model_counterexamples.json", model_evidence())

    cc.need(source_manifest() == before_sources, "SOURCE_CHANGED_DURING_COMPOSITION")
    cc.need(cc.digest(cc.raw_file(native_run, 64 * 1024 * 1024, "RAW_NATIVE_RUN_REQUIRED")) == cc.digest(raw_run)
            and all(cc.digest(cc.raw_file(path / "journal.pnoj1", MAX_BYTES, "RAW_NATIVE_JOURNAL_REQUIRED")) == journal_hashes[name]
                    for name, path in directories.items()), "RAW_INPUT_CHANGED_DURING_COMPOSITION")
    result = {"schema": "pon-certificate-composition-evidence-v1", "status": "PASS",
        "source_base_commit": cc.BASE_COMMIT,
        "source_base_is_previous_commit_not_new_file_authentication": True,
        "source_manifest": before_sources, "source_and_input_samples_stable": True,
        "hash_sampling_is_execution_attestation": False,
        "native_run_path": str(native_run), "native_run_sha256": cc.digest(raw_run),
        "native_journal_sha256": journal_hashes,
        "native_raw_journals_checked": len(summaries),
        "native_journal_records_checked": sum(item["records_checked"] for item in summaries.values()),
        "native_raw_packet_artifacts_checked_across_journals": sum(item["artifacts_checked"] for item in summaries.values()),
        "actual_MLDSA65_signatures_verified": True,
        "native_producer_invoked_by_composition_program": False,
        "native_scenario_execution_independently_attested": False,
        "initial_joint_state_authenticated": False,
        "hidden_inventory_output_extraction_and_cap_attested": False,
        "all_world_queries_or_visible_help_covered": False,
        "authenticated_global_clock": False,
        "native_to_MU1_weight_event_bridge": False,
        "physical_resource_to_effective_weight_tail": False,
        "native_six_successor_failure_probability": None,
        "production_qualified": False}
    write_json(output / "summary.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-run", type=Path, required=True)
    parser.add_argument("--retained-wlc", type=Path,
        default=REPO / "evidence/pon-actual-certificates-20261107/work_lifecycle/run-02-final")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    state = {"schema": "pon-certificate-composition-attempt-v1", "argv": sys.argv,
             "raw_journals_checked": 0, "exact_native_packet_join_checked": False,
             "real_signature_and_full_W1_attribution_counterexample_checked": False,
             "production_qualified": False}
    try:
        result = run(args.native_run, args.retained_wlc, args.output_dir, state)
    except Exception as error:
        state.update(status="FAILED", error_type=type(error).__name__, error=str(error))
        write_json(args.output_dir / "attempt.json", state)
        print(json.dumps(state, sort_keys=True), file=sys.stderr)
        raise
    else:
        state["status"] = "PASS"
        write_json(args.output_dir / "attempt.json", state)
        print(json.dumps({key: result[key] for key in
            ("schema", "status", "native_raw_journals_checked", "native_journal_records_checked",
             "native_scenario_execution_independently_attested", "production_qualified")}, sort_keys=True))


if __name__ == "__main__":
    main()

"""Independently check actual local owner exports and their score witnesses.

The native emitter replays W1, application state and the complete admitted DB
snapshot. This reader checks exported arithmetic, identities and time predicates;
it cannot prove that an arbitrary JSON file was emitted by that process, nor
that an admitted local view covers world-ready work. No risk bound is inferred.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from bounded_process import ProcessFailure, run_bounded
from native_execution_certificate import CertificateError, require, strict_json, view_deficits


SCHEMA = "pon-native-owner-score-bridge-v1"
WORK_MAX = (1 << 512) - 1
ROW_FIELDS = (
    "id", "parent", "height", "chainwork_hex", "required_work_hex", "target",
    "timestamp", "packet_sha256", "proof_sha256", "packet_bytes",
    "ancestry_time_eligible", "active_chain_member", "full_native_work_replayed",
    "full_native_application_replayed", "retained_state_and_deltas_equal",
)
CENSUS_FIELDS = set((
    "schema packet_profile state_backend task_profile network parameters genesis "
    "owner_process_id owner_observation_instance owner_attempt owner_identity_scope "
    "directory_device directory_inode database_device database_inode lock_device lock_inode "
    "started_ns ended_ns clock_scope observed_now observed_now_source future_skew_seconds "
    "confirmation_depth confirmation_work_multiplier "
    "active_tip active_generation state_slot active_score_hex active_time_eligible "
    "eligible_max_score_hex eligible_max_ids raw_selection_deficit_hex rows total_packet_bytes "
    "local_view_commitment complete_for_all_admitted_rows_in_snapshot "
    "local_candidate_relation_rechecked exact_source_schema_rechecked snapshot_released_without_commit owner_caches_may_refresh "
    "unadmitted_local_packets_covered remote_private_branches_covered global_ready_attested "
    "world_coverage_attested physical_clock_authenticated exported_artifact_authenticated "
    "probabilistic_environment_bound six_successor_risk_qualified execution_authority excluded_scope"
).split())
FALSE_FLAGS = (
    "unadmitted_local_packets_covered", "remote_private_branches_covered",
    "global_ready_attested", "world_coverage_attested", "physical_clock_authenticated",
    "exported_artifact_authenticated", "probabilistic_environment_bound",
    "six_successor_risk_qualified", "execution_authority",
)
OBSERVATION_FIELDS = set((
    "transaction genesis policy required_work_delta network parameters included_block "
    "observed_tip included_height observed_height depth work_delta active_generation "
    "observed_now confirmed reorged finalized execution_authority"
).split())


def uint(value, code, maximum=(1 << 64) - 1):
    require(type(value) is int and 0 <= value <= maximum, code)
    return value


def hx(value, size, code):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(2 * size) + "}", value) is not None, code)
    return value


def work(value, code="WORK_ENCODING"):
    return int(hx(value, 64, code), 16)


def fields(value, expected, code):
    require(type(value) is dict and set(value) == set(expected), code)


def wire_hash(tag: bytes, data: bytes) -> str:
    return hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag
                          + len(data).to_bytes(4, "little") + data).hexdigest()


def local_commitment(census):
    # Match the Rust tuple and struct serialization, not input JSON key order.
    rows = [{key: row[key] for key in ROW_FIELDS} for row in census["rows"]]
    data = [list(bytes.fromhex(census[key])) for key in ("network", "parameters", "genesis")]
    data += [list(bytes.fromhex(census["active_tip"])), census["active_generation"],
             census["state_slot"], census["observed_now"], rows]
    encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return wire_hash(b"pon-native-local-owner-view-v1", encoded)


@dataclass
class CheckedCensus:
    raw: dict
    rows: dict
    paths: dict
    scores: dict
    eligible: set


def check_census(census) -> CheckedCensus:
    fields(census, CENSUS_FIELDS, "CENSUS_FIELDS")
    require(census["schema"] == "pon-native-owner-census-v1", "CENSUS_SCHEMA")
    require(census["packet_profile"] == "PNP1" and census["state_backend"] in
            ("legacy-v2", "authenticated-v1") and census["task_profile"] == "legacy-task-v1",
            "CENSUS_PROFILE")
    for key in ("network", "parameters", "genesis", "active_tip", "local_view_commitment"):
        hx(census[key], 32, "CENSUS_" + key.upper())
    for key in ("owner_process_id", "owner_observation_instance", "owner_attempt",
                "directory_device", "directory_inode", "database_device", "database_inode",
                "lock_device", "lock_inode", "started_ns", "ended_ns", "observed_now",
                "future_skew_seconds", "confirmation_depth", "confirmation_work_multiplier",
                "active_generation", "state_slot", "total_packet_bytes"):
        uint(census[key], "CENSUS_" + key.upper())
    require(census["ended_ns"] >= census["started_ns"], "CENSUS_CLOCK_ORDER")
    for key in ("owner_identity_scope", "clock_scope", "observed_now_source"):
        require(type(census[key]) is str and 0 < len(census[key]) <= 256, "CENSUS_SCOPE")
    for key in FALSE_FLAGS:
        require(census[key] is False, "UNSUPPORTED_QUALIFICATION:" + key)
    for key in ("complete_for_all_admitted_rows_in_snapshot", "local_candidate_relation_rechecked", "exact_source_schema_rechecked",
                "snapshot_released_without_commit", "owner_caches_may_refresh"):
        require(census[key] is True, "INCOMPLETE_CENSUS:" + key)
    require(type(census["excluded_scope"]) is list and len(census["excluded_scope"]) == 7
            and all(type(item) is str for item in census["excluded_scope"]), "EXCLUDED_SCOPE")
    require(type(census["rows"]) is list and 1 <= len(census["rows"]) <= 256, "ROW_LIMIT")
    rows, scores, paths, eligible = {}, {}, {}, set()
    total = 0
    for row in census["rows"]:
        fields(row, ROW_FIELDS, "ROW_FIELDS")
        block = hx(row["id"], 32, "BLOCK_ID")
        require(block not in rows, "DUPLICATE_BLOCK")
        height = uint(row["height"], "HEIGHT")
        score, weight = work(row["chainwork_hex"]), work(row["required_work_hex"])
        size = uint(row["packet_bytes"], "PACKET_BYTES", 16 * 1024 * 1024)
        for key in ("ancestry_time_eligible", "active_chain_member", "full_native_work_replayed",
                    "full_native_application_replayed", "retained_state_and_deltas_equal"):
            require(type(row[key]) is bool, "ROW_BOOLEAN")
        require(row["retained_state_and_deltas_equal"] is True, "STATE_NOT_RECHECKED")
        if block == census["genesis"]:
            require(not rows and height == score == weight == size == 0 and row["parent"] is None,
                    "GENESIS_SCORE")
            require(all(row[key] is None for key in ("target", "timestamp", "packet_sha256", "proof_sha256")),
                    "GENESIS_PACKET")
            require(row["full_native_work_replayed"] is False and row["full_native_application_replayed"] is False,
                    "GENESIS_REPLAY")
            paths[block] = (block,)
            is_eligible = True
        else:
            parent = hx(row["parent"], 32, "PARENT_ID")
            require(parent in rows, "MISSING_OR_UNORDERED_PARENT")
            require(height == rows[parent]["height"] + 1, "HEIGHT_STEP")
            target = int(hx(row["target"], 32, "TARGET"), 16)
            require(target > 0 and weight == (1 << 256) // (target + 1), "REQUIRED_WORK")
            require(score == scores[parent] + weight and score <= WORK_MAX, "CHAINWORK_SUM")
            timestamp = uint(row["timestamp"], "TIMESTAMP")
            for key in ("packet_sha256", "proof_sha256"):
                hx(row[key], 32, "PACKET_DIGEST")
            require(size > 0 and row["full_native_work_replayed"] is True
                    and row["full_native_application_replayed"] is True, "NATIVE_REPLAY_REQUIRED")
            paths[block] = paths[parent] + (block,)
            is_eligible = parent in eligible and timestamp <= census["observed_now"] + census["future_skew_seconds"]
        require(row["ancestry_time_eligible"] is is_eligible, "ANCESTRY_TIME_ELIGIBILITY")
        if is_eligible:
            eligible.add(block)
        rows[block], scores[block] = row, score
        total += size
    require([(r["height"], r["id"]) for r in census["rows"]] ==
            sorted((r["height"], r["id"]) for r in census["rows"]), "CENSUS_ROW_ORDER")
    active = census["active_tip"]
    require(active in rows, "ACTIVE_MISSING")
    for block, row in rows.items():
        require(row["active_chain_member"] is (block in paths[active]), "ACTIVE_PATH")
    maximum = max(scores[block] for block in eligible)
    maximum_ids = sorted(block for block in eligible if scores[block] == maximum)
    require(census["eligible_max_ids"] == maximum_ids, "ELIGIBLE_MAX_IDS")
    require(work(census["eligible_max_score_hex"]) == maximum, "ELIGIBLE_MAX_SCORE")
    require(work(census["active_score_hex"]) == scores[active], "ACTIVE_SCORE")
    require(census["active_time_eligible"] is (active in eligible), "ACTIVE_ELIGIBILITY")
    deficit = maximum - scores[active] if active in eligible else None
    require((census["raw_selection_deficit_hex"] is None and deficit is None) or
            (deficit is not None and work(census["raw_selection_deficit_hex"]) == deficit), "RAW_SELECTION_DEFICIT")
    require(total == census["total_packet_bytes"] and total <= 16 * 1024 * 1024, "TOTAL_PACKET_BYTES")
    require(local_commitment(census) == census["local_view_commitment"], "LOCAL_VIEW_COMMITMENT")
    return CheckedCensus(census, rows, paths, scores, eligible)


def check_confirmation(observation, census: CheckedCensus):
    fields(observation, OBSERVATION_FIELDS, "OBSERVATION_FIELDS")
    raw = census.raw
    for key in ("network", "parameters", "genesis", "active_generation", "observed_now"):
        require(observation[key] == raw[key] and type(observation[key]) is type(raw[key]), "OBSERVATION_BINDING:" + key)
    require(observation["observed_tip"] == raw["active_tip"], "OBSERVATION_TIP")
    require(observation["policy"] == "installed-depth-and-required-work", "CONFIRMATION_POLICY")
    for key in ("included_height", "observed_height"):
        uint(observation[key], "OBSERVATION_HEIGHT_TYPE")
    hx(observation["transaction"], 32, "TRANSACTION_ID")
    block = hx(observation["included_block"], 32, "INCLUDED_BLOCK")
    require(block in census.rows and block != raw["genesis"], "INCLUDED_BLOCK_MISSING")
    tip = raw["active_tip"]
    require(tip in census.eligible, "OBSERVATION_TIME_INELIGIBLE")
    require(observation["included_height"] == census.rows[block]["height"] and
            observation["observed_height"] == census.rows[tip]["height"], "OBSERVATION_HEIGHT")
    present = block in census.paths[tip]
    depth = census.rows[tip]["height"] - census.rows[block]["height"] if present else None
    delta = census.scores[tip] - census.scores[block] if present else None
    require(observation["depth"] == depth and (depth is None or type(observation["depth"]) is int), "CONFIRMATION_DEPTH")
    require((observation["work_delta"] is None and delta is None) or
            (delta is not None and work(observation["work_delta"]) == delta), "CONFIRMATION_WORK")
    threshold = work(census.rows[block]["required_work_hex"]) * raw["confirmation_work_multiplier"]
    require(threshold <= WORK_MAX and work(observation["required_work_delta"]) == threshold, "CONFIRMATION_THRESHOLD")
    confirmed = present and depth >= raw["confirmation_depth"] and delta >= threshold
    require(observation["confirmed"] is confirmed and observation["reorged"] is (not present), "CONFIRMATION_AND")
    require(observation["finalized"] is False and observation["execution_authority"] is False, "FINALITY_ESCALATION")
    inclusive = census.scores[tip] - census.scores[census.rows[block]["parent"]] if present else None
    six = raw["confirmation_depth"] == raw["confirmation_work_multiplier"] == 6
    if six and confirmed:
        require(inclusive >= 7 * work(census.rows[block]["required_work_hex"]), "SIX_INCLUSIVE_THRESHOLD")
    return {"included": present, "confirmed": confirmed, "six_successor_profile": six,
            "depth": depth, "work_delta": delta, "required_work_delta": threshold,
            "inclusive_K": inclusive, "membership_rechecked_by_reader": False}


def compare(reference: CheckedCensus, competing: CheckedCensus, observation):
    confirmation = check_confirmation(observation, reference)
    require(confirmation["confirmed"] and confirmation["six_successor_profile"], "CONFIRMED_SIX_REFERENCE_REQUIRED")
    for key in ("network", "parameters", "genesis", "confirmation_depth", "confirmation_work_multiplier"):
        require(reference.raw[key] == competing.raw[key], "INCOMPATIBLE_VIEWS")
    # Same block identities may differ in current time eligibility and membership,
    # but never in intrinsic packet/header/score fields.
    changing = {"ancestry_time_eligible", "active_chain_member"}
    for block in reference.rows.keys() & competing.rows.keys():
        require(all(reference.rows[block][key] == competing.rows[block][key]
                    for key in ROW_FIELDS if key not in changing), "CROSS_VIEW_BLOCK_SUBSTITUTION")
    c0, selected, block = reference.raw["active_tip"], competing.raw["active_tip"], observation["included_block"]
    require(selected in competing.eligible, "SELECTED_TIME_INELIGIBLE")
    require(block not in competing.paths[selected], "NO_TARGET_PREFIX_DISAGREEMENT")
    common = set(reference.paths[c0]) & set(competing.paths[selected])
    ancestor = max(common, key=lambda candidate: reference.rows[candidate]["height"])
    r, maximum, selected_score = reference.scores[c0], work(competing.raw["eligible_max_score_hex"]), competing.scores[selected]
    deficits = view_deficits(r, maximum, selected_score)
    suffix = selected_score - competing.scores[ancestor]
    reference_suffix = r - reference.scores[ancestor]
    require(suffix + deficits["total_comparison_score_deficit"] >= reference_suffix, "FORK_SCORE_WITNESS")
    known = [candidate for candidate in competing.eligible if block in competing.paths[candidate]]
    known_witness = None
    if known:
        best = max(known, key=lambda candidate: (competing.scores[candidate], candidate))
        parent_score = reference.scores[reference.rows[block]["parent"]]
        g = competing.scores[best] - parent_score
        q = maximum - selected_score
        # This bounds the *whole known competing suffix*, never newly produced
        # adversarial work: origin, producer and global ready time are unknown.
        require(suffix >= g - q, "KNOWN_B_CHAIN_WITNESS")
        known_witness = {"best_known_eligible_b_tip": best, "g": g,
                         "raw_selection_deficit_q": q, "g_minus_q": g - q,
                         "known_competing_suffix_lower_bound": max(0, g - q)}
    return {"initial_confirmation": confirmation, "reference_tip": c0, "selected_tip": selected,
            "last_common_ancestor": ancestor, "reference_score": r, "eligible_view_maximum": maximum,
            "selected_score": selected_score, **deficits,
            "whole_competing_suffix_weight": suffix, "reference_suffix_weight": reference_suffix,
            "fork_score_witness_holds": True, "known_b_chain_witness": known_witness,
            "new_adversarial_work_lower_bound": None, "initial_world_inventory": None,
            "global_failure_probability_bound": None}


def read_run(path: Path):
    require(path.stat().st_size <= 16 * 1024 * 1024, "RUN_SIZE_LIMIT")
    return strict_json(path.read_text(encoding="utf-8"))


def check_run(document, artifact_root: Path):
    require(type(document) is dict and document.get("schema") == "pon-native-owner-observation-run-v1", "RUN_SCHEMA")
    require(document.get("native_execution_exercised") is True, "RUN_NOT_NATIVE_DECLARATION")
    for key in ("native_runtime_attested", "exported_artifact_authenticated", "global_ready_attested",
                "world_coverage_attested", "physical_clock_authenticated", "probabilistic_environment_bound",
                "six_successor_risk_qualified"):
        require(document.get(key) is False, "RUN_QUALIFICATION:" + key)
    require(document.get("probability_bound") is None, "UNSUPPORTED_RISK_BOUND")
    snapshots = document.get("snapshots")
    require(type(snapshots) is list and 1 <= len(snapshots) <= 128, "SNAPSHOT_LIMIT")
    checked, node_scopes = {}, {}
    for snapshot in snapshots:
        fields(snapshot, {"name", "node", "census"}, "SNAPSHOT_FIELDS")
        name, node = snapshot["name"], snapshot["node"]
        require(type(name) is str and name not in checked and 0 < len(name) <= 128, "SNAPSHOT_NAME")
        require(type(node) is str and 0 < len(node) <= 128, "NODE_NAME")
        value = check_census(snapshot["census"])
        for key in ("network", "parameters", "genesis"):
            require(document.get(key) == value.raw[key], "RUN_CONTEXT")
        scope = tuple(value.raw[key] for key in ("owner_process_id", "owner_observation_instance",
                     "directory_device", "directory_inode", "database_device", "database_inode", "lock_device", "lock_inode"))
        if node in node_scopes:
            old_scope, attempt, ended = node_scopes[node]
            require(scope == old_scope and value.raw["owner_attempt"] > attempt
                    and value.raw["started_ns"] >= ended, "OWNER_LIFECYCLE_ORDER")
        node_scopes[node] = scope, value.raw["owner_attempt"], value.raw["ended_ns"]
        checked[name] = value
    require(len({item[0] for item in node_scopes.values()}) == len(node_scopes), "SHARED_OWNER_SCOPE")
    artifacts = document.get("packet_artifacts")
    require(type(artifacts) is list and len(artifacts) <= 256, "ARTIFACT_LIMIT")
    verified_artifacts = set()
    paths = set()
    for artifact in artifacts:
        fields(artifact, {"id", "kind", "sha256", "bytes", "path"}, "ARTIFACT_FIELDS")
        block, sha = hx(artifact["id"], 32, "ARTIFACT_ID"), hx(artifact["sha256"], 32, "ARTIFACT_SHA")
        relative = f"packets/{block}.{sha}.pnp1"
        require(artifact["path"] == relative and relative not in paths, "ARTIFACT_PATH")
        paths.add(relative)
        size = uint(artifact["bytes"], "ARTIFACT_BYTES", 16 * 1024 * 1024)
        path = artifact_root / relative
        require(not (artifact_root / "packets").is_symlink() and not path.is_symlink()
                and path.resolve().parent == artifact_root.resolve() / "packets", "ARTIFACT_PATH_ESCAPE")
        require(path.stat().st_size == size, "ARTIFACT_SIZE")
        data = path.read_bytes()
        require(hashlib.sha256(data).hexdigest() == sha, "ARTIFACT_HASH")
        require(artifact["kind"] in ("native_produced_packet", "invalid_product_control"), "ARTIFACT_KIND")
        if artifact["kind"] == "native_produced_packet":
            verified_artifacts.add((block, sha, size))
    for census in checked.values():
        for block, row in census.rows.items():
            if block != census.raw["genesis"]:
                require((block, row["packet_sha256"], row["packet_bytes"]) in verified_artifacts, "MISSING_FULL_PACKET_ARTIFACT")
    observations = document.get("confirmations")
    require(type(observations) is list and 1 <= len(observations) <= 128, "OBSERVATION_LIMIT")
    observation_results = []
    for observation in observations:
        require(type(observation) is dict, "OBSERVATION_TYPE")
        candidates = [value for value in checked.values() if
                      value.raw["active_tip"] == observation.get("observed_tip") and
                      value.raw["active_generation"] == observation.get("active_generation") and
                      value.raw["observed_now"] == observation.get("observed_now") and
                      observation.get("included_block") in value.rows]
        require(bool(candidates), "OBSERVATION_WITHOUT_CENSUS")
        observation_results.append(check_confirmation(observation, candidates[0]))
    scenarios = document.get("scenarios")
    require(type(scenarios) is list and 1 <= len(scenarios) <= 128, "SCENARIO_LIMIT")
    comparisons = []
    for scenario in scenarios:
        fields(scenario, {"name", "reference_snapshot", "confirmation_index", "competing_snapshot"}, "SCENARIO_FIELDS")
        index = uint(scenario["confirmation_index"], "CONFIRMATION_INDEX", len(observations) - 1)
        require(scenario["reference_snapshot"] in checked and scenario["competing_snapshot"] in checked, "SCENARIO_SNAPSHOT")
        result = compare(checked[scenario["reference_snapshot"]], checked[scenario["competing_snapshot"]], observations[index])
        comparisons.append({"name": scenario["name"], **result})
    return {"schema": SCHEMA, "snapshot_count": len(checked), "owner_count": len(node_scopes),
            "packet_artifact_count": len(artifacts), "observations": observation_results,
            "comparisons": comparisons, "exported_arithmetic_and_local_witnesses_checked": True,
            "native_execution_independently_attested": False, "world_coverage_attested": False,
            "physical_clock_authenticated": False, "global_ready_attested": False,
            "actual_resource_lower_bound_established": False, "six_successor_risk_qualified": False,
            "failure_probability": None}


def observe_native(binary: Path, output: Path):
    """Run an explicit existing native executable and retain success or failure.

    No discovery, build, substitute transcript, skip or successful fallback.
    The executable and OS remain trusted local inputs; hashes are not attestation.
    """
    binary = binary.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "NATIVE_EXECUTOR_UNAVAILABLE")
    output.mkdir(parents=True, exist_ok=False)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    report = {"schema": "pon-native-owner-invocation-v1", "binary": str(binary),
              "binary_sha256_before": before, "native_runtime_attested": False}
    try:
        result = run_bounded([str(binary), str(output.resolve() / "native.json")], b"",
                             timeout=300, stdout_limit=65536, stderr_limit=65536)
        (output / "stdout.txt").write_bytes(result.stdout)
        (output / "stderr.txt").write_bytes(result.stderr)
        report["returncode"] = result.returncode
        require(result.returncode == 0, "NATIVE_PROBE_FAILED")
        after = hashlib.sha256(binary.read_bytes()).hexdigest()
        report["binary_sha256_after"] = after
        require(before == after, "NATIVE_BINARY_CHANGED")
        source = output / "native.json"
        report["native_json_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        result = check_run(read_run(source), output)
        (output / "score_bridge.json").write_text(json.dumps(result, indent=2) + "\n")
        report["status"] = "passed"
        return result
    except ProcessFailure as error:
        (output / "stdout.txt").write_bytes(error.stdout)
        (output / "stderr.txt").write_bytes(error.stderr)
        report.update(status="failed", error=str(error), returncode=error.returncode)
        raise
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (output / "invocation.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--native", type=Path)
    mode.add_argument("--input", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.native:
        require(args.out is not None, "NEW_OUTPUT_DIRECTORY_REQUIRED")
        result = observe_native(args.native, args.out)
    else:
        result = check_run(read_run(args.input), args.input.parent)
        if args.out:
            with args.out.open("x", encoding="utf-8") as destination:
                destination.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

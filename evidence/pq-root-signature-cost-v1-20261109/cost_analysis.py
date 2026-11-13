#!/usr/bin/env python3
"""Re-read one frozen PQ root cost observation; never execute native code.

This verifies public bytes, framing, reported outcomes, budgets, sample order,
and arithmetic. It is not an independent signature-verification implementation,
independent executor authentication, a statistical efficacy test, or a production
qualification. The exact raw observations remain the primary evidence.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics


SOURCE = "c9fb3fa61e2aadbdeaf39e85a7e21604d72581b7"
TREE = "704b67dc07f94e1770452f154d72c002b5ac1af0"
SCHEMA = "trnm-pq-root-v3-cost-observation-v1"
ARMS = ["A_fresh_roster_decode_and_full_quorum", "B_retained_roster_full_quorum"]
ROSTER_DOMAIN = b"TRNM/RootV3/RosterWire/v3\0"
ROSTER_RULES = bytes([1, 2, 1, 2, 3, 2, 2, 3])
SUITES = {
    1: ("ML-DSA-87", 2592, 4627, bytes.fromhex("30820a32300b060960864801650304031303820a2100")),
    2: ("SLH-DSA-SHA2-256s", 64, 29792, bytes.fromhex("3050300b0609608648016503040318034100")),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def forbidden_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=forbidden_constant)


def unhex(value):
    require(isinstance(value, str), "hex value is not a string")
    result = bytes.fromhex(value)
    require(result.hex() == value, "noncanonical hex value")
    return result


def framed(domain, parts):
    return domain + b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def digest(data):
    return hashlib.sha512(data).hexdigest()


def roster(record):
    wire = unhex(record["encoded_roster_hex"])
    prefix = ROSTER_DOMAIN + ROSTER_RULES
    require(wire.startswith(prefix), "roster namespace/rules mismatch")
    offset = len(prefix)
    entries = []
    for _ in range(6):
        require(offset + 5 <= len(wire), "short roster member header")
        tag = wire[offset]
        require(tag in SUITES, "unknown suite tag")
        name, public_bytes, signature_bytes, spki_prefix = SUITES[tag]
        length = int.from_bytes(wire[offset + 1:offset + 5], "big")
        offset += 5
        spki = wire[offset:offset + length]
        require(len(spki) == length == public_bytes + len(spki_prefix), "SPKI length mismatch")
        require(spki.startswith(spki_prefix), "noncanonical SPKI/OID")
        offset += length
        identity = digest(framed(b"TRNM/RootV3/Key/v3\0", [name.encode(), spki]))
        entries.append({"tag": tag, "suite": name, "id": identity,
                        "spki_bytes": length, "raw_public_key_bytes": public_bytes,
                        "raw_signature_bytes": signature_bytes})
    require(offset == len(wire) == 8152, "roster trailing bytes or length")
    require(Counter(row["tag"] for row in entries) == {1: 3, 2: 3}, "roster family counts")
    order = [(row["tag"], row["id"]) for row in entries]
    require(order == sorted(order) and len({row["id"] for row in entries}) == 6,
            "roster identity uniqueness/order")
    require(record["encoded_roster_bytes"] == len(wire), "reported roster length")
    require(record["encoded_roster_sha512"] == digest(wire), "roster SHA512 mismatch")
    commitment = digest(framed(b"TRNM/RootV3/RosterCommitment/v3\0", [wire]))
    require(record["roster_commitment_hex"] == commitment, "roster commitment mismatch")
    require(record["spki_bytes_total"] == sum(row["spki_bytes"] for row in entries) == 8088,
            "roster total SPKI bytes")
    reported = [{key: row[key] for key in ("suite", "spki_bytes", "raw_public_key_bytes", "raw_signature_bytes")}
                for row in entries]
    require(record["keys"] == reported, "roster member metadata")
    return wire, entries, bytes.fromhex(commitment)


def signature_lengths(rows, entries, expected_ids):
    require([row["signer_id_hex"] for row in rows] == expected_ids, "signature identities/order")
    index = {row["id"]: row for row in entries}
    lengths = []
    for row in rows:
        length = len(unhex(row["signature_hex"]))
        require(row["raw_signature_bytes"] == length == index[row["signer_id_hex"]]["raw_signature_bytes"],
                "signature byte count")
        lengths.append(length)
    return lengths


def distribution(values):
    require(values and all(type(value) is int and value >= 0 for value in values), "invalid timing sample")
    return {"samples": len(values), "minimum_ns": min(values),
            "median_ns": statistics.median(values), "maximum_ns": max(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, default=Path(__file__).parent / "frozen-campaign-c9fb3fa6")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "cost-analysis.json")
    parser.add_argument("--binary", type=Path, help="optional local binary to hash; never executed")
    args = parser.parse_args()
    base = args.campaign
    inputs = {}

    def read(name):
        data = (base / name).read_bytes()
        inputs[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        return data

    commands = decode_json(read("commands.json"))
    matches = [row for row in commands if row["name"] == "cost-observation"]
    require(len(matches) == 1, "missing/duplicate cost command")
    command = matches[0]
    require(command["source"] == SOURCE and command["exit_code"] == 0
            and command["timed_out"] is False and command["launch_error"] is None,
            "cost command did not terminate normally")
    expected_argv = ["cargo", "run", "--offline", "--locked", "--manifest-path", "trillionnium/Cargo.toml",
                     "--release", "-p", "trnm-crypto-primitives", "--features", "pq-native-openssl",
                     "--example", "pq_root_v3_cost_observation", "--", "--rounds", "8"]
    require(command["argv"] == expected_argv, "cost command arguments differ")
    raw = read("cost-observation.stdout")
    read("cost-observation.stderr")
    for stream in ("stdout", "stderr"):
        reported = command[stream]
        actual = inputs["cost-observation." + stream]
        require(reported["path"] == "cost-observation." + stream and
                reported["bytes"] == actual["bytes"] and reported["sha256"] == actual["sha256"],
                "recorded output byte identity mismatch")
    require(raw.endswith(b"\n"), "missing final JSONL newline")
    lines = raw.decode("utf-8").splitlines()
    require(len(lines) == 41 and all(lines), "missing/extra/empty JSONL rows")
    rows = [decode_json(line) for line in lines]
    require(all(row["schema"] == SCHEMA for row in rows), "JSONL schema mismatch")
    expected_kinds = ["run", "public_fixture"] + ["quorum_sample"] * 34 + ["combined_api_stage"] * 2 + ["arm_summary"] * 2 + ["complete"]
    require([row["kind"] for row in rows] == expected_kinds, "JSONL event order mismatch")
    run, fixture = rows[:2]
    require((run["abba_blocks"], run["measured_samples_per_arm"], run["warmup_samples_per_arm"]) == (8, 16, 1),
            "declared sample counts")
    require(run["execution_context"]["debug_assertions"] is False, "not a release observation")
    require("OpenSSL 3.5.9" in run["openssl_version"], "actual OpenSSL version differs")
    for key in ("budget_setup_and_output_serialization_timed", "roster_drop_timed",
                "provider_identity_attested", "fips140_module_qualification_claimed", "cell_read_measured",
                "owner_history_replay_measured", "complete_transition_latency_measured", "full_pipeline_measured",
                "whole_chain_pq_qualified", "production_activation"):
        require(run[key] is False, f"scope flag changed: {key}")
    require(run["performance_acceptance_threshold"] is None, "performance threshold was introduced")

    current_wire, current, _ = roster(fixture["current"])
    successor_wire, successor, successor_commitment = roster(fixture["successor"])
    statement = unhex(fixture["statement_hex"])
    require(statement == framed(b"TRNM/Observation/RootV3CostStatement/v1\0", [current_wire, successor_wire]),
            "synthetic statement framing")
    message = unhex(fixture["approval_message_hex"])
    require(message == framed(b"TRNM/RootV3/Approval/v3\0", [statement]), "approval message framing")
    require(fixture["statement_bytes"] == len(statement) and fixture["approval_message_bytes"] == len(message)
            and fixture["approval_message_sha512"] == digest(message), "statement/message byte metadata")
    approval_ids = [current[index]["id"] for index in (0, 1, 3, 4)]
    approval_lengths = signature_lengths(fixture["approvals"], current, approval_ids)
    possession_lengths = signature_lengths(fixture["successor_possessions"], successor, [row["id"] for row in successor])
    require(sum(approval_lengths) == 68838 and sum(possession_lengths) == 103257,
            "actual raw signature totals differ")
    require(fixture["signature_only_bytes"] == {"four_approvals": 68838, "six_successor_possessions": 103257, "combined": 172095},
            "declared signature total differs")
    require(fixture["actual_owner_transition_frame_bytes"] is None, "synthetic fixture mislabeled as transition")
    possession_messages = []
    for row in successor:
        blob = framed(b"TRNM/RootV3/SuccessorPossession/v3\0",
                      [statement, successor_commitment, row["suite"].encode(), bytes.fromhex(row["id"])])
        possession_messages.append({"signer_id_hex": row["id"], "message_bytes": len(blob), "message_sha512": digest(blob)})
    require(fixture["successor_possession_messages"] == possession_messages, "possession message bytes/framing")

    charge = len(message) + len(current_wire) + 4 * 64 + sum(approval_lengths)
    possession_charge = (len(statement) + 256) * 6 + len(successor_wire) + 6 * 64 + sum(possession_lengths)
    warmups, samples = rows[2:4], rows[4:36]
    expected_order = [(block, slot, ARMS[index]) for block in range(1, 9) for slot, index in enumerate((0, 1, 1, 0))]
    require([(row["abba_block"], row["slot_in_block"], row["arm"]) for row in samples] == expected_order,
            "ABBA block/arm/sample order")
    require([(row["phase"], row["abba_block"], row["slot_in_block"], row["arm"]) for row in warmups]
            == [("warmup", 0, 0, ARMS[0]), ("warmup", 0, 1, ARMS[1])], "warmup order")
    require(all(row["phase"] == "measured" for row in samples), "non-measured row in sample set")
    for row in warmups + samples:
        for key in ("verification_started", "native_api_accepted", "exact_signer_ids_match", "budget_counters_match"):
            require(row[key] is True, f"sample outcome failed: {key}")
        require(row["error"] is None and row["authorized_external_effect"] is False, "sample error/effect flag")
        require(row["budget"] == {"reserved_verifications": 4, "charged_input_bytes": charge}
                and row["expected_charged_input_bytes"] == charge, "sample budget changed")
        decode_ns = row["roster_decode_wall_ns"]
        if row["arm"] == ARMS[0]:
            require(type(decode_ns) is int and decode_ns >= 0, "fresh decode timing")
        else:
            require(decode_ns is None, "retained sample claims a decode")
        require(type(row["operation_wall_ns"]) is int and type(row["full_quorum_verification_wall_ns"]) is int
                and row["operation_wall_ns"] >= row["full_quorum_verification_wall_ns"] >= 0,
                "sample duration order/type")

    combined = rows[36:38]
    require([row["stage"] for row in combined] == ["four_current_approvals", "six_successor_possessions"], "combined stage order")
    for row, attempts, bytes_ in zip(combined, (4, 10), (charge, charge + possession_charge)):
        require(row["shared_budget_maximum"] == 10 and row["exact_result_and_budget_match"] is True
                and row["native_error"] is None, "combined outcome")
        require(row["budget"] == {"reserved_verifications": attempts, "charged_input_bytes": bytes_},
                "combined cumulative budget")
        require(type(row["wall_ns"]) is int and row["wall_ns"] >= 0, "combined timing")
    require(combined[1]["expected_cumulative_charged_input_bytes"] == charge + possession_charge
            and combined[1]["complete_transition_latency_measured"] is False, "combined claim boundary")
    arm_statistics = []
    for arm, reported in zip(ARMS, rows[38:40]):
        selected = [row for row in samples if row["arm"] == arm]
        require(len(selected) == 16 and reported["arm"] == arm, "arm sample count/summary identity")
        operation = [row["operation_wall_ns"] for row in selected]
        verification = [row["full_quorum_verification_wall_ns"] for row in selected]
        for key, values in (("operation_wall", operation), ("full_quorum_verification_wall", verification)):
            require(reported[key] == distribution(values), f"summary arithmetic: {arm}/{key}")
        require(reported["population_tail_established"] is False and reported["performance_acceptance_threshold"] is None,
                "summary qualification")
        arm_statistics.append({"arm": arm, "operation_wall": distribution(operation),
                               "full_quorum_verification_wall": distribution(verification),
                               "operation_wall_ns_in_measurement_order": operation,
                               "full_quorum_verification_wall_ns_in_measurement_order": verification})
    final = rows[-1]
    expected_final = {"observation_completed": True, "abba_blocks": 8, "measured_samples_per_arm": 16,
                      "measured_quorum_calls": 32, "measured_reserved_verifications": 128,
                      "warmup_quorum_calls": 2, "warmup_reserved_verifications": 8,
                      "combined_api_reserved_verifications": 10, "setup_native_signatures": 10,
                      "setup_native_self_checks": 10, "all_emitted_sample_results_and_counters_checked": True,
                      "whole_chain_pq_qualified": False, "production_activation": False}
    require(all(final[key] == value and type(final[key]) is type(value) for key, value in expected_final.items()),
            "terminal completion counts/scope")
    source_before = decode_json(read("source-before.json"))
    source_after = decode_json(read("source-after.json"))
    require(source_before == source_after and source_before["tested_commit"] == SOURCE
            and source_before["tested_tree"] == TREE and source_before["tracked_worktree_verified"] is True,
            "source endpoint identities mismatch")
    environment = decode_json(read("environment.json"))
    campaign = decode_json(read("summary.json"))
    binary = decode_json(read("cost-binary.json"))
    require(environment["source"] == SOURCE and environment["source_tree"] == TREE
            and environment["shared_executor_load_is_controlled"] is False, "environment identity/scope")
    require(campaign["source"] == SOURCE and campaign["complete_source_endpoints_match"] is True
            and campaign["completed_commands"] == len(commands), "campaign identity/completeness")
    # Other original commands may have failed. Their failures do not disappear
    # when this narrower cost observation completed; preserve the actual status.
    require(campaign["all_commands_exit_zero"] == all(row["exit_code"] == 0 for row in commands),
            "campaign status disagrees with command records")
    require(binary["source"] == SOURCE, "binary source record mismatch")
    local_binary_verified = False
    if args.binary is not None:
        data = args.binary.read_bytes()
        require(len(data) == binary["bytes"] and hashlib.sha256(data).hexdigest() == binary["sha256"],
                "local binary byte identity mismatch")
        local_binary_verified = True
    load = decode_json(read("load-before-cost-observation.json"))
    comparisons = {}
    for metric in ("operation_wall", "full_quorum_verification_wall"):
        first, second = [arm[metric]["median_ns"] for arm in arm_statistics]
        require(first > 0, "zero reference median")
        comparisons[metric] = {"fresh_median_ns": first, "retained_median_ns": second,
                               "retained_minus_fresh_ns": second - first,
                               "retained_median_relative_change_percent": (second / first - 1) * 100,
                               "interpretation": "descriptive ratio of per-arm medians; no population or before/after-code claim"}
    output = {
        "schema": "trnm-pq-root-v3-cost-independent-arithmetic-v1",
        "source": SOURCE, "source_tree": TREE, "cost_command_normal_exit_zero": True,
        "raw_jsonl_rows": len(rows), "terminal_complete_marker_checked": True,
        "abba_blocks": 8, "measured_samples_per_arm": 16, "warmup_samples_per_arm": 1,
        "arm_statistics": arm_statistics, "descriptive_median_comparisons": comparisons,
        "public_byte_checks": {"four_approval_signature_bytes": sum(approval_lengths),
            "six_possession_signature_bytes": sum(possession_lengths), "combined_raw_signature_bytes": 172095,
            "current_encoded_roster_bytes": len(current_wire), "successor_encoded_roster_bytes": len(successor_wire),
            "spki_bytes_per_roster": 8088, "synthetic_statement_bytes": len(statement),
            "approval_message_bytes": len(message),
            "possession_message_bytes": [row["message_bytes"] for row in possession_messages],
            "complete_owner_transition_frame_bytes": None},
        "budgets": {"per_quorum_attempts": 4, "per_quorum_charged_input_bytes": charge,
            "combined_final_attempts": 10, "combined_final_charged_input_bytes": charge + possession_charge,
            "measured_attempts": 128, "measured_charged_input_bytes": len(samples) * charge,
            "warmup_attempts": 8, "warmup_charged_input_bytes": len(warmups) * charge,
            "all_v3_api_attempts_including_warmup_and_combined": 146,
            "all_v3_api_charged_input_bytes": (len(samples) + len(warmups)) * charge + charge + possession_charge,
            "not_a_measurement_of_transferred_bytes_or_hash_queries": True},
        "combined_api_stage_wall_ns": {row["stage"]: row["wall_ns"] for row in combined},
        "setup_wall_ns": fixture["setup_wall_ns"], "openssl_version": run["openssl_version"],
        "openssl_version_number_hex": run["openssl_version_number_hex"],
        "source_endpoint_consistency": source_before, "binary_record": binary,
        "local_binary_bytes_independently_rehashed": local_binary_verified,
        "load_before_cost_observation": load, "shared_executor_load_is_controlled": False,
        "overall_campaign_all_commands_exit_zero": campaign["all_commands_exit_zero"],
        "overall_campaign_completed_commands": len(commands),
        "overall_campaign_failed_commands": [
            {key: row[key] for key in ("name", "exit_code", "timed_out", "launch_error")}
            for row in commands if row["exit_code"] != 0
        ],
        "input_byte_identities": inputs,
        "analysis_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "independent_native_signature_verification_performed_by_this_parser": False,
        "independent_executor_authentication": False, "continuous_source_immutability_proved": False,
        "cell_read_or_owner_transition_performance_measured": False,
        "population_performance_or_p99_established": False, "fips140_validation_established": False,
        "whole_chain_pq_qualified": False, "production_activation": False,
    }
    args.out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"analysis_output": str(args.out), "rows": len(rows), "samples_per_arm": 16,
                      "comparisons": comparisons, "public_bytes": output["public_byte_checks"],
                      "budgets": output["budgets"], "source": SOURCE}, indent=2))


if __name__ == "__main__":
    main()

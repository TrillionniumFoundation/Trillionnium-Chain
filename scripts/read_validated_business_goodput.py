#!/usr/bin/env python3
"""Reconcile unique business confirmations in a pinned original native bundle.

This reader checks retained bytes, source receipts and native observation joins.
It does not execute W1, verify signatures, attest execution or confer finality.
The historical campaign/readback formats and their acceptance gates are intact.
"""
from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
from pathlib import Path, PurePosixPath
import re
import sys

import read_original_native_campaign as original
import pon_public_v3_phase_read as phases

H, header_decode = original.H, original.header_decode
from contract_wire import sequence_root
require, integer, digest = original.require, original.integer, original.exact_digest
SCHEMA = "pon-unique-validated-business-observation-v1"
WINDOW_NS = 30_000_000_000
PROOF_BYTES = 4 + 12 * 4096 + 32
FALSE_FLAGS = ("cryptographic_hardness_qualified", "work_profile_qualified",
               "independent_operators", "wan_qualified", "production_candidate", "release_ready")


def ratio(count, elapsed):
    if elapsed is None:
        return None
    value = Fraction(count * 1_000_000_000, elapsed)
    return {"numerator": value.numerator, "denominator": value.denominator}


def raw_hex(value, maximum):
    require(type(value) is str and 0 < len(value) <= maximum * 2
            and len(value) % 2 == 0 and re.fullmatch("[0-9a-f]+", value),
            "bounded canonical hex required")
    return bytes.fromhex(value)


def packet(value):
    """Reconstruct identity and transactions, without testing the W1 relation."""
    raw = raw_hex(value, 1_048_576)
    require(len(raw) >= 320 + PROOF_BYTES, "complete PNH1 packet required")
    header = header_decode(raw[:318])
    count, position, transactions = int.from_bytes(raw[318:320], "little"), 320, []
    require(count <= 256, "packet transaction bound")
    for _ in range(count):
        require(position + 2 <= len(raw) - PROOF_BYTES, "packet transaction length")
        size = int.from_bytes(raw[position:position + 2], "little")
        position += 2
        require(159 <= size <= 8192 and position + size <= len(raw) - PROOF_BYTES,
                "packet transaction bytes")
        transactions.append(raw[position:position + size].hex())
        position += size
    require(len(raw) - position == PROOF_BYTES and raw[position:position + 4] == b"PNW1",
            "complete W1 bytes required")
    require(header["transactions"] == sequence_root("transactions", [bytes.fromhex(tx) for tx in transactions]),
            "packet transaction commitment mismatch")
    return {"id": H("block", raw[:318], raw[-32:]).hex(), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "header": raw[:318].hex(), "decoded": header, "transactions": transactions}


def prepared_business(report):
    value = report["preparation"]
    require(value["state_backend"] == "authenticated-v1" and value["business_blocks"] == 21
            and value["seed_blocks"] == 4 and value["actual_signed_seed_transfers"] == 1024,
            "original preparation profile required")
    rows = value["business"]
    require(type(rows) is list and len(rows) == 21, "original 21 business packets required")
    seen, output = set(), []
    for index, row in enumerate(rows):
        block = digest(row["id"])
        require(block not in seen, "duplicate prepared block")
        seen.add(block)
        header = header_decode(raw_hex(row["header"], 318))
        require(header["height"] == 5 + index and header["target"] != bytes(32),
                "original business height/target required")
        require(type(row["transactions"]) is list and len(row["transactions"]) == int(index % 7 == 0),
                "original one business transaction followed by six maintenance packets required")
        transactions = [raw_hex(tx, 8192) for tx in row["transactions"]]
        require(all(len(tx) >= 159 for tx in transactions), "complete business transaction bytes required")
        require(header["transactions"] == sequence_root("transactions", transactions),
                "prepared transaction commitment mismatch")
        if output:
            previous = output[-1]
            require(header["parent"].hex() == previous["id"]
                    and header["height"] == previous["decoded"]["height"] + 1
                    and all(header[key] == previous["decoded"][key] for key in ("network", "parameters")),
                    "prepared business chain/context mismatch")
        output.append({**row, "decoded": header,
                       "transaction_id": H("tx-id", transactions[0]).hex() if transactions else None})
    return output


def accepted_phase(slots, name):
    matches = [row for row in slots if row["phase"] == name]
    require(len(matches) == 1, "unique native import phase required")
    return all(matches[0][key] is True for key in ("started", "completed", "accepted"))


def verified_imports(phase, business):
    """Join original complete-page bytes to actual per-packet Work observations.

    Observer-local timestamps are never compared with the campaign clock. Only
    the enclosing original client's timestamps join the round's campaign clock.
    Replayed/cached packets need an earlier retained successful Work observation.
    """
    histories = phase["history"]
    require(type(histories) is list and len(histories) <= 64, "original history call bound")
    prepared = {row["id"]: row for row in business}
    known, observed_bytes, receipts, gaps = {}, {}, [], 0
    for call in histories:
        imported = call.get("client_import")
        if imported is None:
            continue
        require(type(imported) is dict and type(imported.get("succeeded")) is bool,
                "native import result required")
        if imported["succeeded"] is not True:
            continue
        require(call["status"] == "ok" and call["error"] is None
                and call["response"]["ok"] is True and imported.get("error") is None,
                "successful original History response/import required")
        page, request = call["response"]["value"], call["request"]
        require(page["schema"] == "pon-native-history-v1" and request["op"] == "history"
                and page["tip"] == request["tip"] and page["after"] == request["after"],
                "History request/response context mismatch")
        for key in ("tip", "after", "next", "network", "parameters", "genesis"):
            digest(page[key])
        require(type(page["complete"]) is bool and type(page["packets"]) is list
                and len(page["packets"]) <= 16, "bounded original History page required")
        start, finish = integer(imported["started_ns"]), integer(imported["ended_ns"])
        require(integer(call["started_ns"]) <= integer(call["ended_ns"]) <= start <= finish,
                "History/import campaign clock order")
        decoded = [packet(raw) for raw in page["packets"]]
        previous = page["after"]
        for actual in decoded:
            require(actual["decoded"]["parent"].hex() == previous
                    and actual["decoded"]["network"].hex() == page["network"]
                    and actual["decoded"]["parameters"].hex() == page["parameters"],
                    "History bytes/native packet identity mismatch")
            previous = actual["id"]
            require(previous not in observed_bytes or observed_bytes[previous] == actual["raw_sha256"],
                    "same block identity has conflicting complete packet bytes")
            observed_bytes[previous] = actual["raw_sha256"]
            if previous in prepared:
                expected = prepared[previous]
                require(all(actual[key] == expected[key] for key in ("header", "transactions")),
                        "prepared business/History bytes mismatch")
        require(page["next"] == previous and page["complete"] is (previous == page["tip"]),
                "History completion/parent chain mismatch")
        # Even historical successful imports must keep one complete byte identity.
        # Missing Work instrumentation grants neither validation nor confirmation.
        native = imported.get("native_import_observation")
        if native is None:
            gaps += 1
            continue
        phases.validate_history_import_observation(native)
        require(native["measurement_failures"] == 0
                and native["tip"] == list(bytes.fromhex(page["tip"]))
                and native["after"] == list(bytes.fromhex(page["after"]))
                and native["supplied_packets"] == len(page["packets"])
                and accepted_phase(native["phases"], "history_import"),
                "complete successful native History observation required")
        require([row["packet_index"] for row in native["packets"]] == list(range(len(decoded))),
                "complete native packet observation roster required")
        for actual, observed in zip(decoded, native["packets"]):
            require(observed["packet_id"] == list(bytes.fromhex(actual["id"])),
                    "History bytes/native packet identity mismatch")
            if (accepted_phase(observed["phases"], "work")
                    and accepted_phase(observed["phases"], "history_import")):
                known.setdefault(actual["id"], []).append(finish)
        confirmation = call.get("client_confirmation")
        if page["complete"] and confirmation is not None and confirmation.get("succeeded") is True:
            begin, end = integer(confirmation["started_ns"]), integer(confirmation["ended_ns"])
            require(finish <= begin <= end, "native confirmation campaign clock order")
            receipts.append({"tip": page["tip"], "genesis": page["genesis"],
                             "network": page["network"], "parameters": page["parameters"],
                             "started_ns": begin, "ended_ns": end})
    return known, receipts, gaps


def fixed_schedule_completion(outcomes, business):
    """Retain delay before actual round entry under the original 1/5/9s schedule.

    Native round starts can be delayed by the previous round. Its enclosing end
    also includes confirmation bookkeeping, so this is scheduled-to-round-end
    latency, not a reconstructed timestamp of a confirmation event. Missing
    rows have unknown execution, never an invented zero duration. This additive
    diagnostic grants no new confirmation and changes no original criterion.
    """
    rows, counts, successful = [], Counter(), []
    for number in range(3):
        scheduled = (1 + 4 * number) * 1_000_000_000
        row = outcomes[number] if number < len(outcomes) else None
        state = row["state"] if row is not None else "unobserved"
        start = row["started_ns"] if row is not None else None
        end = row["ended_ns"] if row is not None else None
        if row is not None:
            require(row["round"] == number and scheduled <= start <= end,
                    "round precedes original fixed schedule")
        confirmed_elapsed = end - scheduled if state == "validated" else None
        if confirmed_elapsed is not None:
            successful.append(confirmed_elapsed)
        counts[state] += 1
        rows.append({"round": number, "transaction": business[number * 7]["transaction_id"],
                     "scheduled_ns": scheduled, "state": state,
                     "started_ns": start, "ended_ns": end,
                     "start_delay_ns": start - scheduled if start is not None else None,
                     "round_end_from_schedule_ns": end - scheduled if end is not None else None,
                     "on_time_validated_round_end_from_schedule_ns": confirmed_elapsed})
    values = sorted(successful)
    return {"schema": "pon-original-fixed-schedule-completion-v1",
            "planned_rounds": 3, "outcomes": rows,
            "planned_outcome_counts": dict(sorted(counts.items())),
            "on_time_validated_rounds": len(values),
            "rounds_without_observed_on_time_validation": 3 - len(values),
            "successful_scheduled_round_latency_samples": len(values),
            "successful_scheduled_round_latency_p50_nearest_rank_ns":
                values[(len(values) - 1) // 2] if values else None,
            "successful_scheduled_round_latency_p95_ns": None,
            "successful_scheduled_round_latency_p99_ns": None,
            "all_planned_confirmation_p95_ns": None,
            "all_planned_confirmation_p99_ns": None,
            "scope": {"schedule": "original campaign offsets 1, 5, 9 seconds",
                      "clock": "retained campaign monotonic clock, not native observer-local clocks",
                      "latency_end": "enclosing round end, including confirmation bookkeeping",
                      "actual_round_start_excludes_prior_round_delay": True,
                      "missing_round_execution_is_unknown": True,
                      "counts_are_rounds_not_unique_business_effects": True,
                      "three_rounds_are_insufficient_for_p95_or_p99": True,
                      "original_confirmation_criteria_changed": False}}


def phase_goodput(phase, business):
    mode = phase["mode"]
    require(mode in phases.MODES, "original phase mode required")
    if phase.get("startup_or_campaign_error") is not None:
        return {"mode": mode, "planned_rounds": 3, "observed_rounds": 0,
                "unobserved_rounds": 3, "startup_or_campaign_error": phase["startup_or_campaign_error"],
                "unique_validated_business_observed": 0, "validated_goodput_per_second": None,
                "observed_validated_business_per_actual_second": None,
                "actual_parent_phase_wall_ns": None, "finite_phase_criteria_met": False,
                "fixed_schedule_completion": fixed_schedule_completion([], business)}
    require(phase["duration_seconds"] == 30 and phase["state_backend"] == "authenticated-v1",
            "original phase profile required")
    require(type(phase["finite_phase_criteria_met"]) is bool, "typed original phase outcome required")
    if phase["whole_parent_phase_cpu_ns"] is not None:
        integer(phase["whole_parent_phase_cpu_ns"])
    elapsed = phase["whole_parent_phase_wall_ns"]
    if elapsed is not None:
        require(integer(elapsed) >= WINDOW_NS, "actual parent phase shorter than fixed window")
    rows = phase["confirmations"]
    require(type(rows) is list and len(rows) <= 3, "original confirmation round bound")
    indices = [integer(row["round"]) for row in rows]
    require(indices == list(range(len(rows))), "ordered original scheduled rounds required")
    known, receipts, gaps = verified_imports(phase, business)
    counts, outcomes, unique_transactions, seen_transactions, latencies = Counter(), [], set(), set(), []
    previous_end = 0
    for row in rows:
        number = row["round"]
        start, end = integer(row["started_ns"]), integer(row["ended_ns"])
        require(previous_end <= start <= end and (elapsed is None or end <= elapsed),
                "round campaign clock order/bound")
        previous_end = end
        expected = business[number * 7:(number + 1) * 7]
        transaction = digest(row["transaction"])
        require(transaction == expected[0]["transaction_id"]
                and row["included_block"] == expected[0]["id"] and row["tip"] == expected[-1]["id"],
                "confirmation differs from original scheduled business")
        repeated = transaction in seen_transactions
        seen_transactions.add(transaction)
        counts["repeated_transaction_observations"] += repeated
        require(type(row["confirmed_inside_pressure_window"]) is bool, "confirmation flag must be boolean")
        observed = row["observation"]
        state, qualified = "unknown", False
        if observed is None:
            require(row["confirmed_inside_pressure_window"] is False,
                    "confirmation flag has no native observation")
        else:
            require(type(observed) is dict and all(type(observed[key]) is bool for key in
                    ("confirmed", "reorged", "finalized", "execution_authority")),
                    "typed native confirmation required")
            require(observed["policy"] == "installed-depth-and-required-work"
                    and observed["transaction"] == transaction
                    and observed["included_block"] == expected[0]["id"]
                    and observed["observed_tip"] == expected[-1]["id"]
                    and observed["network"] == expected[0]["decoded"]["network"].hex()
                    and observed["parameters"] == expected[0]["decoded"]["parameters"].hex()
                    and observed["finalized"] is False and observed["execution_authority"] is False,
                    "confirmation policy/context mismatch")
            digest(observed["genesis"])
            for field in ("active_generation", "observed_now", "observed_height"):
                integer(observed[field])
            matching_receipts = [r for r in receipts
                                 if start <= r["started_ns"] <= r["ended_ns"] <= end
                                 and all(r[key] == observed[key] for key in ("genesis", "network", "parameters"))
                                 and r["tip"] == row["tip"]]
            if observed["reorged"]:
                require(observed["confirmed"] is False and row["confirmed_inside_pressure_window"] is False,
                        "reorganized transaction cannot be credited")
                state = "reorged" if matching_receipts else "validation_evidence_missing"
            else:
                # Original installed contract: depth six, work multiplier six.
                # Recompute the exact public target arithmetic, not its cost.
                weights = [(1 << 256) // (int.from_bytes(b["decoded"]["target"], "big") + 1)
                           for b in expected]
                required_work = 6 * weights[0]
                actual_work = sum(weights[1:])
                require(type(observed["depth"]) is int and observed["depth"] == 6
                        and integer(observed["included_height"]) == expected[0]["decoded"]["height"]
                        and observed["observed_height"] == expected[-1]["decoded"]["height"]
                        and observed["observed_height"] - observed["included_height"] == 6
                        and int(digest(observed["work_delta"], 128), 16) == actual_work
                        and int(digest(observed["required_work_delta"], 128), 16) == required_work
                        and required_work > 0
                        and observed["confirmed"] is (actual_work >= required_work),
                        "native depth/work confirmation rule not met")
                # The final window check runs after ended_ns; its false value at
                # the boundary is conservative and may not be replaced by ours.
                require(not row["confirmed_inside_pressure_window"] or end < WINDOW_NS,
                        "late confirmation counted inside original window")
                require(observed["confirmed"] or not row["confirmed_inside_pressure_window"],
                        "confirmation aggregate contradicts native result")
                joined = any(all(any(finish <= r["started_ns"] for finish in known.get(b["id"], []))
                                 for b in expected) for r in matching_receipts)
                qualified = joined and observed["confirmed"] and row["confirmed_inside_pressure_window"]
                if not matching_receipts:
                    state = "validation_evidence_missing"
                elif not observed["confirmed"]:
                    state = "unconfirmed"
                elif qualified:
                    state = "validated"
                elif not row["confirmed_inside_pressure_window"]:
                    state = "late_or_window_refused"
                else:
                    state = "validation_evidence_missing"
                if qualified:
                    unique_transactions.add(transaction)
                    latencies.append(end - start)
        counts[state] += 1
        outcomes.append({"round": number, "transaction": transaction, "state": state,
                         "repeated_transaction": repeated, "started_ns": start, "ended_ns": end})
    declared = sum(row["confirmed_inside_pressure_window"] for row in rows)
    require(phase["all_signed_rounds_confirmed_in_window"] is (declared == 3),
            "native confirmation aggregate mismatch")
    complete = (len(rows) == 3 and counts["unknown"] == counts["validation_evidence_missing"] == 0)
    values = sorted(latencies)
    n = len(values)
    return {"mode": mode, "planned_rounds": 3, "observed_rounds": len(rows),
            "unobserved_rounds": 3 - len(rows), "outcomes": outcomes, "counts": dict(sorted(counts.items())),
            "original_claimed_confirmation_rounds": declared,
            "unique_validated_business_observed": len(unique_transactions),
            "unique_validated_transaction_ids": sorted(unique_transactions),
            "complete_declared_round_observations": complete,
            "actual_parent_phase_wall_ns": elapsed, "fixed_pressure_window_ns": WINDOW_NS,
            "observed_validated_business_per_actual_second": ratio(len(unique_transactions), elapsed),
            "validated_goodput_per_second": ratio(len(unique_transactions), elapsed) if complete else None,
            "historical_successful_imports_without_work_observation": gaps,
            "successful_round_latency_samples": n,
            "successful_round_latency_p50_nearest_rank_ns": values[(n - 1) // 2] if n else None,
            "successful_round_latency_p95_ns": values[(95 * n + 99) // 100 - 1] if n >= 20 else None,
            "successful_round_latency_p99_ns": values[(99 * n + 99) // 100 - 1] if n >= 100 else None,
            "fixed_schedule_completion": fixed_schedule_completion(outcomes, business),
            "whole_parent_phase_cpu_ns": phase["whole_parent_phase_cpu_ns"],
            "original_submissions_retained": len(phase["submissions"]),
            "original_history_calls_retained": len(phase["history"]),
            "finite_phase_criteria_met": phase["finite_phase_criteria_met"],
            "stale_work_cost_ns": None,
            "stale_work_scope": "reorged confirmations are counted; complete abandoned producer work is not observed"}


def analyze_report(report):
    require(report["schema"] == "native-public-v3-separate-process-campaign-v2"
            and report["state_backend"] == "authenticated-v1", "original native campaign schema required")
    require(all(report[key] is False for key in FALSE_FLAGS), "unsupported original qualification claim")
    require(report["settings_profile"] == "native-public-evaluation-dev-v1 + continuity_v1 explicit maintenance"
            and all(type(report[key]) is bool for key in ("finite_experiment_criteria_met", "economics_complete")),
            "original settings/outcome profile required")
    require([row["mode"] for row in report["phases"]] == list(phases.MODES),
            "all original phase slots must be retained")
    business = prepared_business(report)
    return {"phases": [phase_goodput(row, business) for row in report["phases"]],
            "finite_experiment_criteria_met": report["finite_experiment_criteria_met"],
            "economics_complete": report["economics_complete"],
            "honest_preparation_cpu_ns": report["preparation"]["cpu_ns"],
            "honest_preparation_wall_ns": report["preparation"]["wall_ns"],
            "acquisition_and_failed_attempt_costs_retained_in_original": True,
            "complete_lifecycle_cost_ns": None,
            "cross_phase_goodput_sum": None,
            "cross_phase_scope": "reset phases replay the same business; they are separate comparisons"}


def attempt_step(bundle, row, name):
    """Retain failed/cancelled processes rather than require a passing harness."""
    expected = ["+1.95.0", "test", "--locked", "--offline", "--release", "--manifest-path",
                "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--test", "public_v3_multiprocess",
                original.SELECTOR, "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"]
    require(row == bundle.json(name + ".step.json") and row["name"] == name
            and row["command"][1:] == expected and PurePosixPath(row["command"][0]).is_absolute()
            and PurePosixPath(row["command"][0]).name == "cargo"
            and row["outer_stage_timeout_seconds"] == 600, "original attempt command/budget mismatch")
    require(row["returncode"] is None or type(row["returncode"]) is int, "typed original process return code")
    require(integer(row["elapsed_ns"]) > 0 and type(row["elapsed_seconds"]) in (int, float)
            and row["elapsed_seconds"] == row["elapsed_ns"] / 1_000_000_000,
            "actual attempt elapsed identity mismatch")
    require(row["complete_success"] is (row["returncode"] == 0 and row["error"] is None),
            "original process outcome contradiction")
    for kind in ("stdout", "stderr"):
        filename = name + "." + kind + ".log"
        require(row[kind] == filename and row[kind + "_truncated"] is False
                and row[kind + "_bytes"] == bundle.files[filename]["bytes"]
                and row[kind + "_sha256"] == bundle.files[filename]["sha256"],
                "complete original attempt log identity required")
        bundle.raw(filename)


def read_bundle(root, expected_manifest_sha256, expected_head, expected_tree, *, retained_subset=False):
    digest(expected_head, 40)
    digest(expected_tree, 40)
    bundle = (original.SubsetBundle if retained_subset else original.Bundle)(root, expected_manifest_sha256)
    try:
        result = bundle.json("results.json")
        require(result["schema"] == "pon-original-native-campaign-ci-v1"
                and result["expected_head"] == expected_head and result["expected_tree"] == expected_tree
                and result["source_kind"] == "head" and result["profile"] == "release"
                and result["toolchain"] == "1.95.0" and result["state_backend"] == "authenticated-v1"
                and result["original_inputs"] == original.INPUTS and result["planned_complete_runs"] == 3,
                "source-bound original campaign identity required")
        if retained_subset:
            require(bundle.retention["source"] == {"head": expected_head, "tree": expected_tree},
                    "retained-subset source mismatch")
        names = ("source-before.json", "source-before-build.json", "source-before-campaigns.json",
                 "source-after-native.json", "source-after.json",
                 *(f"run-{n}-source-after.json" for n in (1, 2, 3)))
        counts = [original.source(bundle.json(name), expected_head, expected_tree) for name in names]
        require(all(count == counts[0] for count in counts)
                and result["source_after"] == bundle.json("source-after-native.json"),
                "source receipts changed")
        require(result["runner_sha256"] == bundle.files["run-native-campaign.py"]["sha256"],
                "original runner identity mismatch")
        resource_names = ("resource-before-build.json", "resource-after-native.json",
                          *(f"run-{n}-resource-{when}.json" for n in (1, 2, 3) for when in ("before", "after")))
        resource_values = [bundle.json(name) for name in resource_names]
        limits = [original.resource(row) for row in resource_values]
        require(all(value == limits[0] for value in limits)
                and all(row["cgroup"] == resource_values[0]["cgroup"] for row in resource_values),
                "recorded outer resource profile changed")
        built = original.step(bundle, result["build"], "build", build=True)
        artifacts = [row for row in map(original.strict_json, built.splitlines())
                     if row.get("reason") == "compiler-artifact"
                     and row.get("target", {}).get("name") == "public_v3_multiprocess"
                     and row.get("profile", {}).get("test") is True and row.get("executable")]
        require(len(artifacts) == 1, "one actual compiler test artifact required")
        binary, artifact = result["binary"], artifacts[0]
        require(binary["retained"] == "public_v3_multiprocess.bin"
                and binary["sha256_before"] == binary["sha256_after"] == bundle.files[binary["retained"]]["sha256"]
                and integer(binary["bytes"]) == bundle.files[binary["retained"]]["bytes"]
                and binary["build_artifact"] == artifact["executable"]
                and binary["actual_compiler_artifact_profile"] == artifact["profile"]
                and artifact["profile"] == {"debug_assertions": False, "debuginfo": 0,
                                           "opt_level": "3", "overflow_checks": False, "test": True},
                "original built binary identity mismatch")
        attempts = result["attempts"]
        require([integer(row["number"]) for row in attempts] == [1, 2, 3],
                "all three attempt slots required; an absent attempt is not zero goodput")
        runs = []
        for attempt in attempts:
            name = "run-" + str(attempt["number"])
            require(attempt == bundle.json(name + "-result.json") and attempt["report_directory"] == name + "-raw",
                    "original attempt receipt mismatch")
            step = attempt["step"]
            attempt_step(bundle, step, name)
            launched = re.findall(r"^\s*Running tests/public_v3_multiprocess\.rs \(([^)]+)\)$",
                                  bundle.raw(step["stderr"]).decode("utf-8"), re.M)
            require(launched == [binary["build_artifact"]] and step["cwd"] == result["build"]["cwd"],
                    "original runtime executable/source mismatch")
            report_name = name + "-raw/report.json"
            require(attempt["report_sha256"] == bundle.files[report_name]["sha256"], "original report identity mismatch")
            report = bundle.json(report_name)
            policy_pin = result.get("expected_public_policy_id")
            if policy_pin is not None:
                digest(policy_pin)
                require(phases.identify_observation(report["public_resource_policy"])["policy_id"] == policy_pin,
                        "original public resource policy mismatch")
            readback = analyze_report(report)
            runs.append({"number": attempt["number"], "report_sha256": attempt["report_sha256"],
                         "actual_complete_attempt_wall_ns": step["elapsed_ns"],
                         "original_process_returncode": step["returncode"], "original_process_error": step["error"],
                         "original_attempt_complete_success": attempt["complete_success"],
                         "original_report_validation_failure": attempt["report_validation_failure"], **readback})
        return {"schema": SCHEMA, "measured_head": expected_head, "measured_tree": expected_tree,
                "artifact_manifest_sha256": expected_manifest_sha256, "artifact_coverage": bundle.coverage,
                "retained_binary_bytes_verified": binary["retained"] in bundle.verified_paths,
                "outer_resource_limits": limits[0],
                "planned_attempts": 3, "runs": runs, "original_campaign_complete_success": result["complete_success"],
                "original_campaign_failure": result["failure"], "original_finalization_failures": result["finalization_failures"],
                "qualification": "HOLD_NO_GO",
                "scope": {"reader_executes_w1_or_verifies_signatures": False, "host_or_execution_attestation": False,
                          "native_observation_and_byte_identity_join_only": True,
                          "source_receipt_internal_consistency_verified": True,
                          "native_finality_authenticated": False, "public_throughput_qualified": False,
                          "missing_observation_is_zero": False, "rounds_are_unique_business": False,
                          "independent_operators_qualified": False, "whole_chain_pq_qualified": False,
                          "model_benefit_measured": False, "application_savings_measured": False,
                          "minimum_legal_work_cost_proved": False, "production_activation": False}}
    finally:
        bundle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--retained-subset", action="store_true")
    args = parser.parse_args()
    import json
    print(json.dumps(read_bundle(args.bundle, args.expected_manifest_sha256, args.expected_head,
                                 args.expected_tree, retained_subset=args.retained_subset),
                     indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)

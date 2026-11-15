#!/usr/bin/env python3
"""Byte-verified, failure-preserving diagnostic for the original native 3x3 ZIP.

This is an ancillary readback, not the original acceptance reader. It neither
executes native tests nor certifies business TPS, service SLOs or resource limits.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zipfile

SCHEMA = "trnm-native-campaign-zip-diagnostic-v1"
MODES = ("baseline", "from-zero", "late-product")
WINDOW_NS = 30_000_000_000
MAX_ARCHIVE_ITEMS = 4096
MAX_TOTAL_BYTES = 1_073_741_824
MAX_MEMBER_BYTES = 67_108_864
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def u64(value):
    require(type(value) is int and 0 <= value < 2**64, "integer u64 required")
    return value


def maybe_u64(value):
    return None if value is None else u64(value)


def hex_exact(value, pattern):
    require(type(value) is str and pattern.fullmatch(value), "exact hex digest required")
    return value


def bytes_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def bounded_path(name):
    require(type(name) is str and name and len(name) <= 1024,
            "invalid archive path")
    pure = PurePosixPath(name)
    require(not name.startswith("/") and "\\" not in name and "\x00" not in name
            and all(chunk not in ("", ".", "..") for chunk in name.split("/"))
            and str(pure) == name, "unsafe or noncanonical archive member")


def verified_zip(path, expected_digest):
    hex_exact(expected_digest, HEX64)
    require(bytes_sha(path) == expected_digest, "original ZIP SHA256 mismatch")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= MAX_ARCHIVE_ITEMS, "bounded ZIP member census required")
        names = [i.filename for i in infos]
        require(len(set(names)) == len(names), "duplicate ZIP member refused")
        for info in infos:
            bounded_path(info.filename)
            require(not info.is_dir() and info.file_size <= MAX_MEMBER_BYTES,
                    "ZIP directory or excessive member size refused")
        require(sum(info.file_size for info in infos) <= MAX_TOTAL_BYTES,
                "excessive ZIP uncompressed total refused")
        require("artifact-files.json" in names and "results.json" in names,
                "original ZIP manifest or campaign result missing")
        manifest = json.loads(archive.read("artifact-files.json"))
        require(type(manifest) is dict and type(manifest.get("files")) is list,
                "original file manifest required")
        listed = manifest["files"]
        require(len(listed) + 1 == len(infos), "original ZIP inventory not complete")
        seen, total = set(), 0
        for row in listed:
            require(type(row) is dict, "manifest file record required")
            name = row.get("path")
            bounded_path(name)
            require(name != "artifact-files.json" and name in names and name not in seen,
                    "missing/repeated manifest member")
            seen.add(name)
            size = u64(row.get("bytes"))
            hex_exact(row.get("sha256"), HEX64)
            require(size == archive.getinfo(name).file_size,
                    "original member length mismatch")
            h, measured = hashlib.sha256(), 0
            with archive.open(name) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    measured += len(block)
                    require(measured <= size, "member expansion exceeds listed size")
                    h.update(block)
            require(measured == size and h.hexdigest() == row["sha256"],
                    "original member digest mismatch: " + name)
            total += size
        require(seen == set(names) - {"artifact-files.json"},
                "original ZIP extra member refused")
        result = json.loads(archive.read("results.json"))
        reports = {i: json.loads(archive.read(f"run-{i}-raw/report.json"))
                   for i in (1, 2, 3)}
        return result, reports, {"zip_sha256": expected_digest,
                                 "listed_member_count": len(listed),
                                 "verified_uncompressed_member_bytes": total,
                                 "all_original_listed_sha256_verified": True}


def positive_native(row):
    """Check the retained native positive binding, not cross-operator finality."""
    start, end = u64(row.get("started_ns")), u64(row.get("ended_ns"))
    require(start <= end < WINDOW_NS, "positive report violates strict window")
    native = row.get("observation")
    require(type(native) is dict and native.get("confirmed") is True
            and native.get("reorged") is False
            and native.get("finalized") is False
            and native.get("execution_authority") is False
            and type(native.get("depth")) is int and native["depth"] == 6,
            "retained positive native observation mismatch")
    included, observed = u64(native.get("included_height")), u64(native.get("observed_height"))
    require(observed - included == 6, "retained positive depth mismatch")
    for raw, tied in (("transaction", "transaction"),
                      ("included_block", "included_block"),
                      ("tip", "observed_tip")):
        hex_exact(row.get(raw), HEX64)
        require(row[raw] == native.get(tied), "retained positive identity mismatch")
    actual = int(hex_exact(native.get("work_delta"), HEX128), 16)
    required = int(hex_exact(native.get("required_work_delta"), HEX128), 16)
    require(actual >= required, "retained positive descendant work mismatch")
    return row["transaction"]


def classify_round(row):
    require(type(row) is dict, "original round object required")
    flag = row.get("confirmed_inside_pressure_window")
    require(flag is None or type(flag) is bool, "original round flag malformed")
    if flag is True:
        return "timely_positive", positive_native(row)
    start, end = maybe_u64(row.get("started_ns")), maybe_u64(row.get("ended_ns"))
    require(start is None or end is None or start <= end, "original round clock reversal")
    if flag is False and end is not None and end >= WINDOW_NS:
        return "not_timely_at_full_window", None
    return "unknown_or_incomplete", None


def inspect(result, reports, source_head, source_tree, inventory):
    hex_exact(source_head, HEX40)
    hex_exact(source_tree, HEX40)
    require(type(result) is dict and result.get("schema") == "pon-original-native-campaign-ci-v1"
            and result.get("expected_head") == source_head
            and result.get("expected_tree") == source_tree,
            "original campaign source identity mismatch")
    source = result.get("source_after") or {}
    require(source.get("tested_commit") == source_head
            and source.get("tested_tree") == source_tree,
            "retained source-after mismatch")
    originals = result.get("original_inputs") or {}
    require(originals.get("attacker_processes") == [0, 24, 24]
            and originals.get("phase_seconds") == 30
            and originals.get("modes") == list(MODES)
            and originals.get("business_blocks") == 21
            and originals.get("seed_transfers") == 1024
            and originals.get("seed_blocks") == 4
            and result.get("planned_complete_runs") == 3,
            "original 0/24/24 workload or budget changed")
    attempts = result.get("attempts")
    require(type(attempts) is list and len(attempts) == 3,
            "all three original attempted runs required")
    by_run = {}
    for row in attempts:
        require(type(row) is dict and type(row.get("number")) is int
                and row["number"] in (1, 2, 3)
                and row["number"] not in by_run,
                "duplicate/missing original run")
        require(row.get("report_directory") == f"run-{row['number']}-raw",
                "original report directory mismatch")
        by_run[row["number"]] = row
    rows, identities = [], []
    for i in (1, 2, 3):
        report = reports[i]
        require(type(report) is dict and report.get("schema") == "native-public-v3-separate-process-campaign-v2"
                and report.get("state_backend") == "authenticated-v1"
                and type(report.get("phases")) is list and len(report["phases"]) == 3,
                "original native report namespace/phase count mismatch")
        # The actual bytes have already been checked against artifact-files.json.
        # The original attempt's SHA is checked by verify_report_sha below.
        for index, mode in enumerate(MODES):
            phase = report["phases"][index]
            require(type(phase) is dict and phase.get("mode") == mode
                    and phase.get("duration_seconds") == 30
                    and phase.get("state_backend") == "authenticated-v1"
                    and type(phase.get("attacker_processes_requested")) is int
                    and phase["attacker_processes_requested"] == (0 if index == 0 else 24),
                    "original phase/attacker plan mismatch")
            ready = maybe_u64(phase.get("attacker_processes_ready"))
            require(ready is None or ready <= phase["attacker_processes_requested"],
                    "attacker-ready count impossible")
            rounds = phase.get("confirmations")
            require(type(rounds) is list and len(rounds) <= 3,
                    "bounded original confirmation rounds required")
            observed, categories = set(), []
            for item in rounds:
                ri = u64(item.get("round")) if type(item) is dict else None
                require(ri in (0, 1, 2) and ri not in observed,
                        "duplicate/unplanned confirmation round")
                observed.add(ri)
            for ri in (0, 1, 2):
                actual = next((v for v in rounds if v["round"] == ri), None)
                if actual is None:
                    categories.append("not_observed")
                    continue
                status, txid = classify_round(actual)
                categories.append(status)
                if txid is not None:
                    identities.append(txid)
            service = phase.get("service_outcome") or {}
            service = service.get("Ok") if type(service) is dict else None
            require(service is None or type(service) is dict, "service outcome malformed")
            cost = {key: maybe_u64((service or {}).get(key)) for key in (
                "accepted_connections", "executor_refusals", "completed_submit",
                "mutation_dispatch_excluding_work_cpu_ns", "mutation_full_work_cpu_ns",
                "mutation_cpu_charged_ns")}
            flow = phase.get("final_actual_flow")
            require(flow is None or type(flow) is dict, "actual CPU flow malformed")
            if flow is not None:
                cost["paid_cpu_debit_ns"] = maybe_u64(flow.get("paid_cpu_debit_ns"))
                cost["credited_refill_ns"] = maybe_u64(flow.get("credited_refill_ns"))
            else:
                cost["paid_cpu_debit_ns"] = cost["credited_refill_ns"] = None
            cost["whole_parent_phase_cpu_ns"] = maybe_u64(phase.get("whole_parent_phase_cpu_ns"))
            cost["whole_parent_phase_wall_ns"] = maybe_u64(phase.get("whole_parent_phase_wall_ns"))
            rows.append({"run": i, "mode": mode,
                         "attacker_processes_requested": phase["attacker_processes_requested"],
                         "attacker_processes_ready": ready,
                         "observation_statuses": categories,
                         "original_phase_gate_met": phase.get("finite_phase_criteria_met") is True,
                         "receiver_client_state_equal": phase.get("receiver_client_state_equal"),
                         "genuine_budget_depletion_observed": phase.get("genuine_budget_depletion_observed"),
                         "verifier_errors": phase.get("verifier_errors"),
                         "costs_observed_not_additive": cost})
    counts = Counter(status for row in rows for status in row["observation_statuses"])
    require(sum(counts.values()) == 27, "original twenty-seven-slot denominator mismatch")
    return {"schema": SCHEMA, "original_head": source_head,
            "original_tree": source_tree, "archive": inventory,
            "original_campaign_complete_success": result.get("complete_success"),
            "original_three_run_gate_met": all(r["original_phase_gate_met"] for r in rows),
            "observations": rows,
            "planned_confirmation_rounds": 27,
            "reported_positive_native_rounds": counts["timely_positive"],
            "full_window_not_timely_rounds": counts["not_timely_at_full_window"],
            "unobserved_round_slots": counts["not_observed"],
            "incomplete_or_conflicting_rounds": counts["unknown_or_incomplete"],
            "distinct_reported_positive_transaction_hashes": len(set(identities)),
            "unique_independent_business_transactions": None,
            "confirmed_unique_business_tps": None,
            "actual_4s_host_gate": None,
            "production_activation": False,
            "qualification": "HOLD_NO_GO",
            "scope": "exact ZIP manifest, original native diagnostic and phase CPU; no independent operation identity, source custody, business census or qualified TPS"}


def recheck(path, digest, head, tree):
    result, reports, inventory = verified_zip(path, digest)
    with zipfile.ZipFile(path) as archive:
        for attempt in result["attempts"]:
            index = u64(attempt["number"])
            name = f"run-{index}-raw/report.json"
            hex_exact(attempt.get("report_sha256"), HEX64)
            require(hashlib.sha256(archive.read(name)).hexdigest() == attempt["report_sha256"],
                    "original result report SHA256 mismatch")
    return inspect(result, reports, head, tree, inventory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = recheck(args.artifact, args.artifact_sha256,
                         args.expected_head, args.expected_tree)
        value = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output is None:
            print(value, end="")
        else:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(value)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, IndexError, json.JSONDecodeError) as error:
        print("original campaign ZIP diagnostic refused: " + str(error), file=sys.stderr)
        return 2
    return 1  # Authentic readback is not service qualification.


if __name__ == "__main__":
    raise SystemExit(main())

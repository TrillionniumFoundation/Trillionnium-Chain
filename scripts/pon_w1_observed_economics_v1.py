#!/usr/bin/env python3
"""Replay fixed classical strategies against an identical finite CPU ledger.

The inputs are complete V4 native observations. No timing is extrapolated, no
sample chooses its fastest strategy, and a later sample cannot skip an expensive
earlier search. This is a conservative accounting replay of recorded CPU phases,
not a newly executed miner, a wall-clock service result, or an attacker minimum.
All cohort overhead is paid before its first search because V4 does not locate
that overhead within the cohort. Partial searches consume budget without being
credited as complete proofs. Quantum hardware prices and energy remain unknown.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
import pon_w1_preparation_strategy_reader_v4 as v4

SCHEMA = "pon-w1-observed-economics-v1"
ROOT = Path(__file__).resolve().parents[1]
BUDGETS_NS = (1_000_000, 10_000_000, 100_000_000, 1_000_000_000)
MAX_MEMBERS = 256
MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_RAW_BYTES = 2 * 1024 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ratio(numerator, denominator):
    if denominator == 0:
        return None
    from fractions import Fraction
    value = Fraction(numerator, denominator)
    return {"numerator": value.numerator, "denominator": value.denominator}


def strict_json(raw):
    return json.loads(raw, object_pairs_hook=v4.common.unique_object,
                      parse_constant=v4.common.reject_number)


class BoundedDecompression:
    """Bound every decompressed byte, including tar headers and trailing data."""
    def __init__(self, source, limit):
        self.source, self.limit, self.consumed = source, limit, 0

    def read(self, size=-1):
        remaining = self.limit - self.consumed
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.source.read(requested)
        self.consumed += len(data)
        require(self.consumed <= self.limit, "TOTAL_DECOMPRESSED_STREAM_BOUND")
        return data


def read_records(source):
    """Validate original rows without creating a gigabyte temporary extraction."""
    records, digest, total, count = v4.Records(), hashlib.sha256(), 0, 0
    maximum = 3 + v4.SAMPLES * (len(v4.STRATEGIES) + max(v4.HORIZONS)
        * (len(v4.STRATEGIES) * (2 + len(v4.PATHS) * len(v4.CASES)) + 1))
    while line := source.readline(v4.MAX_LINE + 1):
        total += len(line)
        count += 1
        require(line.endswith(b"\n") and len(line) <= v4.MAX_LINE
                and total <= v4.MAX_BYTES and count <= maximum, "BOUNDED_COMPLETE_ROWS")
        digest.update(line)
        records.add(v4.common.decode(line))
    require(records.ended, "MISSING_COMPLETE_END")
    return records, {"sha256": digest.hexdigest(), "bytes": total, "rows": count}


def fixed_budget_replay(records, strategy, budget_ns):
    """A fixed sample order, one setup per actual cohort, no partial-proof credit.

    A CPU phase ledger is not an observed timeline. Charging all cohort residual
    overhead upfront is conservative for these retained intervals, but supplies
    no worst-case bound for a different run or faster implementation.
    """
    require(strategy in v4.STRATEGIES, "FIXED_STRATEGY")
    require(type(budget_ns) is int and 0 <= budget_ns <= 10**18, "CPU_BUDGET")
    paid = completed_searches = attempts = winners = setups = 0
    stopped = None

    def charge(amount, identity):
        nonlocal paid, stopped
        require(type(amount) is int and amount > 0, "POSITIVE_RECORDED_PHASE")
        available = budget_ns - paid
        taken = min(amount, available)
        paid += taken
        if taken < amount:
            stopped = {**identity, "phase_cpu_ns": amount, "paid_cpu_ns": taken}
            return False
        return True

    active = charge(records.campaign["material_setup"]["cpu_ns"],
                    {"phase": "common_material_setup"})
    for sample in range(v4.SAMPLES):
        if not active:
            break
        cohort = records.cohorts[sample, strategy]
        searches = cohort["searches"]
        prelude = cohort["total"]["cpu_ns"] - sum(s["timing"]["cpu_ns"] for s in searches)
        require(prelude >= cohort["setup"]["cpu_ns"], "COHORT_OVERHEAD_UNDERCOUNT")
        active = charge(prelude, {"phase": "setup_and_frontloaded_cohort_overhead", "sample": sample})
        setups += int(active)
        for searched in searches:
            if not active:
                break
            active = charge(searched["timing"]["cpu_ns"],
                {"phase": "complete_search", "sample": sample, "search_index": searched["index"]})
            if active:
                completed_searches += 1
                attempts += searched["attempt_count"]
                winners += int(searched["winner"] is not None)
    return {
        "budget_cpu_ns": budget_ns, "paid_cpu_ns": paid,
        "unused_cpu_ns": budget_ns - paid, "complete_setups": setups,
        "complete_searches": completed_searches, "attempts_in_complete_searches": attempts,
        "recorded_relation_valid_proofs": winners if not records.alerts else None,
        "complete_recorded_target_hits": winners,
        "unlocated_attempts_in_partial_search": stopped is not None and stopped["phase"] == "complete_search",
        "stopped_phase": stopped,
        "termination": "budget-censored" if stopped else "recorded-schedule-exhausted",
    }


def summarize_records(records, identity, budgets=BUDGETS_NS):
    require(records.ended, "MISSING_COMPLETE_END")
    require(type(budgets) is tuple and budgets == BUDGETS_NS, "BUDGET_INVENTORY")
    choice = {name: records.campaign[name] for name in ("class", "target_index", "reuse_winners", "purpose")}
    rows = v4.summary(records)
    for row in rows:
        row["common_material_setup_charged_once_cpu_ns"] = records.campaign["material_setup"]["cpu_ns"]
        total = row["inclusive_cohort_total"]["cpu_ns"] + records.campaign["material_setup"]["cpu_ns"]
        row["producer_and_common_material_cpu_ns"] = total
        row["producer_and_common_material_per_recorded_valid_proof_ns"] = (
            ratio(total, row["target_hits"]) if not records.alerts else None)
        row["observed_setup_share_of_producer_cpu"] = ratio(row["setup_total"]["cpu_ns"], row["inclusive_cohort_total"]["cpu_ns"])
        row["fixed_budget_replays"] = [fixed_budget_replay(records, row["strategy"], budget) for budget in budgets]
    return {
        "selection": choice, "raw_observation": identity,
        "material_identity": records.material_identity,
        "semantic_alerts": records.alerts, "strategy_costs": rows,
        "matched_streams": [dict(sample=sample, search_index=index,
            stream_sha256=value[0], attempts=value[1], winner=value[2])
            for (sample, index), value in sorted(records.canonical.items())],
    }


def assemble_report(shards, metadata, *, source_root=ROOT):
    expected = {(name, target, horizon) for name in v4.CLASSES
        for target in v4.COST_TARGET_INDICES for horizon in v4.HORIZONS}
    controls = {(name, target, 1) for name in v4.CLASSES for target in (2, 3)}
    seen, streams = set(), {}
    for shard in shards:
        selected = shard["selection"]
        key = selected["class"], selected["target_index"], selected["reuse_winners"]
        require(key in expected | controls and key not in seen, "SHARD_INVENTORY")
        seen.add(key)
        if key in expected:
            for row in shard["matched_streams"]:
                identity = key[:2] + (row["sample"], row["search_index"])
                require(identity not in streams or streams[identity] == row, "SHARED_PREFIX_CHANGED")
                streams[identity] = row
    require(seen == expected | controls, "COMPLETE_COST_GRID_AND_SEPARATE_CONTROLS_REQUIRED")
    declaration, manifest = metadata["declaration"], metadata["manifest"]
    require(manifest["planned"] == manifest["observed_commands"] == 48
            and len(manifest["commands"]) == 48 and not manifest["unobserved_planned_commands"], "PROCESS_INVENTORY")
    command_names, process_stdout = set(), set()
    by_digest = {item["raw_observation"]["sha256"]: item for item in shards}
    require(len(by_digest) == 48, "DUPLICATE_NATIVE_STDOUT")
    for command in manifest["commands"]:
        receipt = command["process"]
        require(command["name"] not in command_names, "DUPLICATE_PROCESS")
        command_names.add(command["name"])
        require(receipt["stdout_sha256"] in by_digest, "PROCESS_STDOUT_BINDING")
        require(receipt["stdout_sha256"] not in process_stdout, "DUPLICATE_PROCESS_STDOUT")
        process_stdout.add(receipt["stdout_sha256"])
        selected = by_digest[receipt["stdout_sha256"]]["selection"]
        expected_name = (f"{selected['class']}-t{selected['target_index']}-h{selected['reuse_winners']}"
            if selected["purpose"] == "search-cost"
            else f"{selected['class']}-control-t{selected['target_index']}")
        require(command["name"] == expected_name and command["purpose"] == selected["purpose"],
                "PROCESS_SELECTION_BINDING")
        require(type(receipt["argv"]) is list and len(receipt["argv"]) == 8
                and receipt["argv"][1:] == [v4.SELECTOR, "--class", selected["class"],
                    "--target-index", str(selected["target_index"]), "--reuse-winners",
                    str(selected["reuse_winners"])], "PROCESS_ARGUMENT_BINDING")
        observation = command["archives"]["stdout.jsonl"]
        actual = by_digest[receipt["stdout_sha256"]]["raw_observation"]
        require(observation["raw_sha256"] == actual["sha256"]
                and observation["raw_bytes"] == actual["bytes"], "PROCESS_ARCHIVE_BINDING")
        require(receipt["process_complete"] is True and receipt["returncode"] == 0
                and receipt["timed_out"] is False and receipt["observer_interrupted"] is False
                and receipt["resource_failure"] is None, "FAILED_PROCESS_REMAINS_UNQUALIFIED")
    require(process_stdout == set(by_digest), "PROCESS_STDOUT_COVERAGE")
    mismatches = []
    for name, digest in declaration["source_sha256"].items():
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts, "SOURCE_PATH")
        path = Path(source_root) / relative
        actual = sha(path.read_bytes()) if path.is_file() else None
        if actual != digest:
            mismatches.append({"path": name, "observed_sha256": digest, "current_sha256": actual})
    compact = [{key: value for key, value in shard.items() if key != "matched_streams"}
               for shard in shards]
    cost_rows = [s for s in compact if s["selection"]["purpose"] == "search-cost"]
    cost_rows.sort(key=lambda s: (v4.CLASSES.index(s["selection"]["class"]),
        s["selection"]["target_index"], s["selection"]["reuse_winners"]))
    return {
        "schema": SCHEMA, "qualification_status": "HOLD",
        "observation_scope": "derived-from-complete-retained-native-V4-records-no-new-miner-execution",
        "cost_shards": 36, "separate_control_shards": 12,
        "unique_cost_search_streams": len(streams), "cost_grid": cost_rows,
        "controls": [s for s in compact if s["selection"]["purpose"] != "search-cost"],
        "budget_policy": {"cpu_budgets_ns": list(BUDGETS_NS), "sample_order": list(range(v4.SAMPLES)),
            "strategy_choice": "one-fixed-strategy-for-all-samples", "cohort_overhead": "frontloaded",
            "common_material_setup": "charged-once-to-each-counterfactual-strategy",
            "partial_search": "charged-without-completed-attempt-or-proof-credit",
            "future_sample_skipping": False, "beyond_observed_schedule_extrapolation": False,
            "separate_verification_propagation_and_evidence_cpu_in_budget": False},
        "execution_source": {"observed_base_commit": declaration["base_commit"],
            "observed_working_tree_dirty": declaration["tracked_or_untracked_working_changes"],
            "native_binary_sha256": declaration["binary_sha256"],
            "declared_source_files": len(declaration["source_sha256"]),
            "current_source_mismatches": mismatches,
            "current_declared_source_matches": not mismatches,
            "fresh_measurement_on_current_source": False},
        "machine_economics": {"equal_cpu_budget_replay_only": True,
            "concurrent_workers_measured": False, "energy_joules": None,
            "classical_machine_total_price": None, "quantum_machine_total_price": None,
            "same_total_resource_quantum_advantage": None,
            "cheapest_legal_implementation_lower_bound": None},
        "claims": {"native_block_admission_observed": False,
            "cross_horizon_independence_claimed": False, "per_sample_fastest_oracle_used": False,
            "parallel_speedup_measured": False, "quantum_hardware_executed": False,
            "hardware_calibrated": False, "mining_qualified": False, "consensus_security_proved": False},
    }


def analyze_archive(index_path):
    """Check every transport/member byte; execute no archive member."""
    index_path = Path(index_path)
    index_bytes = index_path.read_bytes()
    index = strict_json(index_bytes)
    require(index["schema"] == "pon-w1-preparation-lossless-archive-v4", "ARCHIVE_SCHEMA")
    require(0 < len(index["members"]) <= MAX_MEMBERS, "MEMBER_BOUND")
    declared = {entry["name"]: entry for entry in index["members"]}
    require(len(declared) == len(index["members"]), "DUPLICATE_DECLARED_MEMBER")
    require(all(type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MAX_RAW_BYTES
                for entry in declared.values()), "DECLARED_MEMBER_BYTE_BOUND")
    require(sum(entry["bytes"] for entry in declared.values()) <= MAX_RAW_BYTES, "RAW_ARCHIVE_BOUND")
    require(0 < index["archive_bytes"] <= MAX_COMPRESSED_BYTES, "COMPRESSED_ARCHIVE_BOUND")
    shards, metadata, seen = [], {}, set()
    with tempfile.TemporaryFile() as compressed:
        digest, size = hashlib.sha256(), 0
        for number, part in enumerate(index["parts"]):
            require(part["number"] == number and Path(part["file"]).name == part["file"], "PART_IDENTITY")
            raw = (index_path.parent / part["file"]).read_bytes()
            require(len(raw) == part["bytes"] and sha(raw) == part["sha256"], "PART_DIGEST")
            size += len(raw)
            require(size <= MAX_COMPRESSED_BYTES, "COMPRESSED_ARCHIVE_BOUND")
            digest.update(raw)
            compressed.write(raw)
        require(size == index["archive_bytes"] and digest.hexdigest() == index["archive_sha256"], "ARCHIVE_DIGEST")
        compressed.seek(0)
        process = subprocess.Popen(["zstd", "-d", "-q", "-c"], stdin=compressed, stdout=subprocess.PIPE)
        # USTAR: a 512-byte header and at most 511 bytes of padding per member,
        # plus the final blocking record. PAX or trailing decompression cannot
        # consume unbounded CPU/I/O after the declared members have ended.
        decoded = BoundedDecompression(process.stdout,
            sum(entry["bytes"] for entry in declared.values()) + len(declared) * 1024 + 10240)
        try:
            with tarfile.open(fileobj=decoded, mode="r|") as archive:
                for member in archive:
                    require(member.isfile() and member.name in declared and member.name not in seen, "ARCHIVE_MEMBER")
                    require(not member.pax_headers, "USTAR_WITHOUT_EXTENDED_HEADERS_REQUIRED")
                    expected = declared[member.name]
                    require(member.size == expected["bytes"] and member.mode == expected["mode"], "MEMBER_SIZE_MODE")
                    source = archive.extractfile(member)
                    if member.name.endswith("/stdout.jsonl"):
                        records, identity = read_records(source)
                        shards.append(summarize_records(records, identity))
                        digest_hex = identity["sha256"]
                    else:
                        digest = hashlib.sha256()
                        retained = bytearray()
                        keep = member.name in ("v4-cpu-1/declaration.json", "v4-cpu-1/manifest.json")
                        while block := source.read(1024 * 1024):
                            digest.update(block)
                            if keep:
                                retained.extend(block)
                                require(len(retained) <= 4 * 1024 * 1024, "METADATA_BOUND")
                        digest_hex = digest.hexdigest()
                        if keep:
                            metadata[Path(member.name).stem] = strict_json(retained)
                    require(digest_hex == expected["sha256"], "MEMBER_DIGEST")
                    seen.add(member.name)
            while decoded.read(1024 * 1024):
                pass
            require(process.wait() == 0 and seen == set(declared), "COMPLETE_ARCHIVE_REQUIRED")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        require(set(metadata) == {"declaration", "manifest"}, "MISSING_EXECUTION_METADATA")
    report = assemble_report(shards, metadata)
    report["archive_readback"] = {"index_sha256": sha(index_bytes),
        "archive_sha256": index["archive_sha256"], "verified_members": len(seen),
        "verified_parts": len(index["parts"]), "raw_bytes": sum(x["bytes"] for x in declared.values()),
        "total_decompressed_bytes_including_headers_and_padding": decoded.consumed,
        "all_original_stdout_rows_reparsed": True}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-index", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze_archive(args.archive_index)
    with args.output.open("x") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"), allow_nan=False)
        output.write("\n")


if __name__ == "__main__":
    main()

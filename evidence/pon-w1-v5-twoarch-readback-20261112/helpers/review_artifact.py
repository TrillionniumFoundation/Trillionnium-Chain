#!/usr/bin/env python3
"""Verify one frozen head artifact and analyze every preregistered fixed arm.

No native code is executed. Original source-pinned readers validate all records;
archive/manifest links and raw-record producer arithmetic are checked separately.
The output is an evidence readback, never a security or hardware-cost lower bound.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import zipfile

HEAD = "229b14c2d366a257f51f287d502a550df2332338"
TREE = "b386c32458589f81944ddd69c04a56c28c55e284"
ARCHITECTURES = {
    "arm64": {"zip_bytes": 45024075,
              "zip_sha": "da553653d88eced182fa698e2c4d099cc7bb5c64d29083a87bf6791c2cbde6fd",
              "elf_machine": 183, "machine": "aarch64", "target": "aarch64-unknown-linux-gnu",
              "artifact_id": 13917333858, "job_id": 130949245425},
    "x64": {"zip_bytes": 45074329,
            "zip_sha": "0442f1fc392367d83803944e46bd1c803dfe55a9ec0f2bcb6bb32d37ede152c2",
            "elf_machine": 62, "machine": "x86_64", "target": "x86_64-unknown-linux-gnu",
            "artifact_id": 13917828728, "job_id": 130949245331},
}
SOURCE_PINS = {
    "pon_w1_cost_matrix_reader.py": "fe710e05048916145180cf1cf8870bc31a94dec8",
    "pon_w1_preparation_strategy_reader_v4.py": "7c08d876d51be7226f958f2c6c4509cb072f60d1",
    "pon_w1_rank_batch_reader_v5.py": "9cc4a0a59a3e5dd0d0e2acbcd380ad685c9be287",
}


def need(test, message):
    if not test:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def canon(item):
    return json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False)


def same(left, right, message):
    need(canon(left) == canon(right), message)


def load(path):
    return strict_loads(path.read_bytes())


def relative(root, name):
    item = PurePosixPath(name)
    need(not item.is_absolute() and all(p not in (".", "..", "") for p in item.parts), "unsafe relative path")
    path = root.joinpath(*item.parts)
    need(path.is_file() and not path.is_symlink(), "missing/nonregular artifact: " + name)
    return path


def add(values):
    return {axis: sum(v[axis] for v in values) if all(v[axis] is not None for v in values) else None
            for axis in ("cpu_ns", "wall_ns")}


def ratio(value, count):
    return None if value is None or count == 0 else {"numerator_ns": value, "denominator": count,
                                                     "milliseconds": value / count / 1e6}


def raw_cohorts(path):
    cohorts = []
    current = None
    for line in path.open("rb"):
        row = strict_loads(line)
        kind = row["kind"]
        if kind == "cohort":
            need(current is None, "raw cohort overlap")
            current = {**row, "parts": [row["setup"]], "searches": [], "verifiers": []}
        elif kind == "search":
            current["searches"].append(row)
            current["parts"].extend([row["producer"], row["disposal"]])
        elif kind == "search-cleanup":
            current["parts"].append(row["timing"])
        elif kind == "verifier":
            current["verifiers"].append(row["timing"])
        elif kind == "cohort-end":
            current["parts"].append(row["teardown"])
            current["producer_total"] = add(current["parts"])
            current["inclusive"] = row["total"]
            cohorts.append(current)
            current = None
    need(current is None, "raw incomplete cohort")
    return cohorts


def fixed_arms(reader_report, cohorts):
    result = []
    for expected in reader_report["arms"]:
        index = expected["strategy_index"]
        selected = [c for c in cohorts if c["strategy_index"] == index]
        searches = [s for c in selected for s in c["searches"]]
        wins = sum(s["first_hit_nonce"] is not None for s in searches)
        producer = add([c["producer_total"] for c in selected])
        setup = add([c["setup"] for c in selected])
        same(producer, expected["producer_total"], "raw producer sum differs from original reader")
        same(setup, expected["paid_setup"], "raw setup differs from original reader")
        same(wins, expected["accepted_winners"], "raw winners differ")
        trials = [a for s in searches for a in s["attempts"]]
        physical = len(trials)
        same(physical, expected["physical_attempts"], "raw physical attempts differ")
        hit_count = sum(a["target_hit"] for a in trials)
        same(hit_count, expected["physical_hits"], "raw physical hits differ")
        speculative = sum(s["speculative_attempts"] for s in searches)
        same(speculative, expected["speculative_attempts"], "raw speculation differs")
        row = {**expected, "cpu_per_accepted_winner": ratio(producer["cpu_ns"], wins),
               "wall_per_accepted_winner": ratio(producer["wall_ns"], wins),
               "cpu_per_search": ratio(producer["cpu_ns"], len(searches)),
               "wall_per_search": ratio(producer["wall_ns"], len(searches)),
               "materialized_proofs": sum(s["proof_buffers"] for s in searches),
               "logical_first_hit_attempts": sum(s["attempt_count"] - s["speculative_attempts"] for s in searches),
               "physical_misses": physical - hit_count,
               "cohort_cpu_per_winner_ms": [None if not (n := sum(s["first_hit_nonce"] is not None for s in c["searches"])) or c["producer_total"]["cpu_ns"] is None
                                            else c["producer_total"]["cpu_ns"] / n / 1e6 for c in selected]}
        for axis in ("cpu_ns", "wall_ns"):
            row[axis + "_setup_share"] = None if producer[axis] in (None, 0) else setup[axis] / producer[axis]
        result.append(row)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="extracted ZIP root containing source-before.json and campaign/")
    parser.add_argument("--zip", type=Path, required=True, help="original ZIP; exact bytes/CRC/every extracted member checked")
    parser.add_argument("--arch", choices=sorted(ARCHITECTURES), required=True)
    args = parser.parse_args()
    spec = ARCHITECTURES[args.arch]
    root = args.root.resolve()
    source_root = Path(__file__).resolve().parent
    for name, expected in SOURCE_PINS.items():
        raw = (source_root / name).read_bytes()
        need(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected,
             "source-pinned reader changed: " + name)
    sys.path.insert(0, str(source_root))
    import pon_w1_rank_batch_reader_v5 as reader
    archive = {"checked": False}
    if args.zip:
        need(args.zip.stat().st_size == spec["zip_bytes"], "wrong original ZIP length")
        need(sha(args.zip.read_bytes()) == spec["zip_sha"], "wrong original ZIP hash")
        with zipfile.ZipFile(args.zip) as zipped:
            names = zipped.namelist()
            need(len(names) == len(set(names)), "duplicate ZIP names")
            need(zipped.testzip() is None, "ZIP CRC failure")
            files = 0
            for item in zipped.infolist():
                need(not stat.S_ISLNK(item.external_attr >> 16), "ZIP symlink")
                if item.is_dir():
                    continue
                path = relative(root, item.filename)
                same(sha(path.read_bytes()), sha(zipped.read(item)), "extracted ZIP member changed")
                files += 1
            need(files == 220, "original job declared 220 files")
            archive = {"checked": True, "bytes": spec["zip_bytes"], "sha256": spec["zip_sha"], "files": files,
                       "all_crc_and_extracted_member_hashes_match": True}
    outer_before, outer_after = load(root / "source-before.json"), load(root / "source-after.json")
    same(outer_before, outer_after, "outer source changed")
    need(outer_before["tested_commit"] == HEAD and outer_before["tested_tree"] == TREE,
         "outer source differs from frozen job")
    need(outer_before["tracked_worktree_verified"] is True and outer_before["tracked_entries"] == 28344
         and outer_before["tracked_bytes"] == 2583659022, "outer source guard missing")
    campaign_root = root / "campaign"
    manifest = load(campaign_root / "manifest.json")
    need(manifest["result"] == "COMPLETE_COMPONENT_OBSERVATION" and manifest["architecture"] == args.arch
         and manifest["expected_commit"] == HEAD and manifest["target"] == spec["target"]
         and manifest["host"]["machine"] == spec["machine"], "campaign did not complete on frozen native source")
    same(manifest["source_before"], manifest["source_after"], "campaign source changed")
    need(manifest["source_before"]["commit"] == HEAD and manifest["source_before"]["source_state"] == "committed-clean"
         and manifest["source_before"]["tracked_worktree_verified"] is True, "campaign source guard missing")
    same(manifest["cargo_configuration_before"], manifest["cargo_configuration_after"], "build config changed")
    same(manifest["build_environment_overrides"], {}, "build overrides")
    same(manifest["planned_shards"], [list(t) for t in reader.grid()], "changed planned grid")
    need(len(manifest["shards"]) == 66 and len(manifest["observations"]) == 69
         and manifest["failed_commands"] == 0 and manifest["commands_without_wait4_usage"] == 0,
         "incomplete commands")
    for name, expected in manifest["artifact_sha256"].items():
        need(sha(relative(campaign_root, name).read_bytes()) == expected, "manifest artifact mismatch: " + name)
    binary = relative(campaign_root, "pon_w1_rank_batch_v5").read_bytes()
    need(binary[:4] == b"\x7fELF" and binary[4] == 2 and binary[5] == 1
         and struct.unpack("<H", binary[18:20])[0] == spec["elf_machine"], "wrong ELF architecture")
    for name in ("binary_sha256_before", "binary_sha256_after", "retained_binary_sha256_before", "retained_binary_sha256_after"):
        same(manifest[name], sha(binary), "binary identities differ")
    commands = [strict_loads(line) for line in (campaign_root / "commands.jsonl").open("rb")]
    need(len(commands) == 69, "command JSONL incomplete")
    for observed, journal in zip(manifest["observations"], commands):
        same({k: v for k, v in observed.items() if k != "source_after"}, journal, "command journal binding")
        need(observed["executed"] is True and observed["exit_code"] == 0 and observed["process_exit_code"] == 0
             and observed["timed_out"] is False, "incomplete or failed process")
        same(observed["source_before"], observed["source_after"], "command source changed")
        same(observed["source_before"], manifest["source_before"], "command source identity mismatch")
        for phase in ("stdout", "stderr"):
            raw = relative(campaign_root, observed[phase]).read_bytes()
            need(len(raw) == observed[phase + "_bytes"] and sha(raw) == observed[phase + "_sha256"],
                 "command raw stream mismatch")
    reports, cells = [], []
    for number, expected_grid in enumerate(reader.grid()):
        shard = load(campaign_root / f"campaign-{number:02d}.json")
        same(shard, manifest["shards"][number], "manifest/shard mismatch")
        need(shard["result"] == "COMPLETE_COMPONENT_OBSERVATION", "incomplete shard")
        expected_class, target, horizon = expected_grid
        same(shard["configuration"], {"class": expected_class, "target_index": target, "horizon": horizon}, "shard roster changed")
        raw_path = relative(campaign_root, shard["observation"]["stdout"])
        report = reader.analyze(raw_path)
        same(report, shard["reader"], "original raw reader differs from saved summary")
        reports.append(report)
        arms = fixed_arms(report, raw_cohorts(raw_path))
        cell = {"class": expected_class, "target_index": target, "horizon": horizon,
                "purpose": report["purpose"], "counts": report["counts"], "arms": arms,
                "material_setup": report["material_setup"], "reference_setup": report["reference_setup"]}
        if target < 2:
            for axis in ("cpu_ns", "wall_ns"):
                eligible = [a for a in arms if a["supported"] and a["accepted_winners"] > 0
                            and a["producer_total"][axis] is not None]
                cell["lowest_observed_fixed_arm_" + axis] = min(eligible,
                    key=lambda a: Fraction(a["producer_total"][axis], a["accepted_winners"]))["strategy"] if eligible else None
        cells.append(cell)
    replay = reader.campaign(reports)
    same(replay, manifest["reader"], "complete campaign reader differs")
    for key, value in reader.FALSE_FLAGS.items():
        same(manifest[key], value, "qualification flag changed")
    input_names = ("source-before.json", "source-after.json", "campaign/manifest.json", "campaign/declaration.json", "campaign/commands.jsonl")
    result = {"schema": "w1-artifact-independent-readback-v1", "artifact_id": spec["artifact_id"], "architecture": args.arch,
              "run_id": 43147686753, "job_id": spec["job_id"], "commit": HEAD, "tree": TREE,
              "input_identities": {name: {"bytes": relative(root, name).stat().st_size,
                                           "sha256": sha(relative(root, name).read_bytes())} for name in input_names},
              "archive": archive, "status": "COMPLETE_COMPONENT_EVIDENCE_READBACK",
              "all_66_original_reader_summaries_reproduced": True,
              "all_fixed_arm_producer_sums_recomputed_from_raw_rows": True,
              "total_counts": replay["total_counts"], "cost_cell_count": 44, "control_cell_count": 22,
              "outer_execution": {k: manifest[k] for k in ("elapsed_ns", "observer_user_ns", "observer_system_ns",
                   "observed_wait4_cpu_ns_sum", "failed_commands", "commands_without_wait4_usage", "host")},
              "cells": cells, "security_or_cost_lower_bound": False, "production_activation": False,
              "independent_w1_math_replay": False,
              "aggregation": "ratio of sums separately for every declared class/target/horizon/fixed arm; controls excluded from cost comparisons",
              "limitations": ["8 cohorts are descriptive; correlated horizons are not pooled",
                   "physical post-winner hits are not additional accepted winners",
                   "producer clocks exclude separate fixture/reference, observation, verifier and inclusive-host costs",
                   "separate clocks do not remove same-process cache effects",
                   "reader/clock declarations do not independently authenticate native physical execution"]}
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "HOLD", "error": str(error)}), file=sys.stderr)
        sys.exit(2)

#!/usr/bin/env python3
"""Re-read one actual v2 artifact; never run a miner or manufacture timing data.

The gzip parts are byte-for-byte pieces of the original complete CI log. The
frozen original checker and summarizer remain the observation owners. This
script additionally binds their source, counts shared header contexts once and
reports a prespecified representative cohort without discarding the full grid.
"""
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

HERE = Path(__file__).resolve().parent
SOURCE = "e9c4bb0d3a324b1d79b7b99326512bfb707d0025"
TREE = "28bb7cb923a415ccc30ff5eaac83ffd2b99dd13f"


def require(value, message):
    if not value:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def exact_file(root, item):
    relative = PurePosixPath(item["path"])
    require(not relative.is_absolute() and ".." not in relative.parts, "unsafe evidence path")
    path = root / relative
    require(path.is_file() and not path.is_symlink(), "regular evidence file required")
    data = path.read_bytes()
    require(len(data) == item["bytes"] and hashlib.sha256(data).hexdigest() == item["sha256"],
            "changed evidence bytes: " + str(relative))
    if "git_blob_sha1" in item:
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                == item["git_blob_sha1"], "changed original Git blob")
    return data


def restore(output):
    manifest = load(HERE / "raw-cost-gzip.parts.json")
    require(manifest["schema"] == "pon-w1-lossless-gzip-parts-v1", "part schema")
    digest = hashlib.sha256()
    total = 0
    path = output / "stdout.jsonl.gz"
    with path.open("xb") as destination:
        for index, part in enumerate(manifest["parts"]):
            require(part["index"] == index and part["offset"] == total, "part order/offset")
            raw = exact_file(HERE, part)
            require(0 < len(raw) <= 256 * 1024, "part byte bound")
            destination.write(raw)
            digest.update(raw)
            total += len(raw)
    require(total == manifest["bytes"] == 7292930
            and digest.hexdigest() == manifest["sha256"], "incomplete original gzip")
    with gzip.open(path, "rb") as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    require(len(raw) == manifest["uncompressed_bytes"] == 28291500
            and raw.endswith(b"\n")
            and hashlib.sha256(raw).hexdigest() == manifest["uncompressed_sha256"],
            "incomplete original uncompressed observations")
    return raw, manifest


def review(rows, summary, capture):
    begin = rows[0]
    require(begin["seed"] == 1 and begin["rounds"] == 2 and begin["max_horizon"] == 256
            and begin["attempt_budget"] == 8, "the observed original cohort changed")
    require(len(bytes.fromhex(begin["native_seed_header"])) == 318, "fixed PNH1 header")
    materials = {row["name"]: row["task"] for row in rows if row["kind"] == "material"}
    complete = [row for row in rows if row["kind"] == "cohort" and row["status"] == "complete"]
    offered = [row for row in rows if row["kind"] == "cohort"]
    attempts, wins, native_wins = set(), set(), set()
    for row in complete:
        for search in row["searches"]:
            first = begin["seed"] * (1 << 32) + row["round"] * (1 << 24)
            first += search["search"] * begin["attempt_budget"]
            for offset in range(search["attempts"]):
                attempts.add((materials[row["material"]], row["target"], first + offset))
            if search["winner"]:
                key = (materials[row["material"]], row["target"], first + search["attempts"] - 1)
                wins.add(key)
                if row["material"] == "genesis-maintenance" and row["target"] == begin["native_target"]:
                    native_wins.add(key)
    arms = {}
    for arm in ("low-rank-prefix-scalar", "low-rank-prefix-paired"):
        all_rows = [row for row in offered if row["strategy"] == arm]
        live = [row for row in all_rows if row["status"] == "complete"]
        arms[arm] = {
            "offered_cohorts": len(all_rows), "complete_cohorts": len(live),
            "unsupported_cohorts": len(all_rows) - len(live),
            "supported_materials": sorted({row["material"] for row in live}),
            "attempts": sum(row["attempts"] for row in live),
            "winning_calls": sum(row["winners"] for row in live),
            "native_accepted_calls": sum(row["native_accepted_calls"] for row in live),
        }
    groups = [row for row in summary["groups"] if row["status"] == "complete"]
    for arm, item in arms.items():
        selected = [row for row in groups if row["strategy"] == arm]
        ratios = [1 / row["reference_cpu_over_strategy_cpu"] for row in selected]
        lowest = 0
        for row in selected:
            paired = [other for other in groups if all(other[key] == row[key]
                      for key in ("material", "reuse", "horizon", "target"))]
            if row["total_producer_cpu_ns"] == min(other["total_producer_cpu_ns"] for other in paired):
                lowest += 1
        item.update(supported_aggregate_groups=len(selected),
                    producer_cpu_over_prepared_general_min=min(ratios),
                    producer_cpu_over_prepared_general_max=max(ratios),
                    groups_lower_cpu_than_prepared_general=sum(value < 1 for value in ratios),
                    groups_lowest_cpu_among_all_supported_arms=lowest)
    examples = []
    for target in (begin["native_target"], "07" + "ff" * 31):
        for name in ("zero", "zero-left-rank-one-right", "rank-one", "genesis-maintenance", "full-rank-field"):
            group = [row for row in summary["groups"] if row["status"] == "complete"
                     and row["material"] == name and row["horizon"] == 256
                     and row["reuse"] is True and row["target"] == target]
            require(group and all(row["total_producer_cpu_ns"] is not None for row in group),
                    "complete measured comparison required")
            fastest = min(group, key=lambda row: row["total_producer_cpu_ns"])
            reference = next(row for row in group if row["strategy"] == "prepared-general")
            result = {key: fastest[key] for key in ("material", "target", "horizon", "reuse", "rounds",
                      "strategy", "setup_count", "attempts", "winners", "exhausted", "native_accepted_calls",
                      "total_producer_cpu_ns", "cpu_ns_per_win_including_failed_searches")}
            result["producer_cpu_over_prepared_general"] = fastest["total_producer_cpu_ns"] / reference["total_producer_cpu_ns"]
            result["new_low_rank_cpu_over_prepared_general"] = {
                row["strategy"]: row["total_producer_cpu_ns"] / reference["total_producer_cpu_ns"]
                for row in group if row["strategy"] in arms}
            result["eligibility_scope"] = ("native maintenance admission calls in this fixture"
                if fastest["native_accepted_calls"] else "primitive-only; no native task/reward qualification")
            examples.append(result)
    return {
        "schema": "pon-w1-native-v2-independent-readback-v1", "source_commit": SOURCE,
        "source_tree": TREE, "run_id": 40490909605, "artifact_id": 12729656639,
        "raw_log_bytes": 28291500, "cohorts": summary["input_cohorts"],
        "attempts": summary["attempts"], "winning_calls": summary["winning_calls"],
        "exhausted_searches": summary["exhausted_searches"],
        "deduplicated_header_contexts": len(attempts),
        "deduplicated_winning_header_contexts": len(wins),
        "native_accepted_calls": sum(row["native_accepted_calls"] for row in complete),
        "deduplicated_native_maintenance_winning_contexts": len(native_wins),
        "deduplication_scope": "task/target/nonce tuples within this one fixed-header campaign; all other header fields are identical by pinned source. Reused algorithms, preparation policies and nested horizons are not independent trials. This is not a count of new rewards or finalized blocks.",
        "new_low_rank_arms": arms, "representative_cohorts": examples,
        "original_capture": capture,
        "actual_binary_retained": False,
        "binary_scope": "original artifact contains before/after SHA-256 and build/source observations, not the native executable or hardware attestation",
        "x64_current_v2_executed": True, "arm64_current_v2_executed": False,
        "gpu_current_v2_executed": False, "energy_measured": False,
        "default_miner_changed": False, "hardness_proved": False,
        "production_qualified": False, "consensus_authority": False,
        "scope": "two measured rounds of all fixed cohorts on one shared x64 host. Costs charge setup and every failed/winning attempt, exclude verification/admission/report IO, and are not a cheapest-adversary or stable-speedup proof. The native seed acquisition and material setup remain separate original records.",
    }


def write_new(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    sources = load(HERE / "source-snapshot.json")
    require(sources["source_commit"] == SOURCE and sources["source_tree"] == TREE, "original source pin")
    snapshot = HERE / "original-source"
    for item in sources["files"]:
        exact_file(snapshot, item)
    originals = load(HERE / "original-files.json")
    for item in originals["retained_original_files"]:
        exact_file(HERE, item)
    capture = load(HERE / "originals/cost/capture.json")
    source = load(HERE / "originals/source.json")
    require(source["tested_commit"] == capture["source"]["commit"] == SOURCE
            and source["tested_tree"] == capture["source"]["tree"] == TREE
            and source["tracked_worktree_verified"] is True, "original source observation")
    require(capture["exit_code"] == 0 and capture["timed_out"] is False
            and capture["stable_binary"] is True and capture["stdout_within_bound"] is True
            and capture["binary_sha256_before"] == capture["binary_sha256_after"], "original execution failure")
    args.out.mkdir(parents=True, exist_ok=False)
    raw, manifest = restore(args.out)
    require(capture["stdout_uncompressed_sha256"] == manifest["uncompressed_sha256"]
            and capture["stdout_gzip_sha256"] == manifest["sha256"], "capture bytes differ")
    sys.path.insert(0, str(snapshot / "scripts/ci"))
    from check_pure_pon_cost_campaign import check
    from summarize_pure_pon_cost_campaign import summarize
    rows = [json.loads(line) for line in raw.splitlines()]
    checked = check(rows, source_root=snapshot)
    checked["input_sha256"] = manifest["uncompressed_sha256"]
    summary = summarize(rows)
    summary["input_sha256"] = manifest["uncompressed_sha256"]
    result = review(rows, summary, capture)
    write_new(args.out / "source-checked-consistency.json", checked)
    write_new(args.out / "all-fixed-cohort-summary.json", summary)
    write_new(args.out / "review.json", result)
    columns = sorted({key for row in summary["groups"] for key in row})
    with (args.out / "all-fixed-cohort-summary.csv").open("x", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(summary["groups"])
    print(json.dumps({"complete_original_v2_readback": "PASS", "cohorts": result["cohorts"],
                      "attempts": result["attempts"], "new_native_proof_run": False,
                      "production_qualified": False}))


if __name__ == "__main__":
    main()

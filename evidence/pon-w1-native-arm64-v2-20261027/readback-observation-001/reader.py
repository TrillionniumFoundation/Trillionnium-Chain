#!/usr/bin/env python3
"""Read the full actual ARM artifact; compare every fixed x64 cohort.
No Cargo, miner, node or retained ARM executable is run by this program.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
X64 = HERE.parent / "pon-w1-native-v2-e9c4bb0-20261027"
SOURCE = "2b070fafcdd253c142da90fd7306d211057d3418"
TREE = "2cf9c9813928ffdda3b181f521c51fe5e0e51f77"
ZIP_SHA = "fd92550ad8efb9271dd4bc1e2de3e470200fcefeb7f75396f087974fa2d64cc7"
BINARY_SHA = "a41d0d8eaa131af03cdb782ff797ac140042fa4c37e54ab63bb686e20eb678ee"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def exact(root, row):
    name = PurePosixPath(row["path"])
    require(not name.is_absolute() and ".." not in name.parts, "unsafe retained path")
    path = root / name
    require(path.is_file() and not path.is_symlink(), "regular retained file required")
    data = path.read_bytes()
    require(len(data) == row["bytes"] and sha(data) == row["sha256"], "changed retained bytes")
    if "git_blob_sha1" in row:
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                == row["git_blob_sha1"], "changed original Git blob")
    return data


def pieces(root, manifest):
    result = bytearray()
    for index, part in enumerate(manifest["parts"]):
        require(part["index"] == index and part["offset"] == len(result), "part order")
        data = exact(root, part)
        require(0 < len(data) <= 256 * 1024, "part byte cap")
        result.extend(data)
    require(len(result) == manifest["bytes"] and sha(result) == manifest["sha256"], "incomplete stream")
    return bytes(result)


def raw_rows(compressed, capture):
    require(sha(compressed) == capture["stdout_gzip_sha256"]
            and len(compressed) == capture["stdout_gzip_bytes"], "gzip capture binding")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    require(len(raw) == capture["stdout_bytes"] and raw.endswith(b"\n")
            and sha(raw) == capture["stdout_uncompressed_sha256"], "complete raw stream")
    return [json.loads(line) for line in raw.splitlines()]


def without_cost(value):
    if isinstance(value, dict):
        return {k: without_cost(v) for k, v in value.items() if not k.endswith("_ns")}
    if isinstance(value, list):
        return [without_cost(v) for v in value]
    return value


def cohort_key(row):
    return tuple(row[key] for key in ("material", "strategy", "reuse", "horizon", "target", "round"))


def native_costs(summary, target):
    groups = [g for g in summary["groups"] if g["status"] == "complete"
              and g["material"] == "genesis-maintenance" and g["target"] == target]
    result = []
    for horizon in (1, 8, 64, 256):
        for reuse in (False, True):
            same = [g for g in groups if g["horizon"] == horizon and g["reuse"] is reuse]
            require(len(same) == 8 and all(g["native_accepted_calls"] == g["winners"] for g in same),
                    "eight actually native-admitted arms required")
            best = min(same, key=lambda g: g["total_producer_cpu_ns"])
            baseline = next(g for g in same if g["strategy"] == "prepared-general")
            row = {k: best[k] for k in ("horizon", "reuse", "rounds", "strategy", "setup_count",
                   "attempts", "winners", "exhausted", "native_accepted_calls",
                   "total_producer_cpu_ns", "cpu_ns_per_win_including_failed_searches")}
            row.update(prepared_cpu_ns_per_win=baseline["cpu_ns_per_win_including_failed_searches"],
                       best_cpu_over_prepared=best["total_producer_cpu_ns"] / baseline["total_producer_cpu_ns"])
            result.append(row)
    return result


def save(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    if path.suffix == ".gz":
        data = gzip.compress(data, mtime=0)
    with path.open("xb") as handle:
        handle.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    archive = load(HERE / "archive.parts.json")
    require(archive["source_commit"] == SOURCE and archive["source_tree"] == TREE
            and archive["bytes"] == 10226619 and archive["sha256"] == ZIP_SHA, "ARM archive identity")
    zipped = pieces(HERE, archive)
    with zipfile.ZipFile(io.BytesIO(zipped)) as stream:
        names = stream.namelist()
        require(len(names) == len(set(names)) == 18, "complete original ZIP members")
        require(set(names) == {r["path"] for r in archive["members"]}, "original member set")
        require(sum(i.file_size for i in stream.infolist()) <= 32 * 1024 * 1024, "ZIP byte budget")
        original = {}
        for row in archive["members"]:
            item = stream.getinfo(row["path"])
            require(item.file_size == row["bytes"], "ZIP member size")
            data = stream.read(item)
            require(sha(data) == row["sha256"], "ZIP member bytes")
            original[row["path"]] = data
        require(stream.testzip() is None, "original ZIP CRC")
    capture = json.loads(original["cost/capture.json"])
    before = json.loads(original["source-before.json"])
    require(original["source-before.json"] == original["source-after.json"]
            and before["tested_commit"] == capture["source"]["commit"] == SOURCE
            and before["tested_tree"] == capture["source"]["tree"] == TREE
            and before["tracked_worktree_verified"] is True, "exact complete ARM source")
    require(capture["machine"] == "aarch64" and capture["exit_code"] == 0
            and capture["timed_out"] is False and capture["stable_binary"] is True
            and capture["stdout_within_bound"] is True, "actual native ARM completion")
    binary = original["pon_pure_cost_campaign.arm64"]
    require(len(binary) == 8533968 and sha(binary) == BINARY_SHA
            == capture["binary_sha256_before"] == capture["binary_sha256_after"], "actual executable binding")
    require(binary[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", binary, 18)[0] == 183,
            "actual ELF64 little-endian AArch64 executable")
    require(all(line.split()[0] == BINARY_SHA for line in original["binary-before.sha256"].decode().splitlines()),
            "original binary copies")
    exact(X64, archive["comparison_reader"])
    spec = importlib.util.spec_from_file_location("original_x64_reduction", X64 / "readback.py")
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    snapshot = load(X64 / "source-snapshot.json")
    for item in snapshot["files"]:
        exact(X64 / "original-source", item)
    sys.path.insert(0, str(X64 / "original-source/scripts/ci"))
    from check_pure_pon_cost_campaign import check
    from summarize_pure_pon_cost_campaign import summarize
    rows = raw_rows(original["cost/stdout.jsonl.gz"], capture)
    checked = check(rows, source_root=X64 / "original-source")
    summary = summarize(rows)
    original_summary = json.loads(original["cost/summary.json"])
    require(original_summary["input_sha256"] == capture["stdout_uncompressed_sha256"], "summary input")
    require(summary == {k: v for k, v in original_summary.items() if k != "input_sha256"},
            "independent summary differs from original CI")
    xcap = load(X64 / "originals/cost/capture.json")
    xrows = raw_rows(pieces(X64, load(X64 / "raw-cost-gzip.parts.json")), xcap)
    xchecked = check(xrows, source_root=X64 / "original-source")
    xsummary = summarize(xrows)
    fixed = ("compiled_source_sha256", "seed", "rounds", "max_horizon", "attempt_budget",
             "native_seed_header", "native_seed_packet_sha256", "native_target", "batch_schedule", "warmup")
    require(all(rows[0][k] == xrows[0][k] for k in fixed), "different fixed workload or compiled source")
    arm = {cohort_key(r): without_cost(r) for r in rows if r["kind"] == "cohort"}
    x64 = {cohort_key(r): without_cost(r) for r in xrows if r["kind"] == "cohort"}
    require(len(arm) == len(x64) == 4032 and arm == x64,
            "cross-architecture proof streams, tickets, misses, setup or admissions differ")
    require([without_cost(r) for r in rows if r["kind"] == "material"]
            == [without_cost(r) for r in xrows if r["kind"] == "material"], "different material bytes")
    # Reuse only the original reducer's data-derived fields, not its x64 labels.
    derived_keys = ("cohorts", "attempts", "winning_calls", "exhausted_searches",
                    "deduplicated_header_contexts", "deduplicated_winning_header_contexts",
                    "native_accepted_calls", "deduplicated_native_maintenance_winning_contexts",
                    "deduplication_scope", "new_low_rank_arms", "representative_cohorts")
    a_reduction = old.review(rows, summary, capture)
    x_reduction = old.review(xrows, xsummary, xcap)
    arm_reduction = {k: a_reduction[k] for k in derived_keys}
    x64_reduction = {k: x_reduction[k] for k in derived_keys}
    report = dict(schema="pon-w1-native-arm64-v2-complete-readback-v1", source_commit=SOURCE, source_tree=TREE,
                  run_id=40507587240, artifact_id=12737063030, original_zip_sha256=ZIP_SHA,
                  source_before_after=before, actual_arm64_binary_retained=True, binary_sha256=BINARY_SHA,
                  actual_x64_binary_retained=False, arm_capture=capture, x64_capture=xcap,
                  fixed_workload_equal=True, compared_cohorts=4032, all_cohort_non_timing_fields_equal=True,
                  arm_reduction=arm_reduction, x64_reduction=x64_reduction,
                  arm_native_costs=native_costs(summary, rows[0]["native_target"]),
                  x64_native_costs=native_costs(xsummary, xrows[0]["native_target"]),
                  observations=json.loads(original["host.json"]), lscpu=json.loads(original["lscpu.json"]),
                  gpu_executed=False, energy_measured=False, physical_hardware_authenticated=False,
                  default_miner_changed=False, cheapest_adversary_proved=False, hardness_proved=False,
                  public_service_qualified=False, consensus_authority=False,
                  cost_scope="producer CPU includes preparation and all winning/failed attempts; excludes verification, admission and report IO",
                  comparison_scope="two rounds per fixed group on each of two shared hosts with different architectures; observations are not causal hardware effects or confidence bounds")
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "complete-original-artifact.zip").write_bytes(zipped)
    save(args.out / "review.json", report)
    save(args.out / "source-checked-consistency.json.gz", checked)
    save(args.out / "all-fixed-cohort-summary.json.gz", summary)
    save(args.out / "x64-source-checked-consistency.json.gz", xchecked)
    print(json.dumps(dict(complete_original_arm64_readback="PASS", compared_cohorts=4032,
                         fixed_inputs_proof_streams_tickets_and_outcomes_equal=True,
                         actual_arm64_binary_retained=True, new_miner_execution=False,
                         native_contexts=arm_reduction["deduplicated_native_maintenance_winning_contexts"],
                         hardness_proved=False)))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Read-only audit of the exact failed E W1 artifact; stdlib Python 3.10+.

Usage: python3 -B audit_w1_terminal_E.py --archive ORIGINAL.zip --output NEW.json
Only NEW.json is written (exclusive creation). No extraction, Git, network,
subprocess, SDK, or proof verification occurs. Source-check receipts are checked
as recorded evidence; this script does not reconstruct the Git tree. The SDK
serial-loop interpretation is identified as a separately reviewed premise.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import statistics
import zipfile


COMMIT = "974932be6dcfe830ce1ce92d58cb10e89cb8358d"
TREE = "d4435ebdecac15e9a3fb2852eb1f835b336e452e"
ARCHIVE_SHA256 = "5bd0f32b18dcc3af29905a7655728ec8e23402ecbac550333b68a10ac7262d7f"
ARCHIVE_BYTES = 305935
OBSERVER_SHA256 = "fb3fd8a033ac0781052b5da55577bbeb59e6f4c714d2b4b3ff8e2c6c866e62bd"
SOURCE_PINS = {
    "../../src/pon_work/full_relation.rs": "ed51cb82d417d35a0f8af636422d10abff913c868032dc3e414af63f30449c97",
    "relation/src/lib.rs": "afe2f2cb5a0605eae3b6cd643e4a7bbb09fa0b0fe4db36fd2fe1155875152fb7",
    "relation/src/parameters.rs": "53d9d680fe76ac57203e10c7642b5add2da07dd05f2c76d036d59cb420360428",
    "guest/src/main.rs": "02567b1388b074138c2993bc5769692bff0d81ddc1207f2091df91dfc1d8f22e",
    "Cargo.toml": "315b2227e5dc453328a4627727911ebcf4df7ada2d024dacd838d4864faf3861",
    "guest/Cargo.toml": "c750dd4c1551df139880dda3583c6f1af27b3d01e3aadfc6a84441c06710104c",
    "relation/Cargo.toml": "d54c76ef1f5d5a5682ad63e1b3d9afb87b869551d113ff0718bdd0d6904faeb5",
    "Cargo.lock": "b3bb8518308ee9a175d878e5cafaab269be20f2bf990ec3fbb4d6e49bf110996",
}


class AuditFailure(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AuditFailure(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          AuditFailure(f"nonfinite JSON constant: {value}")))


def utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def summary(values):
    require(bool(values) and all(math.isfinite(x) for x in values), "finite nonempty series")
    return {"min": min(values), "median": statistics.median(values),
            "max": max(values), "mean": statistics.mean(values)}


def audit(archive):
    with archive.open("rb") as stream:
        archive_bytes = stream.read(ARCHIVE_BYTES + 1)
    require(len(archive_bytes) == ARCHIVE_BYTES, "exact archive byte count")
    require(sha256(archive_bytes) == ARCHIVE_SHA256, "exact original archive SHA-256")
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as opened:
        infos = opened.infolist()
        require(len(infos) == len({i.filename for i in infos}) == 55, "55 unique members")
        require(all(not i.is_dir() and "/" not in i.filename and "\\" not in i.filename
                    for i in infos), "original flat member names")
        require(sum(i.file_size for i in infos) < 8 * 1024**2, "bounded uncompressed archive")
        require(opened.testzip() is None, "CRC of every member")
        data = {i.filename: opened.read(i) for i in infos}
    inventory = [{"name": name, "bytes": len(raw), "sha256": sha256(raw)}
                 for name, raw in sorted(data.items())]
    load = lambda name: decode(data[name])
    before, after = load("source-before.json"), load("source-after.json")
    require(data["source-before.json"] == data["source-after.json"], "source receipts byte-identical")
    require(before == after and before["tested_commit"] == before["candidate"] == COMMIT
            and before["tested_tree"] == TREE and before["kind"] == "head"
            and before["tracked_worktree_verified"] is True
            and before["tracked_entries"] == 6184 and before["tracked_bytes"] == 819895633,
            "recorded fixed E source identity")
    manifest = load("backend-manifest.json")
    require(manifest["guest_source_sha256"] == SOURCE_PINS, "eight reviewed manifest source pins")
    require(manifest["backend_version"] == "3.0.6"
            and manifest["backend_source_commit"] == "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9"
            and manifest["proof_receipt_kind"] == "Composite"
            and manifest["independent_hashcash_grinding"] is False
            and manifest["work_n"] == 64 and manifest["work_r"] == 8
            and manifest["work_intermediate_tiles"] == 512, "recorded W1 backend profile")
    for name, key in [("guest.bin", "guest_program_sha256"),
                      ("guest.raw.elf", "guest_raw_elf_sha256")]:
        require(sha256(data[name]) == manifest[key], f"{name} hash binding")

    observer, process = load("prove.observer.json"), load("prove.process.json")
    require(observer["schema"] == "pon-w1-proof-process-observer-v1"
            and process["schema"] == "pon-w1-observed-process-v2", "original observer schemas")
    require(process["supplement_sha256"] == sha256(data["prove.observer.json"]), "supplement binding")
    for row in [observer, process]:
        require(row["source_sha"] == COMMIT and row["timeout_seconds"] == 5400
                and row["returncode"] == 124 and row["timed_out"] is True
                and row["family_capture_complete"] is False
                and row["complete_family_cpu_seconds"] is None, "recorded original failure and scopes")
    require(observer["failure"] == "work-timeout" and not observer["secondary_failures"], "timeout cause")
    require(observer["wall_seconds"] == process["wall_seconds"]
            and 5400 <= observer["wall_seconds"] < 5405, "actual bounded timeout observation")
    require(observer["host_before"] == observer["host_after"]
            and observer["backend_before"] == observer["backend_after"], "executable before/after identity")
    require(sha256(data["prove.backend-shim.py"]) == OBSERVER_SHA256
            == observer["observer_source"]["sha256"] == observer["shim_source"]["sha256"],
            "actual observer/shim source binding")
    require(set(observer["streams"]) == {"stdout", "stderr", "backend-stdout", "backend-stderr"},
            "all four capture streams")
    for name, record in observer["streams"].items():
        raw = data[f"prove.{name}.log"]
        require(record["bytes"] == len(raw) and record["sha256"] == sha256(raw)
                and record["truncated"] is False
                and len(raw) <= observer["stream_limits"][name], f"captured stream {name}")
    for name, key in [("prove.process-samples.jsonl", "samples"),
                      ("prove.host-phases.jsonl", "host_phases")]:
        require(observer[key]["bytes"] == len(data[name])
                and observer[key]["sha256"] == sha256(data[name]), f"{name} observer binding")

    phases = [decode(line) for line in data["prove.host-phases.jsonl"].splitlines()]
    require(phases == observer["host_phases"]["events"]
            and observer["host_phases"]["status"] == "parsed"
            and observer["host_phases"]["complete"] is False
            and observer["host_phases"]["error"] is None, "partial phase readback")
    require([p["event"] for p in phases] == ["host-enter", "input-native-check-enter",
            "input-native-check-return", "sdk-prove-enter"], "actual terminal host phase")
    require([p["sequence"] for p in phases] == list(range(4))
            and all(p["pid"] == observer["leader_pid"] and p["consensus_authority"] is False for p in phases)
            and all(a["elapsed_ns"] < b["elapsed_ns"] for a, b in zip(phases, phases[1:])),
            "phase identity and monotonic order")

    samples = [decode(line) for line in data["prove.process-samples.jsonl"].splitlines()]
    require(len(samples) == observer["samples"]["count"] == 1078, "all 1078 samples")
    require(observer["user_ticks_per_second"] == 100, "recorded tick conversion")
    require(len(data["prove.process-samples.jsonl"]) <= observer["sample_limit"], "sample byte cap")
    by_identity = defaultdict(list)
    thread_counts = Counter()
    for index, sample in enumerate(samples):
        require(not sample["errors"] and sample["historical_family_complete"] is False,
                "no sampling errors; finite historical scope")
        require(index == 0 or sample["monotonic_ns"] > samples[index - 1]["monotonic_ns"],
                "sample monotonic timestamps")
        require(sample["monotonic_ns"] < observer["work_finished_monotonic_ns"], "samples before work end")
        for p in sample["processes"]:
            a, b = p["before"], p["after"]
            require(p["stable_starttime"] is True and (a["pid"], a["starttime_ticks"])
                    == (b["pid"], b["starttime_ticks"]), "stable sampled process identity")
            require(a["process_group"] == b["process_group"] == observer["leader_pid"]
                    == a["session"] == b["session"], "observed owned group/session")
            require(b["user_ticks"] >= a["user_ticks"] and b["system_ticks"] >= a["system_ticks"],
                    "CPU monotonic within one sample")
            identity = (b["pid"], b["starttime_ticks"], p["actual_executable"]["sha256"])
            by_identity[identity].append((index, sample["monotonic_ns"], b))
        thread_counts[len([r for r in sample["children_rows"] if r["pid"] == 14296])] += 1
    expected = {
        (14294, 29910, observer["host_before"]["sha256"]): ("host", 1078),
        (14296, 29916, observer["backend_before"]["sha256"]): ("backend", 1077),
    }
    require(set(by_identity) == set(expected), "exact two stable sampled identities")
    process_series = []
    for identity, rows in sorted(by_identity.items()):
        role, expected_count = expected[identity]
        require(len(rows) == expected_count, f"{role} sample count")
        intervals = [(b[1] - a[1]) / 1e9 for a, b in zip(rows, rows[1:])]
        deltas = [(b[2]["user_ticks"] + b[2]["system_ticks"]
                   - a[2]["user_ticks"] - a[2]["system_ticks"]) / 100
                  for a, b in zip(rows, rows[1:])]
        require(all(x >= 0 for x in deltas), f"{role} CPU monotonic between samples")
        if role == "backend":
            require(len(deltas) == 1076 and all(x > 0 for x in deltas), "every backend interval grows")
        bins = []
        for lower in range(0, 5400, 600):
            selected = [r for r in rows if lower <= (r[1] - samples[0]["monotonic_ns"]) / 1e9 < lower + 600]
            if len(selected) > 1:
                a, b = selected[0], selected[-1]
                wall = (b[1] - a[1]) / 1e9
                cpu = (b[2]["user_ticks"] + b[2]["system_ticks"]
                       - a[2]["user_ticks"] - a[2]["system_ticks"]) / 100
                bins.append({"elapsed_lower_seconds": lower, "samples": len(selected),
                             "observed_wall_span_seconds": wall, "observed_cpu_seconds": cpu,
                             "cpu_seconds_per_wall_second": cpu / wall})
        process_series.append({"role": role, "pid": identity[0], "starttime_ticks": identity[1],
            "executable_sha256": identity[2], "samples": len(rows),
            "first_sample_index": rows[0][0], "last_sample_index": rows[-1][0],
            "first_user_system_ticks": [rows[0][2]["user_ticks"], rows[0][2]["system_ticks"]],
            "last_user_system_ticks": [rows[-1][2]["user_ticks"], rows[-1][2]["system_ticks"]],
            "sample_interval_seconds": summary(intervals), "cpu_delta_seconds": summary(deltas),
            "zero_or_negative_cpu_intervals": sum(x <= 0 for x in deltas),
            "cpu_seconds_per_wall_second": sum(deltas) / sum(intervals),
            "sampled_main_task_states": dict(Counter(r[2]["state"] for r in rows)),
            "maximum_sampled_rss_pages": max(r[2]["rss_pages"] for r in rows),
            "bins_600_seconds": bins})

    backend_log = re.sub(r"\x1b\[[0-9;]*m", "", data["prove.backend-stdout.log"].decode())
    lines = backend_log.splitlines()
    require(len(lines) == 63, "63 backend log entries")
    session = re.search(r'exit_code = Halted\(0\), journal = Some\("([0-9a-f]+)"\), segments: (\d+)$', lines[0])
    require(session is not None and int(session.group(2)) == 62, "62-segment halted session")
    preflight, cores = [], []
    for index, line in enumerate(lines[1:], 1):
        target, label = (preflight, "segment_preflight") if index % 2 else (cores, "prove_segment_core")
        require(line.endswith(label), "strict alternating preflight/core entries")
        target.append(utc(line.split()[0]))
    require(len(preflight) == len(cores) == 31, "31 segment entry pairs")
    entry_intervals = [(b - a).total_seconds() for a, b in zip(cores, cores[1:])]
    preflight_intervals = [(b - a).total_seconds() for a, b in zip(preflight, cores)]
    require(all(x > 0 for x in entry_intervals + preflight_intervals), "segment event order")
    executed, native = load("execute.stdout.log"), load("native-execute.stdout.log")
    require(executed["segments"] == 62 and executed["segment_po2_limit"] == 18
            and executed["guest_matches_native"] is True
            and executed["cryptographic_proof_verified"] is False
            and executed["journal_hex"] == native["journal_hex"] == session.group(1)
            and executed["image_id"] == manifest["guest_image_id"], "execution/session journal and image binding")
    missing = ["receipt.bin", "verify.process.json", "audit.process.json"]
    require(all(name not in data for name in missing), "complete receipt and subsequent observations absent")

    direct, adopted = observer["direct_wait4"], observer["adopted_wait4"]
    require(len(adopted) == 1 and observer["subreaper"]["enabled"] is True
            and observer["final_group_signal"] == "SIGKILL"
            and observer["adoption_probe"] == "ECHILD-observed-not-full-family-certification"
            and observer["finite_cleanup_observed"] is True
            and observer["leader_exit_observation"] is None, "actual finite timeout cleanup")
    require(direct["pid"] == 14294 and adopted[0]["pid"] == 14296, "actual wait4 events")
    for row in [direct] + adopted:
        require(row["raw_wait_status"] == 9 and row["returncode"] == -9
                and row["starttime_ticks"] is None, "wait4 events kept separate from sampled identities")
        require(0 <= (row["observed_monotonic_ns"] - observer["work_finished_monotonic_ns"]) / 1e9 < 5,
                "wait4 within cleanup allowance")
    require(process["user_cpu_seconds"] == direct["user_cpu_seconds"]
            and process["system_cpu_seconds"] == direct["system_cpu_seconds"]
            and process["max_waited_descendant_rss_kib"] == direct["max_rss_kib"],
            "compatibility process summary is direct-host scope only")

    return {
        "verdict": "PASS_FOR_FAILURE_EVIDENCE_ONLY", "cryptographic_proof_success": False,
        "p0_complete": False, "archive": {"bytes": ARCHIVE_BYTES, "sha256": ARCHIVE_SHA256,
            "member_count": len(inventory), "all_member_crcs_checked": True, "members": inventory},
        "source_evidence": {"recorded_source_before": before, "recorded_source_after": after,
            "receipts_byte_identical": True, "recorded_manifest_matches_eight_reviewed_pins": True,
            "manifest_source_pins": SOURCE_PINS, "source_files_retrieved_by_this_script": False,
            "git_tree_reconstructed_or_rebuilt": False,
            "scope": "Archive receipts and reviewed expected hashes only; no independent reconstruction of 6184 tracked files.",
            "host_before_after_identical": True, "backend_before_after_identical": True,
            "host_sha256": observer["host_before"]["sha256"],
            "backend_sha256": observer["backend_before"]["sha256"], "observer_sha256": OBSERVER_SHA256,
            "guest_raw_and_program_hashes_match_manifest": True,
            "input_bytes": len(data["input.bin"]), "input_sha256": sha256(data["input.bin"])},
        "terminal": {"failure": observer["failure"], "returncode": 124, "timed_out": True,
            "started_utc": observer["started_utc"], "finished_utc": observer["finished_utc"],
            "timeout_seconds": 5400, "wall_seconds": observer["wall_seconds"],
            "secondary_failures": observer["secondary_failures"], "host_phases": phases,
            "last_host_phase": phases[-1]["event"], "absent_members": missing,
            "strict_verification_codec_receipt_write_observed": False},
        "sampling": {"samples": len(samples), "all_sample_errors_empty": True,
            "all_sampled_identities_stable": True, "historical_family_complete": False,
            "span_seconds": (samples[-1]["monotonic_ns"] - samples[0]["monotonic_ns"]) / 1e9,
            "tick_rate": 100, "process_series": process_series,
            "backend_thread_rows_per_sample_histogram": dict(sorted(thread_counts.items())),
            "scope": "Sampled identities include starttime and executable hash. Main-task S alone does not establish backend idleness; counters grew every backend interval."},
        "segment_progress": {"session_segments": 62, "preflight_entries": 31, "core_entries": 31,
            "first_core_utc": cores[0].isoformat(), "last_core_utc": cores[-1].isoformat(),
            "core_entry_intervals_seconds": entry_intervals,
            "core_entry_interval_statistics_seconds": summary(entry_intervals),
            "preflight_to_core_statistics_seconds": summary(preflight_intervals),
            "last_core_to_owner_finished_utc_seconds": (utc(observer["finished_utc"]) - cores[-1]).total_seconds(),
            "native_execute_and_prove_session_journals_match": True,
            "guest_user_cycles": executed["user_cycles"],
            "separately_reviewed_sdk_inference": {"previous_segment_calls_returned": 30,
                "current_segment_ordinal": 31, "inference_not_a_stored_partial_receipt": True,
                "source_retrieved_by_this_script": False,
                "basis": "Pinned SDK serial loop advances after prove_segment returns; core verifies segment integrity before returning. This external code premise was separately reviewed, not embedded or re-fetched here.",
                "upstream_commit": "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9",
                "reviewed_git_blobs": {"risc0/zkvm/src/host/server/prove/prover_impl.rs": "43198e72b392399c44e2a2e63f76a9bae3618317",
                    "risc0/zkvm/src/host/server/prove/mod.rs": "be131724a25bc89989b873a56b5a304c590ca7aa"}}},
        "cleanup": {"finite_cleanup_observed": True, "final_group_signal": "SIGKILL",
            "adoption_probe": observer["adoption_probe"], "cleanup_allowance_seconds": 5,
            "direct_wait4": direct, "adopted_wait4": adopted,
            "direct_wait4_seconds_after_work": (direct["observed_monotonic_ns"] - observer["work_finished_monotonic_ns"]) / 1e9,
            "adopted_wait4_seconds_after_work": (adopted[0]["observed_monotonic_ns"] - observer["work_finished_monotonic_ns"]) / 1e9,
            "adopted_row_cpu_seconds": adopted[0]["user_cpu_seconds"] + adopted[0]["system_cpu_seconds"],
            "family_capture_complete": False, "complete_family_cpu_seconds": None,
            "scope": "Raw direct/adopted wait4 events remain separate from sampled identities. No sum with proc ticks; no historical family-total or aggregate peak claim."},
        "cgroup_observation": load("cgroup-observations.json"),
        "conditional_planning_projection": {"based_only_on_this_run_entry_intervals": True,
            "mean_entry_interval_seconds": statistics.mean(entry_intervals),
            "62_intervals_seconds": 62 * statistics.mean(entry_intervals),
            "62_intervals_minutes": 62 * statistics.mean(entry_intervals) / 60,
            "scope": "Planning extrapolation only: assumes observed cadence persists. Not a completed proof cost, guarantee, worst-case bound, or hardware scaling model. Final receipt work, independent verification, and audit are not budgeted by this calculation.",
            "pipeline_deadlock_demonstrated": False,
            "internal_compute_verify_lock_costs_separately_measured": False},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = {"schema": "pon-w1-terminal-E-independent-audit-v1",
        "auditor_sha256": sha256(Path(__file__).read_bytes()),
        "required_inputs": "This script and the exact original ZIP; Python 3.10+ standard library.",
        "network_used": False, "archive_extracted": False, "sdk_executed": False,
        "git_tree_rebuilt": False, "archive_mutated": False}
    try:
        report.update(audit(args.archive))
        status = 0
    except (AuditFailure, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        report.update(verdict="FAIL", error=f"{type(error).__name__}: {error}")
        status = 1
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"verdict": report["verdict"], "output": str(args.output),
                      "cryptographic_proof_success": False}))
    return status


if __name__ == "__main__":
    raise SystemExit(main())

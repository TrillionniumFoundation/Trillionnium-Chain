#!/usr/bin/env python3
"""Read fixed hosted originals with their exact Git-source Python readers.

No retained native executable is run. Exit zero means this readback reproduced
the original observations, including service failures; it grants no acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import zipfile

RUN = 42771007925
SOURCE = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
TREE = "00479a98dabc6b1fd91a0ceef82ffbdbffb78067"
ARTIFACTS = {"x64": 13742695023, "arm64": 13741569215, "fresh-service-head": 13741424505}
ARCHIVE_SHA256 = {
    "x64": "563b273106cd6d123ee42d2a6ba1f6ff41972e41622daf459372b7d50386750a",
    "arm64": "57025dd4c0516cfb7d090d140e6bc9b20193773fa639faac9b15254dec12060a",
    "fresh-service-head": "50d19f5690bbac21e5a7a6c8e9d6578f26acb57437e77dfde9ba64a231e966de",
}
ARCHITECTURES = {"x64": (62, "x86_64-unknown-linux-gnu"), "arm64": (183, "aarch64-unknown-linux-gnu")}
READER_PATHS = (
    "scripts/pon_w1_false_trace_reuse_reader_v1.py",
    "scripts/pon_w1_cost_matrix_reader.py",
    "config/pon/work-security-acceptance-v1.json",
    "config/pon/ledger-v1.json",
    "config/pon/work-profile-v1.json",
    "config/pon/model-family-v1.json",
    "config/pon/devnet-v1.json",
    "config/pon/evaluation-round-v1.json",
    "scripts/ci/run_w1_fresh_service_v1.py",
    "scripts/ci/run_from_zero_native.py",
    "scripts/ci/ci_observation.py",
    "scripts/ci/check_required_native_test.py",
    "scripts/ci/replay_pinned_native.py",
    "scripts/ci/verify_ci_source.py",
    "scripts/pon_public_v3_phase_read.py",
    "scripts/pon_public_v3_policy_read.py",
    "formal/pon-nakamoto-v1/bounded_process.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
)


def require(ok, label):
    if not ok:
        raise ValueError(label)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def load(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON key: " + key)
            value[key] = item
        return value
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def relative(name):
    value = PurePosixPath(name)
    require(not value.is_absolute() and value.parts and all(p not in ("", ".", "..") for p in value.parts), "unsafe member path")
    return value


def extract(archive, destination):
    with zipfile.ZipFile(archive) as retained:
        members = retained.infolist()
        require(len({m.filename for m in members}) == len(members), "duplicate ZIP member")
        require(sum(m.file_size for m in members) < 200 * 1024 * 1024, "expanded ZIP size")
        require(retained.testzip() is None, "ZIP CRC mismatch")
        for member in members:
            path = relative(member.filename)
            kind = stat.S_IFMT(member.external_attr >> 16)
            require(kind in (0, stat.S_IFREG, stat.S_IFDIR), "nonregular ZIP member")
            target = destination.joinpath(*path.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                # Create ordinary data files. Do not restore executable modes.
                with target.open("xb") as output:
                    output.write(retained.read(member))
        return {"members": len(members), "expanded_bytes": sum(m.file_size for m in members)}


def verify_files(base, files):
    for name, expected in files.items():
        path = relative(name)
        require(re.fullmatch("[0-9a-f]{64}", expected) is not None, "noncanonical file hash")
        require(digest(base.joinpath(*path.parts)) == expected, "artifact hash mismatch: " + name)
    return len(files)


def source_inventory(value):
    require(value["commit"] == SOURCE and value["tree"] == TREE, "source commit/tree")
    require(value["source_state"] == "committed-clean" and value["tracked_worktree_verified"] is True, "complete source receipt")
    require(value["tracked_entries"] == 27660 and value["tracked_bytes"] == 2527867778, "source inventory")


def cost_readback(arch, root, output, reader):
    machine, target = ARCHITECTURES[arch]
    require(load(root / "source-before.json") == load(root / "source-after.json"), "whole-job source drift")
    results = []
    for mode, full_limb in (("w1-false-trace-reuse-v1", False), ("w1-full-limb-reuse-v1", True)):
        base = root / mode
        manifest = load(base / "manifest.json")
        require(manifest["result"] == "PASS" and manifest["architecture"] == arch, "manifest result/architecture")
        require(manifest["execution_context"] == "github-hosted", "hosted execution context")
        require(manifest["source_before"] == manifest["source_after"] and manifest["source_changed"] is False, "source before/after")
        source_inventory(manifest["source_before"])
        require(manifest["expected_source_commit"] == SOURCE, "expected source")
        require(manifest["target"] == target and manifest["compiler_channel"] == "1.95.0" and manifest["build_profile"] == "release", "compiler/target/profile")
        require(manifest["build_environment_overrides"] == {} and manifest["default_release_configuration_checked"] is True, "compiler configuration")
        require(manifest["cargo_configuration_before"] == manifest["cargo_configuration_after"] and manifest["cargo_configuration_changed"] is False, "Cargo configuration before/after")
        require(manifest["cargo_configuration_before"]["violations"] == [], "Cargo configuration violations")
        context = manifest["runner_context"]
        require(context["GITHUB_RUN_ID"] == str(RUN) and context["GITHUB_RUN_ATTEMPT"] == "1" and context["GITHUB_REPOSITORY"] == "TrillionniumFoundation/Trillionnium-Chain", "workflow context")
        files_verified = verify_files(base, manifest["artifact_sha256"])
        binary = base / "pon_w1_false_trace_reuse_v1"
        with binary.open("rb") as stream:
            header = stream.read(20)
        require(header[:4] == b"\x7fELF" and header[5] == 1 and struct.unpack("<H", header[18:20])[0] == machine, "retained ELF machine")
        binary_sha = digest(binary)
        for key in ("binary_sha256_before", "binary_sha256_after", "retained_binary_sha256_before", "retained_binary_sha256_after"):
            require(binary_sha == manifest[key], key)
        require(len(manifest["observations"]) == 5, "original command denominator")
        for observation in manifest["observations"]:
            require(observation["exit_code"] == 0 and observation["timed_out"] is False and observation["elapsed_ns"] > 0, "original process outcome")
            require((base / observation["stdout"]).is_file() and (base / observation["stderr"]).is_file(), "original process streams")
        selector = reader.FULL_LIMB_SELECTOR if full_limb else reader.SELECTOR
        require(manifest["observations"][-1]["command"][-1] == selector, "native selector")
        actual = reader.analyze(base / "campaign.stdout", full_limb=full_limb)
        require(actual == manifest["reader"], "independent reader differs from original")
        expected = {"campaign": 1, "material": 9, "cohort": 72, "search": 288, "candidate": 288, "verifier": 1440 if full_limb else 1152, "end": 1}
        require(actual["record_counts"] == expected and actual["record_consistency"] == "PASS" and actual["semantic_alerts"] == [], "complete fixed grid/verdict")
        for flag in reader.FALSE_FLAGS:
            require(actual[flag] is False and manifest[flag] is False, "qualification promoted: " + flag)
        dump(output / (arch + "-" + mode + "-reader.json"), actual)
        rows = actual["actual_reuse_cohorts"]
        require(sum(row["attempts"] for row in rows) == 573, "retained trial denominator")
        identities = []
        with (base / "campaign.stdout").open() as stream:
            for line in stream:
                record = json.loads(line)
                if record["kind"] == "candidate":
                    identities.append({key: record[key] for key in
                        ("class", "sample", "search_index", "task", "target", "challenge", "proof_sha256")})
        encoded = [json.dumps(row, sort_keys=True, separators=(",", ":")) for row in identities]
        require(len(encoded) == len(set(encoded)) == 288, "candidate identity denominator")
        identity_hash = hashlib.sha256(("\n".join(sorted(encoded)) + "\n").encode()).hexdigest()
        attacker = sum(row["full_attacker_cohort_total"]["cpu_ns"] for row in rows)
        receiver = sum(row["verification"]["production"]["cpu_ns"] for row in rows)
        results.append({"architecture": arch, "mode": mode, "source": manifest["source_before"],
            "binary_sha256": binary_sha, "manifest_sha256": digest(base / "manifest.json"),
            "raw_campaign_sha256": actual["input_sha256"], "raw_campaign_bytes": actual["input_bytes"],
            "record_counts": actual["record_counts"], "manifest_files_verified": files_verified,
            "trial_attempts": 573, "candidate_identity_sha256": identity_hash,
            "reader_matches_original": True, "attacker_cpu_ns": attacker, "production_rejection_cpu_ns": receiver,
            "aggregate_production_receiver_over_full_attacker_cpu": receiver / attacker,
            "class_production_ratio": {row["class"]: row["receiver_rejection_cpu_over_full_attacker_cpu"]["production"] for row in rows},
            "qualifications_preserved_false": reader.FALSE_FLAGS})
    return results


def service_readback(root, output, reader):
    require(load(root / "source.json") == load(root / "source-after.json"), "service whole-job source drift")
    base = root / "fresh-service"
    manifest = load(base / "manifest.json")
    require(manifest["source_before"] == manifest["source_after"] and manifest["source_expected"] == SOURCE, "service source before/after")
    source = manifest["source_before"]
    require(source["commit"] == SOURCE and source["tree"] == TREE, "service source identity")
    tracked = source["tracked_source_identity"]
    require(tracked["tested_commit"] == SOURCE and tracked["tested_tree"] == TREE and tracked["tracked_worktree_verified"] is True and tracked["tracked_entries"] == 27660 and tracked["tracked_bytes"] == 2527867778, "service source inventory")
    files_verified = verify_files(base, manifest["files"])
    binary_sha = digest(base / "public_v3_from_zero")
    require(binary_sha == manifest["binary_sha256_before"] == manifest["binary_sha256_after"], "service binary identity")
    require(manifest["requested_window_ns"] == 4_000_000_000 and manifest["attack_workers"] == 16 and manifest["passed"] is False and manifest["execution_finished"] is True, "original service gate")
    require(len(manifest["runs"]) == 2, "service invocation denominator")
    summaries, replays, failures = {}, [], []
    for case, run, expected_error, expected_exit in zip(("original", "fresh"), manifest["runs"], ("CONFIRMATION_TARGET", "FRESH_NATIVE_PROCESS_REQUIRED"), (0, 101)):
        require(run["process"]["process_exit_code"] == expected_exit and run["process"]["timed_out"] is False, "original native exit")
        try:
            reader.validate_execution(run["process"], base / run["process"]["log"], run["name"], base / run["report_path"])
            error = None
        except ValueError as failure:
            error = str(failure)
        diagnostic = reader.failure_diagnostic(run["process"], run["name"], base / run["report_path"])
        require(error == run["failure"] == expected_error and diagnostic == run["failure_diagnostic"], "retained failure changed")
        failures.append({"name": run["name"], "reproduced_reader_failure": error, "diagnostic": diagnostic})
        report = load(base / run["report_path"])
        require(report["finite_target_met"] is False, "service failure promoted")
        summary = {"native_exit_code": expected_exit, "timed_out": False, "reader_failure": error,
            "diagnostic": diagnostic, "finite_target_met": False, "phases": []}
        for phase in report["phases"]:
            scalars = {key: value for key, value in phase.items() if value is None or type(value) in (int, str, float, bool)}
            scalars.update(honest_submissions_count=len(phase["honest_submissions"]),
                honest_submit_successes=sum((row.get("response") or {}).get("ok") is True for row in phase["honest_submissions"]),
                attacks_count=sum(len(worker.get("calls", worker.get("attempts", []))) for worker in phase["attacks"]),
                history_calls=len(phase["honest_history"]))
            summary["phases"].append(scalars)
            for replay in phase["independent_history_page_replay"]:
                observed = replay["native_import_observation"]
                def phases(rows):
                    return [{key: row[key] for key in ("phase", "accepted", "error_code", "thread_cpu_ns", "wall_ns")} for row in rows if row["started"]]
                replays.append({"cohort": case, "phase": phase["mode"], "history_call_index": replay["history_call_index"],
                    "accepted": replay["replay_accepted"], "error": replay["replay_error"],
                    "replay_thread_cpu_ns": replay["replay_thread_cpu_ns"], "replay_wall_ns": replay["replay_wall_ns"],
                    "host_checks": observed["host_checks"], "page_phases": phases(observed["phases"]),
                    "packets": [{"packet_index": packet["packet_index"], "phases": phases(packet["phases"])} for packet in observed["packets"]]})
        summaries[case] = summary
    fresh = load(base / "fresh/report.json")
    cache = reader.validate_negative_cache_observation(fresh, fresh["phases"])
    dump(output / "fresh-service-head-summary.json", {"source_commit": SOURCE, "cohorts": summaries})
    dump(output / "fresh-service-reader-replay.json", {"source_commit": SOURCE, "runs": failures, "fresh_cache_path_independent_readback": cache})
    dump(output / "fresh-service-replay-phases.json", {"source_commit": SOURCE, "nested_costs_not_additive": True, "rows": replays})
    return {"manifest_files_verified": files_verified, "binary_sha256": binary_sha,
        "source": source, "retained_failures_reproduced": failures, "business_qualification": "HOLD"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    require(args.source == SOURCE, "this package binds only its original da1374a source")
    repo, archives, output = args.repo.resolve(), args.archive_dir.resolve(), args.output_dir.resolve()
    require(subprocess.check_output(["git", "rev-parse", args.source + "^{tree}"], cwd=repo, text=True).strip() == TREE, "Git source tree")
    output.mkdir(parents=True, exist_ok=False)
    frozen = output / "frozen-reader"
    hashes = {}
    for name in READER_PATHS:
        content = subprocess.check_output(["git", "show", args.source + ":" + name], cwd=repo)
        path = frozen / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(frozen / "scripts"), str(frozen / "scripts/ci")]
    import pon_w1_false_trace_reuse_reader_v1 as cost_reader
    import run_w1_fresh_service_v1 as service_reader
    receipts, costs, service = [], [], None
    for name, artifact_id in ARTIFACTS.items():
        archive = archives / (name + ".zip")
        metadata = load(archives / (name + ".metadata.json"))
        require(metadata["id"] == artifact_id and metadata["workflow_run"]["id"] == RUN and metadata["workflow_run"]["head_sha"] == SOURCE, "original artifact metadata")
        require(digest(archive) == ARCHIVE_SHA256[name] and metadata["digest"] == "sha256:" + ARCHIVE_SHA256[name] and metadata["size_in_bytes"] == archive.stat().st_size, "original ZIP SHA256/size")
        root = output / "extracted" / name
        members = extract(archive, root)
        receipts.append({"name": name, "artifact_id": artifact_id, "archive_sha256": digest(archive),
            "archive_bytes": archive.stat().st_size, "metadata_sha256": digest(archives / (name + ".metadata.json")), **members})
        if name in ARCHITECTURES:
            costs.extend(cost_readback(name, root, output, cost_reader))
        else:
            service = service_readback(root, output, service_reader)
    candidate_hashes = {campaign["candidate_identity_sha256"] for campaign in costs}
    require(len(candidate_hashes) == 1, "the four original campaigns repeat the same candidate grid")
    result = {"schema": "pon-da1374a-hosted-original-independent-readback-v2", "readback_status": "PASS",
        "source_commit": SOURCE, "source_tree": TREE, "workflow_run": RUN, "attempt": 1,
        "reader_source_sha256": hashes, "archives": receipts, "cost_campaigns": costs, "service": service,
        "repeated_candidate_grid": {"candidate_count": 288, "campaign_count": 4,
            "candidate_identity_sha256": next(iter(candidate_hashes)), "independent_fresh_candidate_samples": False},
        "new_native_campaign_run": False, "retained_binary_executed": False,
        "public_attack_amplification_measured": False, "production_activation": False,
        "business_qualification": "HOLD", "fastest_adversary_lower_bound_proved": False}
    dump(output / "independent-readback.json", result)
    print(json.dumps({"readback_status": "PASS", "business_qualification": "HOLD", "archives": len(receipts),
        "cost_campaigns": len(costs), "retained_service_failures": len(service["retained_failures_reproduced"]),
        "retained_binary_executed": False}, sort_keys=True))


if __name__ == "__main__":
    main()

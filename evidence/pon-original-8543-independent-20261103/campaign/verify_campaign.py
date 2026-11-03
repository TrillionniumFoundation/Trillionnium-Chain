#!/usr/bin/env python3
"""Verify and project one frozen original native campaign artifact; never execute it.

The archive remains the source of the observations. Nested phase/Host timings
are not exclusive costs, and calling-thread CPU is not whole-worker CPU.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile


HEAD = "8543bd9f9777d3ef97dbbe55459fa6cb11ec5c2f"
TREE = "d6b33883fe26700a84aa12f64bafd5a7ef99520b"
ZIP_SHA256 = "f3d190b7264ed42e2aa200c58ceac38692ff6514190364387abf905a0b3c693b"
ZIP_BYTES = 60_700_399
MAX_DECODED = 512 * 1024 * 1024
BINARY_SHA256 = "3ddc47794978515a45b6be143b79f0bee4d26579e7bf01cbc3469af5f2564e4c"
WORKFLOW = ".github/workflows/pon-native-campaign-qualification.yml"
SELECTOR = "separate_process_work_and_signed_confirmation_campaign"
COMMON = ["+1.95.0", "test", "--locked", "--offline", "--release",
          "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node",
          "--test", "public_v3_multiprocess"]
SCOPE = ("Existing source-bound readback observations; intervals are nested; "
         "thread CPU excludes scoped workers; Host CPU is not complete worker "
         "CPU. Projections add no consensus authority.")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=pairs_unique)


def file_hash(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "--no-replace-objects", "-C",
                                    str(repo), *args])


def project_phase(number, phase):
    imports = []
    for rec in phase["client_history_import_observations"]["records"]:
        item = rec["client_import"]
        observation = item["native_import_observation"]
        require(observation["cpu_intervals_are_nested_not_additive"] is True,
                "missing nested CPU scope")
        require(observation["host_checks_are_nested_not_additive"] is True,
                "missing nested Host scope")
        require(observation["observation_has_consensus_authority"] is False,
                "unexpected observation authority")
        require(observation["phase_cpu_excludes_scoped_workers"] is True,
                "unexpected phase CPU scope")
        require(observation["host_cpu_is_full_worker_cpu"] is False,
                "unexpected Host CPU scope")
        totals = {}
        for packet in observation["packets"]:
            for span in packet["phases"]:
                if not span["started"]:
                    continue
                total = totals.setdefault(span["phase"], {
                    "count": 0, "wall_ns": 0, "thread_cpu_ns": 0,
                    "unknown_cpu": 0, "errors": []})
                total["count"] += 1
                total["wall_ns"] += span["wall_ns"] or 0
                total["thread_cpu_ns"] += span["thread_cpu_ns"] or 0
                total["unknown_cpu"] += span["thread_cpu_ns"] is None
                if span["error_code"] is not None:
                    total["errors"].append(span["error_code"])
        checkpoint = [s for s in observation["host_checks"]
                      if s["phase"] == "checkpoint"]
        require(len(checkpoint) == 1, "checkpoint observation count changed")
        imports.append({
            "index": rec["history_call_index"],
            **{k: item[k] for k in ["wall_ns", "thread_cpu_ns", "succeeded",
                                    "error", "started_ns", "ended_ns"]},
            "host_checkpoint": checkpoint[0],
            "packet_phase_totals_nested_not_additive": totals,
            "page_stages": [s for s in observation["phases"] if s["started"]],
        })
    result = {
        "run": number, "phase": phase["mode"],
        "window_seconds": phase["window_seconds"],
        "planned": phase["scheduled_confirmation_rounds"],
        "confirmed": phase["confirmed_rounds"],
        "observed": phase["observed_confirmation_rounds"],
        "rounds": phase["confirmation_rounds"],
        "error": phase["native_verifier_errors"],
        "startup_error": phase["startup_or_campaign_error"],
        "actors": phase["attacker_processes_ready"],
        "actual_flow": phase["final_actual_flow"],
        "meter": phase["final_cpu_meter"], "imports": imports,
    }
    for name in ["submissions", "history"]:
        calls = phase[name]
        result[name] = {"attempts": calls["attempts"],
                        "ack_on_time": calls["acknowledged_on_time"],
                        "wall": calls["elapsed_wall_ns"]}
    return result


def verify(archive, repo):
    require(archive.stat().st_size == ZIP_BYTES, "archive byte count mismatch")
    require(file_hash(archive) == ZIP_SHA256, "archive SHA256 mismatch")
    require(git(repo, "rev-parse", HEAD + "^{tree}").decode().strip() == TREE,
            "Git source tree mismatch")
    workflow = git(repo, "show", HEAD + ":" + WORKFLOW)
    start = b'          cat > "$OUT/run-native-campaign.py" <<\'PY\'\n'
    require(workflow.count(start) == 1, "runner heredoc start changed")
    body = workflow.split(start, 1)[1].split(b"          PY\n", 1)[0]
    require(body and all(not line or line.startswith(b"          ")
                         for line in body.splitlines()), "runner indentation changed")
    runner = b"\n".join(line[10:] if line else line for line in body.splitlines()) + b"\n"
    runner_sha = hashlib.sha256(runner).hexdigest()
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        names = [i.filename for i in entries]
        require(len(names) == len(set(names)) == 1766, "duplicate/member count")
        require(all(not i.is_dir() for i in entries), "unexpected directory")
        require(all(not PurePosixPath(n).is_absolute() and ".." not in
                    PurePosixPath(n).parts and "\\" not in n for n in names),
                "unsafe member name")
        require(sum(i.file_size for i in entries) == 356_468_251,
                "declared decoded byte count mismatch")
        require(z.getinfo("artifact-files.json").file_size < 1024 * 1024,
                "oversize archive manifest")
        manifest = parse_json(z.read("artifact-files.json"))
        expected = {i["path"]: i for i in manifest["files"]}
        require(len(expected) == len(manifest["files"]) == 1765,
                "duplicate manifest path or count")
        require(set(expected) == set(names) - {"artifact-files.json"},
                "manifest and archive membership differ")
        total = 0
        for info in entries:
            digest = hashlib.sha256()
            count = 0
            with z.open(info) as stream:
                while True:
                    require(total < MAX_DECODED, "decoded read budget exhausted")
                    chunk = stream.read(min(1024 * 1024, MAX_DECODED - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    count += len(chunk)
                    digest.update(chunk)
            require(count == info.file_size, "actual member size mismatch")
            if info.filename in expected:
                item = expected[info.filename]
                require(item["bytes"] == count and item["sha256"] == digest.hexdigest(),
                        "member bytes/hash mismatch: " + info.filename)
        require(total == 356_468_251, "actual decoded byte count mismatch")

        def read(name):
            require(z.getinfo(name).file_size < 2 * 1024 * 1024, "oversize JSON")
            return parse_json(z.read(name))

        source = read("source-before.json")
        require(source["candidate"] == source["tested_commit"] == HEAD and
                source["tested_tree"] == TREE and source["kind"] == "head" and
                source["base"] is None and source["prospective_merge"] is None and
                source["tracked_worktree_verified"] is True, "source identity")
        for name in ["source-before-build.json", "source-before-campaigns.json",
                     "source-after-native.json", "source-after.json"]:
            require(read(name) == source, "source before/after mismatch")
        result = read("results.json")
        require(result["source_after"] == source, "result source mismatch")
        require(result["runner_sha256"] == runner_sha, "runner source mismatch")
        require(z.read("run-native-campaign.py") == runner,
                "retained runner differs from exact workflow heredoc")
        require(result["expected_head"] == HEAD and result["expected_tree"] == TREE,
                "expected source mismatch")
        require(result["source_kind"] == "head" and result["toolchain"] == "1.95.0"
                and result["profile"] == "release", "build mode mismatch")
        require(z.read("rustc-version.txt").decode().splitlines()[0] ==
                "rustc 1.95.0 (59807616e 2026-04-14)", "rustc mismatch")
        require(z.read("cargo-version.txt").decode().splitlines()[0] ==
                "cargo 1.95.0 (f2d3ce0bd 2026-03-21)", "Cargo mismatch")
        require(result["build"]["command"][1:] == COMMON +
                ["--no-run", "--message-format=json"], "build command changed")
        require(result["build"]["returncode"] == 0 and
                result["build_timeout_seconds"] == 1800, "build result changed")
        binary = result["binary"]
        require(binary["sha256_before"] == binary["sha256_after"] == BINARY_SHA256
                and binary["bytes"] == 11_567_560, "binary binding changed")
        require(expected[binary["retained"]]["sha256"] == BINARY_SHA256,
                "retained binary mismatch")
        require(result["original_inputs"] == {
            "attacker_processes": [0, 24, 24], "business_blocks": 21,
            "modes": ["baseline", "from-zero", "late-product"],
            "phase_seconds": 30, "seed_blocks": 4, "seed_transfers": 1024},
                "original workload changed")
        require(result["expected_resources"] == {
            "cpu_max": "400000 100000", "memory_max": "17179869184", "nice": 10},
                "controller resources changed")
        require(result["public_phase_placement"] == {
            "attacker_processes_remain_in_original_controller_domain": True,
            "fixed_parent": "/sys/fs/cgroup/trnmponpublic.slice",
            "original_3x3_workload_and_depletion_predicates_changed": False,
            "profile": "fixed-public-phase-external-actors-v1",
            "receiver_and_verifier_cpu_max": "25000 100000",
            "receiver_and_verifier_memory_max": "2147483648"},
                "fixed public placement changed")
        require(result["failure"] == "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED" and
                result["complete_success"] is False and result["finalization_failures"] == [],
                "original failure classification changed")
        require(result["planned_complete_runs"] == len(result["attempts"]) == 3 and
                result["original_campaign_outer_timeout_seconds"] == 600,
                "original attempts/outer deadline changed")
        phases = []
        for number, attempt in enumerate(result["attempts"], 1):
            require(attempt["number"] == number and
                    attempt["step"]["command"][1:] == COMMON + [SELECTOR, "--",
                    "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                    "original execution command changed")
            require(attempt["step"]["returncode"] == 101 and
                    attempt["step"]["outer_stage_timeout_seconds"] == 600 and
                    attempt["original_criteria_met"] is False and
                    attempt["phase_startup_errors"] == [] and
                    attempt["report_validation_failure"] is None,
                    "original failure observation changed")
            require(read(f"run-{number}-source-after.json") == source,
                    "per-attempt source mismatch")
            report = read(f"run-{number}-phase-readback.json")
            raw = expected[f"run-{number}-raw/report.json"]
            require(raw["sha256"] == report["input"]["sha256"] == attempt["report_sha256"]
                    and raw["bytes"] == report["input"]["bytes"], "raw report binding")
            require([p["mode"] for p in report["phases"]] ==
                    ["baseline", "from-zero", "late-product"], "phase order changed")
            for index, phase in enumerate(report["phases"]):
                require(phase["window_seconds"] == 30 and
                        phase["scheduled_confirmation_rounds"] == 3 and
                        phase["confirmed_rounds"] == (1 if index == 0 else 0) and
                        phase["attacker_processes_ready"] == (0 if index == 0 else 24),
                        "phase result/workload changed")
                phases.append(project_phase(number, phase))
        return {
            "schema": "chain-original-campaign-artifact-readback-v1",
            "source": {"head": HEAD, "tree": TREE, "kind": "head"},
            "run_id": 41715157839, "job_id": 126193117561, "artifact_id": 13270905947,
            "zip_bytes": ZIP_BYTES, "zip_sha256": ZIP_SHA256,
            "zip_members_verified": 1765, "zip_members_including_manifest": 1766,
            "decoded_members_total": total, "native_test_rerun": False,
            "results": result, "phase_projection_scope": SCOPE, "phase_projection": phases,
        }


def main():
    require(not sys.flags.optimize, "run without -O: evidence replay forbids optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = verify(args.archive, args.repo)
    if args.compare:
        require(result == parse_json(args.compare.read_bytes()), "prior projection mismatch")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"archive_verified": True, "original_native_passed": False,
                      "replayed_projection_sha256": file_hash(args.output),
                      "verifier_sha256": file_hash(Path(__file__))}))


if __name__ == "__main__":
    main()

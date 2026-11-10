#!/usr/bin/env python3
"""Recompute retained M14 observations without granting service qualification."""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
HEAD = "ac8501a85a770ba34f34e1bed507ca747e5c3f8d"
TREE = "3f321d412ab7eb1f5c03f18ba21201e96a3db144"
ARCHIVES = {
    "campaign": "7996763ffc628f025f2d8e47bf3a6f184805a4b5b24dd13b273ee508903b1f78",
    "f0": "8185871bcc22c9c3d67a99620ccafc9b5457fab24a4924c629ac5d5ddba2e238",
}
HISTORY = [
    ("history", "x64", "head", 13712641233,
     "d9d4b4656159fa19d150c3c25df5832baed82adcdbb3c93c34b8a162cbd44177"),
    ("history-13711273994", "arm64", "head", 13711273994,
     "44e57a33ba80890d3532d148d1223efea3c695c0bda2eb7bcf99c1aa8554f270"),
    ("history-13710089902", "x64", "prospective-merge", 13710089902,
     "67cd4f349b3ae2ed7b316cb33e96c5bfb3ca50773a65e5ff3aeba21ac6cad7b8"),
    ("history-13712350460", "arm64", "prospective-merge", 13712350460,
     "8bee86bba1e6cb4ef538746b4b6da55ae8ef7cd8d2407d14fe5191a38b1fabeb"),
]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def read(path: Path):
    return json.loads(path.read_text())


def verify_archive(name: str, expected: str) -> dict:
    archive = BASE / (name + ".zip")
    assert digest(archive) == expected
    directory = BASE / name
    manifest_path = directory / "artifact-files.json"
    manifest = read(manifest_path)
    observed = {}
    for row in manifest["files"]:
        relative = Path(row["path"])
        assert not relative.is_absolute() and ".." not in relative.parts
        path = directory / relative
        assert not path.is_symlink() and path.is_file()
        assert path.stat().st_size == row["bytes"]
        assert digest(path) == row["sha256"]
        assert row["path"] not in observed
        observed[row["path"]] = row["sha256"]
    actual = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file()}
    # The final inventory cannot hash itself. Later cleanup receipt is retained
    # after that inventory in the original campaign, so report it separately.
    extra = sorted(actual - set(observed) - {"artifact-files.json"})
    assert set(observed) <= actual
    for point in ("source-before.json", "source-after.json"):
        source = read(directory / point)
        assert source["tested_commit"] == HEAD and source["tested_tree"] == TREE
        assert source["tracked_worktree_verified"] is True
    return {"zip_sha256": expected, "manifest_entries_verified": len(observed),
            "actual_files": len(actual), "post_inventory_files": [
                {"path": p, "bytes": (directory / p).stat().st_size,
                 "sha256": digest(directory / p)} for p in extra]}


def stage_delta(phase: dict, owner: str, stage: str) -> dict:
    before = phase[owner + "_before"]
    after = phase[owner + "_after"]
    a = next(r["totals"] for r in after["stages"] if r["stage"] == stage)
    b = next(r["totals"] for r in before["stages"] if r["stage"] == stage)
    return {k: a[k] - b[k] for k in ("calls", "cpu_ns", "wall_ns")}


def inspect_history(entry: tuple) -> dict:
    name, architecture, source_kind, artifact_id, archive_sha256 = entry
    archive = BASE / (name + ".zip")
    assert digest(archive) == archive_sha256
    inventory = []
    with zipfile.ZipFile(archive) as stream:
        names = set()
        for item in stream.infolist():
            assert item.filename not in names
            names.add(item.filename)
            relative = Path(item.filename)
            assert not relative.is_absolute() and ".." not in relative.parts
            data = stream.read(item)  # validates ZIP CRC as well
            extracted = BASE / name / relative
            assert extracted.is_file() and not extracted.is_symlink()
            value = hashlib.sha256(data).hexdigest()
            assert extracted.stat().st_size == len(data) and digest(extracted) == value
            inventory.append({"path": item.filename, "bytes": len(data), "sha256": value})
    inventory_path = BASE / (name + "-inventory.json")
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n")
    directory = BASE / name / "history-native"
    manifest = read(directory / "manifest.json")
    before, after = manifest["source_before"], manifest["source_after"]
    assert before == after
    assert before["tree"] == TREE
    assert before["tracked_source_identity"]["candidate"] == HEAD
    assert before["tracked_source_identity"]["kind"] == source_kind
    assert manifest["binary_before"]["sha256"] == manifest["binary_after"]["sha256"]
    events = [json.loads(line) for line in (directory / "history.log").read_text().splitlines()
              if line.startswith("{")]
    server = next(e for e in events if e.get("schema") == "native-ancestry-public-server-exit-evidence-v1")
    sync = next(e for e in events if e.get("schema") == "native-ancestry-independent-sync-exit-evidence-v1")
    progresses = [e for e in events if e.get("kind") == "independent-native-fullsync-progress"]
    timings = {}
    for line in (directory / "history-resources.txt").read_text().splitlines():
        for label in ("User time (seconds)", "System time (seconds)",
                      "Maximum resident set size (kbytes)",
                      "Major (requiring I/O) page faults", "Minor (reclaiming a frame) page faults",
                      "Voluntary context switches", "Involuntary context switches",
                      "File system inputs", "File system outputs", "Exit status"):
            if line.strip().startswith(label + ":"):
                timings[label] = line.strip().split(":", 1)[1].strip()
    summary = manifest["summary"]
    return {
        "architecture": architecture, "source_kind": source_kind,
        "commit": before["commit"], "tree": before["tree"],
        "binary_sha256": manifest["binary_before"]["sha256"],
        "artifact_id": artifact_id, "zip_sha256": archive_sha256,
        "member_count": len(inventory), "member_inventory_sha256": digest(inventory_path),
        "passed": manifest["passed"], "exit_code": manifest["process"]["exit_code"],
        "failures": manifest["failures"], "confirmed_packets": summary.get("confirmed_packets"),
        "sync_exit_elapsed_from_test_start_ns": sync["elapsed_ns"],
        "successful_test_summary_elapsed_ns": summary.get("elapsed_ns"),
        "server_elapsed_ns": server["service_elapsed_ns"],
        "server_loop_exit": server["loop_exit_before_internal_shutdown"],
        "sync_error": sync.get("sync_error"), "failure_location": sync.get("failure_location"),
        "sync_progress": progresses, "resources": timings,
        "corrupt_active_index_reopen_refused": summary.get("corrupt_active_index_reopen_refused"),
        "legacy_reorg_observation": sync["native_legacy_reorg_observation"],
        "production_activation": False, "independent_wan_qualified": False,
    }


def main() -> None:
    result = {
        "schema": "m14-original-host-readback-v1", "head": HEAD, "tree": TREE,
        "scope": "offline audit of already executed hosted observations; no new native run",
        "archives": {n: verify_archive(n, h) for n, h in ARCHIVES.items()},
        "campaign_run_id": 42693805359, "f0_run_id": 42693805049,
        "campaigns": [], "qualification": "HOLD_NO_GO",
        "independent_wan_qualified": False, "production_activation": False,
        "stage_intervals_are_nested_not_additive": True,
    }
    envelope = read(BASE / "campaign/results.json")
    assert envelope["expected_head"] == HEAD and envelope["expected_tree"] == TREE
    assert envelope["build"]["returncode"] == 0
    assert envelope["complete_success"] is False
    for number in range(1, 4):
        report = read(BASE / f"campaign/run-{number}-raw/report.json")
        attempt = envelope["attempts"][number - 1]
        assert attempt["step"]["returncode"] == 101
        assert attempt["phase_startup_errors"] == []
        assert attempt["report_sha256"] == digest(BASE / f"campaign/run-{number}-raw/report.json")
        phases = []
        assert [p["mode"] for p in report["phases"]] == ["baseline", "from-zero", "late-product"]
        for phase in report["phases"]:
            confirmed = sum(c["confirmed_inside_pressure_window"] is True for c in phase["confirmations"])
            phase_row = {
                "mode": phase["mode"], "passed": phase["finite_phase_criteria_met"],
                "planned_confirmations": 3, "observed_rounds": len(phase["confirmations"]),
                "confirmed_inside_30_second_window": confirmed,
                "accepted_full_work": phase["full_work_accepted"],
                "failed_full_work": phase["full_work_failed"],
                "receiver_client_state_equal": phase["receiver_client_state_equal"],
                "verifier_errors": phase["verifier_errors"],
                "history_fetch_wall_ns": [h["elapsed_wall_ns"] for h in phase["history"]],
                "client_import_wall_ns": [h["client_import"]["wall_ns"] for h in phase["history"] if "client_import" in h],
                "client_stages": {s: stage_delta(phase, "client_native_history_arithmetic", s)
                                  for s in ("account_graph", "verify_state", "admission", "activation")},
            }
            phases.append(phase_row)
        result["campaigns"].append({"number": number, "exit_code": 101, "phases": phases})
    execution = read(BASE / "f0/execution/results.json")
    finalization = read(BASE / "f0/finalization/result.json")
    raw = read(BASE / "f0/execution/raw/report.json")
    assert execution["head"] == HEAD and execution["tree"] == TREE
    assert execution["report_sha256"] == digest(BASE / "f0/execution/raw/report.json")
    rounds = raw["all_planned_rounds"]
    assert len(rounds) == 6
    successes = sum(r["four_second_slo_met"] is True for r in rounds)
    assert successes == execution["four_second_slo_successes"]
    result["f0"] = {
        "planned_confirmations": execution["planned_confirmations"],
        "four_second_slo_successes": successes,
        "native_failure": execution["native_result_failure"],
        "report_validation_failure": execution["report_validation_failure"],
        "controller_resources_complete": execution["controller_resources_complete"],
        "all_services_known_empty": finalization["all_services_known_empty"],
        "services_observed_empty": [r["known_empty"] for r in finalization["services"]],
        "rounds": [{k: r[k] for k in ("phase", "round", "four_second_slo_met",
                    "confirmed_inside_original_window", "elapsed_from_scheduled_ns")}
                   for r in rounds],
    }
    history = {"schema": "m14-history-cross-architecture-readback-v1", "candidate": HEAD,
               "tree": TREE, "run_id": 42693804647,
               "scope": "four finite observations, two architectures and head/merge commit identities with identical tree; no stability or WAN qualification",
               "lanes": [inspect_history(e) for e in HISTORY]}
    for architecture in ("x64", "arm64"):
        assert len({r["binary_sha256"] for r in history["lanes"]
                    if r["architecture"] == architecture}) == 1
    history_path = BASE / "M14_HISTORY_COMPARISON.json"
    history_path.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n")
    result["history_comparison_sha256"] = digest(history_path)
    destination = BASE / "M14_HOST_READBACK.json"
    destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"report": str(destination), "sha256": digest(destination),
                      "archives_verified": 2, "campaigns_passed": sum(
                          all(p["passed"] for p in c["phases"]) for c in result["campaigns"]),
                      "phases_passed": sum(p["passed"] for c in result["campaigns"] for p in c["phases"]),
                      "f0_four_second_slo_successes": successes}, sort_keys=True))


if __name__ == "__main__":
    main()

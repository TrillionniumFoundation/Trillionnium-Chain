#!/usr/bin/env python3
"""Verify a retained failed F0 campaign without executing the workload."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts/ci"))
import run_fixed_host_root_f0 as f0

HEAD = "e6af21fd47347ba900ef87842447ed6fe227a6f0"
TREE = "af911ad472b7820f8c6c7d4c9a425097263d80ac"
ZIP_SHA256 = "6ab6d65c68a2d0b36e49995507dbcc7f7728e16fec3fe6e20de53cb1fdff62fa"
# SHA-256 of original imported Git blobs at HEAD above.
ORIGINAL_READER_SHA256 = {
    "formal/pon-nakamoto-v1/bounded_process.py": "16fa98206e75db5e925a31508e889df9d1968c32f518554f52c2a0711047b356",
    "formal/pon-nakamoto-v1/contract_wire.py": "cbe45d72ad20ed5683d50dceaa97b93bc74cdafced7d0896386edf9cbe9f98f6",
    "scripts/ci/fixed_root_f0_ownership.py": "a6376e43166cd782a90ac782c1619ef6ec6cd5cbb8d25093aedaf870c2d5dba1",
    "scripts/ci/fixed_root_f0_resources.py": "43b86bdab5715917cd7e7140765099a75178815e730a66d438b820b9cb370a4a",
    "scripts/ci/public_host_ci_observation.py": "cc0facf46d14bc113d6a83d6b1215afe91c7b5cf22d65892f34921c8f1b983e3",
    "scripts/ci/run_fixed_root_phase_host.py": "f572b12727d119f7d1c1490d2a8c70de69e596155e20a837ebf94d19e24911e7",
    "scripts/pon_public_v3_phase_read.py": "f2dd54ec905117e26fc7128218acb74c36a3ae7c16229d56c7cc04dae1a5ef41",
    "scripts/pon_public_v3_policy_read.py": "89c45bebc01691bf42fcd65bc19625797b32d4112907f3d24ada094c6b9d698a",
    "scripts/pon_w1_cost_matrix_reader.py": "6a967274b93394494a2606c08173d4c755f255742bdca6cecd9665ce9f3686fa",
    "scripts/read_original_native_campaign.py": "4381e3af6dac9ea2301cb78ff1761628a3b0e236750d1f291f4d51118c31b417",
    "scripts/run_fixed_host_root_f0.py": "abf75f729dcb54d7c2bebf2c54c253c5164e801b7ebcc642bb8ba58290518cca",
    "scripts/run_pon_w1_native_campaign.py": "eff0930837331f08882a0d69a6909e8f8dda2b23dad58cf0e6bc60d175f0a431"
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return f0.receipt(path, 160 * 1024 * 1024)


def expected_failure(function, expected, *args):
    try:
        function(*args)
    except ValueError as error:
        require(str(error) == expected, "original refusal changed: " + str(error))
        return str(error)
    raise ValueError("original failed business gate unexpectedly passed")


def history_cost(phase):
    rows = []
    for ordinal, attempt in enumerate(phase["history"]):
        imported = attempt.get("client_import")
        if imported is None:
            rows.append({"history_index": ordinal, "import_observed": False,
                         "client_thread_cpu_ns": None, "host_checkpoint_cpu_ns": None})
            continue
        observation = imported["native_import_observation"]
        checkpoints = [entry for entry in observation["host_checks"]
                       if entry["phase"] == "checkpoint"]
        require(len(checkpoints) == 1, "one original checkpoint accumulator required")
        checkpoint = checkpoints[0]
        require(checkpoint["calls_started"] == checkpoint["calls_completed"]
                and checkpoint["calls_unfinished"] == 0
                and checkpoint["cpu_clock_unknown_calls"] == 0
                and observation["measurement_failures"] == 0,
                "unknown checkpoint cost cannot become zero")
        require(type(imported["thread_cpu_ns"]) is int
                and type(checkpoint["thread_cpu_ns"]) is int,
                "actual caller and Host CPU clocks required")
        rows.append({"history_index": ordinal, "import_observed": True,
                     "network_ended_ns": attempt["ended_ns"],
                     "import_wall_ns": imported["wall_ns"],
                     "import_error": imported["error"],
                     "client_thread_cpu_ns": imported["thread_cpu_ns"],
                     "host_checkpoint_cpu_ns": checkpoint["thread_cpu_ns"],
                     "host_checkpoint_calls": checkpoint["calls_completed"]})
    observed = [row for row in rows if row["import_observed"]]
    return {"phase": phase["mode"], "attempts": rows,
            "observed_imports": len(observed), "history_calls": len(rows),
            "client_thread_cpu_ns": sum(row["client_thread_cpu_ns"] for row in observed),
            "host_checkpoint_cpu_ns": sum(row["host_checkpoint_cpu_ns"] for row in observed),
            "host_checkpoint_calls": sum(row["host_checkpoint_calls"] for row in observed),
            "scope": "actual observed client imports; Host CPU is nested; do not add; not whole-process cost"}


def review(archive):
    require(archive.stat().st_size == 19573624 and digest(archive) == ZIP_SHA256,
            "original GitHub ZIP identity changed")
    with tempfile.TemporaryDirectory(prefix="chain-f0-readback-") as temporary:
        root = Path(temporary).resolve()
        with zipfile.ZipFile(archive) as zipped:
            entries = zipped.infolist()
            require(sum(entry.file_size for entry in entries) < 512 * 1024 * 1024,
                    "archive expansion bound")
            names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)), "duplicate archive member")
            for entry in entries:
                require((root / entry.filename).resolve().is_relative_to(root)
                        and not Path(entry.filename).is_absolute()
                        and not stat.S_ISLNK(entry.external_attr >> 16), "unsafe archive member")
            zipped.extractall(root)
        inventory = read(root / "artifact-files.json")
        require(inventory["all_files_retained"] is True and inventory["errors"] == [],
                "incomplete provider inventory")
        require(set(names) == {row["path"] for row in inventory["files"]}
                | {"artifact-files.json"}, "archive roster differs from original inventory")
        for row in inventory["files"]:
            path = root / row["path"]
            require(path.resolve().is_relative_to(root) and path.is_file()
                    and path.stat().st_size == row["bytes"] and digest(path) == row["sha256"],
                    "changed original member: " + row["path"])
        for prefix in ("", "prepared/", "execution/"):
            before, after = (read(root / (prefix + "source-" + moment + ".json"))
                             for moment in ("before", "after"))
            require(before == after and before["tested_commit"] == HEAD
                    and before["tested_tree"] == TREE
                    and before["tracked_worktree_verified"] is True,
                    "source identity changed: " + prefix)
        prepared = read(root / "prepared/prepared.json")
        execution = read(root / "execution/results.json")
        final = read(root / "finalization/result.json")
        report = read(root / "execution/raw/report.json")
        require(prepared["prepared"] is True and prepared["failure"] is None
                and prepared["runner_sha256"] == digest(Path(f0.__file__))
                and prepared["rust_source_control_selectors"] == list(f0.SOURCE_CONTROLS)
                and prepared["inputs"] == execution["inputs"] == f0.INPUTS,
                "original preparation contract changed")
        require(execution["prepared_sha256"] == digest(root / "prepared/prepared.json")
                and execution["report_sha256"] == digest(root / "execution/raw/report.json")
                and execution["binary"] == prepared["binary"], "original execution binding changed")
        binary = root / "prepared/public_v3_multiprocess.bin"
        require(digest(binary) == prepared["binary"]["sha256"]
                and binary.stat().st_size == prepared["binary"]["bytes"], "retained native ELF changed")
        for ordinal, control in enumerate(prepared["rust_source_controls"]):
            require(control["complete_success"] is True and control["returncode"] == 0
                    and control["command"][2] == f0.SOURCE_CONTROLS[ordinal],
                    "original preparation control failed")
        step = execution["step"]
        stdout = (root / "execution" / step["stdout"]).read_text()
        require(step["returncode"] == 101 and step["complete_success"] is False
                and step["command"][2] == f0.SELECTOR
                and "test " + f0.SELECTOR + " ... FAILED" in stdout
                and "0 passed; 1 failed; 0 ignored;" in stdout,
                "actual original failed test identity changed")
        rounds, packets = f0.f0_rounds(report), f0.f0_packets(report)
        require(rounds == execution["all_planned_rounds"]
                == final["denominator"]["all_planned_rounds"]
                and packets == execution["all_planned_business_packets"]
                == final["denominator"]["all_planned_business_packets"],
                "original failed/unobserved denominator changed")
        require(len(rounds) == 6 and len(packets) == 42
                and sum(row["confirmed_inside_original_window"] for row in rounds) == 2
                and sum(row["four_second_slo_met"] for row in rounds) == 0,
                "original actual business result changed")
        cgroup = report["controller_identity_before"]["process"]["cgroup"]
        resources = f0.check_controller_resources(report, cgroup)
        require(resources == execution["controller_resource_summary"], "resource reader disagrees")
        failure = expected_failure(f0.check_report, "BASELINE_MUST_PASS", report, cgroup)
        slo_failure = expected_failure(f0.check_f0_placement_and_timing,
                                      "F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED", report, cgroup)
        require(execution["complete_success"] is False and final["complete_success"] is False
                and execution["report_validation_failure"] == failure
                and final["all_services_known_empty"] is True, "failure or cleanup was reclassified")
        return {"schema": "chain-fixed-root-f0-independent-readback-v1",
                "run_id": 44335832525, "artifact_id": 14444536755,
                "archive_sha256": ZIP_SHA256, "archive_bytes": archive.stat().st_size,
                "manifest_files_checked": len(inventory["files"]), "head": HEAD, "tree": TREE,
                "native_binary_sha256": digest(binary), "native_exit_code": step["returncode"],
                "prepared_controls_checked": len(prepared["rust_source_controls"]),
                "confirmed_in_original_thirty_second_phases": 2, "planned_confirmations": 6,
                "four_second_slo_successes": 0, "planned_packet_exposures": 42,
                "original_business_failure": failure, "original_slo_failure": slo_failure,
                "all_planned_rounds": rounds, "all_planned_business_packets": packets,
                "controller_resource_summary": resources,
                "history_cost": [history_cost(phase) for phase in report["phases"]],
                "public_phase_process_cost": [{"phase": phase["mode"],
                    "whole_parent_phase_cpu_ns": phase["whole_parent_phase_cpu_ns"],
                    "whole_parent_phase_wall_ns": phase["whole_parent_phase_wall_ns"],
                    "scope": "original public phase process including receiver and independent client; not external controller"}
                    for phase in report["phases"]],
                "complete_success": False, "all_services_known_empty": True,
                "full_physical_cost_closed": False, "production_activation": False,
                "unknown_cost_dimensions": ["concurrent whole-system RSS", "storage byte-seconds",
                    "physical storage I/O", "physical network bytes", "GPU activity", "energy", "provider charges"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    readers = {str(Path(module.__file__).resolve().relative_to(ROOT)): digest(Path(module.__file__))
               for module in tuple(sys.modules.values()) if getattr(module, "__file__", None)
               and Path(module.__file__).resolve().is_relative_to(ROOT)
               and Path(module.__file__).suffix == ".py"
               and Path(module.__file__).resolve() != Path(__file__).resolve()}
    require(readers == ORIGINAL_READER_SHA256, "reader differs from original source graph")
    result = review(args.archive)
    result["original_reader_source_sha256"] = readers
    result["readback_source_sha256"] = digest(Path(__file__))
    with args.out.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"readback": "VERIFIED_FAILURE", "business_pass": False,
                      "original_window_confirmations": "2/6", "four_second_slo": "0/6",
                      "controller_boundaries": "6/6", "full_physical_cost_closed": False}))


if __name__ == "__main__":
    main()

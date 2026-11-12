#!/usr/bin/env python3
"""Independently audit original CI 43125548321 bytes; execute no native program."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

HEAD = "0bc51795a978494af1b4659712ecf78c290c1a88"
ZIP_SHA = "db8960d8388dadb29450e525de1e3eaa71a2ae87d5d897c0e1ce9afb711bf312"
PREFIX = "sp27-receiver-controls/"
HOST = "sp27-receiver-controls-host/"
LIMITS = {"cpu.max": "25000 100000", "cpu.max.burst": "0",
          "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "256"}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def write_new(path, value):
    with path.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
    path.chmod(0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw_zip = args.archive.read_bytes()
    assert len(raw_zip) == 5_389_637 and digest(raw_zip) == ZIP_SHA
    with zipfile.ZipFile(args.archive) as archive:
        assert archive.testzip() is None
        names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
        assert len(names) == len(set(names))
        for name in names:
            path = Path(name)
            assert not path.is_absolute() and ".." not in path.parts
        members = {name: {"bytes": len(value), "sha256": digest(value)}
                   for name in names for value in [archive.read(name)]}
        def load(name):
            return json.loads(archive.read(name))
        prepared = load(PREFIX + "preparation.json")
        manifest = load(PREFIX + "manifest.json")
        source = manifest["source_before"]
        assert source == manifest["source_after"] == prepared["source_before"] == prepared["source_after"]
        assert source["commit"] == HEAD
        identity = load("source.json")
        assert identity["tested_commit"] == HEAD and identity["tested_tree"] == source["tree"]
        assert identity["tracked_worktree_verified"] is True
        actual_tree = subprocess.check_output([
            "git", "-C", str(args.source_repo), "rev-parse", HEAD + "^{tree}"
        ], text=True).strip()
        assert actual_tree == source["tree"]
        source_files = {}
        for path, expected in source["files_sha256"].items():
            value = subprocess.check_output(["git", "-C", str(args.source_repo), "show", HEAD + ":" + path])
            assert digest(value) == expected, path
            source_files[path] = {"bytes": len(value), "sha256": expected,
                                  "git_blob": hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()}
        actual_binary = members[PREFIX + "public_v3_from_zero"]
        assert manifest["binary_before"] == manifest["binary_after"] == prepared["binary"]
        assert actual_binary["sha256"] == prepared["binary"]["sha256"]
        assert actual_binary["bytes"] == prepared["binary"]["size_bytes"]
        before = load(PREFIX + "native/identity-before.json")
        after = load(PREFIX + "native/identity-after.json")
        assert before == after
        assert before["binary_sha256"] == actual_binary["sha256"] and before["binary_identity_error"] is None
        assert before["runner_declared_source_sha"] == HEAD
        assert before["github_run_id"] == "43125548321" and before["github_run_attempt"] == "1"
        assert before["compiled_test_source_sha256"] == source["files_sha256"]["trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs"]
        assert before["compiled_health_module_sha256"] == source["files_sha256"]["trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_controls.rs"]
        runner_hosts = [load(HOST + "inside-before.json"), load(HOST + "inside-after.json")]
        native_hosts = [load(PREFIX + "native/host-before.json"), load(PREFIX + "native/host-after.json")]
        controller = load(HOST + "controller-result.json")
        child = load(HOST + "child-result.json")
        assert controller["passed"] is True and controller["final_host_errors"] == []
        assert child["native_child_exit"] == 0 and child["host_errors"] == []
        assert controller["parent_reused"] is False
        assert controller["parent_lease"] == controller["final_parent_lease"]
        for host in runner_hosts:
            assert host["limits"] == LIMITS and host["read_errors"] == {}
            assert host["boot_id"] == before["boot_id"]
            assert host["uid"] == host["gid"] == 1001
            assert host["thread_privileges"] == {"CapBnd": "0000000000000000", "NoNewPrivs": "1"}
        assert runner_hosts[0]["parent"] == runner_hosts[1]["parent"]
        for host in native_hosts:
            assert host["verified"] is True and host["error"] is None
            assert host["fixed_parent"] == "/sys/fs/cgroup/trnmponpublic.slice"
        report = load(PREFIX + "native/report.json")
        assert report["qualification"] == "HEALTH_GATE_PASSED_CONTROLS_PENDING"
        assert all(report[key] == 3 for key in ["planned_health_repetitions", "attempted_health_repetitions", "completed_health_repetitions"])
        assert all(report[key] == 0 for key in ["incomplete_health_repetitions", "not_executed_health_repetitions", "pressure_controls_executed"])
        assert report["first_divergence"] is None and report["health_gate_passed"] is True
        assert report["causal_mechanism_status"] == "UNKNOWN"
        phases = []
        for row in report["health_phases"]:
            member = PREFIX + "native/" + row["raw_record"]
            assert members[member]["sha256"] == row["raw_sha256"]
            phase = load(member)
            assert phase["requested_window_ns"] == 4_000_000_000 and phase["workers"] == 0
            assert phase["client_confirmed_before_original_window_end"] is True
            assert phase["client_confirmed_transactions"] == 1
            assert all(phase[k] is True for k in ["invariant_target_met", "finite_business_target_met", "full_native_state_equal"])
            assert 0 <= phase["confirmation_ended_ns"] < 4_000_000_000
            assert phase["verification_errors"] == []
            assert phase["observations"]["records_not_retained"] == phase["observations"]["measurement_failures"] == 0
            assert phase["observations"]["counter_overflow"] is False
            anomalies = [{"field": field, "row": index, "status": value["status"],
                          "ended_ns": value.get("ended_ns"), "error": value.get("error")}
                         for field in ["honest_submissions", "honest_history"]
                         for index, value in enumerate(phase[field])
                         if value["status"] != "ok" or value["returned_after_window"] is not False]
            phases.append({"index": row["health_index"], "raw_member": member,
                           "raw_sha256": row["raw_sha256"], "workers": 0,
                           "requested_window_ns": 4_000_000_000, "confirmed": 1, "native_final_gate": True,
                           "business_started_ns": phase["business_started_ns"],
                           "confirmation_ended_ns": phase["confirmation_ended_ns"],
                           "remaining_window_ns": 4_000_000_000 - phase["confirmation_ended_ns"],
                           "honest_submit_calls": len(phase["honest_submissions"]),
                           "history_calls": len(phase["honest_history"]),
                           "independent_replay_attempts": len(phase["independent_history_page_replay"]),
                           "recorded_business_anomalies": anomalies,
                           "observer_records": len(phase["observations"]["records"]),
                           "verification_errors": [], "state_equal": True,
                           "observer_measurement_failures": 0, "observer_dropped": 0})
        acquisition = load(PREFIX + "native/acquisition.json")
        packets = []
        for index, encoded in enumerate(acquisition["signed_honest_packets"]):
            packet = bytes.fromhex(encoded)
            count, pos = int.from_bytes(packet[318:320], "little"), 320
            lengths = []
            for _ in range(count):
                size = int.from_bytes(packet[pos:pos + 2], "little")
                lengths.append(size)
                pos += 2 + size
            assert len(packet) - pos == 49188
            packets.append({"index": index, "packet_bytes": len(packet), "transactions": count,
                            "transaction_bytes": lengths, "proof_bytes": 49188,
                            "canonical_submit_json_bytes": len(json.dumps({"op": "submit", "packet": encoded}, separators=(",", ":")).encode())})
        process = load(PREFIX + "run/process.json")
        assert process == manifest["process"] and process["exit_code"] == 0 and process["timed_out"] is False
        assert process["stdout_sha256"] == members[PREFIX + "run/stdout"]["sha256"]
        assert process["stderr_sha256"] == members[PREFIX + "run/stderr"]["sha256"]
        dt = [datetime.datetime.fromisoformat(x["observed_utc"]) for x in runner_hosts]
        audit = {
            "schema": "sp27-02-original-health-ci-audit-v1", "source_commit": HEAD, "source_tree": actual_tree,
            "run_id": 43125548321, "job_id": 130876572920, "artifact_id": 13902664465,
            "artifact_bytes": len(raw_zip), "artifact_sha256": ZIP_SHA, "members_checked": len(members),
            "archive_crc_verified": True, "source_files": source_files, "binary": actual_binary,
            "native_identity_before_and_after": before, "runner_host_before": runner_hosts[0],
            "runner_host_after": runner_hosts[1], "native_host_before": native_hosts[0], "native_host_after": native_hosts[1],
            "cooperative_parent_lease": controller["parent_lease"], "parent_reused": False,
            "physical_cpu_exclusivity": "NOT_ESTABLISHED; cooperative fixed-parent lease and resource eligibility are verified",
            "qualification": report["qualification"], "planned": 3, "attempted": 3, "completed": 3,
            "incomplete": 0, "unstarted": 0, "independently_confirmed": 3,
            "pressure_controls_executed": 0, "first_divergence": None, "phases": phases,
            "mechanism_status": "UNKNOWN", "new_native_runs_executed_by_audit": 0,
            "native_process": process, "native_child_timeout_seconds": 90,
            "native_timeout_scope": "run_child around the named native executable; excludes earlier/later Python source-identity and Host-wrapper work",
            "runner_inside_snapshot_interval_ns": int((dt[1] - dt[0]).total_seconds() * 1_000_000_000),
            "acquisition": {key: acquisition[key] for key in ["honest_chain_acquisition_wall_ns", "honest_chain_process_cpu_ns", "process_cpu_scope"]},
            "packet_sizes": packets, "sixteen_distinct_valid_sibling_cost": "NOT_MEASURED by this batch",
            "audit_script_sha256": digest(Path(__file__).read_bytes()),
            "raw_archive_member_index": "RAW_SHA256.json",
        }
    args.out.mkdir(parents=True, exist_ok=True)
    write_new(args.out / "RAW_SHA256.json", members)
    write_new(args.out / "HEALTH_CI_AUDIT.json", audit)
    print(json.dumps({"qualification": audit["qualification"], "confirmed": 3, "planned": 3,
                      "members_checked": len(members), "output": str(args.out),
                      "audit_sha256": digest((args.out / "HEALTH_CI_AUDIT.json").read_bytes())}, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Read retained DAG observations; do not execute any embedded command."""

import collections
import hashlib
import io
import json
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parent
HEAD = "12fe5f2c1f19704fe7eb635dede6839ed8b1e91e"
MERGE = "0357031364787574cb7058b05329aa2e2730f947"
TREE = "c44112da731e3f958e55eb024e5762d6723ea2c9"
TEST = "signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    results = []
    for path in sorted(ROOT.glob("*.manifest.json")):
        manifest = json.loads(path.read_bytes())
        metadata = manifest["artifact"]
        raw = (ROOT / manifest["payload_file"]).read_bytes()
        assert len(raw) == manifest["payload_bytes"]
        assert digest(raw) == manifest["payload_sha256"]
        assert metadata["workflow_run"]["id"] == 41628135442
        assert metadata["workflow_run"]["head_sha"] == HEAD
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
            members = archive.getmembers()
            assert all(member.isfile() for member in members)
            assert len(members) == len({member.name for member in members})
            data = {member.name: archive.extractfile(member).read() for member in members}
        assert set(data) == {row["path"] for row in manifest["members"]}
        for row in manifest["members"]:
            content = data[row["path"]]
            assert len(content) == row["bytes"] and digest(content) == row["sha256"]

        source = json.loads(data["source.json"])
        receipt = json.loads(data["rust-shard.json"])
        assert source == receipt["before"] == receipt["after"]
        assert source["candidate"] == HEAD
        assert source["tested_commit"] in (HEAD, MERGE)
        assert source["tested_tree"] == TREE
        assert source["tracked_worktree_verified"] is True
        assert source["tests_executed_by_identity_check"] is False
        assert receipt["shard"] == "runtime"
        assert receipt["status"] == "failed" and receipt["exit_code"] == 101
        assert receipt["run"] == {"GITHUB_RUN_ID": "41628135442", "GITHUB_RUN_ATTEMPT": "1"}
        assert digest(data["rust-shard.sh"]) == receipt["command_sha256"]
        log = data["workspace-tests.log"].decode(errors="strict")
        assert "test " + TEST + " ... FAILED" in log
        assert "retained native delivery/replay invariants failed" in log
        assert "test result: FAILED. 1 passed; 1 failed; 0 ignored;" in log

        report = json.loads(data["architecture-delivery-comparison.json"])
        assert report["schema"] == "native-signed-dag-delivery-comparison-v1"
        assert report["balanced_cyclic_mode_order"] is True
        assert report["same_signed_packets_across_modes_and_repetitions"] is True
        assert report["samples_per_workload_and_mode"] == 3
        for flag in ("all_finite_business_targets_met", "architecture_winner_declared",
                     "independent_accepted", "production_activation", "protocol_switch_qualified",
                     "wan_tested"):
            assert report[flag] is False
        rows = report["samples"]
        assert len(rows) == 18
        assert sorted(collections.Counter(row["mode"] for row in rows).values()) == [6, 6, 6]
        observations = []
        for row in rows:
            assert row["errors"] == ["PUBLIC_HOST_KERNEL_PARENT"]
            assert row["confirmed_transactions"] == 0
            assert row["finite_business_target_met"] is False
            assert row["native_state_equal"] is False and row["cold_reopen_equal"] is True
            assert len(row["block_submissions"]) == 7
            assert all(item["ok"] is True for item in row["block_submissions"])
            assert len(row["history_calls"]) == 1 and row["history_calls"][0]["ok"] is True
            observations.append({key: row[key] for key in (
                "sample", "scenario", "mode", "position", "errors", "confirmed_transactions",
                "finite_business_target_met", "native_state_equal", "cold_reopen_equal",
                "full_business_latency_ns")})
        results.append(dict(artifact_id=metadata["id"], original_zip_sha256=metadata["digest"],
                            source=source, runtime_exit_code=101,
                            report_sha256=digest(data["architecture-delivery-comparison.json"]),
                            full_log_sha256=digest(data["workspace-tests.log"]),
                            samples=observations, failure_waived=False, workload_rerun=False))
    assert {row["source"]["tested_commit"] for row in results} == {HEAD, MERGE}
    output = dict(schema="trnm-dag-parent-refusal-readback-v1", observations=results,
                  whole_system_qualified=False, production_activation=False)
    (ROOT / "observations.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"verified_lanes": len(results), "samples_per_lane": 18,
                      "original_error": "PUBLIC_HOST_KERNEL_PARENT",
                      "original_runtime_exit_code": 101, "qualification": False}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Verify retained decoded logs only; execute no Chain/native code."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
HEAD = "362fbebe5027d731f16c88f710bfef7e922cd230"
TREE = "5a7a2eadfcfb75b9fdf38fa0e8a05c6a503d776d"

def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def objects(name):
    text = (ROOT / name).read_bytes().decode("utf-8")
    values = []
    for line in text.splitlines():
        line = re.sub(r"^\\d{4}-\\d\\d-\\d\\dT\\S+ ", "", line)
        if not line.startswith("{"):
            continue
        try:
            values.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return values

def unique_schema(name, schema):
    found = [x for x in objects(name) if x.get("schema") == schema]
    need(len(found) == 1, "exactly one real JSON receipt: " + name)
    return found[0]

def main():
    manifest = json.loads((ROOT / "FILES.json").read_bytes())
    need(manifest["schema"] == "trnm-decoded-evidence-files-v1", "manifest schema")
    seen = set()
    for item in manifest["files"]:
        name = item["path"]
        need(isinstance(name, str) and Path(name).name == name and name not in seen, "file path")
        seen.add(name)
        raw = (ROOT / name).read_bytes()
        need(len(raw) == item["bytes"], "length: " + name)
        need(hashlib.sha256(raw).hexdigest() == item["sha256"], "sha256: " + name)
        need(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\\0" + raw).hexdigest() == item["git_blob"], "git blob: " + name)
    need(seen == {"README.md", "SNAPSHOT.json", "replay_decoded_logs.py",
                  "job-126300603089-campaign.decoded.log",
                  "job-126300606020-fresh-head.decoded.log",
                  "job-126300605572-fresh-merge.decoded.log"}, "complete file set")
    snapshot = json.loads((ROOT / "SNAPSHOT.json").read_bytes())
    campaign = unique_schema("job-126300603089-campaign.decoded.log", "pon-original-native-campaign-ci-v1")
    need(campaign == snapshot["campaign"]["actual_receipt"], "campaign exact receipt")
    need(campaign["expected_head"] == HEAD and campaign["expected_tree"] == TREE, "source")
    need(campaign["source_after"]["tested_commit"] == HEAD and campaign["source_after"]["tested_tree"] == TREE and campaign["source_after"]["tracked_worktree_verified"] is True, "tracked source")
    need(campaign["build"]["returncode"] == 0, "actual build")
    need(campaign["binary"]["sha256_before"] == campaign["binary"]["sha256_after"], "reported binary stability")
    need(campaign["failure"] == "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED" and campaign["complete_success"] is False and campaign["finalization_failures"] == [], "original campaign failed")
    need(campaign["original_inputs"] == {"attacker_processes": [0, 24, 24], "business_blocks": 21, "modes": ["baseline", "from-zero", "late-product"], "phase_seconds": 30, "seed_blocks": 4, "seed_transfers": 1024}, "original workload")
    need(campaign["public_phase_placement"]["receiver_and_verifier_cpu_max"] == "25000 100000" and campaign["public_phase_placement"]["receiver_and_verifier_memory_max"] == "2147483648", "original public Host")
    need(len(campaign["attempts"]) == 3, "complete attempt denominator")
    expected = ["/home/runner/.cargo/bin/cargo", "+1.95.0", "test", "--locked", "--offline", "--release", "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--test", "public_v3_multiprocess", "separate_process_work_and_signed_confirmation_campaign", "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"]
    for number, attempt in enumerate(campaign["attempts"], 1):
        step = attempt["step"]
        need(attempt["number"] == number and step["command"] == expected, "exact campaign selector")
        need(step["returncode"] == 101 and step["outer_stage_timeout_seconds"] == 600 and step["error"] is None, "actual original native failure")
        need(attempt["original_criteria_met"] is False and attempt["complete_success"] is False, "business failure")
        need(attempt["phase_startup_errors"] == [] and attempt["report_validation_failure"] is None, "no startup/shape relabel")
    files = ["job-126300606020-fresh-head.decoded.log", "job-126300605572-fresh-merge.decoded.log"]
    for item, name in zip(snapshot["fresh"], files):
        control = unique_schema(name, "trnm-ci-original-public-host-controller-v2")
        need(control == item["actual_controller"], "exact fresh controller")
        need(control["failure"] is None and control["final_host_errors"] == [] and control["systemd_run_exit"] == 1 and control["passed"] is False, "real Host child failure")
        prep = control["preparation"]
        need(prep["completed"] is True and prep["process"]["exit_code"] == 0 and prep["source_error"] is None, "fresh build")
        need(prep["source_before"] == prep["source_after"] and prep["source_before"]["tree"] == TREE, "fresh source stability")
        limits = control["parent_lease"]["parent_identity"]["limits"]
        need(limits == {"cpu.max": "25000 100000", "cpu.max.burst": "0", "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "256"}, "original fixed Host limits")
    need(all(x is False for x in snapshot["qualification"].values()), "no qualification promotion")
    print(json.dumps({"schema": "trnm-decoded-readback-replay-v1", "passed": True,
                      "files_verified": len(seen), "campaign_attempts_failed": 3,
                      "fresh_host_child_failures": 2, "native_tests_executed": 0,
                      "performance_qualified": False, "activation_qualified": False}, sort_keys=True))

if __name__ == "__main__":
    main()

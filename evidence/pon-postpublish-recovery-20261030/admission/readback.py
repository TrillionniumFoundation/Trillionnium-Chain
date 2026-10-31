#!/usr/bin/env python3
"""Read retained CI bytes; never rerun native work or promote qualification."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

HEAD = "1d11f875493f8125e36b9adceacb342df108e5e5"
TREE = "64b82137eebeb96b572abc62e5fce39af3593200"
X64_SHA = "0cba4a65b534be04492764bd6ba0b67c81712e23e154c0e1643bebc40e4e4a37"
ARM_SHA = "35bd0454c8f700e1488290ee03496bf28052e4716f6fb0218ef240c81bd73426"

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def round_summary(report):
    imports = [r["client_import"] for r in report["history"] if r.get("client_import")]
    return {
        "phase": report["phase"], "window_ns": report["window_ns"],
        "errors": report["errors"], "history_import_count": len(imports),
        "history_import_process_cpu_total_ns": sum(r["process_cpu_ns"] for r in imports),
        "last_history_import": {k: imports[-1].get(k) for k in
            ("process_cpu_ns", "process_wall_ns", "thread_cpu_ns", "wall_ns")} if imports else None,
        "rounds": [{k:r.get(k) for k in ("round", "started_ns", "ended_ns",
                                       "confirmed_inside_pressure_window", "depletion_observed_during_round")}
                   | {"observed_depth": r.get("observation", {}).get("depth")}
                   for r in report["rounds"]],
    }

def observed_callers(report):
    """Recount joins in original records; does not independently derive Ed25519."""
    by_body, offered = {}, set()
    for wrapper in report["actors"]:
        actor = wrapper["report"]
        if actor is None or actor["error"] is not None:
            continue
        for call in actor["result"]["calls"]:
            body, key = call["body_digest"], call["caller_public_key"]
            assert body not in by_body and key not in offered
            by_body[body] = key
            offered.add(key)
    authenticated = set()
    for capture in report["observations"]:
        assert capture["coverage_complete"] is True
        assert capture["snapshot"]["schema"] == "public-v3-local-request-resource-observation-v4"
        for row in capture["snapshot"]["records"]:
            key = row.get("authenticated_caller")
            if key is None or row["body_digest"] is None:
                continue
            body = bytes(row["body_digest"]).hex()
            if body in by_body:
                assert by_body[body] == key
                authenticated.add(key)
    return {"phase": report["phase"], "offered_distinct_attack_callers": len(offered),
            "authenticated_distinct_attack_callers": len(authenticated)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-x64", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    provenance = json.loads((root/"provenance.json").read_text())
    manifest = json.loads((root/"selection-manifest.json").read_text())
    assert provenance["head"] == HEAD and provenance["tree"] == TREE
    assert provenance["native_rerun"] is False
    for log in provenance["job_logs"]:
        path = root/log["file"]
        assert path.stat().st_size == log["bytes"] and sha(path) == log["sha256"]
        decoded = gzip.decompress(path.read_bytes())
        assert len(decoded) == log["decoded_log_bytes"]
        assert hashlib.sha256(decoded).hexdigest() == log["decoded_log_sha256"]
    selected = root/manifest["file"]
    assert selected.stat().st_size == manifest["bytes"] < 8*1024*1024
    assert sha(selected) == manifest["sha256"]
    assert manifest["original_archive_sha256"] == X64_SHA
    members = manifest["members"]
    assert len(members) == len({r["artifact_member"] for r in members}) == 45
    raw = {}
    with ZipFile(selected) as z:
        assert len(z.namelist()) == len(members)
        assert set(z.namelist()) == {r["artifact_member"] for r in members}
        for row in members:
            assert 0 <= row["bytes"] <= 32*1024*1024
            assert z.getinfo(row["artifact_member"]).file_size == row["bytes"]
            data = z.read(row["artifact_member"])
            assert len(data) == row["bytes"]
            assert hashlib.sha256(data).hexdigest() == row["sha256"]
            raw[row["artifact_member"]] = data
    original_checked = args.original_x64 is not None
    if original_checked:
        assert args.original_x64.stat().st_size == 98015214
        assert sha(args.original_x64) == X64_SHA
        with ZipFile(args.original_x64) as z:
            assert len(z.namelist()) == len(set(z.namelist())) == 1587
            assert all(z.read(name) == data for name, data in raw.items())
    def read(name):
        return json.loads(raw[name])
    arm_path = root/"arm64-original-artifact.zip"
    assert arm_path.stat().st_size == 28003 and sha(arm_path) == ARM_SHA
    with ZipFile(arm_path) as z:
        assert len(z.namelist()) == len(set(z.namelist())) == 10
        arm_sources = [json.loads(z.read(n)) for n in ("source-checkout.json", "source-final.json")]
        arm_environment = json.loads(z.read("reader-environment-probe.json"))
        toolchain = z.read("toolchain.log").decode()
        assert "recovering from a partially installed toolchain" in toolchain
        assert "detected conflict: 'bin/cargo-clippy'" in toolchain
    sources = [read(n) for n in ("source-checkout.json", "source-final.json",
                                 "campaign/source-before.json", "campaign/source-after.json")]
    assert all(s == sources[0] for s in sources + arm_sources)
    assert sources[0]["tested_commit"] == HEAD and sources[0]["tested_tree"] == TREE
    assert sources[0]["tracked_worktree_verified"] is True
    jobs = json.loads((root/"metadata/jobs.json").read_text())["jobs"]
    assert {j["id"] for j in jobs} == {123845534896, 123845534628}
    assert all(j["status"] == "completed" and j["conclusion"] == "failure" for j in jobs)
    result = read("campaign/results.json")
    assert result["expected_head"] == HEAD and result["complete_success"] is False
    assert result["failure"] is None and result["finalization_failures"] == []
    assert len(result["native_verdicts"]) == len(result["required_native_gates"]) == 19
    assert len(result["required_client_reader_gates"]) == 6
    steps = {r["name"]:r for r in result["steps"]}
    assert len(steps) == len(result["steps"])
    assert all(name in steps for name in result["required_client_reader_gates"])
    campaigns = []
    for name in ("pure-pressure", "receiver-owner-supplement", "fresh-caller-pressure"):
        assert steps[name]["returncode"] == 101 and steps[name]["complete_success"] is False
        campaigns.append({k:steps[name][k] for k in ("name", "returncode", "elapsed_ns",
                                                   "outer_stage_timeout_seconds")})
    assert all(steps[name]["complete_success"] is True for name in ("build-crypto", "build-node", "strict-clippy"))
    fresh = read("campaign/fresh-caller-qualification.json")
    assert fresh["input_consistent"] is True and fresh["finite_qualification"] is False
    assert fresh["reader_environment"]["cryptography_version"] == "50.0.2"
    assert arm_environment["cryptography_version"] == "50.0.2"
    fresh_reports = [read("campaign/fresh-caller-native/"+phase+".json")
                     for phase in ("baseline", "from-zero", "correct-product-false-trace")]
    recount = [observed_callers(r) for r in fresh_reports]
    assert [r["authenticated_distinct_attack_callers"] for r in recount] == [0, 3715, 2834]
    for a, b in zip(recount, fresh["phases"]):
        assert all(a[k] == b[k] for k in a)
        assert b["fresh_caller_coverage_qualified"] is True
    manifests = [read("campaign/"+ns+"/campaign.json") for ns in ("pressure-native", "fresh-caller-native")]
    assert all(m["window_ns"] == 30000000000 and m["attackers"] == 24 and m["actor_call_cap"] == 480
               and m["rounds"] == 3 and m["policy"]["call_deadline_ns"] == 2000000000
               and m["policy"]["ticket_bits"] == 0 for m in manifests)
    failure = read("campaign/receiver-owner-native/correct-product-false-trace/receiver-report-failure-v1.json")
    partial = failure["partial_controller_observations"]
    assert failure["receiver_report_available"] is False and failure["finite_qualification"] is False
    assert len(partial["actors"]) == len(partial["actor_process_costs"]) == 24
    assert all(r["successful_reaps"] == 1 for r in partial["actor_process_costs"])
    assert partial["errors"] == ["RECEIVER_IPC_ABSOLUTE_DEADLINE"]
    assert partial["receiver_wait4"]["parent_forced_kill"] is True
    summary = {
        "schema":"pon-admission-recovered-ci-readback-v1", "head":HEAD, "tree":TREE, "run_id":40988668819,
        "original_sources":sources[0], "native_campaigns":campaigns,
        "native_gates":{"attempted":19, "passed":sum(v["qualified"] is True for v in result["native_verdicts"]), "failed":3},
        "mandatory_reader_gates":[{k:steps[n][k] for k in ("name", "returncode", "complete_success")}
                                  for n in result["required_client_reader_gates"]],
        "driver_exception":result["failure"], "driver_finalization_failures":result["finalization_failures"],
        "original_baseline":round_summary(read("campaign/pressure-native/baseline.json")),
        "fresh_phases":[round_summary(r) for r in fresh_reports],
        "receiver_owner_baseline":round_summary(read("campaign/receiver-owner-native/baseline.json")),
        "original_qualification":read("campaign/pressure-qualification.json"),
        "fresh_original_pressure_qualification":fresh["original_pressure_qualification"],
        "fresh_caller_coverage":fresh["phases"], "recounted_caller_body_joins":recount,
        "reader_environment":fresh["reader_environment"],
        "original_fixed_host_reader":read("campaign/pure-client-readback-v1.json"),
        "fresh_fixed_host_reader":read("campaign/fresh-caller-client-readback-v1.json"),
        "receiver_owner_qualification":read("campaign/receiver-owner-observation-v2.json"),
        "receiver_partial_failure":{"error":failure["error"], "errors":partial["errors"],
            "actor_count":24, "actor_wait4_count":24, "all_actor_successful_reaps_one":True,
            "receiver_wait4":partial["receiver_wait4"], "finite_qualification":False},
        "arm64":{"job_id":123845534628, "outcome":"setup-failed-before-native",
            "reader_environment":arm_environment, "error":"Rustup partially installed toolchain / bin/cargo-clippy conflict",
            "native_campaigns_attempted":0},
        "finite_qualification":False, "production_qualified":False, "public_fairness_qualified":False,
        "work_hardness_qualified":False, "pq128_qualified":False,
        "scope":"Readback of original CI bytes. Counts original caller/body joins but does not independently derive keys, verify signatures, authenticate the CI host, rerun native code, or remeasure time. Nested CPU scopes are not additive. The retained CI reader independently derived keys with pinned cryptography50.0.2."
    }
    if args.output:
        args.output.write_bytes(encode(summary))
    else:
        assert (root/"summary.json").read_bytes() == encode(summary)
    print(json.dumps({"schema":"pon-admission-recovery-verification-v1",
        "selected_original_members_verified":45, "arm64_original_archive_verified":True,
        "full_x64_original_archive_rechecked":original_checked, "source_records_agree":True,
        "actual_record_caller_body_join_counts":[3715,2834], "native_rerun":False,
        "signature_verification_rerun":False, "finite_qualification":False,
        "summary_consistent":True},sort_keys=True,indent=2))

if __name__ == "__main__":
    main()

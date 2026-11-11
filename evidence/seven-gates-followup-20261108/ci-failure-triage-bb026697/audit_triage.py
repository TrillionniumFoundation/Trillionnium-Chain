#!/usr/bin/env python3
"""Read-only triage of three retained original GitHub ZIP artifacts; runs no native test."""
from pathlib import Path, PurePosixPath
import argparse
import datetime
import hashlib
import json
import stat
import subprocess
import zipfile

HEAD = "bb026697a972521009bc133ae6ed2b653e18e931"
MERGE = "4b55e3b3a01ad44f4da37a76298232e4a29d031a"
TREE = "18175756871bf341586fc37be1b17a00ef1dd099"
ARTIFACTS = {
    13629186603: (198416, "087095a9fe7703a089f5951cd17fde528e72f6db8b276f16dd89e2632b62fac5"),
    13628771427: (5726125, "207f91a2bd632941b38e97dc2ba3543409c595330dfc06562aefdf8a941234a3"),
    13628443294: (5756162, "a10c9bdebbd5432601e3899aa3f04c64f29d6556de43bf18ccb37f6088d61261"),
}
LIMITS = {"cpu.max": "25000 100000", "cpu.max.burst": "0", "memory.max": "2147483648",
          "memory.swap.max": "0", "pids.max": "256"}
UNIT_SHA = "74eb36a63559bf8603c15ddd3753a1db143684a2cefd84cce5aff10a76bbd622"
BINARY_SHA = "4942d95ef6b826c38ac5e680cf76e04655bbddb35c43ba48bb1d851cac6271cf"

def require(value, detail):
    if not value:
        raise ValueError(detail)

def digest(stream):
    h = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        h.update(chunk)
        size += len(chunk)
    return size, h.hexdigest()

def member_digest(z, path):
    with z.open(path) as f:
        return digest(f)

def read_json(z, path):
    return json.loads(z.read(path))

def new_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")

def retain(z, dest, path):
    member = PurePosixPath(path)
    require(not member.is_absolute() and ".." not in member.parts, "unsafe member")
    out = dest / path
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("xb") as f:
        f.write(z.read(path))

def archive(base, aid):
    path = base / f"artifact-{aid}.zip"
    with path.open("rb") as f:
        size, sha = digest(f)
    require((size, sha) == ARTIFACTS[aid], "GitHub artifact size/digest mismatch")
    z = zipfile.ZipFile(path)
    infos = z.infolist()
    names = [x.filename for x in infos]
    require(len(names) == len(set(names)), "duplicate ZIP members")
    for x in infos:
        p = PurePosixPath(x.filename)
        require(not p.is_absolute() and ".." not in p.parts, "unsafe ZIP member")
        require(not stat.S_ISLNK(x.external_attr >> 16), "symlink ZIP member")
    return z, {"artifact_id": aid, "archive": path.name, "bytes": size, "sha256": sha,
               "member_count": len(infos), "uncompressed_bytes": sum(x.file_size for x in infos)}

def audit_codeql(base):
    aid = 13629186603
    z, summary = archive(base, aid)
    with z:
        root = read_json(z, "sha256.json")
        require(set(root) | {"sha256.json", "analysis/sha256.json"} == set(z.namelist()), "CodeQL full inventory coverage")
        for path, expected in root.items():
            require(member_digest(z, path)[1] == expected, "CodeQL member digest: " + path)
        nested = read_json(z, "analysis/sha256.json")
        for path, expected in nested.items():
            require(member_digest(z, "analysis/" + path)[1] == expected, "CodeQL analysis digest")
        result = read_json(z, "analysis/result.json")
        source_before = read_json(z, "exporter-source-before.json")
        require(source_before == read_json(z, "exporter-source-after.json"), "CodeQL source changed")
        require(source_before["tested_commit"] == HEAD and source_before["tested_tree"] == TREE, "CodeQL source identity")
        polls = sorted({PurePosixPath(x).parts[1] for x in z.namelist()
                        if x.startswith("analysis/poll-")})
        require(len(polls) == 39, "unexpected poll denominator")
        observations = []
        for p in polls:
            analyses = read_json(z, f"analysis/{p}/analyses-1.json")
            checks = [read_json(z, f"analysis/{p}/checks-{sha}-1.json") for sha in (HEAD, MERGE)]
            selection = read_json(z, f"analysis/{p}/selection.json")
            require(analyses == [] and all(x == {"total_count": 0, "check_runs": []} for x in checks), "nonempty upstream response")
            require(selection == {"analyses": [], "checks": [], "ready": False}, "unexpected selection")
            observations.append({"poll": p, "analyses": 0, "head_checks": 0, "merge_checks": 0, "ready": False})
        selected = ["analysis/result.json", "analysis/target.json", "exporter-source-before.json",
                    "exporter-source-after.json", "exporter-offline-tests.log", "preflight.log"]
        selected += [f"analysis/{p}/{name}" for p in (polls[0], polls[-1])
                     for name in ("selection.json", "analyses-1.json", f"checks-{HEAD}-1.json", f"checks-{MERGE}-1.json")]
        for name in selected:
            retain(z, base / "selected-original" / str(aid), name)
        summary.update({"classification": "UPSTREAM_EXACT_SOURCE_CODEQL_INPUT_ABSENT_UNTIL_EXPORT_DEADLINE",
                        "full_root_manifest_members_verified": len(root),
                        "self_inventory_files_not_listed_by_root_manifest": ["sha256.json", "analysis/sha256.json"],
                        "nested_analysis_manifest_members_verified": len(nested),
                        "result": result, "source_before_after_equal": True,
                        "successful_empty_poll_count": len(polls), "polls": observations,
                        "observed_permission_denial": False, "selected_original_members": selected})
    return summary

def phase_projection(phase):
    keys = ("mode", "requested_window_ns", "workers", "business_started_ns", "confirmation_ended_ns",
            "client_confirmation_latency_ns", "client_confirmed_before_original_window_end",
            "client_confirmed_transactions", "finite_business_target_met", "invariant_target_met",
            "full_native_state_equal", "no_attack_accepted", "accounting_closed", "verification_errors",
            "resource_fairness_qualified", "work_profile_qualified", "public_network_ready",
            "production_activation")
    out = {k: phase.get(k) for k in keys}
    confirmation = phase.get("independent_client_confirmation")
    out["observed_confirmation_depth"] = confirmation.get("depth") if confirmation else None
    replays = phase.get("independent_history_page_replay", [])
    out["history_replays"] = len(replays)
    if replays:
        last = replays[-1]
        out["last_history_replay"] = {k: last.get(k) for k in ("history_call_index", "replay_accepted", "replay_error")}
    return out

def audit_fresh(base, aid, expected):
    z, summary = archive(base, aid)
    with z:
        manifest = read_json(z, "fresh-service/manifest.json")
        for path, expected_sha in manifest["files"].items():
            require(member_digest(z, "fresh-service/" + path)[1] == expected_sha, "W1 member digest: " + path)
        source = read_json(z, "source.json")
        require(source == read_json(z, "source-after.json"), "W1 source changed")
        require(source["tested_commit"] == expected and source["tested_tree"] == TREE, "W1 source identity")
        require(manifest["source_before"] == manifest["source_after"], "W1 native source changed")
        require(manifest["source_before"]["commit"] == expected and manifest["source_expected"] == expected, "native source binding")
        require(manifest["binary_sha256_before"] == manifest["binary_sha256_after"] == BINARY_SHA, "native binary binding")
        require(member_digest(z, "fresh-service/public_v3_from_zero")[1] == BINARY_SHA, "retained ELF")
        before = read_json(z, "fresh-service-host/inside-before.json")
        after = read_json(z, "fresh-service-host/inside-after.json")
        controller = read_json(z, "fresh-service-host/controller-result.json")
        child = read_json(z, "fresh-service-host/child-result.json")
        for row in (before, after):
            require(row["limits"] == LIMITS and row["read_errors"] == {}, "original Host limits/readback")
            require(row["uid"] == row["gid"] == 1001 and row["thread_privileges"] == {"CapBnd": "0000000000000000", "NoNewPrivs": "1"}, "unprivileged original Host")
            require(row["installed_unit_sha256"] == UNIT_SHA, "reviewed unit hash")
        require(before["boot_id"] == after["boot_id"] and before["parent"] == after["parent"]
                and before["thread_cgroup"] == after["thread_cgroup"], "Host parent identity drift")
        require(controller["final_host_errors"] == child["host_errors"] == [], "reported Host error")
        reports = []
        for name in ("original", "fresh"):
            path = f"fresh-service/{name}/report.json"
            report = read_json(z, path)
            require(report["finite_target_met"] is False, "unexpected native target")
            require(len(report["phases"]) == 2, "original paired phase denominator")
            phases = [phase_projection(p) for p in report["phases"]]
            require(phases[0]["finite_business_target_met"] is True
                    and phases[0]["observed_confirmation_depth"] == 6, "baseline finite observation")
            require(phases[1]["finite_business_target_met"] is False
                    and phases[1]["verification_errors"] == ["PUBLIC_REQUEST_DEADLINE"]
                    and phases[1]["client_confirmation_latency_ns"] is None, "hostile finite refusal")
            size, sha = member_digest(z, path)
            reports.append({"path_in_original_zip": path, "bytes": size, "sha256": sha,
                            "schema": report["schema"], "finite_target_met": report["finite_target_met"],
                            "phases": phases, "qualified_goodput": None, "qualified_latency_tail": None})
        selected = ["source.json", "source-after.json", "fresh-service/manifest.json",
                    "fresh-service/original.log", "fresh-service/fresh.log",
                    "fresh-service-host/inside-before.json", "fresh-service-host/inside-after.json",
                    "fresh-service-host/controller-result.json", "fresh-service-host/child-result.json",
                    "fresh-service-host/prepare-build.json", "fresh-service-host/prepare-build/process.json",
                    "fresh-service-host/systemd-run.log", "public-fixture-parent.json"]
        for name in selected:
            retain(z, base / "selected-original" / str(aid), name)
        summary.update({"classification": "ACTUAL_FINITE_BUSINESS_TARGET_FAILURE_UNDER_ORIGINAL_HOST",
                        "source": source, "source_before_after_equal": True,
                        "retained_elf_sha256": BINARY_SHA,
                        "native_manifest_members_verified": len(manifest["files"]),
                        "build": manifest["build"], "runs": manifest["runs"],
                        "native_all_named_tests_passed": manifest["all_named_tests_passed"],
                        "native_pair_passed": manifest["passed"], "host_limits": LIMITS,
                        "host_before_after_same_parent_and_cgroup": True,
                        "host_read_errors": [], "host_controller_reported_errors": [],
                        "actual_reports": reports, "selected_original_members": selected,
                        "source_and_binary_are_ci_receipt_bindings_not_external_custody_attestation": True})
    return summary

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", type=Path, default=Path(__file__).resolve().parent)
    p.add_argument("--source", type=Path, required=True)
    args = p.parse_args()
    def git(*parts):
        return subprocess.check_output(["git", "--no-replace-objects", "-C", str(args.source), *parts])
    require(git("rev-parse", "HEAD").decode().strip() == HEAD, "reader source HEAD")
    require(git("status", "--porcelain=v1", "--untracked-files=all") == b"", "reader source not clean")
    sources = []
    for path in (".github/workflows/codeql-analysis-export.yml", ".github/workflows/codeql-real-exact-source.yml",
                 "scripts/export_codeql_analysis.py", ".github/workflows/pon-w1-work-security.yml",
                 "scripts/ci/run_w1_fresh_service_v1.py", "trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/fresh_challenge.rs"):
        raw = git("show", HEAD + ":" + path)
        sources.append({"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                        "git_blob": git("rev-parse", HEAD + ":" + path).decode().strip()})
    report = {"schema": "bb-codeql-and-w1-readonly-failure-triage-v1",
              "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "head": HEAD, "prospective_merge": MERGE, "tree": TREE, "native_tests_rerun": False,
              "source_contract_files": sources, "codeql": audit_codeql(args.base),
              "w1_fresh_service": [audit_fresh(args.base, 13628771427, HEAD),
                                   audit_fresh(args.base, 13628443294, MERGE)],
              "qualification": "HOLD", "performance_contract_changed": False,
              "limits": ["CodeQL empty upstream records do not independently explain Default Setup configuration.",
                         "Head and prospective-merge are separate commits despite equal trees and ELF hashes.",
                         "Archive verification and invariant native success do not qualify the finite performance target.",
                         "No independent operators, external WAN, full binary/load closure or production qualification claimed."]}
    new_json(args.base / "triage.json", report)
    print(json.dumps({"written": str(args.base / "triage.json"), "codeql_polls": report["codeql"]["successful_empty_poll_count"],
                      "w1_lanes": len(report["w1_fresh_service"]), "qualification": "HOLD"}, indent=2))
if __name__ == "__main__":
    main()

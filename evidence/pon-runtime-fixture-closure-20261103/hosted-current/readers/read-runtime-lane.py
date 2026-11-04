#!/usr/bin/env python3
"""Preserve exact runtime artifact text and inspect nine original Host selectors.

Read-only: never executes code from an artifact, invokes Cargo, or changes repo files.
Missing and partial selector records remain incomplete. No performance PASS is inferred.
"""
import argparse
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import zipfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument("--directory", required=True, type=Path)
ap.add_argument("--candidate", required=True)
ap.add_argument("--source", required=True)
ap.add_argument("--tree", required=True)
ap.add_argument("--run-id", required=True, type=int)
ap.add_argument("--job-id", required=True, type=int)
ap.add_argument("--artifact-id", required=True, type=int)
ap.add_argument("--zip", required=True, type=Path)
ap.add_argument("--lane", required=True, choices=("head", "actual-merge"))
a = ap.parse_args()
directory = a.directory.resolve(strict=True)
receipt = json.loads((directory / (str(a.artifact_id) + "-download-receipt.json")).read_text())
meta = receipt["metadata"]
archive = a.zip.read_bytes()
assert meta["id"] == a.artifact_id and meta["workflow_run"]["id"] == a.run_id
assert meta["workflow_run"]["head_sha"] == a.candidate
assert len(archive) == meta["size_in_bytes"] == receipt["actual_bytes"]
assert sha(archive) == meta["digest"].removeprefix("sha256:") == receipt["actual_sha256"]
plan = json.loads((Path(__file__).parent / "collector-plan.json").read_text())
expected = [(row["target"], row["selector"]) for row in plan["public_host_fixtures"]]
assert len(expected) == len(set(expected)) == 9
records = []
observations = []
missing = []
with zipfile.ZipFile(a.zip) as z:
    names = set(z.namelist())
    assert len(names) == len(z.namelist()), "duplicate ZIP members"
    shard = json.loads(z.read("rust-shard.json")) if "rust-shard.json" in names else None
    source = json.loads(z.read("source.json")) if "source.json" in names else None
    identity = shard["before"] if shard is not None else source
    assert identity is not None, "no original source identity"
    assert identity["tested_commit"] == a.source and identity["candidate"] == a.candidate
    assert identity["tested_tree"] == a.tree and identity["tracked_worktree_verified"] is True
    if shard is not None:
        assert shard["run"]["GITHUB_RUN_ID"] == str(a.run_id)
        assert shard["command_sha256"] == sha(z.read("rust-shard.sh"))
        assert shard["before"] == shard["after"], "original runtime source changed"
    for target, selector in expected:
        base = "public-fixtures/" + target + "/" + selector
        mpath = base + "/manifest.json"
        if mpath not in names:
            missing.append({"target": target, "selector": selector,
                            "preparation_present": base + "/preparation.json" in names,
                            "execution_start_present": base + "/execution-start.json" in names,
                            "native_log_present": base + "/native.log" in names,
                            "status": "no_complete_execution_manifest"})
            continue
        mraw = z.read(mpath)
        m = json.loads(mraw)
        assert (m["target"], m["selector"]) == (target, selector)
        prraw = z.read(base + "/preparation.json")
        pr = json.loads(prraw)
        native = z.read(base + "/native.log") if base + "/native.log" in names else None
        native_text = native.decode("utf-8") if native is not None else ""
        controller_path = base + "-host/controller-result.json"
        controller = json.loads(z.read(controller_path)) if controller_path in names else None
        launch_path = base + "/launch.json"
        launch = json.loads(z.read(launch_path)) if launch_path in names else None
        process = m.get("process") or {}
        before = m.get("source_before") or {}
        logfile = m.get("log") or {}
        checks = {
            "preparation_sha256": m.get("preparation_sha256") == sha(prraw),
            "source_before_after": m.get("source_before") == m.get("source_after")
                == pr.get("source_before") == pr.get("source_after")
                and before.get("commit") == a.source and before.get("tree") == a.tree,
            "tracked_source_identity": before.get("tracked_source_identity") == identity,
            "same_binary_before_after": m.get("binary_before") is not None
                and m.get("binary_before") == m.get("binary_after") == pr.get("binary"),
            "same_cli_before_after": m.get("cli_binary_before") == m.get("cli_binary_after") == pr.get("cli_binary"),
            "native_log_bytes_sha256": native is not None
                and len(native) == logfile.get("size_bytes") and sha(native) == logfile.get("sha256"),
            "original_exact_command": process.get("command") == [
                (m.get("binary_before") or {}).get("path"), selector, "--exact", "--show-output", "--test-threads=1"],
        }
        assert all(checks.values()), (target, selector, checks)
        report = m.get("report_file")
        if report is not None:
            report_raw = z.read(base + "/native/report.json")
            assert len(report_raw) == report["size_bytes"] and sha(report_raw) == report["sha256"]
        result_lines = re.findall(r"^test result:.*$", native_text, re.M)
        native_state = "incomplete"
        if len(result_lines) == 1:
            result = re.search(r"(\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", result_lines[0])
            if result:
                counts = tuple(map(int, result.groups()))
                if counts[:4] == (1, 0, 0, 0) and process.get("exit_code") == 0:
                    native_state = "PASS"
                elif counts[:4] == (0, 1, 0, 0) and process.get("exit_code") not in (None, 0):
                    native_state = "FAIL"
        panic_lines = re.findall(r"^thread .*panicked at.*$|^called .*$|^assertion .*failed.*$", native_text, re.M)
        observations.append({
            "target": target, "selector": selector, "native_status": native_state,
            "native_result_lines": result_lines, "native_panic_lines": panic_lines,
            "process": process, "manifest_passed": m.get("passed"), "manifest_failures": m.get("failures"),
            "named_execution": m.get("named_execution"), "source_before_after": before,
            "binary": m.get("binary_before"), "cli_binary": m.get("cli_binary_before"),
            "binary_hash_scope": "Original hosted adapter observations; ELF bytes are not duplicated in this text bundle.",
            "build_environment": pr.get("build_env"), "manifest_sha256": sha(mraw),
            "preparation_sha256": sha(prraw), "log_bytes": len(native), "log_sha256": sha(native),
            "integrity_checks": checks, "launch": launch, "controller": controller,
            "native_execution_authenticated": m.get("native_execution_authenticated"),
            "runtime_limits_or_deadlines_changed": m.get("runtime_limits_or_deadlines_changed"),
        })
    actual = set()
    for name in names:
        if name.startswith("public-fixtures/") and name.endswith("/manifest.json"):
            row = json.loads(z.read(name))
            actual.add((row["target"], row["selector"]))
    assert actual == {(row["target"], row["selector"]) for row in observations}
    assert actual <= set(expected)
    wanted = {name for name in ("source.json", "rust-shard.json", "rust-shard.sh", "workspace-tests.log", "public-fixture-parent.json") if name in names}
    for name in names:
        if not name.startswith("public-fixtures/"):
            continue
        pieces = name.split("/")
        direct = len(pieces) == 4 and name.endswith((".json", ".log", ".jsonl", ".txt"))
        report = name.endswith("/native/report.json")
        if direct or report:
            wanted.add(name)
    total = 0
    for name in sorted(wanted):
        info = z.getinfo(name)
        assert info.file_size <= 64 * 1024 * 1024, ("oversized text member", name)
        total += info.file_size
        assert total <= 192 * 1024 * 1024, "text selection requires explicit bounded review"
        data = z.read(name)
        records.append({"member": name, "bytes": len(data), "sha256": sha(data), "text": data.decode("utf-8")})

prefix = "runtime-" + a.lane + "-" + str(a.artifact_id)
bundle = {
    "schema": "exact-candidate-runtime-lane-original-records-v1", "candidate": a.candidate,
    "source": a.source, "tree": a.tree, "run_id": a.run_id, "job_id": a.job_id,
    "artifact_id": a.artifact_id, "artifact_sha256": sha(archive), "record_count": len(records),
    "scope": "Complete original workspace log, source/command receipts, per-selector execution and Host logs, and full architecture report. SQLite, packet/cell data and duplicate ELF bytes are excluded.",
    "records": records,
}
packed = gzip.compress((json.dumps(bundle, indent=2) + "\n").encode(), mtime=0)
original_file = write_new(directory / (prefix + "-original-records.json.gz"), packed)
out = {
    "schema": "exact-candidate-runtime-lane-terminal-readback-v1", "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "candidate": a.candidate, "source": a.source, "tree": a.tree, "lane": a.lane,
    "run_id": a.run_id, "job_id": a.job_id, "artifact_id": a.artifact_id,
    "artifact_bytes": len(archive), "artifact_sha256": sha(archive), "artifact_metadata": meta,
    "rust_shard": shard, "original_source_identity": identity,
    "public_fixture_denominator": 9, "public_fixture_observations": observations,
    "public_fixture_unobserved_or_incomplete": missing,
    "counts": {"native_pass": sum(row["native_status"] == "PASS" for row in observations),
               "native_fail": sum(row["native_status"] == "FAIL" for row in observations),
               "native_incomplete": sum(row["native_status"] == "incomplete" for row in observations),
               "no_complete_manifest": len(missing)},
    "original_records": original_file,
    "qualification_scope": "Inspection of actual artifact records only. Native summaries, adapter/Host acceptance, workspace completion and business performance are distinct. No later selector or other source qualification is inferred.",
    "reader": {"file": str(Path(__file__).resolve()), "sha256": sha(Path(__file__).read_bytes()), "executes_native_code": False},
}
readback_file = write_new(directory / (prefix + "-readback.json"), (json.dumps(out, indent=2) + "\n").encode())
print(json.dumps({"readback": readback_file, "original_records": original_file, "counts": out["counts"],
                  "observed": [{key: row[key] for key in ("target", "selector", "native_status", "native_panic_lines")}
                               for row in observations]}, indent=2))

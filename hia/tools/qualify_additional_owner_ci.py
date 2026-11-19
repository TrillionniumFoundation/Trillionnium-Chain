"""Bind actual Peer Unix, Task and public PQ execution to one exact CI source."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ("peer-unix", "task-store", "task-boundary", "pq-auth")
FALSE_SCOPES = ("whole_chain_native", "whole_package_retired", "node_integration_complete",
                "original_service_budget_qualified", "cross_target_qualified", "production_activation")
PQ_COUNTS = {"original_retained": 343, "original_doctests": 2, "native_original_pairs": 1609,
             "native_abi_calls": 24671, "exports": 55, "allocation_controls": 190,
             "actual_allocation_failures": 125, "lifetime_abi_calls": 1329, "parallel_readers": 8,
             "reader_integrity_controls": 49, "native_partitions": 6, "real_process_controls": 8,
             "native_execution_limit_seconds": 240, "single_cleanup_limit_seconds": 3}
PQ_FALSE_SCOPES = ("whole_chain_native", "whole_crypto_crate_ported", "openssl_owned_provider_ported",
                   "tuf_ported", "constant_time_qualified", "foreign_arbitrary_pointer_gate_qualified",
                   "register_stack_secret_erasure_qualified", "production_activation")


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(path):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode), "Regular retained input required: " + str(path))
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(stamp(before) == stamp(opened) == stamp(after) == stamp(path.lstat()), "Input changed")
    return {"bytes": before.st_size, "sha256": digest}


def read(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, "Duplicate report key")
            value[key] = item
        return value
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def write(path, value):
    with Path(path).open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def directory(path):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and ROOT not in path.parents and path != ROOT,
         "Runner-owned output outside the checkout required")
    return path


def peer_summary(report, independent):
    need(report.get("schema") == "trnm.hia.peer-unix-qualification.v1"
         and report.get("status") == "PASS" and report.get("source_inputs_stable") is True
         and report.get("retained_original_tests", {}).get("outer_tests") == 121
         and report.get("integrity_controls", {}).get("count") == 14
         and set(report.get("groups", {})) == {"codec", "client", "client-owner", "cli", "daemon",
                                               "storage-faults", "syscall-faults"}
         and independent.get("status") == "PASS", "Incomplete actual Peer Unix gate")


def pq_summary(report, independent, head, tree):
    need(report.get("schema") == "trnm.hia.pq-public-qualification.v2"
         and report.get("status") == "PASS" and report.get("source_unchanged_during_tests") is True
         and independent.get("status") == "PASS", "Incomplete supervised public PQ gate")
    need(all(type(independent.get(name)) is int and independent[name] == count
             for name, count in PQ_COUNTS.items()), "Incomplete public PQ original/native/control roster")
    for value in (report, independent):
        need(value.get("source_commit_observed") == head and value.get("source_tree_observed") == tree
             and value.get("source_dirty_observed") == "", "PQ evidence is not from this clean committed head")
        limits = value.get("limits", {})
        need(set(limits) == set(PQ_FALSE_SCOPES) | {"live_pointer_const_and_exclusive_budget_contract_required"}
             and all(limits.get(name) is False for name in PQ_FALSE_SCOPES)
             and limits.get("live_pointer_const_and_exclusive_budget_contract_required") is True,
             "PQ component evidence was promoted beyond its qualified scope")
    sources = report.get("source_inputs")
    need(type(sources) is dict and sources and all(type(name) is str and name
             and not Path(name).is_absolute() and ".." not in Path(name).parts
             and Path(name).as_posix() == name and "\\" not in name and "\0" not in name
             and type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
             for name, digest in sources.items()),
         "Missing or malformed PQ source closure")
    digest = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode()).hexdigest()
    need(independent.get("source_files") == len(sources)
         and independent.get("source_set_sha256") == report.get("source_set_sha256") == digest,
         "PQ reader and execution belong to different source graphs")


def run(component, root, rust_bin):
    root = directory(root)
    observation = root / "observations"
    need(observation.is_dir(), "Missing independently initialized observation directory")
    qualified = root / ("q" if component == "peer-unix" else "qualification")
    need(not qualified.exists(), "A fresh component output is required")
    if component == "peer-unix":
        commands = [("qualification", [sys.executable, "-B", "-m",
                     "hia.platform.peer_lease_unix.qualify", "run", "--output", str(qualified)]),
                    ("readback", [sys.executable, "-B", "-m", "hia.platform.peer_lease_unix.qualify",
                     "readback", "--input", str(qualified)])]
    elif component == "pq-auth":
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "Canonical original Rust toolchain directory required")
        commands = [("qualification", [sys.executable, "-I", "-S", "-B",
                     str(ROOT / "hia/platform/pq_auth/qualify.py"), "--output", str(qualified),
                     "--rust-bin", str(rust_bin), "--provider-receipt",
                     str(root / "provider-receipts/pq-provider/provider.json"),
                     "--provider-environment", str(root / "provider.env")]),
                    ("readback", [sys.executable, "-I", "-S", "-B",
                     str(ROOT / "hia/platform/pq_auth/readback.py"), "--report", str(qualified)])]
    else:
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "Canonical original Rust toolchain directory required")
        commands = [("qualification", [sys.executable, "-B", str(ROOT / "hia/tools/qualify_task_ci.py"),
                     "--component", component, "--output", str(qualified), "--rust-bin", str(rust_bin)])]
    result = {"schema": "trnm.hia.additional-owner-process.v1", "component": component,
              "status": "FAIL", "stages": [], **{name: False for name in FALSE_SCOPES}}
    write(observation / "run-intent.json", {
        "schema": "trnm.hia.additional-owner-intent.v1", "component": component,
        "commands": [{"name": name, "argv": argv, "cwd": str(ROOT)} for name, argv in commands],
        "outer_deadline_owner": "GitHub Actions job timeout-minutes: 20",
        "component_deadlines_replaced": False,
        "final_observation_guaranteed_after_runner_termination": False,
    })
    try:
        qualified_report = None
        for name, argv in commands:
            started = time.monotonic_ns()
            row = {"name": name, "argv": argv, "cwd": str(ROOT), "started": False,
                   "exit_code": None, "failure": None,
                   "interpreter": {"path": str(Path(argv[0]).resolve(strict=True)),
                                   **identity(Path(argv[0]).resolve(strict=True))}}
            result["stages"].append(row)
            write(observation / (name + ".intent.json"), row)
            try:
                if name == "readback":
                    row["qualification_report_before"] = identity(qualified / "report.json")
                    need(row["qualification_report_before"] == qualified_report,
                         "Qualification report changed before independent readback")
                with (observation / (name + ".stdout.raw")).open("xb") as stdout, \
                        (observation / (name + ".stderr.raw")).open("xb") as stderr:
                    row["started"] = True
                    child = subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr)
                row["exit_code"] = child.returncode
                need(child.returncode == 0, "Actual component process failed: " + name)
                row["qualification_report_after"] = identity(qualified / "report.json")
                if name == "readback":
                    need(row["qualification_report_after"] == qualified_report,
                         "Qualification report changed during independent readback")
                else:
                    qualified_report = row["qualification_report_after"]
            except BaseException as error:
                row["failure"] = repr(error)
                raise
            finally:
                row["elapsed_ns"] = time.monotonic_ns() - started
                for stream in ("stdout", "stderr"):
                    path = observation / (name + "." + stream + ".raw")
                    if path.exists():
                        row[stream] = identity(path)
                write(observation / (name + ".receipt.json"), row)
        result["status"] = "PASS"
    finally:
        write(observation / "process.json", result)
    return result


def bind(component, root, rust_bin):
    root = directory(root)
    observation = root / "observations"
    expected = os.environ["TRNM_EXPECTED_SOURCE_SHA"]
    need(re.fullmatch(r"[0-9a-f]{40}", expected), "Exact CI head required")
    git = lambda *args: subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT)
    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    need(head == expected, "Current CI head differs")
    before, after = (read(observation / name) for name in ("source-before.json", "source-after.json"))
    need(before == after and before["kind"] == "head"
         and before["tested_commit"] == before["candidate"] == head
         and before["tested_tree"] == tree and before["tracked_worktree_verified"] is True,
         "Whole committed source before/after qualification differs")
    process = read(observation / "process.json")
    stages = ["qualification", "readback"] if component in ("peer-unix", "pq-auth") else ["qualification"]
    need(process["schema"] == "trnm.hia.additional-owner-process.v1"
         and process["component"] == component and process["status"] == "PASS"
         and [row["name"] for row in process["stages"]] == stages
         and all(process.get(name) is False for name in FALSE_SCOPES), "Failed or foreign execution")
    qualified_path = root / ("q" if component == "peer-unix" else "qualification")
    if component == "peer-unix":
        expected_commands = {
            "qualification": [sys.executable, "-B", "-m", "hia.platform.peer_lease_unix.qualify",
                              "run", "--output", str(qualified_path)],
            "readback": [sys.executable, "-B", "-m", "hia.platform.peer_lease_unix.qualify",
                         "readback", "--input", str(qualified_path)],
        }
    elif component == "pq-auth":
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "The actual original Rust directory must remain explicit")
        expected_commands = {
            "qualification": [sys.executable, "-I", "-S", "-B",
                              str(ROOT / "hia/platform/pq_auth/qualify.py"), "--output", str(qualified_path),
                              "--rust-bin", str(rust_bin), "--provider-receipt",
                              str(root / "provider-receipts/pq-provider/provider.json"),
                              "--provider-environment", str(root / "provider.env")],
            "readback": [sys.executable, "-I", "-S", "-B",
                         str(ROOT / "hia/platform/pq_auth/readback.py"), "--report", str(qualified_path)],
        }
    else:
        need(rust_bin is not None and rust_bin.resolve(strict=True) == rust_bin,
             "The actual original Rust directory must remain explicit")
        expected_commands = {"qualification": [sys.executable, "-B", str(ROOT / "hia/tools/qualify_task_ci.py"),
                             "--component", component, "--output", str(qualified_path),
                             "--rust-bin", str(rust_bin)]}
    for row in process["stages"]:
        need(read(observation / (row["name"] + ".receipt.json")) == row,
             "Independently retained stage receipt differs")
        need(row["started"] is True and type(row["exit_code"]) is int and row["exit_code"] == 0
             and row["failure"] is None and row["cwd"] == str(ROOT)
             and row["argv"] == expected_commands[row["name"]], "Actual stage failed or its command differs")
        need(row.get("qualification_report_after") == identity(qualified_path / "report.json")
             and (row["name"] != "readback"
                  or row.get("qualification_report_before") == row["qualification_report_after"]),
             "Current qualification differs from the actually executed and read report")
        interpreter = Path(row["interpreter"]["path"])
        need(interpreter == Path(sys.executable).resolve(strict=True)
             and identity(interpreter) == {k: row["interpreter"][k] for k in ("bytes", "sha256")},
             "Actual qualification interpreter changed")
        for stream in ("stdout", "stderr"):
            need(identity(observation / (row["name"] + "." + stream + ".raw")) == row[stream],
                 "Complete actual process stream changed")
    qualification = qualified_path
    report = read(qualification / "report.json")
    need(report["status"] == "PASS", "The component gate did not pass")
    if component == "peer-unix":
        independent = read(observation / "readback.stdout.raw")
        peer_summary(report, independent)
        inputs = {str(ROOT / name): row for name, row in report["source_inputs"].items()}
    elif component == "pq-auth":
        independent = read(observation / "readback.stdout.raw")
        pq_summary(report, independent, head, tree)
        need(independent.get("qualification_report_sha256") == identity(qualification / "report.json")["sha256"],
             "Independent PQ reader belongs to a different qualification report")
        inputs = {str(ROOT / name): {"bytes": identity(ROOT / name)["bytes"], "sha256": digest}
                  for name, digest in report["source_inputs"].items()}
    else:
        need(report["component"] == component and report["finalized"] is True
             and report["source_before"] == report["source_after"], "Incomplete Task source-bound gate")
        inputs = report["source_before"]
    committed = {}
    for name, wanted in inputs.items():
        path = Path(name)
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_relative_to(ROOT):
            continue
        relative = path.relative_to(ROOT).as_posix()
        need(path.resolve(strict=True) == path and identity(path) == wanted,
             "Qualified checkout input differs: " + relative)
        raw = git("cat-file", "blob", "HEAD:" + relative)
        need({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} == wanted,
             "Qualified input is not this exact Git blob: " + relative)
        committed[relative] = wanted
    need(committed, "The executed component has no committed source closure")
    required = ["hia/tools/qualify_additional_owner_ci.py", ".github/workflows/hia-native-migration.yml",
                "scripts/ci/verify_ci_source.py", "scripts/project-preflight.sh"]
    if component in ("task-store", "task-boundary"):
        required.append("hia/tools/qualify_task_ci.py")
    elif component == "pq-auth":
        required.extend(("hia/platform/pq_auth/qualify.py", "hia/platform/pq_auth/readback.py",
                         "hia/platform/pq_auth/qualification/contract.py",
                         "hia/platform/pq_auth/qualification/supervision.py",
                         "hia/platform/pq_auth/qualification/supervision_controls.py",
                         "scripts/ci/prepare_pq_provider.sh"))
    readers = {}
    for name in required:
        raw = git("cat-file", "blob", "HEAD:" + name)
        readers[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        need(identity(ROOT / name) == readers[name], "CI driver differs from this commit")
    tool_files = {}
    tools = [row["interpreter"] for row in process["stages"]]
    if component == "peer-unix":
        tools.extend(read(qualification / "original/build.json")["tools"].values())
    elif component == "pq-auth":
        tools.extend(report["tools"].values())
    captured = root / "ci-inputs"
    captured.mkdir(mode=0o700)
    for row in tools:
        source = Path(row["path"])
        wanted = {key: row[key] for key in ("bytes", "sha256")}
        need(identity(source) == wanted, "Actual qualification tool changed before capture")
        target = captured / wanted["sha256"]
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(source.read_bytes())
        need(identity(target) == identity(source) == wanted, "Tool capture changed")
        tool_files[str(source)] = {**wanted, "captured": str(target.relative_to(root))}
    result = {"schema": "trnm.hia.additional-owner-ci-binding.v1", "status": "PASS", "component": component,
              "head": head, "tree": tree, "run_id": os.environ["GITHUB_RUN_ID"],
              "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "job": os.environ["GITHUB_JOB"],
              "process": identity(observation / "process.json"),
              "qualification": identity(qualification / "report.json"),
              "tool_files": tool_files, "full_host_dependency_closure_claimed": False,
              "committed_source_inputs": committed, "ci_reader_sources": readers,
              "source_set_sha256": hashlib.sha256(json.dumps(committed, sort_keys=True,
                  separators=(",", ":")).encode()).hexdigest(), **{name: False for name in FALSE_SCOPES}}
    write(observation / "binding.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("run", "bind"))
    parser.add_argument("--component", choices=COMPONENTS, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--rust-bin", type=Path)
    args = parser.parse_args()
    result = (run(args.component, args.root, args.rust_bin) if args.phase == "run"
              else bind(args.component, args.root, args.rust_bin))
    print(json.dumps({key: result[key] for key in ("schema", "status", "component")}, sort_keys=True))


if __name__ == "__main__":
    main()

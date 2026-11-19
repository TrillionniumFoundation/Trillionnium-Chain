"""Read source, raw streams, executable identities and complete named rosters."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

from .build import ROOT, HERE, EXECUTABLES, IMAGES, identity, need, source_capture, cargo_configuration
from .original_build import TEST_COUNTS, PROFILE, cargo_events, completed_original_tests
from .process import MAX_PROCESS_OBSERVATIONS
from scripts import w1_owned_process_collector_v1 as owned

CONTENTS = "contents.json"
GROUPS = {
    "codec": {"script": "qualify_codec.py", "native": "peer-unix-codec.so", "original": "codec",
              "directory": "k", "count": 4755},
    "client": {"script": "qualify_client.py", "native": "peer-unix-client", "original": "client",
               "directory": "c", "count": 299,
               "roster": "0caa935b15095095b70ccceebfd90ade1c59a8a7a72439def88d28c60cdf9a04"},
    "client-owner": {"script": "qualify_client_owner.py", "native": "peer-unix-client-owner",
                     "original": "client-owner", "directory": "o", "count": 1782,
                     "roster": "24958a6be0f9b284c7a9431b2b695bad9ec30c33fd2aeec4a315dba4f8473dca"},
    "cli": {"script": "qualify_cli.py", "native": "peer-unix-daemon", "original": "cli",
            "directory": "l", "count": 37,
            "roster": "224c2fb8d7ae836fdaa67843cfe47df9905ed77c2fed6753d8aa06630bb33d7b"},
    "daemon": {"script": "qualify_daemon.py", "native": "peer-unix-api", "original": "daemon",
               "directory": "d", "count": 18,
               "roster": "19a41dc260bf105adef131ae1c021c787aab02e344b7a39b747859e1545c583d"},
    "storage-faults": {"script": "qualify_daemon_storage_faults.py", "native": "peer-unix-api",
                       "original": "daemon", "directory": "f", "count": 9,
                       "roster": "0090ca39786d89eb459dc4ec6d899f7ee54693a057fcfb08614c53df2ae6eb59"},
    "syscall-faults": {"script": "qualify_daemon_syscall_faults.py", "native": "peer-unix-api",
                       "original": "daemon", "directory": "s", "count": 30,
                       "roster": "30ab802cba8216b185566f4a48ffac077f0c684367df25534dd2ad4e97117452"},
}
FALSE_CLAIMS = ("runtime_host_proxy", "rust_or_interpreter_fallback", "whole_peer_package_retired",
                "whole_chain_native", "production_activation", "original_service_budget_qualified",
                "foreign_pointer_ownership_or_concurrent_arena_qualified")


def document(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), "Missing or linked report")
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def regular_identity(path):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode), "Expected an actual regular file")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = path.lstat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
         "Retained file changed during readback")
    return {"bytes": before.st_size, "sha256": digest}


def inventory(root):
    root = Path(root)
    result = {}
    for directory, directories, filenames in os.walk(root, followlinks=False):
        for name in sorted([*directories, *filenames]):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative in {"report.json", CONTENTS}:
                continue
            mode = path.lstat().st_mode
            row = {"mode": stat.S_IMODE(mode)}
            if stat.S_ISREG(mode):
                row.update(kind="file", **regular_identity(path))
            elif stat.S_ISDIR(mode):
                row.update(kind="directory")
            elif stat.S_ISLNK(mode):
                row.update(kind="symlink", target=os.readlink(path))
            elif stat.S_ISSOCK(mode):
                row.update(kind="socket")
            else:
                raise ValueError("Unexpected retained filesystem object: " + relative)
            need(relative not in result, "Repeated retained path")
            result[relative] = row
    return result


def check_identity(path, wanted):
    need(type(wanted) is dict and type(wanted.get("bytes")) is int
         and wanted["bytes"] >= 0 and re.fullmatch(r"[0-9a-f]{64}", wanted.get("sha256", ""))
         and regular_identity(path) == {key: wanted[key] for key in ("bytes", "sha256")},
         "Retained bytes differ: " + str(path))


def processes(root, expected_rows):
    rows = document(root / "stages.json")
    need(rows == expected_rows and type(rows) is list and rows, "Actual stage roster differs")
    names = [row.get("name") for row in rows]
    need(len(names) == len(set(names)), "Duplicate executed stage")
    for row in rows:
        name = row["name"]
        need(type(name) is str and re.fullmatch(r"[a-z0-9-]+", name), "Stage path escapes")
        directory = root / name
        need(document(directory / "receipt.json") == row, "Actual stage receipt differs")
        need(row.get("started") is True and type(row.get("exit_code")) is int
             and row["exit_code"] == 0 and row.get("timed_out") is False
             and row.get("failure") is None and row.get("cleanup_errors") == []
             and type(row.get("wall_limit_seconds")) is int and 0 < row["wall_limit_seconds"] <= 240
             and type(row.get("cleanup_limit_seconds")) is int and row["cleanup_limit_seconds"] == 3
             and type(row.get("max_process_observations")) is int
             and row["max_process_observations"] == MAX_PROCESS_OBSERVATIONS
             and row.get("cwd") == str(ROOT), "Failed, incomplete or relocated actual stage")
        for stream in ("stdout", "stderr"):
            check_identity(directory / (stream + ".raw"), row[stream])
        check_identity(directory / "command.json", row["command"])
        specification = document(directory / "command.json")
        need(specification.get("argv") == row["argv"] and specification.get("cwd") == str(ROOT),
             "Actual command specification was substituted")
        check_identity(Path(specification["executable"]), specification["executable_identity"])
        environment = specification.get("environment")
        allowed = {"PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR", "LANG", "LC_ALL", "TZ",
                   "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTC", "CARGO", "RUSTDOC", "RUSTFMT",
                   "RUSTUP_TOOLCHAIN", "PYTHONDONTWRITEBYTECODE", "TRNM_PEER_UNIX_CONTROL_ROOT"}
        need(type(environment) is dict and set(environment) <= allowed
             and all(type(key) is str and type(value) is str for key, value in environment.items()),
             "Unbound command environment")
        if "TRNM_PEER_UNIX_CONTROL_ROOT" in environment:
            need(name == "integrity-controls" and environment["TRNM_PEER_UNIX_CONTROL_ROOT"]
                 == str(root.parent / "integrity-controls"), "Integrity control output escaped its stage")
        cargo_configuration(environment)
        check_identity(directory / "owned/intent.json", row["intent"])
        result = owned.read_result(directory / "owned", row["collector_exit_code"],
            observed_boot_id=row["original_boot_id"],
            observed_completed_monotonic_ns=row["observed_completed_monotonic_ns"],
            expected_intent_sha256=row["intent"]["sha256"])
        need(result == row["collector_readback"] and result["command_success"] is True
             and result["collector_wait_domain_reaped"] is True and result["deadline_qualified"] is True
             and result["result"]["root_returncode"] == row["exit_code"],
             "Actual owned family was not completely reaped before the original deadline")
        intent = document(directory / "owned/intent.json")
        python = Path(sys.executable).resolve(strict=True)
        command = [str(python), "-B", "-m", "hia.platform.peer_lease_unix.process", "--execute",
                   str(directory / "command.json"), "--sha256", row["command"]["sha256"]]
        need(intent.get("command") == command and intent.get("cleanup_grace_seconds") == 3
             and intent.get("max_process_records") == MAX_PROCESS_OBSERVATIONS
             and intent.get("max_log_bytes_per_stream") == 16 * 1024 * 1024
             and intent.get("original_deadline_monotonic_ns") == row["original_deadline_monotonic_ns"]
             and intent.get("original_boot_id") == row["original_boot_id"]
             and intent.get("executable_sha256") == regular_identity(python)["sha256"],
             "Owned collector command, executable or original limits changed")
        expected = [str(python), "-B", str(ROOT / "scripts/w1_owned_process_collector_v1.py"),
                    "--out", str(directory / "owned"), "--cwd", str(ROOT),
                    "--deadline-monotonic-ns", str(row["original_deadline_monotonic_ns"]),
                    "--deadline-boot-id", row["original_boot_id"], "--cleanup-grace-seconds", "3",
                    "--executable-sha256", regular_identity(python)["sha256"],
                    "--max-processes", str(MAX_PROCESS_OBSERVATIONS), "--max-log-bytes",
                    str(16 * 1024 * 1024), "--", *command]
        need(row.get("collector_argv") == expected, "Caller collector command differs from the retained intent")
        for stream in ("stdout", "stderr"):
            data = result["result"]["streams"][stream]
            need(data["eof"] is True and data["truncated"] is False
                 and data["stored_bytes"] == data["seen_bytes"]
                 and (directory / (stream + ".raw")).read_bytes()
                 == (directory / "owned" / (stream + ".log")).read_bytes(),
                 "Actual child stream is incomplete or was replaced")
    return {row["name"]: row for row in rows}


def original_readback(root, value):
    need(value.get("schema") == "trnm.hia.peer-unix-original.v1" and value.get("status") == "PASS"
         and value.get("reused_prior_execution") is False and value.get("source_inputs_stable") is True
         and value.get("complete_original_tests_preserved") is True, "Original complete gate failed")
    rows = processes(root / "processes", value["stages"])
    need(value.get("absent_cargo_configuration") == cargo_configuration(os.environ),
         "Original Cargo configuration boundary changed")
    expected_names = {"project-preflight", "rust-sysroot", "rust-version", "clippy-version",
                      "clippy-driver-version", "complete-cargo-graph", "retained-original-tests",
                      "workspace-fmt", "strict-original-clippy"}
    expected_names |= {"original-roster-" + str(i).zfill(2) for i in range(len(TEST_COUNTS))}
    expected_names |= {"build-observer-" + name for name in ("daemon", "client", "client-owner", "codec")}
    need(set(rows) == expected_names, "Missing, extra or substituted original stage")
    tools = value["tools"]
    for row in tools.values():
        check_identity(Path(row["path"]), row)
    args = ["--offline", "--locked", "--manifest-path", str(ROOT / "trillionnium/Cargo.toml")]
    target = root / "cargo-target"
    commands = {
        "project-preflight": ["bash", "scripts/project-preflight.sh", "--audit"],
        "rust-version": [tools["rustc"]["path"], "-Vv"],
        "clippy-version": [tools["cargo-clippy"]["path"], "--version"],
        "clippy-driver-version": [tools["clippy-driver"]["path"], "--version"],
        "complete-cargo-graph": [tools["cargo"]["path"], "metadata", *args, "--all-features", "--format-version", "1"],
        "retained-original-tests": [tools["cargo"]["path"], "test", *args, "-p", "trnm-peer-lease",
            "--all-features", "--no-fail-fast", "--target-dir", str(target), "--message-format=json",
            "--", "--test-threads=1"],
        "workspace-fmt": [tools["cargo-fmt"]["path"], "fmt", "--all", "--manifest-path",
                          str(ROOT / "trillionnium/Cargo.toml"), "--", "--check"],
        "strict-original-clippy": [tools["cargo-clippy"]["path"], "clippy", *args, "-p", "trnm-peer-lease",
            "--all-features", "--all-targets", "--target-dir", str(target), "--", "-D", "warnings"],
    }
    for name, command in commands.items():
        need(rows[name]["argv"] == command, "Original command changed: " + name)
    metadata = document(root / "processes/complete-cargo-graph/stdout.raw")
    need(len(metadata["workspace_members"]) == 26
         and identity(json.dumps(metadata, sort_keys=True).encode()) == value["cargo_graph"],
         "The unchanged complete 26-package Cargo graph was substituted")
    version = (root / "processes/rust-version/stdout.raw").read_bytes()
    need(b"release: 1.95.0\n" in version and b"host: x86_64-unknown-linux-gnu\n" in version,
         "Original pinned Rust release or host changed")
    sysroot = (root / "processes/rust-sysroot/stdout.raw").read_text().strip()
    need(rows["rust-sysroot"]["argv"][1:] == ["--print", "sysroot"]
         and str(Path(tools["rustc"]["path"]).parent.parent) == sysroot,
         "Actual original compiler sysroot was substituted")
    raw = (root / "processes/retained-original-tests/stdout.raw").read_bytes()
    need(completed_original_tests(raw) == value["retained_tests"], "Original observed test results changed")
    events = cargo_events(raw)
    actual = {}
    for event in events:
        for name in event["filenames"]:
            path = Path(name)
            need(path.is_relative_to(target), "Actual original artifact escaped")
            relative = path.relative_to(root).as_posix()
            row = value["artifacts"].get(relative)
            need(row is not None and row["profile"] == event["profile"]
                 and row["target"] == event["target"] and row["features"] == event["features"]
                 and row["package_id"] == event["package_id"], "Actual Cargo artifact provenance changed")
            check_identity(path, row)
            actual[relative] = row
    need(actual == value["artifacts"], "Original artifact roster was edited")
    need(set(value["test_rosters"]) == set(TEST_COUNTS), "Original test target roster changed")
    test_events = {event["target"]["name"]: event for event in events
                   if event["manifest_path"] == str(ROOT / "trillionnium/crates/trnm-peer-lease/Cargo.toml")
                   and event["profile"]["test"]}
    need(set(test_events) == set(TEST_COUNTS), "Missing original test executable")
    for index, name in enumerate(sorted(TEST_COUNTS)):
        event = test_events[name]
        label = "original-roster-" + str(index).zfill(2)
        need(event["profile"] == {**PROFILE, "test": True}
             and rows[label]["argv"] == [event["executable"], "--list", "--format", "terse"],
             "Original test listing was filtered or relabelled")
        listing = (root / "processes" / label / "stdout.raw").read_text()
        names = [line[:-6] for line in listing.splitlines() if line.endswith(": test")]
        need(names == value["test_rosters"][name] and len(names) == len(set(names)) == TEST_COUNTS[name],
             "Actual complete test names changed")
    need(set(value["observers"]) == {"daemon", "client", "client-owner", "codec", "cli"},
         "Original observer roster changed")
    dependencies = sorted({str(Path(path).parent) for event in events
                           for path in event["filenames"] if path.endswith((".rlib", ".rmeta"))})
    libraries = {}
    for name in ("trnm_peer_lease", "libc"):
        matches = [event for event in events if event["target"]["name"] == name
                   and not event["profile"]["test"]
                   and any(path.endswith(".rlib") for path in event["filenames"])]
        need(len(matches) == 1 and matches[0]["profile"] == PROFILE,
             "Actual original observer dependency is absent or ambiguous")
        event = matches[0]
        paths = [path for path in event["filenames"] if path.endswith(".rlib")]
        need(len(paths) == 1, "Actual original rlib identity is ambiguous")
        if name == "trnm_peer_lease":
            need(event["manifest_path"] == str(ROOT / "trillionnium/crates/trnm-peer-lease/Cargo.toml")
                 and set(event["features"]) == {"candidate-recovery-socket", "default"},
                 "Original peer package or complete feature set changed")
        else:
            need(event["package_id"].endswith("#libc@0.2.184"), "Original locked libc identity changed")
        libraries[name] = paths[0]
    for role, observer in value["observers"].items():
        path = Path(observer["path"])
        need(not path.is_absolute() and ".." not in path.parts, "Original observer path escapes")
        check_identity(root / path, observer)
        if role != "cli":
            argv = rows["build-observer-" + role]["argv"]
            filename = {"daemon": "daemon_reference.rs", "client": "client_reference.rs",
                        "client-owner": "client_owner_reference.rs", "codec": "codec_reference.rs"}[role]
            expected = [tools["rustc"]["path"], "--edition=2021", "-C", "opt-level=0", "-C",
                        "debug-assertions=yes", "-C", "overflow-checks=yes", "-C", "debuginfo=2",
                        str(HERE / filename)]
            for directory in dependencies:
                expected += ["-L", "dependency=" + directory]
            if role != "codec":
                expected += ["--extern", "trnm_peer_lease=" + libraries["trnm_peer_lease"]]
            if role in {"client", "client-owner"}:
                expected += ["--extern", "libc=" + libraries["libc"]]
            need(argv == [*expected, "-o", str(root / path)],
                 "Original public observer or debug profile was substituted")
        else:
            matches = [event for event in events if event["target"]["name"] == "trnm-peer-lease-daemon"
                       and event["profile"] == PROFILE and event.get("executable")]
            need(len(matches) == 1 and matches[0]["executable"] == str(root / path)
                 == str(target / "debug/trnm-peer-lease-daemon"), "Original Cargo CLI was substituted")
    return value["retained_tests"]


def integrity_readback(output, row):
    import unittest
    from . import test_qualification
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_qualification.QualificationControls)
    names = [test.id() for test in suite]
    need(len(names) == len(set(names)) == 13, "Integrity control source roster changed")
    raw = (output / "observations/integrity-controls/stderr.raw").read_text()
    actual = re.findall(r"^test_[a-z0-9_]+ \(([^()]+)\) \.\.\. ok$", raw, re.M)
    need(actual == names and len(re.findall(r"^Ran 13 tests in [0-9.]+s$", raw, re.M)) == 1
         and raw.endswith("\nOK\n") and row["argv"] == [sys.executable, "-B", "-m", "unittest", "-v",
             "hia.platform.peer_lease_unix.test_qualification"]
         and row["wall_limit_seconds"] == 30, "Complete actual integrity controls did not execute")
    return {"count": len(names), "names": names, "status": "PASS"}


def codec_readback(root, value):
    from .qualify_codec import cases
    need(value.get("status") == "PASS" and value.get("comparisons") == 4755
         and value.get("capacity_controls") == 40 and value.get("original_exit_code") == 0
         and value.get("source_and_binaries_unchanged") is True
         and value.get("whole_peer_package_retired") is False
         and value.get("production_activation") is False, "Codec gate incomplete")
    for name, wanted in value["streams"].items():
        need(Path(name).name == name, "Codec stream escapes")
        check_identity(root / name, wanted)
    observations = [json.loads(line) for line in (root / "observations.jsonl").read_bytes().splitlines()]
    primary = [row for row in observations if "equal" in row]
    capacity = [row for row in observations if "capacity" in row]
    expected = list(cases())
    need(len(primary) == len(expected) == 4755 and len(capacity) == 40
         and len(observations) == 4795, "Codec full observation roster changed")
    streams = {name: (root / name).read_bytes()
               for name in ("stdin.raw", "native.stdout.raw", "original.stdout.raw")}
    positions = dict.fromkeys(streams, 0)

    def take(name, count):
        position = positions[name]
        raw = streams[name][position:position + count]
        need(len(raw) == count, "Truncated actual codec stream")
        positions[name] += count
        return raw

    for (name, payload), row in zip(expected, primary, strict=True):
        size = struct.unpack("<I", take("stdin.raw", 4))[0]
        need(size == len(payload) and take("stdin.raw", size) == payload
             and row.get("case") == name and row.get("equal") is True
             and row.get("input_sha256") == identity(payload)["sha256"], "Codec input roster differs")
        outputs = []
        for kind in ("native", "original"):
            code, count = struct.unpack("<QQ", take(kind + ".stdout.raw", 16))
            need(count <= 4096 and type(row.get(kind + "_status")) is int
                 and row[kind + "_status"] == code and row.get(kind + "_bytes") == count,
                 "Actual codec result differs from its observation")
            outputs.append((code, take(kind + ".stdout.raw", count)))
        need(outputs[0] == outputs[1], "Actual native/original codec mismatch")
    need(all(positions[name] == len(raw) for name, raw in streams.items()), "Extra codec execution stream")
    need(all(row.get("status") == 102 and row.get("all_output_guard_bytes_preserved") is True
             for row in capacity), "Codec capacity refusal changed output")


def named_group(root, group, value, native, original):
    spec = GROUPS[group]
    rows = value.get("cases", value.get("rows"))
    need(type(rows) is list and type(value.get("total")) is int
         and value.get("status") == "PASS" and value["total"] == value.get("passed") == len(rows) == spec["count"],
         "Named group is failed, partial or count-only")
    names = [row.get("name") for row in rows]
    need(all(type(name) is str for name in names) and len(names) == len(set(names))
         and hashlib.sha256(json.dumps(names, separators=(",", ":")).encode()).hexdigest() == spec["roster"],
         "Actual complete named roster changed: " + group)
    need(all(row.get("status") == "PASS" for row in rows), "Actual named observation failed")
    if group == "client-owner":
        progress = [json.loads(line) for line in (root / "progress.jsonl").read_bytes().splitlines()]
    else:
        progress = document(root / "progress.json")
    need(progress == rows, "Actual started/completed progress differs from final group")
    if group in {"client", "client-owner", "cli"}:
        for row in rows:
            need(type(row.get("checks")) is dict and row["checks"]
                 and all(flag is True for flag in row["checks"].values()), "A native comparison failed")
    if group in {"client", "cli"}:
        for row in rows:
            for short, role, binary in (("r", "original", original), ("n", "native", native)):
                directory = root / row["name"] / (short if group == "client" else short + "-process")
                receipt = document(directory / "receipt.json")
                need(receipt == row[role] and receipt.get("timed_out") is False
                     and type(receipt.get("exit_code")) is int
                     and receipt["exit_code"] in ({0} if group == "client" else {1, 2})
                     and receipt.get("wall_limit_seconds") == 4 and receipt.get("cleanup_limit_seconds") == 3,
                     "Actual client or CLI process did not complete in its original budget")
                need(receipt["executable"] == binary, "Executed public observer/native binary substituted")
                for field, filename in (("stdout", "stdout.raw"), ("stderr", "stderr.raw"), ("trace", "syscalls.raw")):
                    check_identity(directory / filename, receipt[field])
                if group == "client":
                    check_identity(directory / "stdin.raw", receipt["input"])
            first = root / row["name"] / ("r" if group == "client" else "r-process")
            second = root / row["name"] / ("n" if group == "client" else "n-process")
            for name in ("stdout.raw", "stderr.raw"):
                need((first / name).read_bytes() == (second / name).read_bytes(), "Actual client/CLI bytes differ")
    elif group == "client-owner":
        need(value.get("actual_native_calls") == value.get("actual_original_calls") == 1782
             and value.get("failure") is None and value.get("runtime_fallback") is False,
             "Persistent owner execution incomplete")
        for role, binary in (("original", original), ("native", native)):
            final = document(root / role / "process.json")
            need(final in value["processes"] and final.get("exit_code") == 0
                 and final.get("forced_cleanup") is False and final.get("commands") == 1782
                 and final.get("executable") == binary, "Persistent owner process was replaced or killed")
            check_identity(root / role / "stderr.raw", final["stderr"])
            check_identity(root / role / "syscalls.raw", final["syscalls"])
        for index, row in enumerate(rows, 1):
            raw_values = []
            for role in ("original", "native"):
                stem = root / role / str(index).zfill(5)
                receipt = document(stem.with_suffix(".receipt.json"))
                need(receipt == row[role] and receipt.get("index") == index
                     and receipt.get("wall_limit_seconds") == 4 and receipt.get("cleanup_limit_seconds") == 3,
                     "Persistent owner actual command identity differs")
                check_identity(stem.with_suffix(".stdin.raw"), receipt["input"])
                check_identity(stem.with_suffix(".stdout.raw"), receipt["stdout"])
                raw_values.append(stem.with_suffix(".stdout.raw").read_bytes())
            first, second = raw_values
            if row["op"] == 10:
                need(len(first) == 40 and len(second) == 72 and first[:24] == second[:24]
                     and first[32:] == second[32:40], "Private arena observation changed public live count")
            else:
                need(first == second, "Persistent original/native result bytes differ")
        need(all(row["before"] == row["after_network_calls"] == 3 for row in value["fd_observations"])
             and len(value["fd_observations"]) == 2, "Persistent owner leaked descriptors")
        need(value["limits"]["whole_peer_owner_qualified"] is False
             and value["limits"]["original_service_budget_qualified"] is False,
             "Persistent finite arena was promoted to whole owner or service qualification")
    else:
        for row in rows:
            need(row.get("original") == row.get("native"), "Actual normalized daemon result differs")
            for role, binary in (("original", original), ("native", native)):
                receipts = list((root / row["name"] / role).rglob("receipt.json"))
                actual = []
                for path in receipts:
                    value = document(path)
                    if "executable" not in value:
                        continue
                    need(value["executable"] == binary, "Executed daemon binary substituted")
                    terminal = value.get("terminal_expected")
                    ended = value.get("termination")
                    need(type(terminal) is bool and type(ended) is dict
                         and ended.get("mode") == ("natural-terminal" if terminal else
                                                   "tracee-pidfd-then-tracer-wait")
                         and ended.get("tracer_pid") == value["pid"]
                         and ended.get("returncode") == value["exit_code"],
                         "Actual tracer termination receipt differs")
                    start, deadline, finish = (ended.get(name) for name in
                        ("started_monotonic_ns", "deadline_monotonic_ns", "completed_monotonic_ns"))
                    need(all(type(item) is int for item in (start, deadline, finish))
                         and deadline - start == (4 if terminal else 3) * 1_000_000_000
                         and start <= finish <= deadline, "Tracer terminal deadline was renewed or exceeded")
                    if ended.get("signal") is not None:
                        tracee = ended.get("tracee")
                        need(not terminal and ended["signal"] == 9 and type(tracee) is dict
                             and tracee.get("parent") == value["pid"]
                             and type(tracee.get("pid")) is int and tracee["pid"] > 0
                             and type(tracee.get("start_ticks")) is int and tracee["start_ticks"] > 0
                             and ended.get("executable_sha256") == binary["sha256"]
                             and value["exit_code"] in (-9, 137),
                             "Controlled shutdown did not stop and reap the bound tracee")
                    else:
                        need(ended.get("tracee") is None and value["exit_code"] == 0,
                             "Natural tracer exit failed")
                    for field, filename in (("input", "stdin.raw"), ("stdout", "stdout.raw"),
                                            ("stderr", "stderr.raw"), ("trace", "syscalls.raw")):
                        check_identity(path.parent / filename, value[field])
                    actual.append(value)
                need(actual, "Actual daemon process receipt absent")
        if group == "syscall-faults":
            for row in rows[1:]:
                need(row["original"].get("exact_actual_target_verified") is True,
                     "Syscall fault never reached its exact actual target")


def readback(output):
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Optimized Python is not admitted")
    output = Path(output).absolute()
    report = document(output / "report.json")
    need(report.get("schema") == "trnm.hia.peer-unix-qualification.v1" and report.get("status") == "PASS"
         and report.get("source_inputs_stable") is True and all(report.get(key) is False for key in FALSE_CLAIMS),
         "Failed, incomplete or overstated whole qualification")
    check_identity(output / CONTENTS, report["contents"])
    retained = inventory(output)
    need(retained == document(output / CONTENTS) and len(retained) == report["retained_entries"],
         "Complete retained filesystem differs")
    inputs = {name: identity(raw) for name, raw in source_capture().items()}
    need(inputs == report["source_inputs"], "Exact current source graph differs from the executed source")
    for name, wanted in inputs.items():
        check_identity(output / "native/source-snapshot" / name, wanted)
    check_identity(output / "native/build.json", report["native_build"])
    native = document(output / "native/build.json")
    need(native.get("status") == "PASS" and native.get("source_inputs_stable") is True
         and native["source_inputs"] == inputs and set(native["images"]) == set(IMAGES)
         and set(native["executables"]) == set(EXECUTABLES), "Native build source/image roster differs")
    from hia.tools.toolchain import checked_source
    from hepta.hia_agent_assembly import render_assembly
    need(set(native["cores"]) == {*IMAGES, "codec"}, "Native core roster differs")
    for name in (*IMAGES, "codec"):
        checked, composed, *_ = checked_source(HERE / (name + ".hepta"))
        core = checked.as_dict()
        limits = {"functions": len(core["functions"]),
                  "blocks": sum(len(f["blocks"]) for f in core["functions"]),
                  "ops": sum(len(b["ops"]) for f in core["functions"] for b in f["blocks"]),
                  "max_blocks": max(len(f["blocks"]) for f in core["functions"])}
        need(limits == native["cores"][name] and limits["functions"] <= 128
             and limits["blocks"] <= 1536 and limits["ops"] <= 8192 and limits["max_blocks"] <= 256,
             "Native source exceeded the unchanged compiler limits")
        if name == "codec":
            core["module"] = "selfhost_elf"
        need((output / "native" / (name + ".composed.hepta")).read_bytes() == composed
             and (output / "native" / (name + ".compiler-input.hepta")).read_bytes()
             == render_assembly(core).encode(), "Actual native compiler input did not derive from bound HIA")
    for name, wanted in native["images"].items():
        check_identity(output / "native" / (name + ".native"), wanted)
    for name, (order, profile) in EXECUTABLES.items():
        raw = (output / "native" / name).read_bytes()
        row = native["executables"][name]
        check_identity(output / "native" / name, row)
        prefix = (output / "native" / (name + ".prefix")).read_bytes()
        need(len(prefix) == 5120 and row["profile"] == profile and row["images"] == list(order)
             and raw == prefix + b"".join((output / "native" / (image + ".native")).read_bytes() for image in order),
             "Native executable no longer contains its exact admitted HIA images")
    check_identity(output / "native/peer-unix-codec.so", native["codec"])
    codec = native["codec"]
    check_identity(output / "native/codec.o", codec["object"])
    check_identity(output / "native/codec.compiler-input.hepta", codec["compiler_wire"])
    check_identity(Path(codec["linker"]["path"]), codec["linker"])
    need(codec.get("exports") == ["f0"] and codec.get("backend") == "selfhost"
         and codec.get("python_emitter_used") is False and codec.get("fallback_used") is False,
         "Codec build used a different implementation path")
    linker = processes(output / "native/hosted-linker", codec["link_stages"])
    need(set(linker) == {"link-codec"} and linker["link-codec"]["wall_limit_seconds"] == 30
         and linker["link-codec"]["argv"] == [codec["linker"]["path"], "-m", "elf_x86_64", "-shared",
             "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none",
             "--hash-style=both", str(output / "native/codec.o"), "-lc", "-o",
             str(output / "native/peer-unix-codec.so")], "Exact recorded native link command changed")
    labels = ["compile-" + name for name in IMAGES]
    labels += ["emit-" + name for name in EXECUTABLES]
    labels += ["compile-codec"]
    need([row.get("stage") for row in native["stages"]] == labels, "Native compiler/emitter stage roster differs")
    binding = document(ROOT / "hia/qualification/compiler-binding.json")
    need(native["compiler_qualification_binding"] == binding
         and native["compiler"]["sha256"] == binding["compiler_sha256"] == codec["compiler"]["sha256"],
         "Native compiler cold-qualification binding changed")
    for row in native["stages"]:
        directory = output / "native/pinned-native" / row["stage"]
        need(document(directory / "receipt.json") == row and type(row.get("exit_code")) is int
             and row["exit_code"] == 0 and row.get("timed_out") is False and row.get("cleanup") is None
             and row.get("wall_limit_seconds") == 30 and row.get("cleanup_limit_seconds") == 3
             and row.get("environment") == {"PATH": ""} and row.get("stderr_hex") == "",
             "Native compiler/emitter did not complete its original bounded stage")
        payload = (directory / "stdin.raw").read_bytes()
        actual = (directory / "stdout.raw").read_bytes()
        need(identity(payload) == {"bytes": row["input_bytes"], "sha256": row["input_sha256"]}
             and identity(actual) == {"bytes": row["output_bytes"], "sha256": row["output_sha256"]}
             and (directory / "stderr.raw").read_bytes() == b"", "Native raw stage changed")
        if row["stage"].startswith("compile-"):
            name = row["stage"][8:]
            need(row["executable_sha256"] == binding["compiler_sha256"]
                 and payload == (output / "native" / (name + ".compiler-input.hepta")).read_bytes()
                 and actual == (output / "native" / ("codec.o" if name == "codec" else name + ".native")).read_bytes(),
                 "Actual compiler input or output was substituted")
        else:
            name = row["stage"][5:]
            order, profile = EXECUTABLES[name]
            expected = b"HCSHD001" + struct.pack("<QQ", len(order), profile)
            expected += b"".join(struct.pack("<Q", native["images"][image]["bytes"]) for image in order)
            need(payload == expected and row["executable_sha256"] == native["images"]["linux_emitter"]["sha256"]
                 and actual == (output / "native" / (name + ".prefix")).read_bytes(),
                 "Actual HIA platform prefix emission differs")
    check_identity(output / "original/build.json", report["original_build"])
    original = document(output / "original/build.json")
    retained_tests = original_readback(output / "original", original)
    need(retained_tests == report["retained_original_tests"], "Original test report differs")
    rows = processes(output / "observations", report["stages"])
    need(list(rows) == ["integrity-controls", *GROUPS] and set(report["groups"]) == set(GROUPS),
         "Complete native group roster differs")
    need(integrity_readback(output, rows["integrity-controls"]) == report["integrity_controls"],
         "Actual integrity control report differs")
    result = {}
    for group, spec in GROUPS.items():
        row = report["groups"][group]
        directory = output / "cases" / spec["directory"]
        need(row["directory"] == str(directory.relative_to(output)), "Group observation path substituted")
        native_path = output / "native" / spec["native"]
        original_path = output / "original" / original["observers"][spec["original"]]["path"]
        check_identity(native_path, row["native"])
        check_identity(original_path, row["original"])
        flag = "--reference" if group == "codec" else "--original"
        need(rows[group]["argv"] == [sys.executable, "-B", str(HERE / spec["script"]), "--native",
            str(native_path), flag, str(original_path), "--output", str(directory)]
             and rows[group]["wall_limit_seconds"] == 240, "Actual observer command or budget changed")
        check_identity(directory / "report.json", row["report"])
        value = document(directory / "report.json")
        if group == "codec":
            codec_readback(directory, value)
        else:
            named_group(directory, group, value, row["native"], row["original"])
        result[group] = {"status": "PASS", "named_observations": spec["count"]}
    need(inventory(output) == retained, "Retained files changed during independent readback")
    return {"schema": "trnm.hia.peer-unix-readback.v1", "status": "PASS", "groups": result,
            "original_outer_tests": 121, "retained_entries": len(retained),
            "whole_peer_package_retired": False, "whole_chain_native": False,
            "production_activation": False, "original_service_budget_qualified": False}

"""Run complete, source-bound Task Store or mechanical-boundary qualification.

All runtime decisions remain in the existing HIA implementation and its pinned
provider. This entry only orchestrates actual gates and preserves their bytes.
It does not qualify ArchiveStore, StateImport, the complete Task crate, or Node.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TASK = ROOT / "hia/platform/task_kernel"
Q = TASK / "qualification"
COMPONENT_SECONDS = 1200
CLEANUP_SECONDS = 3
SQLITE_VERSION = "0.39.1"
PROVIDER_NEGATIVES = (
    "unsupported-target", "environment-override", "missing-dependency", "existing-output",
    "modified-header", "modified-abi", "real-timeout", "missing-executable",
)
READER_NEGATIVES = (
    "original-retained-tests-executable", "original-retained-tests-manifest", "original-retained-tests-package",
    "original-clippy-executable", "original-clippy-manifest", "original-clippy-package",
    "cargo-positional-test-filter", "cargo-missing-locked", "cargo-different-target", "cargo-different-cwd",
    "cargo-relaxed-timeout", "clippy-missing-all-targets", "clippy-missing-all-features", "clippy-allow-warnings",
    "fmt-different-manifest", "fmt-different-package", "fmt-different-cwd", "environment-CARGO_NET_OFFLINE",
    "environment-RUSTUP_TOOLCHAIN", "environment-GIT_NO_LAZY_FETCH", "environment-PATH",
    "environment-RUSTC_WORKSPACE_WRAPPER", "native-observer-executable", "native-build-different-provider",
    "original-git-source-omitted", "actual-cargo-artifact-omitted", "wrong-original-sha2-package",
    "source-reader-omitted", "source-roster-omitted", "source-document-omitted", "external-identical-reader",
    "external-identical-roster", "source-foreign-extra", "function-owner-not-fenced", "function-foreign-unfenced",
    "function-foreign-fenced", "include-owner-not-fenced",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode, value.st_mtime_ns, value.st_ctime_ns)


def file_identity(path, destination=None):
    """Read one regular, stable file; optionally preserve those exact read bytes."""
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "Regular evidence input required: " + str(path))
    digest = hashlib.sha256()
    size = 0
    output = destination.open("xb") if destination is not None else None
    try:
        with path.open("rb") as stream:
            require(stamp(os.fstat(stream.fileno())) == stamp(before), "Input changed before read: " + str(path))
            while True:
                data = stream.read(1024 * 1024)
                if not data:
                    break
                digest.update(data)
                size += len(data)
                if output is not None:
                    output.write(data)
            require(stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(path.lstat()),
                    "Input changed during read: " + str(path))
    finally:
        if output is not None:
            output.close()
    return {"bytes": size, "sha256": digest.hexdigest()}


def select_dependency(metadata, lock, repo):
    """Select the unique locked SQLite package reachable from the actual Task node."""
    packages = metadata.get("packages", [])
    ids = {p["id"]: p for p in packages}
    require(len(ids) == len(packages), "Duplicate Cargo metadata package identity")
    manifest = repo / "trillionnium/crates/trnm-task-kernel/Cargo.toml"
    owners = [p for p in packages if p.get("name") == "trnm-task-kernel" and Path(p["manifest_path"]) == manifest]
    require(len(owners) == 1 and owners[0]["id"] in metadata.get("workspace_members", []),
            "Missing or ambiguous current Task package in actual Cargo graph")
    resolved = metadata.get("resolve")
    require(isinstance(resolved, dict), "Full resolved Cargo dependency graph required")
    rows = resolved.get("nodes", [])
    nodes = {row["id"]: row for row in rows}
    require(len(rows) == len(nodes), "Duplicate Cargo metadata dependency node")
    reached = set()
    pending = [owners[0]["id"]]
    while pending:
        package = pending.pop()
        if package in reached:
            continue
        require(package in nodes and package in ids, "Cargo dependency node has no package")
        reached.add(package)
        node = nodes[package]
        dependencies = node.get("dependencies", [])
        require(set(dependencies) == {entry["pkg"] for entry in node.get("deps", [])},
                "Cargo dependency edge representations differ")
        pending.extend(dependencies)
    candidates = [ids[p] for p in reached if ids[p].get("name") == "libsqlite3-sys"]
    require(len(candidates) == 1 and candidates[0].get("version") == SQLITE_VERSION,
            "Exactly one libsqlite3-sys 0.39.1 must be reachable from Task")
    dependency = candidates[0]
    locked = [p for p in lock.get("package", []) if p.get("name") == "libsqlite3-sys" and p.get("version") == SQLITE_VERSION]
    require(len(locked) == 1 and locked[0].get("source") == dependency.get("source") and
            isinstance(locked[0].get("checksum"), str) and re.fullmatch(r"[0-9a-f]{64}", locked[0]["checksum"]),
            "Resolved SQLite dependency differs from Cargo.lock")
    path = Path(dependency["manifest_path"])
    require(path.is_absolute() and path.name == "Cargo.toml" and path.parent.name == "libsqlite3-sys-0.39.1",
            "Exact registry SQLite manifest path required")
    require(path.resolve(strict=True) == path, "Canonical SQLite manifest path required")
    return path.parent, {"package_id": dependency["id"], "manifest_path": str(path),
                         "source": dependency["source"], "lock_checksum": locked[0]["checksum"],
                         "task_package_id": owners[0]["id"], "reachable_packages": sorted(reached)}


class Qualification:
    def __init__(self, component, output, rust_bin):
        require(component in ("task-store", "task-boundary"), "Unknown Task component")
        self.output = output.absolute()
        require(self.output.resolve() == self.output and not self.output.exists() and self.output != ROOT and
                ROOT not in self.output.parents, "Fresh canonical output outside the checkout required")
        self.output.mkdir(parents=True, mode=0o700)
        self.rust = rust_bin.resolve(strict=True)
        self.component = component
        self.started = time.monotonic()
        self.references = {}
        self.objects = {}
        self.capture_errors = []
        self.sources = {}
        self.report = {"schema": "trnm.hia.task-ci-qualification.v1", "component": component,
                       "status": "FAIL", "finalized": False, "stages": [], "checks": {},
                       "source_before": {}, "source_after": {},
                       "scope": "Main TaskKernelStore" if component == "task-store" else "Mechanical SQLite/filesystem boundary",
                       "component_limit_seconds": COMPONENT_SECONDS, "cleanup_limit_seconds": CLEANUP_SECONDS,
                       "full_task_kernel_owner_qualified": False, "archive_business_qualified": False,
                       "state_import_qualified": False, "node_qualified": False, "whole_chain_native": False,
                       "pure_hia_sqlite": False}
        self.environment = os.environ.copy()
        removed = []
        for key in ("RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
                    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CLIPPY_ARGS", "CARGO_TARGET_DIR", "RUST_TEST_THREADS"):
            if key in self.environment:
                removed.append(key)
                self.environment.pop(key)
        self.environment.update(PATH=str(self.rust) + os.pathsep + self.environment.get("PATH", ""),
            RUSTUP_TOOLCHAIN="1.95.0", RUSTC=str(self.rust / "rustc"), RUSTDOC=str(self.rust / "rustdoc"),
            CLIPPY_DRIVER=str(self.rust / "clippy-driver"), CARGO=str(self.rust / "cargo"),
            CARGO_NET_OFFLINE="true", CARGO_BUILD_JOBS="4", GIT_NO_LAZY_FETCH="1", PYTHONDONTWRITEBYTECODE="1")
        keys = ("PATH", "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTDOC", "CLIPPY_DRIVER", "CARGO", "CARGO_HOME",
                "CARGO_NET_OFFLINE", "CARGO_BUILD_JOBS", "GIT_NO_LAZY_FETCH", "PYTHONDONTWRITEBYTECODE",
                "HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256")
        self.report["environment"] = {k: self.environment[k] for k in keys if k in self.environment}
        self.report["removed_external_rust_override_names"] = removed
        self.save()

    def save(self):
        (self.output / "report.json").write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")

    def capture(self, path, expected=None):
        path = Path(path).absolute()
        require(path.resolve() == path, "Canonical captured input required: " + str(path))
        name = str(path)
        if name in self.references:
            actual = file_identity(path)
            require(actual == {k: self.references[name][k] for k in ("bytes", "sha256")}, "Captured input changed: " + name)
        elif path.is_relative_to(self.output):
            actual = file_identity(path)
            self.references[name] = {**actual, "location": "output", "path": str(path.relative_to(self.output)),
                                     "mode": stat.S_IMODE(path.stat().st_mode)}
        else:
            directory = self.output / "captured-inputs/objects"
            directory.mkdir(parents=True, exist_ok=True)
            temporary = directory / ("pending-" + str(len(self.references)))
            actual = file_identity(path, temporary)
            target = directory / actual["sha256"]
            if target.exists():
                require(file_identity(target) == actual, "Preserved content object changed")
                temporary.unlink()
            else:
                temporary.rename(target)
            relative = str(target.relative_to(self.output))
            self.objects[actual["sha256"]] = {**actual, "path": relative}
            self.references[name] = {**actual, "location": "captured", "path": relative,
                                     "mode": stat.S_IMODE(path.stat().st_mode)}
        if expected is not None:
            require(actual == {k: expected[k] for k in ("bytes", "sha256")}, "Referenced source identity differs: " + name)
        return actual

    def stage(self, name, argv, limit):
        require(all(row["name"] != name for row in self.report["stages"]), "Duplicate stage")
        directory = self.output / "stages" / name
        directory.mkdir(parents=True)
        for stream in ("stdin", "stdout", "stderr"):
            (directory / (stream + ".raw")).write_bytes(b"")
        remaining = COMPONENT_SECONDS - (time.monotonic() - self.started)
        row = {"name": name, "argv": list(map(str, argv)), "cwd": str(ROOT), "timeout_seconds": limit,
               "effective_timeout_seconds": min(limit, max(0, remaining)), "started": False, "completed": False}
        self.report["stages"].append(row)
        self.save()
        process = None
        cleanup_started = False
        start = time.monotonic_ns()
        try:
            require(remaining > 0, "Component wall deadline exhausted")
            with (directory / "stdout.raw").open("wb") as stdout, (directory / "stderr.raw").open("wb") as stderr:
                process = subprocess.Popen(row["argv"], cwd=ROOT, env=self.environment, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                row["started"] = True
                row["pid"] = process.pid
                self.save()
                try:
                    process.wait(timeout=row["effective_timeout_seconds"])
                except subprocess.TimeoutExpired:
                    row["timed_out"] = True
                    cleanup_started = True
                    cleanup = time.monotonic_ns()
                    deadline = time.monotonic() + CLEANUP_SECONDS
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        pass
                    finally:
                        row["cleanup"] = {"signal": "SIGKILL", "complete": process.poll() is not None,
                                          "elapsed_ns": time.monotonic_ns() - cleanup}
                    raise
            row.update(completed=True, exit_code=process.returncode)
            require(process.returncode == 0, "Stage exited unsuccessfully: " + name)
        except BaseException as error:
            row["failure"] = repr(error)
            if process is not None:
                if process.poll() is None and not cleanup_started:
                    cleanup_started = True
                    cleanup = time.monotonic_ns()
                    deadline = time.monotonic() + CLEANUP_SECONDS
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        pass
                    row["cleanup"] = {"signal": "SIGKILL", "complete": process.poll() is not None,
                                      "elapsed_ns": time.monotonic_ns() - cleanup}
                row["exit_code"] = process.poll()
            raise
        finally:
            row["elapsed_ns"] = time.monotonic_ns() - start
            for stream in ("stdin", "stdout", "stderr"):
                row[stream] = file_identity(directory / (stream + ".raw"))
            self.save()
            print(json.dumps({"stage": name, "exit_code": row.get("exit_code"), "completed": row["completed"],
                              "seconds": row["elapsed_ns"] / 1e9}), flush=True)
        return (directory / "stdout.raw").read_bytes()

    def passed(self, path):
        value = json.loads(self.read(path))
        require(value.get("status") == "PASS" and value.get("finalized") is True, "Incomplete qualification: " + str(path))
        if "source_before" in value:
            require(value["source_before"] == value["source_after"], "Qualification source fence differs")
        return value

    def read(self, path):
        expected = self.capture(path)
        raw = Path(path).read_bytes()
        require({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} == expected,
                "Recorded evidence changed between capture and read: " + str(path))
        return raw

    def collect_report(self, path, required=False):
        """Preserve only actual input maps, never fabricated negative-control expectations."""
        if not path.is_file():
            require(not required and str(path) not in self.references, "A consumed or mandatory report disappeared: " + str(path))
            return
        value = json.loads(self.read(path))
        references = []
        for key in ("source_before", "checked_files", "toolchain", "original_libraries"):
            for name, expected in value.get(key, {}).items():
                references.append((name, expected))
        compiler = value.get("compiler")
        if isinstance(compiler, dict) and {"path", "bytes", "sha256"} <= compiler.keys():
            references.append((compiler["path"], compiler))
        for name, expected in references:
            try:
                self.capture(name, expected)
            except BaseException as error:
                self.capture_errors.append({"report": str(path), "input": str(name), "expected": expected,
                                            "failure": repr(error)})

    def capture_all(self):
        reports = [(self.output / "provider/build.json", "provider-build")]
        if self.component == "task-store":
            reports += [(self.output / "store/report.json", "store-complete"),
                        (self.output / "readback/report.json", "store-independent-readback"),
                        (self.output / "reader-controls/positive/report.json", "store-reader-negative-controls")]
            for name in ("records-native/build.json", "public-native/build.json", "public-allocations/build.json"):
                reports.append((self.output / "store" / name, "store-complete"))
        else:
            reports += [(self.output / "boundary/build.json", "boundary-native-build"),
                        (self.output / "boundary-qualification/report.json", "boundary-native-original"),
                        (self.output / "filesystem-qualification/observations.json", "boundary-filesystem-original")]
        complete_stages = {row["name"] for row in self.report["stages"] if row.get("completed") and row.get("exit_code") == 0}
        for path, stage in reports:
            try:
                self.collect_report(path, stage in complete_stages)
            except BaseException as error:
                self.capture_errors.append({"report": str(path), "failure": repr(error)})
        for original, value in self.references.items():
            try:
                preserved = self.output / value["path"]
                require(file_identity(preserved) == {k: value[k] for k in ("bytes", "sha256")},
                        "Captured reference no longer resolves to its exact bytes: " + original)
            except BaseException as error:
                self.capture_errors.append({"input": original, "preserved": value["path"], "failure": repr(error)})
        manifest = {"schema": "trnm.hia.task-ci-captured-inputs.v1", "component": self.component,
                    "complete": not self.capture_errors, "references": self.references, "objects": self.objects,
                    "capture_errors": self.capture_errors,
                    "contract": "Every actual reader checked_file is mapped to exact output bytes or a captured external content object"}
        target = self.output / "captured-inputs.json"
        target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        self.report["captured_inputs"] = {"path": target.name, **file_identity(target),
                                         "references": len(self.references), "external_content_objects": len(self.objects),
                                         "complete": not self.capture_errors}
        self.save()

    def store(self):
        gate = self.output / "store"
        self.stage("store-complete", [sys.executable, TASK / "qualify_task_store.py", "--provider", self.output / "provider",
                   "--rust-bin", self.rust, "--output", gate], 1200)
        self.passed(gate / "report.json")
        reader = TASK / "readback_task_store.py"
        roster = Q / "task_store_roster.json"
        self.stage("store-independent-readback", [sys.executable, reader, "--evidence", gate, "--repo", ROOT,
                   "--roster", roster, "--output", self.output / "readback"], 180)
        readback = self.passed(self.output / "readback/report.json")
        require(readback.get("checked_files") and readback.get("reader_source") == file_identity(reader) and
                readback.get("roster_source") == file_identity(roster), "Canonical source-bound reader did not complete")
        self.stage("store-reader-negative-controls", [sys.executable, Q / "readback_negative_controls.py", "--reader", reader,
                   "--evidence", gate, "--repo", ROOT, "--roster", roster, "--output", self.output / "reader-controls"], 180)
        controls = self.passed(self.output / "reader-controls/report.json")
        require(tuple(row["name"] for row in controls["controls"]) == READER_NEGATIVES and
                all(row["rejected"] and row["failure"] for row in controls["controls"]) and
                controls["negative_controls"] == 37 and controls["source_evidence_unchanged"] and
                controls["reader"] == file_identity(reader) and controls["harness"] == file_identity(Q / "readback_negative_controls.py"),
                "Exact 37 actual reader rejections did not complete")
        self.report["checks"].update(main_task_store=True, canonical_complete_readback=True, actual_reader_rejections=37,
                                     readback_checks=readback["checks"])

    def boundary(self):
        provider = self.output / "provider"
        boundary = self.output / "boundary"
        observed = self.output / "boundary-qualification"
        fs = self.output / "filesystem-qualification"
        self.stage("provider-negative-controls", [sys.executable, Q / "provider_controls.py", provider,
                   self.output / "provider-controls"], 180)
        controls = self.passed(self.output / "provider-controls/report.json")
        require(tuple(row["name"] for row in controls["cases"]) == PROVIDER_NEGATIVES and
                all(row.get("exit_code", 1) != 0 for row in controls["cases"][:6]) and
                controls["cases"][6].get("actual_exception") == "TimeoutExpired" and
                controls["cases"][7].get("actual_exception") == "FileNotFoundError" and
                controls["positive_source_unchanged"], "Exact provider rejection roster differs")
        self.stage("boundary-native-build", [sys.executable, TASK / "build_boundary.py", "--provider", provider,
                   "--output", boundary], 180)
        self.stage("boundary-native-original", [sys.executable, TASK / "qualify_boundary.py", "--boundary", boundary,
                   "--output", observed, "--rustc", self.rust / "rustc"], 300)
        result = self.passed(observed / "report.json")
        self.stage("boundary-filesystem-original", [sys.executable, Q / "filesystem_observer.py", boundary, fs,
                   self.rust / "rustc"], 300)
        self.check_boundary(observed, fs, result)

    def check_boundary(self, observed, fs, result):
        expected_stages = ("preflight", "compile-fd-observer", "execute-fd-observer", "compile-allocator-wrapper",
                           "compile-read-observer", "execute-read-observer", "link-fault-native", "execute-native-fd",
                           "rust-version", "compile-original-link", "execute-original-link")
        require(tuple(row["name"] for row in result["stages"]) == expected_stages and
                all(row["completed"] and row["exit_code"] == 0 and row["timeout_seconds"] == 60 for row in result["stages"]),
                "Boundary actual stage roster differs")
        for name, expected in (
            ("execute-fd-observer", {"status": "PASS", "cases": 8}),
            ("execute-read-observer", {"status": "PASS", "cases": 13, "real_signal_interruptions": 1}),
            ("execute-native-fd", {"status": "PASS", "serial_calls": 19, "concurrent_calls": 256,
                                   "actual_allocation_failure_cases": 4, "explicit_hia_oom_cleanup_cases": 1}),
            ("execute-original-link", {"status": "PASS", "actual_original_provider_pairs": 4}),
        ):
            require(json.loads(self.read(observed / (name + ".stdout.raw")).splitlines()[-1]) == expected,
                    "Actual boundary process output differs: " + name)
        fd = self.passed(observed / "native-fd-observations.json")
        require(len(fd["calls"]) == 19 and [r["mode"] for r in fd["cases"]] == [0, 1, 2, 3, 4, 5, 6, 9] and
                [r["expected"] for r in fd["cases"]] == [0, 104, 103, 104, 103, 103, 100, 103], "Native fd roster differs")
        expected_modes = [value for mode in (0, 1, 2, 3, 4, 5, 6, 9) for value in (mode, 0)] + [8, 8, 0]
        expected_codes = [0, 0, 104, 104, 103, 104, 104, 104, 103, 104, 103, 104, 100, 0, 103, 104, 0, 103, 104]
        require([row["mode"] for row in fd["calls"]] == expected_modes and
                [row["code"] for row in fd["calls"]] == expected_codes, "Serial retry and poisoned-owner results differ")
        for index, row in enumerate(fd["cases"]):
            actual = row["actual"]
            require(actual == fd["calls"][index * 2], "Descriptor case is not bound to its actual call")
            require(actual["code"] == row["expected"], "Native fd outcome differs")
            if row["expected"]:
                require(not actual["published"] and actual["bytes"] == 0 and not actual["actual_output"], "Failed fd call published output")
            counts = row["allocation_and_syscall_observations"]
            require((counts[1] == counts[2] == 0 and row["last_opened_fd_is_closed"] is None) if row["mode"] == 4 else
                    (counts[1] == counts[2] == 1 and row["last_opened_fd_is_closed"] is True), "Native descriptor cleanup differs")
        concurrent = fd["concurrent_nonce_calls"]
        require(len(concurrent) == 256 and all(r["code"] == 0 and r["published"] and r["bytes"] == 8 for r in concurrent) and
                sorted(struct.unpack("<Q", bytes.fromhex(r["actual_output"]))[0] for r in concurrent) == list(range(256)),
                "Actual concurrent nonce calls differ")
        require(fd["concurrent_syscall_observations"][1:3] == [256, 256], "Concurrent descriptors did not all close")
        success, failed = fd["native_read_success"], fd["native_read_capacity_allocation_failure"]
        data = bytes(range(256)) * 513
        require(success["actual"] == fd["calls"][16] and success["source_bytes"] == len(data) and
                success["source_sha256"] == hashlib.sha256(data).hexdigest() and
                bytes.fromhex(success["actual"]["actual_output"]) == struct.pack("<QQQ", 0, len(data), 0) + data and
                success["observations"][1] == success["observations"][2] == success["observations"][6] == 1,
                "Actual retained-descriptor read bytes differ")
        require(failed["actual"] == fd["calls"][17] and not failed["actual"]["published"] and
                not failed["actual"]["actual_output"] and failed["observations"][1:3] == [1, 1] and failed["observations"][6] == 0,
                "Read allocation failure did not preserve cleanup")
        links = self.passed(observed / "link-pairs/report.json")
        require([r["name"] for r in links["cases"]] == ["empty-target", "empty-source", "both-empty", "ordinary-target"],
                "Original hard_link roster differs")
        for i, row in enumerate(links["cases"]):
            original = json.loads(self.read(observed / "link-pairs" / (str(i) + ".stdout.raw")))
            require(row["completed"] and row["exit"] == 0 and row["equal"] and row["original"] == original and
                    row["provider_return"] == 24 and struct.unpack("<QQQ", bytes.fromhex(row["provider_output_hex"])) ==
                    (original["errno"], 0, 0), "Original/provider hard_link bytes differ")
        linked = [observed / "link-pairs" / name for name in ("source", "ordinary", "ordinary-rust")]
        require(len({path.stat().st_ino for path in linked}) == 1 and
                self.read(linked[0]) == self.read(linked[1]) == self.read(linked[2]), "Actual successful hard_link inode or bytes differ")
        filesystem = self.passed(fs / "observations.json")
        for prefix, count in (("pure", 6174), ("filesystem", 73)):
            inputs = self.read(fs / (prefix + "-original-run.stdin.raw")).splitlines()
            originals = self.read(fs / (prefix + "-original-run.stdout.raw")).splitlines()
            rows = [json.loads(line) for line in self.read(fs / (prefix + "-native-observations.jsonl")).splitlines()]
            require(len(inputs) == len(originals) == len(rows) == count, "Complete filesystem differential roster differs")
            for i, (source, raw, row) in enumerate(zip(inputs, originals, rows)):
                code, output = raw.split(b"|", 1)
                require(row["index"] == i and row["input"] == source.decode() and row["code"] == row["original_code"] == int(code) and
                        row["actual_output"] == row["original_output"] == output.decode(), "Filesystem native/original raw bytes differ")
        contracts = [json.loads(line) for line in self.read(fs / "native-contract-observations.jsonl").splitlines()]
        require(len(contracts) == 30 and filesystem["reserve_nonces"] == list(range(16)), "Native filesystem contract roster differs")
        for i, row in enumerate(contracts):
            raw = bytes.fromhex(row["actual_output"])
            require(row["native_code"] == 0 and len(raw) >= 48, "Filesystem contract did not execute")
            code, message, _, _, _, size = struct.unpack_from("<6Q", raw)
            require(len(raw) == 48 + message + size, "Filesystem contract framing differs")
            if i < 14:
                require(row["index"] == i and code == row["expected_business_code"] and
                        raw[48:48 + message] == bytes.fromhex(row["expected_message"]), "Filesystem contract result differs")
            else:
                match = re.fullmatch(rb"contracts/directory/\.trnm-task-archive-init-([0-9]+)-([0-9]+)-([0-9]+)", raw[48:])
                require(row["reserve"] == i - 14 and row["published"] and code == message == 0 and match and
                        int(match[1]) > 0 and int(match[2]) > 0 and int(match[3]) == i - 14, "Temporary reservation nonce differs")
        require(json.loads(self.read(fs / "original-filesystem.json")) == json.loads(self.read(fs / "native-filesystem.json")),
                "Original/native filesystem effects differ")
        self.report["checks"].update(provider_rejections=8, descriptor_controls=8, read_controls=13, real_signal_interruptions=1,
            native_serial_calls=19, native_concurrent_calls=256, actual_allocation_failures=4, explicit_hia_oom_cleanup=1,
            original_hard_link_pairs=4, original_path_pairs=6174, original_filesystem_pairs=73, native_filesystem_contracts=30,
            actual_raw_readback=True)

    def run(self):
        failure = None
        try:
            require(__debug__, "Optimized qualification refused")
            self.stage("preflight", ["bash", "scripts/project-preflight.sh", "--audit"], 60)
            paths = {Path(__file__).resolve(), ROOT / "trillionnium/Cargo.toml", ROOT / "trillionnium/Cargo.lock",
                     ROOT / "scripts/project-preflight.sh", ROOT / "scripts/ci/project_boundary.py"}
            for directory in (TASK, ROOT / "hia/src/task_kernel"):
                paths.update(p for p in directory.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
            self.sources = {str(p): self.capture(p) for p in sorted(paths)}
            self.report["source_before"] = self.sources
            for name, prefix in (("rustc", b"rustc 1.95.0 "), ("cargo", b"cargo 1.95.0 ")):
                self.capture(self.rust / name)
                actual = self.stage("version-" + name, [self.rust / name, "--version", "--verbose"], 60)
                require(actual.startswith(prefix), "Pinned Rust 1.95.0 required: " + name)
            raw = self.stage("locked-cargo-metadata", [self.rust / "cargo", "metadata", "--locked", "--offline",
                "--manifest-path", ROOT / "trillionnium/Cargo.toml", "--format-version", "1",
                "--filter-platform", "x86_64-unknown-linux-gnu"], 60)
            dependency, selection = select_dependency(json.loads(raw), tomllib.loads((ROOT / "trillionnium/Cargo.lock").read_text()), ROOT)
            self.report["sqlite_dependency"] = selection
            self.capture(dependency / "Cargo.toml")
            self.stage("provider-build", [sys.executable, TASK / "build_provider.py", "--dependency", dependency,
                       "--output", self.output / "provider"], 1200)
            self.passed(self.output / "provider/build.json")
            if self.component == "task-store":
                self.store()
            else:
                self.boundary()
            self.report["source_after"] = {p: file_identity(p) for p in self.sources}
            require(self.sources == self.report["source_after"], "Current Task inputs changed during qualification")
        except BaseException as error:
            failure = error
            self.report["failure"] = repr(error)
        try:
            self.capture_all()
            require(not self.capture_errors, "Referenced original evidence could not be preserved completely")
        except BaseException as error:
            self.report["capture_failure"] = repr(error)
            if failure is None:
                failure = error
        after = {}
        for name in self.sources:
            try:
                after[name] = file_identity(name)
            except BaseException as error:
                after[name] = {"failure": repr(error)}
                if failure is None:
                    failure = error
        self.report["source_after"] = after
        if failure is None and after != self.sources:
            failure = ValueError("Current Task inputs changed during evidence capture")
        self.report["elapsed_seconds"] = time.monotonic() - self.started
        if failure is None and self.report["elapsed_seconds"] > COMPONENT_SECONDS:
            failure = ValueError("Component deadline exceeded during final evidence capture")
        if failure is None:
            self.report.update(status="PASS", finalized=True)
        else:
            self.report.setdefault("failure", repr(failure))
        self.save()
        if failure is not None:
            raise failure
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", required=True, choices=("task-store", "task-boundary"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rust-bin", required=True, type=Path)
    args = parser.parse_args()
    result = Qualification(args.component, args.output, args.rust_bin).run()
    print(json.dumps({"status": result["status"], "component": result["component"], "checks": result["checks"],
                      "captured_inputs": result["captured_inputs"], "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()

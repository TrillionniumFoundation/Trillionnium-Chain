"""Build the unchanged Cargo graph, all original tests and public API observers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import traceback

from .build import ROOT, HERE, identity, need, cargo_configuration
from .process import Processes

PACKAGE = ROOT / "trillionnium/crates/trnm-peer-lease"
PROFILE = {"debug_assertions": True, "debuginfo": 2, "opt_level": "0",
           "overflow_checks": True, "test": False}
ADAPTERS = {"daemon": "daemon_reference.rs", "client": "client_reference.rs",
            "client-owner": "client_owner_reference.rs", "codec": "codec_reference.rs"}
TEST_COUNTS = {
    "trnm_peer_lease": 97,
    "trnm-peer-lease-daemon": 0,
    "trnm-peer-lease-daemon-v1": 0,
    "trnm-payload-replay-recovery-v1": 6,
    "trnm-payload-replay-recovery-owner-v1": 1,
    "cross_process": 8,
    "payload_recovery_quarantine_collision": 1,
    "payload_replay_cross_process": 2,
    "payload_replay_recovery_owner_socket": 1,
    "payload_replay_recovery_process": 2,
    "payload_replay_recovery_process_matrix": 3,
}


def cargo_events(raw):
    events = []
    finished = False
    for line in raw.splitlines():
        if not line.startswith(b"{"):
            continue
        value = json.loads(line)
        if value.get("reason") == "build-finished":
            need(not finished and value.get("success") is True, "Actual Cargo build did not finish")
            finished = True
        elif value.get("reason") == "compiler-artifact":
            need(not finished, "Compiler artifact followed Cargo completion")
            events.append(value)
    need(finished and events, "Actual complete Cargo event stream absent")
    return events


def completed_original_tests(raw):
    pattern = (rb"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
               rb"(\d+) measured; (\d+) filtered out; finished in [0-9.]+s$")
    rows = [tuple(map(int, values)) for values in re.findall(pattern, raw, re.M)]
    need(len(rows) == 14 and all(failed == ignored == measured == 0
                               for _, failed, ignored, measured, _ in rows),
         "Complete original tests must all execute and pass")
    outer = [passed for passed, _, _, _, filtered in rows if filtered == 0]
    children = [row for row in rows if row[4] != 0]
    # The unchanged cross-process test explicitly re-executes two named child
    # helpers. These are retained observations, not two additional outer tests.
    need(sorted(outer) == sorted([*TEST_COUNTS.values(), 0])
         and children == [(1, 0, 0, 0, 1), (1, 0, 0, 0, 1)],
         "Original outer roster or the two existing child re-executions changed")
    return {"outer_tests": sum(outer), "doctests": 0, "child_reexecutions": 2,
            "summaries": [list(row) for row in rows], "unfiltered_cargo_command": True}


class Original:
    def __init__(self, output, check):
        self.output = Path(output)
        self.output.mkdir(mode=0o700)
        self.check = check
        self.environment = dict(os.environ)
        configuration_guard = cargo_configuration(self.environment)
        forbidden = ("RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                     "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                     "RUST_TEST_THREADS", "RUST_TEST_NOCAPTURE", "RUST_TEST_FORCE_RUN_IN_PROCESS")
        need(not any(self.environment.get(name) for name in forbidden),
             "Original build or test process override is not admitted")
        self.environment = {name: self.environment[name] for name in (
            "PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR", "LANG", "LC_ALL", "TZ",
            "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL") if name in self.environment}
        self.processes = Processes(self.output / "processes", ROOT, self.environment, check)
        self.target = self.output / "cargo-target"
        need(not self.target.exists(), "Original Cargo target must be fresh")
        self.report = {"schema": "trnm.hia.peer-unix-original.v1", "status": "RUNNING",
                       "reused_prior_execution": False, "artifacts": {},
                       "test_rosters": {}, "observers": {}, "absent_cargo_configuration": configuration_guard}

    def stage(self, label, argv, timeout=240):
        return self.processes.run(label, argv, timeout=timeout)

    def build(self):
        try:
            self.stage("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"], 30)
            shim = shutil.which("rustc")
            need(shim, "Actual pinned Rust compiler required")
            sysroot = Path(self.stage("rust-sysroot", [shim, "--print", "sysroot"], 30).decode().strip())
            binary = sysroot / "bin"
            tools = {name: (binary / name).resolve(strict=True)
                     for name in ("rustc", "cargo", "rustdoc", "cargo-fmt", "rustfmt",
                                  "cargo-clippy", "clippy-driver")}
            version = self.stage("rust-version", [tools["rustc"], "-Vv"], 30)
            need(b"release: 1.95.0\n" in version and b"host: x86_64-unknown-linux-gnu\n" in version,
                 "Original Rust version or host differs from the repository pin")
            self.environment.update(PATH=str(binary) + os.pathsep + self.environment.get("PATH", ""),
                                    RUSTC=str(tools["rustc"]), CARGO=str(tools["cargo"]),
                                    RUSTDOC=str(tools["rustdoc"]), RUSTFMT=str(tools["rustfmt"]),
                                    RUSTUP_TOOLCHAIN="1.95.0-x86_64-unknown-linux-gnu")
            self.processes.environment = dict(self.environment)
            self.report["tools"] = {name: {"path": str(path), **identity(path.read_bytes())}
                                    for name, path in tools.items()}
            self.stage("clippy-version", [tools["cargo-clippy"], "--version"], 30)
            self.stage("clippy-driver-version", [tools["clippy-driver"], "--version"], 30)
            args = ["--offline", "--locked", "--manifest-path", ROOT / "trillionnium/Cargo.toml"]
            metadata = json.loads(self.stage("complete-cargo-graph",
                [tools["cargo"], "metadata", *args, "--all-features", "--format-version", "1"], 60))
            need(len(metadata["workspace_members"]) == 26, "The original 26-package Cargo graph changed")
            self.report["cargo_graph"] = identity(json.dumps(metadata, sort_keys=True).encode())
            raw = self.stage("retained-original-tests", [tools["cargo"], "test", *args,
                "-p", "trnm-peer-lease", "--all-features", "--no-fail-fast", "--target-dir",
                self.target, "--message-format=json", "--", "--test-threads=1"])
            self.report["retained_tests"] = completed_original_tests(raw)
            artifacts = cargo_events(raw)
            self.stage("workspace-fmt", [tools["cargo-fmt"], "fmt", "--all", "--manifest-path",
                                         ROOT / "trillionnium/Cargo.toml", "--", "--check"], 60)
            self.stage("strict-original-clippy", [tools["cargo-clippy"], "clippy", *args,
                "-p", "trnm-peer-lease", "--all-features", "--all-targets", "--target-dir",
                self.target, "--", "-D", "warnings"])
            tests = {}
            for event in artifacts:
                for filename in event["filenames"]:
                    path = Path(filename)
                    need(path.is_relative_to(self.target) and path.is_file() and not path.is_symlink(),
                         "Actual original artifact escapes its fresh target")
                    self.report["artifacts"][str(path.relative_to(self.output))] = {
                        **identity(path.read_bytes()), "target": event["target"],
                        "profile": event["profile"], "features": event["features"],
                        "package_id": event["package_id"], "executable": event.get("executable") == filename}
                if event["manifest_path"] == str(PACKAGE / "Cargo.toml") and event["profile"]["test"]:
                    target = event["target"]
                    need(event["profile"] == {**PROFILE, "test": True}
                         and target["name"] not in tests and event.get("executable"),
                         "Original test profile or unique executable changed")
                    tests[target["name"]] = Path(event["executable"])
            need(set(tests) == set(TEST_COUNTS), "An original Cargo test target is missing or substituted")
            for index, (name, executable) in enumerate(sorted(tests.items())):
                listing = self.stage("original-roster-" + str(index).zfill(2),
                                     [executable, "--list", "--format", "terse"], 30).decode()
                names = [line[:-6] for line in listing.splitlines() if line.endswith(": test")]
                other = [line for line in listing.splitlines() if line and not line.endswith(": test")]
                need(len(names) == len(set(names)) == TEST_COUNTS[name]
                     and (not other or len(other) == 1 and re.fullmatch(
                         str(len(names)) + r" tests?, 0 benchmarks?", other[0])),
                     "The actual original test roster differs: " + name)
                self.report["test_rosters"][name] = names

            def library(name, package_suffix=None):
                rows = [event for event in artifacts if event["target"]["name"] == name
                        and not event["profile"]["test"]
                        and (package_suffix is None or event["package_id"].endswith(package_suffix))
                        and any(path.endswith(".rlib") for path in event["filenames"])]
                need(len(rows) == 1 and rows[0]["profile"] == PROFILE,
                     "Actual original library/profile is not unique: " + name)
                paths = [Path(path) for path in rows[0]["filenames"] if path.endswith(".rlib")]
                need(len(paths) == 1, "Unique original rlib required")
                if name == "trnm_peer_lease":
                    need(rows[0]["manifest_path"] == str(PACKAGE / "Cargo.toml")
                         and set(rows[0]["features"]) == {"candidate-recovery-socket", "default"},
                         "All original package features must remain enabled")
                return paths[0]

            peer, libc = library("trnm_peer_lease"), library("libc", "#libc@0.2.184")
            directories = sorted({str(Path(path).parent) for event in artifacts
                                  for path in event["filenames"] if path.endswith((".rlib", ".rmeta"))})
            need(directories, "Actual original dependency graph absent")
            for role, filename in ADAPTERS.items():
                executable = self.output / (role + ".elf")
                argv = [tools["rustc"], "--edition=2021", "-C", "opt-level=0", "-C",
                        "debug-assertions=yes", "-C", "overflow-checks=yes", "-C", "debuginfo=2",
                        HERE / filename]
                for directory in directories:
                    argv += ["-L", "dependency=" + directory]
                if role != "codec":
                    argv += ["--extern", "trnm_peer_lease=" + str(peer)]
                if role in {"client", "client-owner"}:
                    argv += ["--extern", "libc=" + str(libc)]
                self.stage("build-observer-" + role, [*argv, "-o", executable])
                self.report["observers"][role] = {"path": executable.name,
                    **identity(executable.read_bytes()), "source": str((HERE / filename).relative_to(ROOT))}
            cli = [event for event in artifacts if event["target"]["name"] == "trnm-peer-lease-daemon"
                   and event["profile"] == PROFILE and event.get("executable")]
            need(len(cli) == 1 and cli[0]["executable"] == str(self.target / "debug/trnm-peer-lease-daemon"),
                 "Actual original daemon CLI is missing or substituted")
            self.report["observers"]["cli"] = {"path": str(Path(cli[0]["executable"]).relative_to(self.output)),
                **identity(Path(cli[0]["executable"]).read_bytes()), "source": "unchanged original Cargo bin"}
            self.check()
            self.report.update(status="PASS", complete_original_tests_preserved=True,
                               source_inputs_stable=True)
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", failure=repr(error), traceback=traceback.format_exc())
            raise
        finally:
            self.report["stages"] = self.processes.rows
            (self.output / "build.json").write_text(json.dumps(self.report, sort_keys=True, indent=2) + "\n")

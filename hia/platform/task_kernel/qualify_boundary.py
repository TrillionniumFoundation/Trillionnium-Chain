"""Execute current, source-bound provider/HIA ownership and syscall controls."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.task_kernel.build_provider import identity, need, write_json

HERE = Path(__file__).resolve().parent
QUALIFICATION = HERE / "qualification"


class Qualification:
    def __init__(self, output, boundary, rustc):
        self.output = Path(output).absolute()
        need(self.output.resolve() == self.output and not self.output.exists(), "Fresh output required")
        need(ROOT not in self.output.parents, "Evidence must be outside the checkout")
        self.output.mkdir(parents=True, mode=0o700)
        self.boundary = Path(boundary).resolve(strict=True)
        self.rustc = Path(rustc).resolve(strict=True)
        self.report = {"schema": "trnm.hia.task-kernel.boundary-qualification.v1",
                       "status": "FAIL", "finalized": False, "stages": [],
                       "scope": "Mechanical provider and HIA driver fixtures; no full TaskKernel business claim"}
        self.inputs = {}
        self.write()

    def write(self):
        write_json(self.output / "report.json", self.report)

    def capture(self, path):
        path = Path(path).absolute()
        self.inputs[str(path)] = identity(path)

    def fence(self):
        need({p: identity(p) for p in self.inputs} == self.inputs, "Qualification input changed")

    def stage(self, name, argv, timeout=60, environment=None, expected_exit=0):
        row = {"name": name, "argv": list(map(str, argv)), "cwd": str(ROOT),
               "timeout_seconds": timeout, "started": True, "completed": False}
        self.report["stages"].append(row)
        self.write()
        (self.output / (name + ".stdin.raw")).write_bytes(b"")
        start = time.monotonic_ns()
        try:
            p = subprocess.run(row["argv"], input=b"", capture_output=True, timeout=timeout,
                               cwd=ROOT, env=environment)
        except subprocess.TimeoutExpired as error:
            (self.output / (name + ".stdout.raw")).write_bytes(error.stdout or b"")
            (self.output / (name + ".stderr.raw")).write_bytes(error.stderr or b"")
            row.update(error="TimeoutExpired", elapsed_ns=time.monotonic_ns() - start)
            self.write()
            raise
        except OSError as error:
            (self.output / (name + ".stdout.raw")).write_bytes(b"")
            (self.output / (name + ".stderr.raw")).write_bytes(b"")
            row.update(error=repr(error), elapsed_ns=time.monotonic_ns() - start)
            self.write()
            raise
        (self.output / (name + ".stdout.raw")).write_bytes(p.stdout)
        (self.output / (name + ".stderr.raw")).write_bytes(p.stderr)
        row.update(completed=True, exit_code=p.returncode, elapsed_ns=time.monotonic_ns() - start)
        self.write()
        need((p.returncode == 0) if expected_exit == 0 else (p.returncode != 0),
             "Unexpected process result: " + name)
        return p

    def run(self):
        try:
            need(__debug__, "Optimized Python observer refused")
            self.stage("preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
            build_path = self.boundary / "build.json"
            self.capture(build_path)
            build = json.loads(build_path.read_text())
            need(build["status"] == "PASS" and build["finalized"] and
                 build["source_before"] == build["source_after"], "Boundary build not qualified")
            for path, expected in build["source_before"].items():
                self.capture(path)
                need(identity(path) == expected, "Boundary source differs")
            for name, expected in build["artifacts"].items():
                self.capture(self.boundary / name)
                need(identity(self.boundary / name) == expected, "Boundary artifact differs")
            self.capture(__file__)
            self.capture(self.rustc)
            self.report["boundary_build"] = str(build_path)
            provider_path = Path(build["provider_build"])
            provider = provider_path.parent
            provider_build = json.loads(provider_path.read_text())
            cc = provider_build["compiler"]["path"]
            common = [cc, "-std=c11", "-O0", "-fPIC", "-Wall", "-Wextra", "-Werror"]
            objects = [provider / (name + ".o") for name in ("provider", "sqlite", "witness")]
            wrappers = ["-Wl,--wrap=" + name for name in
                        ("malloc", "calloc", "open", "close", "read", "sqlite3_finalize", "sqlite3_close_v2")]
            self.stage("compile-fd-observer", [*common, QUALIFICATION / "fd_observer.c", *objects,
                       *wrappers, "-ldl", "-lm", "-lpthread", "-o", self.output / "fd-observer"])
            direct = self.stage("execute-fd-observer", [self.output / "fd-observer", self.output / "fd-target"])
            need(json.loads(direct.stdout.splitlines()[-1]) == {"status": "PASS", "cases": 8},
                 "Direct descriptor controls differ")
            self.stage("compile-allocator-wrapper", [*common, "-DTRNM_OBSERVER_NO_MAIN", "-c",
                       QUALIFICATION / "fd_observer.c", "-o", self.output / "allocator-wrapper.o"])
            self.stage("compile-read-observer", [*common, QUALIFICATION / "read_observer.c",
                       self.output / "allocator-wrapper.o", *objects, *wrappers, "-ldl", "-lm", "-lpthread",
                       "-o", self.output / "read-observer"])
            reads = self.stage("execute-read-observer", [self.output / "read-observer", self.output])
            need(json.loads(reads.stdout.splitlines()[-1]) ==
                 {"status": "PASS", "cases": 13, "real_signal_interruptions": 1}, "Read controls differ")
            hia = [self.boundary / name for name in
                   ("driver.o", "dispatch.o", "fd-named.o", "query-named.o", "files-named.o")]
            self.stage("link-fault-native", [cc, "-shared",
                       "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections,-Bsymbolic-functions",
                       *hia, *objects, self.output / "allocator-wrapper.o", *wrappers,
                       "-ldl", "-lm", "-lpthread", "-o", self.output / "native-fd.so"])
            native = self.stage("execute-native-fd", [sys.executable,
                               QUALIFICATION / "native_fd_observer.py", self.output])
            observed = json.loads(native.stdout.splitlines()[-1])
            need(observed == {"status": "PASS", "serial_calls": 19, "concurrent_calls": 256,
                              "actual_allocation_failure_cases": 4, "explicit_hia_oom_cleanup_cases": 1},
                 "Native ownership controls differ")
            version = self.stage("rust-version", [self.rustc, "--version", "--verbose"])
            need(version.stdout.splitlines()[0].startswith(b"rustc 1.95.0 "), "Exact Rust 1.95.0 required")
            self.stage("compile-original-link", [self.rustc, "--edition=2021",
                       QUALIFICATION / "link_original.rs", "-o", self.output / "link-original"])
            pairs = self.stage("execute-original-link", [sys.executable,
                               QUALIFICATION / "link_observer.py", provider,
                               self.output / "link-original", self.output / "link-pairs"])
            need(json.loads(pairs.stdout.splitlines()[-1]) ==
                 {"status": "PASS", "actual_original_provider_pairs": 4}, "Original hard_link differs")
            self.report["provider_objects_in_fault_fixture"] = {
                "scope": "This statically linked injection fixture runs only in a separate observer process",
                "production_boundary_dynamic_provider": str(self.boundary / "provider.so")}
            self.fence()
            self.report["source_before"] = self.inputs
            self.report["source_after"] = {p: identity(p) for p in self.inputs}
            self.report["artifacts"] = {name: identity(self.output / name) for name in
                ("fd-observer", "read-observer", "allocator-wrapper.o", "native-fd.so", "link-original")}
            self.report.update(status="PASS", finalized=True, direct_descriptor_cases=8,
                               direct_read_cases=13, actual_signal_interruptions=1,
                               native_serial_calls=19, native_concurrent_calls=256,
                               actual_allocation_failure_cases=4, explicit_hia_oom_cleanup_cases=1,
                               original_hard_link_pairs=4, full_task_kernel_owner_qualified=False)
            self.write()
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error), source_before=self.inputs)
            self.write()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boundary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    report = Qualification(args.output, args.boundary, args.rustc).run()
    print(json.dumps({k: v for k, v in report.items() if k not in
                      {"stages", "source_before", "source_after", "artifacts"}}))


if __name__ == "__main__":
    main()

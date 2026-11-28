"""Fresh-source TaskKernelStore qualification; archive and StateImport remain separate work."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
Q = HERE / "qualification"
ORIGINAL = ROOT / "trillionnium/crates/trnm-task-kernel/src"


def identity(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class Qualification:
    def __init__(self, output, provider, rust_bin):
        self.output = output.absolute()
        if self.output.resolve() != self.output or self.output.exists() or ROOT in self.output.parents:
            raise ValueError("Fresh canonical evidence directory outside the checkout required")
        self.output.mkdir(parents=True, mode=0o700)
        self.provider = provider.resolve(strict=True)
        self.rust_bin = rust_bin.resolve(strict=True)
        self.target = self.output / "cargo-target"
        self.report = {
            "schema": "trnm.hia.task-kernel.public-store-qualification.v1",
            "scope": "Main TaskKernelStore, its six transitions, private audits and public owned values",
            "status": "FAIL", "finalized": False, "stages": [],
            "full_task_kernel_owner_qualified": False,
            "archive_business_qualified": False, "state_import_qualified": False,
            "no_original_source_changes": True,
        }
        self.sources = {}
        self.environment = os.environ.copy()
        for key in ("RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
                    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CLIPPY_ARGS", "CARGO_TARGET_DIR", "RUST_TEST_THREADS"):
            self.environment.pop(key, None)
        self.environment.update(
            PATH=str(self.rust_bin) + os.pathsep + self.environment.get("PATH", ""),
            RUSTUP_TOOLCHAIN="1.95.0", RUSTC=str(self.rust_bin / "rustc"),
            RUSTDOC=str(self.rust_bin / "rustdoc"), CLIPPY_DRIVER=str(self.rust_bin / "clippy-driver"),
            CARGO=str(self.rust_bin / "cargo"), CARGO_NET_OFFLINE="true", CARGO_BUILD_JOBS="4",
            GIT_NO_LAZY_FETCH="1", CARGO_MANIFEST_DIR=str(ORIGINAL.parent), CARGO_PKG_NAME="trnm-task-kernel",
        )
        self.report["environment"] = {k: self.environment[k] for k in (
            "PATH", "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTDOC", "CLIPPY_DRIVER", "CARGO", "CARGO_NET_OFFLINE",
            "CARGO_BUILD_JOBS", "GIT_NO_LAZY_FETCH", "CARGO_MANIFEST_DIR", "CARGO_PKG_NAME")}
        if "CARGO_HOME" in self.environment:
            self.report["environment"]["CARGO_HOME"] = self.environment["CARGO_HOME"]
        self.save()

    def save(self):
        (self.output / "report.json").write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")

    def capture(self, path):
        path = Path(path).absolute()
        if path.is_symlink() or not path.is_file():
            raise ValueError("Regular source required: " + str(path))
        value = identity(path)
        if str(path) in self.sources:
            if self.sources[str(path)] != value:
                raise ValueError("Source changed: " + str(path))
            return
        target = self.output / "source-snapshots" / value["sha256"] / path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        if identity(target) != value or identity(path) != value:
            raise ValueError("Source changed during capture: " + str(path))
        self.sources[str(path)] = value

    def fence(self):
        actual = {p: identity(p) for p in self.sources}
        if actual != self.sources:
            raise ValueError("Qualification source changed")
        return actual

    def stage(self, name, argv, timeout=180):
        argv = [str(x) for x in argv]
        entry = {"name": name, "argv": argv, "cwd": str(ROOT), "timeout_seconds": timeout, "completed": False}
        self.report["stages"].append(entry)
        self.save()
        directory = self.output / "stages" / name
        directory.mkdir(parents=True)
        (directory / "stdin.raw").write_bytes(b"")
        started = time.monotonic_ns()
        try:
            result = subprocess.run(argv, cwd=ROOT, env=self.environment, input=b"", capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (directory / "stdout.raw").write_bytes(error.stdout or b"")
            (directory / "stderr.raw").write_bytes(error.stderr or b"")
            entry.update(error=repr(error), elapsed_ns=time.monotonic_ns() - started)
            self.save()
            raise
        except OSError as error:
            (directory / "stdout.raw").write_bytes(b"")
            (directory / "stderr.raw").write_bytes(b"")
            entry.update(error=repr(error), elapsed_ns=time.monotonic_ns() - started)
            self.save()
            raise
        (directory / "stdout.raw").write_bytes(result.stdout)
        (directory / "stderr.raw").write_bytes(result.stderr)
        entry.update(completed=True, exit_code=result.returncode, elapsed_ns=time.monotonic_ns() - started,
                     stdout=identity(directory / "stdout.raw"), stderr=identity(directory / "stderr.raw"))
        self.save()
        print(json.dumps({"stage": name, "exit_code": result.returncode, "seconds": entry["elapsed_ns"] / 1e9}), flush=True)
        result.check_returncode()
        self.fence()
        return result.stdout

    def original_build(self):
        b = self.rust_bin
        for name, args, prefix in (
            ("rustc", ["--version", "--verbose"], b"rustc 1.95.0 "),
            ("cargo", ["--version", "--verbose"], b"cargo 1.95.0 "),
            ("clippy-driver", ["--version"], b"clippy 0.1.95 "),
        ):
            value = self.stage("version-" + name, [b / name, *args], 60)
            if not value.startswith(prefix):
                raise ValueError("Exact Rust 1.95.0 required: " + name)
        self.stage("version-rustfmt", [b / "rustfmt", "--version"], 60)
        self.report["toolchain"] = {str(b / name): identity(b / name) for name in (
            "rustc", "cargo", "rustdoc", "clippy-driver", "cargo-clippy", "rustfmt", "cargo-fmt")}
        self.report["source_commit"] = self.stage("source-commit", ["git", "rev-parse", "HEAD"], 60).strip().decode()
        tree = self.stage("original-git-tree", ["git", "ls-tree", "-r", "-z", "HEAD", "--",
            "trillionnium/crates/trnm-task-kernel", "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
            "trillionnium/rust-toolchain.toml", "rust-toolchain.toml"], 60)
        objects = {}
        for item in tree.split(b"\0"):
            if not item:
                continue
            metadata, name = item.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            if kind != b"blob" or mode not in (b"100644", b"100755"):
                raise ValueError("Unexpected original source entry")
            path = ROOT / name.decode()
            raw = path.read_bytes()
            actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if actual != oid.decode():
                raise ValueError("Original source differs from Git: " + str(path))
            objects[name.decode()] = actual
            self.capture(path)
        if not objects:
            raise ValueError("Missing original Task source tree")
        self.report["original_git_objects"] = objects
        self.report["source_before"] = self.sources.copy()
        common = ["--manifest-path", ROOT / "trillionnium/Cargo.toml", "--locked", "--offline", "-p", "trnm-task-kernel",
                  "--target-dir", self.target]
        self.cargo_common = common
        raw = self.stage("original-retained-tests", [b / "cargo", "test", *common, "--message-format=json"], 600)
        summaries = re.findall(rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", raw)
        if not summaries or any(any(int(x) for x in row[1:]) for row in summaries) or sum(int(row[0]) for row in summaries) != 41:
            raise ValueError("Expected the complete unchanged 41-test original roster")
        self.report["original_test_summaries"] = [list(map(int, row)) for row in summaries]
        self.report["original_retained_tests"] = 41
        lock = tomllib.loads((ROOT / "trillionnium/Cargo.lock").read_text())
        owners = [p for p in lock["package"] if p["name"] == "trnm-task-kernel"]
        if len(owners) != 1:
            raise ValueError("Ambiguous original Task package in Cargo.lock")
        direct = {}
        for dependency in owners[0]["dependencies"]:
            fields = dependency.split()
            if fields[0] not in ("sha2", "borsh", "rusqlite", "ed25519-dalek"):
                continue
            candidates = [p for p in lock["package"] if p["name"] == fields[0] and
                          (len(fields) == 1 or p["version"] == fields[1])]
            if len(candidates) != 1:
                raise ValueError("Ambiguous locked original dependency: " + dependency)
            direct[fields[0].replace("-", "_")] = fields[0] + "@" + candidates[0]["version"]
        if set(direct) != {"sha2", "borsh", "rusqlite", "ed25519_dalek"}:
            raise ValueError("Original Task direct dependency roster differs")
        self.report["original_direct_package_ids"] = direct
        graph, retained, libraries, candidates = [], {}, {}, {}
        for line in raw.splitlines():
            if not line.startswith(b"{"):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("reason") != "compiler-artifact":
                continue
            graph.append(row)
            names = list(row.get("filenames", []))
            if row.get("executable"):
                names.append(row["executable"])
            for name in names:
                path = Path(name)
                if not path.is_file():
                    continue
                value = identity(path)
                destination = self.output / "retained-original-artifacts" / value["sha256"] / path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                if identity(destination) != value:
                    raise ValueError("Original artifact capture mismatch")
                retained[name] = {**value, "retained": str(destination.relative_to(self.output))}
                library = row["target"]["name"]
                if (path.suffix == ".rlib" and library in direct and
                        row["package_id"].rsplit("#", 1)[-1] == direct[library]):
                    candidates.setdefault(library, set()).add(str(destination))
        (self.output / "cargo-actual-graph.json").write_text(json.dumps(graph, indent=2) + "\n")
        self.report["cargo_graph"] = identity(self.output / "cargo-actual-graph.json")
        self.report["original_artifacts"] = retained
        self.save()
        if set(candidates) != set(direct) or any(len(paths) != 1 for paths in candidates.values()):
            raise ValueError("Actual original direct dependency graph is incomplete or ambiguous")
        libraries = {name: next(iter(paths)) for name, paths in candidates.items()}
        self.report["original_libraries"] = {p: identity(p) for p in libraries.values()}
        self.libraries = libraries
        self.save()

    def adapter(self, kind, public=False):
        directory = self.output / ("original-" + kind)
        directory.mkdir()
        prefix = "store_public" if public else kind.replace("-", "_")
        adapter = (Q / (prefix + "_original.rs")).read_text()
        sources = {name: ORIGINAL / filename for name, filename in (
            ("ERROR", "error.rs"), ("CODEC", "codec.rs"), ("TYPES", "types.rs"), ("STORE", "store.rs"))}
        row = {"status": "FAIL", "source_prefix": identity(sources["STORE"]), "original_source_changed": False}
        if not public:
            hook = Q / (prefix + "_hook.rs")
            combined = directory / "original-store.rs"
            combined.write_bytes(sources["STORE"].read_bytes() + b"\n" + hook.read_bytes())
            row.update(hook=identity(hook), combined=identity(combined))
            sources["STORE"] = combined
        else:
            adapter = adapter.replace("PUBLIC_OBSERVATION_PATH", str(Q / "store_public_hook.rs"))
        for name, path in sources.items():
            if any(ch in str(path) for ch in ('"', "\\", "\r", "\n")):
                raise ValueError("Original module path cannot be quoted")
            adapter = adapter.replace("ORIGINAL_" + name + "_PATH", str(path))
        source = directory / (prefix.replace("_", "-") + "-original.rs")
        source.write_text(adapter)
        executable = directory / (prefix.replace("_", "-") + "-original")
        argv = [self.rust_bin / "rustc", "--edition=2021", "-C", "opt-level=2", source]
        for name, path in sorted(self.libraries.items()):
            argv += ["--extern", name + "=" + path]
        argv += ["-L", "dependency=" + str(self.target / "debug/deps"), "-o", executable]
        row.update(source=identity(source), argv=list(map(str, argv)))
        receipt = directory / "receipt.json"
        receipt.write_text(json.dumps(row, indent=2) + "\n")
        self.stage("compile-original-" + kind, argv, 120)
        row.update(status="PASS", executable=identity(executable))
        receipt.write_text(json.dumps(row, indent=2) + "\n")
        return executable

    def run(self):
        try:
            if not __debug__:
                raise ValueError("Optimized qualification refused")
            self.stage("preflight", ["bash", "scripts/project-preflight.sh", "--audit"], 60)
            for subtree in (HERE, ROOT / "hia/src/task_kernel"):
                for path in sorted(subtree.rglob("*")):
                    if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                        self.capture(path)
            self.original_build()
            cache = self.output / "signature-cache"
            self.stage("signature-cache-regression", [sys.executable, Q / "store_signature_cache_observer.py",
                       "--output", cache], 180)
            cache_result = json.loads((cache / "report.json").read_text())
            if (cache_result["status"] != "PASS" or not cache_result["finalized"] or
                    cache_result["schema"] != "trnm.hia.task-store.signature-cache-qualification.v2" or
                    cache_result["cases"] != 124 or cache_result["native_calls"] != 257 or
                    len(cache_result["payload_interleaving"]) != 9 or
                    cache_result["source_before"] != cache_result["source_after"]):
                raise ValueError("Private signature cache differential did not pass")
            policy = self.adapter("kernel-policy")
            auditor = self.adapter("store-audit")
            records = self.adapter("store-records")
            public = self.adapter("store-public", public=True)
            private_build = self.output / "records-native"
            self.stage("records-native-build", [sys.executable, HERE / "build_store_records.py", "--provider", self.provider,
                       "--output", private_build], 180)
            private = self.output / "records-qualification"
            self.stage("records-native-original", [sys.executable, Q / "store_records_observer.py", private_build,
                       records, auditor, policy, private], 180)
            result = json.loads((private / "report.json").read_text())
            if result["status"] != "PASS" or not result["finalized"] or result["native_calls"] != 1390 or result["original_calls"] != 1390:
                raise ValueError("Complete private transaction differential did not pass")
            public_build = self.output / "public-native"
            self.stage("public-native-build", [sys.executable, HERE / "build_store_public.py", "--provider", self.provider,
                       "--output", public_build], 180)
            observed = self.output / "public-qualification"
            self.stage("public-native-original", [sys.executable, Q / "store_public_observer.py", public_build,
                       public, private, observed], 180)
            actual = json.loads((observed / "report.json").read_text())
            if (actual["status"] != "PASS" or not actual["finalized"] or
                    actual["native_method_calls"] != 445 or actual["original_method_calls"] != 445 or
                    actual["native_getter_calls"] != 1877 or actual["native_method_drop_compare_calls"] != 413 or
                    actual["native_total_abi_calls"] != 2290 or actual["public_exports"] != 51 or
                    actual["live_values_after"] != 0 or actual["provider_operations_unchanged"] != 29):
                raise ValueError("Public owner differential did not pass")
            allocations = self.output / "public-allocations"
            self.stage("public-allocation-lifecycle", [sys.executable, HERE / "qualify_store_owned_allocations.py",
                       "--build", public_build, "--records", private, "--output", allocations], 240)
            lifecycle = json.loads((allocations / "qualification/report.json").read_text())
            counts = lifecycle.get("final_allocator", {})
            if (lifecycle["status"] != "PASS" or not lifecycle["finalized"] or lifecycle["controls_count"] != 112 or
                    counts.get("failures") != 96 or any(counts.get(k) != 0 for k in ("live", "bytes", "bad_frees")) or
                    lifecycle["provider_operations_unchanged"] != 29):
                raise ValueError("Actual allocation lifecycle did not pass")
            self.stage("original-clippy", [self.rust_bin / "cargo", "clippy", *self.cargo_common,
                       "--all-targets", "--all-features", "--", "-D", "warnings"], 600)
            self.stage("original-format", [self.rust_bin / "cargo", "fmt", "--manifest-path", ROOT / "trillionnium/Cargo.toml",
                       "-p", "trnm-task-kernel", "--", "--check"], 120)
            self.report["qualifications"] = {str(p.relative_to(self.output)): identity(p) for p in (
                cache / "report.json",
                private_build / "build.json", private / "report.json", public_build / "build.json", observed / "report.json",
                allocations / "build.json", allocations / "run.json", allocations / "qualification/report.json")}
            self.report["source_after"] = self.fence()
            self.report.update(status="PASS", finalized=True, main_task_store_qualified=True)
            self.save()
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error))
            self.save()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider", type=Path, required=True, help="Exact independently built provider directory")
    parser.add_argument("--rust-bin", type=Path, required=True, help="Pinned Rust 1.95.0 toolchain bin directory")
    args = parser.parse_args()
    result = Qualification(args.output, args.provider, args.rust_bin).run()
    print(json.dumps({"status": result["status"], "original_tests": result["original_retained_tests"],
                      "report": str(args.output / "report.json"), "full_task_kernel_owner_qualified": False}))


if __name__ == "__main__":
    main()

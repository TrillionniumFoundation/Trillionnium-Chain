"""Source-bound native build for Bench primitives; no hosted runtime algorithms."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build as PinnedBuild, INPUTS as PINNED_INPUTS
from hia.platform.task_kernel.build_boundary import FUNCTION, SourceBuild
from hia.platform.task_kernel.build_provider import identity, need

COMPONENTS = {
    "workload": ("hia/src/bench/workload.hepta", ()),
    "digests": ("hia/src/bench/digests.hepta", (
        "hia/src/bench/workload.hepta", "hia/src/executor/schedule.hepta",
        "hia/src/crypto/sha256_stream.hepta")),
    "schedule": ("hia/src/executor/schedule.hepta", ("hia/src/math/binary64.hepta",)),
    "repeat": ("hia/src/bench/repeat.hepta", (
        "hia/src/bench/workload.hepta", "hia/src/bench/digests.hepta",
        "hia/src/executor/schedule.hepta", "hia/src/math/binary64.hepta",
        "hia/src/crypto/sha256_stream.hepta")),
}


class BenchBuild(SourceBuild):
    def run(self):
        self.report.update(schema="trnm.hia.bench-primitives.build.v1",
                           scope="workloads, canonical digests and existing seven-strategy scheduler",
                           whole_bench_native_qualified=False)
        self.write()
        try:
            need(__debug__, "Optimized Python builder refused")
            fence_paths = [ROOT / name for name in (
                "scripts/project-preflight.sh", "scripts/ci/project_boundary.py",
                "PROJECT_BOUNDARY.json", "PROJECT_ID", "config/portability-inventory-v1.json",
                "trillionnium/Cargo.toml")]
            members = tomllib.loads((ROOT / "trillionnium/Cargo.toml").read_text())["workspace"]["members"]
            fence_paths.extend(ROOT / "trillionnium" / m / "Cargo.toml" for m in members)
            for path in fence_paths:
                self.capture(path)
            self.stage("preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
            self.pinned = PinnedBuild(self.output / "pinned-native")
            sys.path.insert(0, str(self.pinned.toolchain))
            from hia.tools import toolchain
            from hepta.hia_agent_assembly import render_assembly
            from hepta.object_symbols import inspect_object_symbols
            from hepta.elf_shared_abi import inspect_owned_shared_elf
            need(toolchain.HIA_ROOT == ROOT / "hia", "Canonical Bench source root required")
            for relative in PINNED_INPUTS:
                self.capture(ROOT / "hia" / relative)
            for relative in ("hia/platform/bench/build.py", "hia/src/bench/README.md",
                             "hia/tests/test_bench_native.py",
                             "hia/tests/rust_bench_reference.rs", "hia/tests/native_support.py",
                             "hia/tests/test_executor_schedule.py", "hia/tools/toolchain.py",
                             "hia/platform/task_kernel/build_boundary.py",
                             "hia/platform/task_kernel/build_provider.py", "trillionnium/Cargo.lock"):
                self.capture(ROOT / relative)
            for package in ("trnm-bench", "trnm-executor", "trnm-types"):
                for path in sorted((ROOT / "trillionnium/crates" / package).rglob("*")):
                    if path.is_file():
                        self.capture(path)
            self.capture(self.pinned.compiler_path)
            closures, receipts = {}, {}
            self.report["native_builds"] = []
            for name, (source, _) in COMPONENTS.items():
                source = ROOT / source
                checked, raw, _, _, inputs = toolchain.checked_source(source)
                owners = {}
                for path, captured in inputs:
                    self.capture(path)
                    need(path.read_bytes() == captured, "Canonical Bench input changed")
                    if path.suffix == ".hepta":
                        for match in FUNCTION.finditer(captured):
                            if path != source and match[1] == b"f0":
                                continue
                            owners[match[1]] = (path, match[0])
                closure = {}
                for match in FUNCTION.finditer(raw):
                    path, body = owners[match[1]]
                    need(match[0] == body, "Canonical composition altered a Bench function")
                    closure[match[1].decode()] = {
                        "source": str(path), "sha256": hashlib.sha256(body).hexdigest()}
                document = checked.as_dict()
                document["module"] = "selfhost_elf"
                wire = render_assembly(document).encode()
                (self.output / (name + ".hepta")).write_bytes(wire)
                receipts[name] = {}
                for kind, suffix in (("object", ".o"), ("shared", ".so")):
                    output = self.output / (name + suffix)
                    row = {"component": name, "kind": kind, "started": True,
                           "completed": False, "output": str(output)}
                    self.report["native_builds"].append(row)
                    self.write()
                    receipt, actual_document = toolchain.build_native(
                        source, output, byte_exports=("f0",), kind=kind,
                        backend="selfhost", compiler=self.pinned.compiler_path,
                        compiler_sha256=hashlib.sha256(self.pinned.compiler).hexdigest())
                    row.update(completed=True, receipt=receipt)
                    self.write()
                    need(actual_document == checked.as_dict(), "Canonical Bench Core changed")
                    need(receipt["compiler_wire_sha256"] == hashlib.sha256(wire).hexdigest()
                         and receipt["chain_migration"]["composed_source_sha256"]
                         == hashlib.sha256(raw).hexdigest(), "Actual Bench compiler input differs")
                    receipts[name][kind] = receipt
                obj, shared = self.output / (name + ".o"), self.output / (name + ".so")
                native = obj.read_bytes()
                inventory = inspect_object_symbols(native, "ELF64", 62)
                need(inventory["defined"] == frozenset({"f0"})
                     and inventory["undefined"] <= {"calloc", "free"},
                     "Unexpected Bench native object ABI")
                need(receipts[name]["shared"]["object_sha256"] == hashlib.sha256(native).hexdigest(),
                     "Object and shared Bench builds used different compiler output")
                inspect_owned_shared_elf(shared.read_bytes(), ("f0",))
                closures[name] = closure
            (self.output / "native-compiler").write_bytes(self.pinned.compiler)
            self.fence()
            self.report.update(status="PASS", finalized=True, source_before=self.sources,
                source_after={p: identity(p) for p in self.sources}, function_sources=closures,
                canonical_receipts=receipts,
                compiler_sha256=hashlib.sha256(self.pinned.compiler).hexdigest(),
                artifacts={p.name: identity(p) for p in self.output.iterdir()
                           if p.is_file() and p.suffix in {".hepta", ".o", ".so"}})
            self.write()
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error),
                               source_before=self.sources)
            if hasattr(self, "pinned"):
                self.report["native_stages"] = self.pinned.stages
            self.write()
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = BenchBuild(args.output).run()
    print(json.dumps({"status": report["status"], "whole_bench_native_qualified": False,
                      "report": str(args.output / "build.json")}))

"""Build the finite SQLite/descriptor boundary using the pinned native HIA compiler.

This is a boundary qualification image, not the complete TaskKernel store. The
production-facing image dynamically shares one exact provider.so. Fault injection
uses a separate, explicitly qualified executable/library in another process.
"""
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

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build as PinnedBuild, INPUTS as PINNED_INPUTS
from hia.platform.task_kernel.build_provider import identity, need, write_json

HERE = Path(__file__).resolve().parent
QUALIFICATION = HERE / "qualification"
DEPENDENCIES = (
    "hia/src/task_kernel/store_files.hepta",
    "hia/src/task_kernel/store_path.hepta",
    "hia/src/task_kernel/store_common.hepta",
    "hia/src/task_kernel/codec.hepta",
    "hia/src/control_plane/core.hepta",
    "hia/src/crypto/sha256_stream.hepta",
    "hia/src/codec/json_primitives.hepta",
)
FUNCTION = re.compile(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)")
CALLEE = re.compile(rb'\{"function":"([A-Za-z_][A-Za-z_0-9]*)"\}')


class SourceBuild:
    def __init__(self, output: Path):
        self.output = output.absolute()
        need(self.output.resolve() == self.output and not self.output.exists(),
             "Fresh canonical output required")
        need(ROOT not in self.output.parents, "Evidence must be outside the checkout")
        self.output.mkdir(parents=True, mode=0o700)
        self.report = {"schema": "trnm.hia.task-kernel.boundary-build.v1",
                       "status": "FAIL", "finalized": False, "stages": [],
                       "scope": "SQLite, descriptor and HIA driver boundary; not full TaskKernel"}
        self.sources = {}
        self.write()

    def write(self):
        write_json(self.output / "build.json", self.report)

    def capture(self, path: Path):
        path = path.absolute()
        value = identity(path)
        if str(path) in self.sources:
            need(value == self.sources[str(path)], "Source changed before recapture")
            return
        self.sources[str(path)] = value
        if path.is_relative_to(ROOT):
            relative = path.relative_to(ROOT)
        else:
            relative = Path("external") / hashlib.sha256(str(path).encode()).hexdigest() / path.name
        target = self.output / "source-snapshots" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        need(identity(target) == value, "Source changed during capture")

    def fence(self):
        need({p: identity(p) for p in self.sources} == self.sources,
             "Boundary source or provider object changed")
        self.pinned.check_pin()

    def verify_provider(self, directory):
        """Bind every actual native provider/witness compiler stream and link."""
        from hia.platform.task_kernel.readback_provider import check_provider
        self.capture(HERE / "readback_provider.py")
        def read(path, expected=None):
            path = Path(path).absolute()
            self.capture(path)
            need(expected is None or identity(path) == {key: expected[key] for key in ("bytes", "sha256")},
                 "Provider readback content differs")
            raw = path.read_bytes()
            need(identity(path) == self.sources[str(path)], "Provider readback input changed")
            return raw
        self.report["provider_native_readback"] = check_provider(read, directory, ROOT)

    def stage(self, name, argv, timeout=60):
        row = {"name": name, "argv": list(map(str, argv)), "cwd": str(ROOT),
               "started": True, "completed": False, "timeout_seconds": timeout}
        self.report["stages"].append(row)
        self.write()
        (self.output / (name + ".stdin.raw")).write_bytes(b"")
        start = time.monotonic_ns()
        try:
            p = subprocess.run(row["argv"], input=b"", capture_output=True,
                               cwd=ROOT, timeout=timeout)
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
        p.check_returncode()
        return p.stdout

    def compose(self, source: Path, dependencies):
        functions, owners = {}, {}
        for index, path in enumerate([source, *dependencies]):
            self.capture(path)
            raw = path.read_bytes()
            matches = list(FUNCTION.finditer(raw))
            need(len(matches) == len(re.findall(rb"(?m)^fn ", raw)),
                 "Ambiguous HIA function boundaries")
            for match in matches:
                name = match[1].decode()
                if index and name == "f0":
                    continue
                need(name not in functions, "Duplicate HIA function: " + name)
                functions[name], owners[name] = match[0], str(path)
        pending, selected = ["f0"], set()
        while pending:
            name = pending.pop()
            if name in selected:
                continue
            need(name in functions, "Missing canonical callee: " + name)
            selected.add(name)
            pending.extend(x.decode() for x in CALLEE.findall(functions[name]))
        raw = b"hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n" + b"".join(
            body.rstrip() + b"\n" for name, body in functions.items() if name in selected)
        core = self.assemble(raw).as_dict()
        need(set(selected) == {f["name"] for f in core["functions"]}, "Closure changed on assembly")
        return raw, {name: {"source": owners[name],
                           "sha256": hashlib.sha256(functions[name]).hexdigest()}
                     for name in sorted(selected)}

class BoundaryBuild(SourceBuild):
    def __init__(self, output: Path, provider: Path):
        super().__init__(output)
        self.provider = provider.resolve(strict=True)

    def run(self):
        try:
            need(__debug__, "Optimized observer refused")
            self.stage("preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
            self.pinned = PinnedBuild(self.output / "pinned-native")
            sys.path.insert(0, str(self.pinned.toolchain))
            from hepta.hia_agent_assembly import assemble_program
            self.assemble = assemble_program
            for relative in PINNED_INPUTS:
                self.capture(ROOT / "hia" / relative)
            for p in [Path(__file__), HERE / "provider_abi.json", HERE / "build_provider.py",
                      HERE / "provider_native.hepta", HERE / "build_witness.py", HERE / "witness_emitter.hepta",
                      HERE / "readback_provider.py", ROOT / "hia/tools/toolchain.py",
                      ROOT / "scripts/project-preflight.sh", ROOT / "scripts/ci/project_boundary.py"]:
                self.capture(p)
            for p in sorted(QUALIFICATION.iterdir()):
                if p.is_file():
                    self.capture(p)
            build_path = self.provider / "build.json"
            self.capture(build_path)
            build = json.loads(build_path.read_text())
            need(build["status"] == "PASS" and build["finalized"] and
                 build["source_before"] == build["source_after"], "Provider build not qualified")
            need(build["fence"] == json.loads((HERE / "provider_abi.json").read_text())["build_fence"],
                 "Provider ABI fence differs")
            for path, expected in build["source_before"].items():
                self.capture(Path(path))
                need(identity(path) == expected, "Provider source changed")
            for name, expected in build["artifacts"].items():
                self.capture(self.provider / name)
                need(identity(self.provider / name) == expected, "Provider artifact changed")
            self.verify_provider(self.provider)
            self.capture(Path(build["compiler"]["path"]))
            self.capture(self.pinned.compiler_path)
            (self.output / "native-compiler").write_bytes(self.pinned.compiler)
            self.report["provider_build"] = str(build_path)
            self.report["compiler"] = identity(self.pinned.compiler_path)
            self.report["function_sources"] = {}
            dependencies = [ROOT / p for p in DEPENDENCIES]
            images = {
                "fd": (QUALIFICATION / "fd_fixture.hepta", []),
                "path": (QUALIFICATION / "path_fixture.hepta", dependencies),
                "filesystem": (QUALIFICATION / "filesystem_fixture.hepta", dependencies),
                "query": (ROOT / "hia/src/task_kernel/store_query.hepta", dependencies),
                "files": (dependencies[0], dependencies[1:]),
                "driver-emitter": (HERE / "native_driver.hepta", []),
                "dispatch-emitter": (HERE / "native_dispatch.hepta", []),
            }
            for name, (source, deps) in images.items():
                raw, closure = self.compose(source, deps)
                (self.output / (name + ".hepta")).write_bytes(raw)
                self.report["function_sources"][name] = closure
                result = self.pinned.stage(self.pinned.compiler, raw, "compile-" + name)
                need(result.startswith(b"\x7fELF\x02\x01"), "Compiler did not emit ELF64LE")
                (self.output / (name + ".o")).write_bytes(result)
                if name.endswith("-emitter") or name == "path":
                    self.stage("link-" + name, ["ld", "-shared", "-z", "defs", "-z", "noexecstack",
                               "--build-id=none", self.output / (name + ".o"), "-lc",
                               "-o", self.output / (name + ".so")])
                else:
                    index = {"fd": 0, "filesystem": 0, "query": 1, "files": 2}[name]
                    self.stage("rename-" + name, ["objcopy", "--redefine-sym",
                               "f0=trnm_task_step_" + str(index), self.output / (name + ".o"),
                               self.output / (name + "-named.o")])
                self.fence()
            for name, tag in [("driver", "TKDRV001"), ("dispatch", "TKDSP001")]:
                self.stage("emit-" + name, [sys.executable, QUALIFICATION / "emit_observer.py",
                                           self.output, name, tag])
                self.stage("inspect-" + name, ["objdump", "-dr", self.output / (name + ".o")])
            cc = build["compiler"]["path"]
            shutil.copyfile(self.provider / "provider.so", self.output / "provider.so")
            common = [cc, "-shared", "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections",
                      self.output / "driver.o", self.output / "dispatch.o", self.output / "query-named.o",
                      self.output / "files-named.o"]
            for kind in ("fd", "filesystem"):
                self.stage("link-" + kind, [*common, self.output / (kind + "-named.o"),
                           "-L" + str(self.output), "-Wl,-rpath,$ORIGIN", "-l:provider.so",
                           "-lm", "-ldl", "-lpthread", "-o", self.output / (kind + "-native.so")])
            self.fence()
            self.report["source_before"] = self.sources
            self.report["source_after"] = {p: identity(p) for p in self.sources}
            self.report["native_stages"] = self.pinned.stages
            self.report["artifacts"] = {p.name: identity(p) for p in sorted(self.output.iterdir())
                                        if p.is_file() and p.suffix in {".so", ".o", ".hepta"}}
            self.report.update(status="PASS", finalized=True,
                               full_task_kernel_owner_qualified=False,
                               provider_runtime="shared external SQLite image; HIA controls calls")
            self.write()
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error), source_before=self.sources)
            if hasattr(self, "pinned"):
                self.report["native_stages"] = self.pinned.stages
            self.write()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = BoundaryBuild(args.output, args.provider).run()
    print(json.dumps({"status": result["status"], "images": len(result["function_sources"]),
                      "report": str(args.output / "build.json")}))


if __name__ == "__main__":
    main()

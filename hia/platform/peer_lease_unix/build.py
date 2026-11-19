"""Build native Linux peer-lease executables from the admitted HIA source graph."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time
import traceback

from hia.platform.build import Build as PinnedBuild, INPUTS, inspect_executable
from hia.tools.toolchain import checked_source, compose_source, pinned_toolchain, _source_path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
DAEMON = ("daemon_setup", "store_bridge", "service", "cleanup", "errors", "errno")
CLIENT = ("client", "store_bridge", "client_io", "client_finish")
OWNER = ("client_owner", "store_bridge", "client_io", "client_finish", "client")
IMAGES = tuple(dict.fromkeys((*DAEMON, *CLIENT, *OWNER, "linux_emitter")))
EXECUTABLES = {
    "peer-unix-daemon": (DAEMON, 1),
    "peer-unix-api": (DAEMON, 2),
    "peer-unix-client": (CLIENT, 2),
    "peer-unix-client-owner": (OWNER, 2),
}
ORIGINAL_ROOTS = ("trillionnium", "tests/fixtures", "tests/fuzz", "tests/vectors")


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def capture(path):
    need(path.is_file() and not path.is_symlink(), "Missing or nonregular source: " + str(path))
    for parent in path.parents:
        if parent == ROOT.parent:
            break
        need(not parent.is_symlink(), "Symlinked source ancestor: " + str(parent))
    return path.read_bytes()


def cargo_configuration(environment):
    cargo = Path(environment.get("CARGO_HOME", Path.home() / ".cargo")).absolute()
    directory = ROOT / "trillionnium"
    locations = [cargo, *(path / ".cargo" for path in (directory, *directory.parents))]
    checked = []
    for location in locations:
        for filename in ("config", "config.toml"):
            path = location / filename
            need(not path.exists() and not path.is_symlink(), "Unbound Cargo configuration: " + str(path))
            checked.append(str(path))
    return checked


def source_capture():
    pinned_toolchain()
    cargo_configuration(os.environ)
    values = {}

    def add(path):
        raw = capture(path)
        relative = path.relative_to(ROOT).as_posix()
        need(relative not in values or values[relative] == raw, "Source changed during capture")
        values[relative] = raw
        return raw

    for path in sorted(HERE.iterdir()):
        if path.suffix in {".py", ".rs", ".json", ".md", ".hepta"}:
            add(path)
    for name in INPUTS:
        add(ROOT / "hia" / name)
    for name in ("hia/tools/toolchain.py", "hia/components.json", "hia/toolchain.lock.json",
                 "AGENTS.md", "PROJECT_ID", "PROJECT_BOUNDARY.json", "rust-toolchain.toml",
                 "scripts/project-preflight.sh", "scripts/ci/project_boundary.py",
                 "scripts/w1_owned_process_collector_v1.py",
                 "config/portability-inventory-v1.json", "config/pon/work-profile-v1.json",
                 "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"):
        add(ROOT / name)
    # compose_source independently checks every declared component key's path,
    # including keys outside this executable. Bind and materialize those real
    # HIA sources as well; a sparse qualification must not invent placeholders.
    component_manifest = json.loads(values["hia/components.json"])
    for name in sorted(component_manifest["includes"]):
        add(_source_path(name))
    for name in (*IMAGES, "codec"):
        _, dependencies = compose_source(HERE / (name + ".hepta"))
        for path, raw in dependencies:
            need(add(path) == raw, "Composed source changed")
    entries = subprocess.check_output(
        ["git", "ls-tree", "-rz", "HEAD", "--", *ORIGINAL_ROOTS], cwd=ROOT
    ).split(b"\0")
    for entry in entries:
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        need(kind == b"blob" and mode in {b"100644", b"100755"}, "Unsupported original source object")
        raw = add(ROOT / os.fsdecode(name))
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        need(actual == object_id.decode(), "Original tracked source changed: " + os.fsdecode(name))
    return values


class Build:
    def __init__(self, output):
        need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Optimized Python is not admitted")
        self.output = Path(output).absolute()
        need(not self.output.exists() and not self.output.is_symlink(), "Fresh build output required")
        need(ROOT / "hia" not in self.output.resolve().parents, "Output must be outside HIA sources")
        self.output.mkdir(parents=True, mode=0o700)
        self.pinned = PinnedBuild(self.output / "pinned-native")
        self.inputs = source_capture()
        self.manifest = {name: identity(raw) for name, raw in sorted(self.inputs.items())}
        for name, raw in self.inputs.items():
            path = self.output / "source-snapshot" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.report = {"schema": "trnm.hia.peer-unix-build.v1", "status": "RUNNING",
                       "source_inputs": self.manifest, "images": {}, "cores": {},
                       "executables": {}, "started_ns": time.monotonic_ns(),
                       "runtime_host_proxy": False, "rust_or_interpreter_fallback": False,
                       "whole_peer_package_retired": False, "production_activation": False}

    def check(self):
        self.pinned.check_pin()
        need(source_capture() == self.inputs, "Complete peer Unix source graph changed")

    def build(self):
        try:
            self.check()
            from hepta.hia_agent_assembly import render_assembly
            images = {}
            for name in IMAGES:
                core, composed, *rest = checked_source(HERE / (name + ".hepta"))
                document = core.as_dict()
                limits = {"functions": len(document["functions"]),
                          "blocks": sum(len(f["blocks"]) for f in document["functions"]),
                          "ops": sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
                          "max_blocks": max(len(f["blocks"]) for f in document["functions"])}
                need(limits["functions"] <= 128 and limits["blocks"] <= 1536
                     and limits["ops"] <= 8192 and limits["max_blocks"] <= 256,
                     "Unchanged native compiler limits exceeded")
                for path, raw in rest[-1]:
                    need(self.inputs[path.relative_to(ROOT).as_posix()] == raw, "Unbound compiler input")
                assembly = render_assembly(document).encode()
                (self.output / (name + ".composed.hepta")).write_bytes(composed)
                (self.output / (name + ".compiler-input.hepta")).write_bytes(assembly)
                native = self.pinned.stage(self.pinned.compiler, assembly, "compile-" + name)
                need(name == "linux_emitter" or 0 < len(native) <= 524288, "Native image extent")
                (self.output / (name + ".native")).write_bytes(native)
                images[name] = native
                self.report["images"][name] = identity(native)
                self.report["cores"][name] = limits
            inspect_executable(images["linux_emitter"])
            for name, (order, profile) in EXECUTABLES.items():
                payload = (b"HCSHD001" + struct.pack("<QQ", len(order), profile)
                           + b"".join(struct.pack("<Q", len(images[item])) for item in order))
                prefix = self.pinned.stage(images["linux_emitter"], payload, "emit-" + name)
                need(len(prefix) == 5120, "Native platform prefix changed extent")
                executable = prefix + b"".join(images[item] for item in order)
                elf = inspect_executable(executable)
                path = self.output / name
                path.write_bytes(executable)
                path.chmod(0o500)
                (self.output / (name + ".prefix")).write_bytes(prefix)
                self.report["executables"][name] = {**identity(executable), "elf": elf,
                                                     "images": list(order), "profile": profile,
                                                     "prefix": identity(prefix)}
            # The private borrowed codec is also compiled by the pinned native
            # compiler. Its external linker joins that object; no hosted emitter
            # or Rust business implementation participates in the native path.
            from hepta.object_symbols import inspect_object_symbols
            from hepta.elf_shared_abi import inspect_owned_shared_elf
            from .process import Processes
            codec = self.output / "peer-unix-codec.so"
            checked, composed, *rest = checked_source(HERE / "codec.hepta")
            core = checked.as_dict()
            first = core["functions"][0]
            need(first["name"] == "f0" and [p["type"] for p in first["params"]]
                 == ["readbuf", "mutbuf", "mutbuf"] and first["returns"] == ["u32"]
                 and "exports" not in core, "Exact private borrowed codec profile required")
            core["module"] = "selfhost_elf"
            assembly = render_assembly(core).encode()
            (self.output / "codec.composed.hepta").write_bytes(composed)
            (self.output / "codec.compiler-input.hepta").write_bytes(assembly)
            object_bytes = self.pinned.stage(self.pinned.compiler, assembly, "compile-codec")
            symbols = inspect_object_symbols(object_bytes, "ELF64", 62)
            need(symbols["defined"] == frozenset({"f0"}) and symbols["undefined"] <= {"calloc", "free"},
                 "Codec native object import/export inventory differs")
            obj = self.output / "codec.o"
            obj.write_bytes(object_bytes)
            linker = Path(shutil.which("ld")).resolve(strict=True)
            linked = Processes(self.output / "hosted-linker", ROOT,
                               {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, self.check)
            linked.run("link-codec", [linker, "-m", "elf_x86_64", "-shared", "-z", "defs",
                "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none",
                "--hash-style=both", obj, "-lc", "-o", codec], timeout=30)
            inspect_owned_shared_elf(codec.read_bytes(), ("f0",))
            self.report["codec"] = {**identity(codec.read_bytes()), "object": identity(object_bytes),
                "compiler_wire": identity(assembly), "compiler": identity(self.pinned.compiler),
                "linker": {"path": str(linker), **identity(linker.read_bytes())},
                "link_stages": linked.rows, "exports": ["f0"], "backend": "selfhost",
                "python_emitter_used": False, "fallback_used": False}
            self.report["cores"]["codec"] = {"functions": len(core["functions"]),
                "blocks": sum(len(f["blocks"]) for f in core["functions"]),
                "ops": sum(len(b["ops"]) for f in core["functions"] for b in f["blocks"]),
                "max_blocks": max(len(f["blocks"]) for f in core["functions"])}
            self.check()
            self.report.update(status="PASS", source_inputs_stable=True,
                               compiler=identity(self.pinned.compiler), toolchain=self.pinned.lock,
                               compiler_qualification_binding=self.pinned.binding)
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", failure=repr(error), traceback=traceback.format_exc())
            raise
        finally:
            self.report.update(finished_ns=time.monotonic_ns(), stages=self.pinned.stages)
            (self.output / "build.json").write_text(json.dumps(self.report, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = Build(args.output).build()
    print(json.dumps({key: report[key] for key in ("status", "cores", "executables")}, sort_keys=True))


if __name__ == "__main__":
    main()

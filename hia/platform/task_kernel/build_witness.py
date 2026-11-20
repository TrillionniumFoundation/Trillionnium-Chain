"""Emit the four SQLite metadata witness ABIs with the pinned native HIA compiler.

The original C translation unit is a build-time probe only. Its actual current
layout, compile options (including the real COMPILER= value), version and source
ID form the emitter input. The resulting witness.o has no relocations or
undefined symbols and is the only witness object intended for the final link.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build, INPUTS as PINNED_INPUTS
from hia.platform.task_kernel.build_provider import (
    AMALGAMATION, DEPENDENCY_MANIFEST, FLAGS, HEADER, LAYOUT, OPTIONS,
    SOURCE_ID, TARGET, UPSTREAM_BUILD, environment_fence, identity, need, write_json,
)
from hia.tools.toolchain import pinned_toolchain

MAGIC = b"TWIT0001"
EXPORTS = ("trnm_io_witness_layout", "trnm_io_witness_compileoption",
           "trnm_io_witness_version", "trnm_io_witness_source_id")


def observation(library):
    library.trnm_io_witness_layout.argtypes = [ctypes.c_int]
    library.trnm_io_witness_layout.restype = ctypes.c_uint64
    library.trnm_io_witness_compileoption.argtypes = [ctypes.c_int]
    library.trnm_io_witness_compileoption.restype = ctypes.c_char_p
    library.trnm_io_witness_version.argtypes = []
    library.trnm_io_witness_version.restype = ctypes.c_int
    library.trnm_io_witness_source_id.argtypes = []
    library.trnm_io_witness_source_id.restype = ctypes.c_char_p
    options = []
    for index in range(257):
        value = library.trnm_io_witness_compileoption(index)
        if value is None:
            break
        need(index < 256, "Observed option count exceeds the bounded emitter format")
        options.append(value.decode("ascii"))
    else:
        raise ValueError("Unterminated observed option list")
    return {"layout": [library.trnm_io_witness_layout(index) for index in range(19)],
            "options": options, "version": library.trnm_io_witness_version(),
            "source_id": library.trnm_io_witness_source_id().decode("ascii")}


def frame(observed):
    options = b"".join(value.encode("ascii") + b"\0" for value in observed["options"])
    source = observed["source_id"].encode("ascii")
    return (MAGIC + struct.pack("<4Q", observed["version"], len(observed["options"]), len(source), len(options)) +
            struct.pack("<19Q", *observed["layout"]) + options + source + b"\0")


def emitter_function(library):
    function = library.f0
    function.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    function.restype = ctypes.c_uint32
    return function


def emit(function, request, capacity=131072):
    source = ctypes.create_string_buffer(request)
    result = ctypes.create_string_buffer(bytes([0xA5]) * capacity, capacity)
    scratch = ctypes.create_string_buffer(1)
    code = function(source, len(request), result, capacity, scratch, 0)
    need(source.raw[:-1] == request, "Native emitter modified its input")
    return code, result.raw


def inspect_object(raw):
    need(len(raw) >= 64 and raw[:16] == b"\x7fELF\x02\x01\x01" + bytes(9), "ELF64LE object required")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    need(header[1:4] == (1, 62, 1) and header[4:6] == (0, 0) and header[7:12] == (0, 64, 0, 0, 64) and
         header[12:] == (6, 4) and header[6] + 6 * 64 == len(raw), "Exact witness object profile required")
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, header[6] + index * 64) for index in range(6)]
    need(sections[0] == (0,) * 10, "Null ELF section differs")
    need(sections[1][1:3] == (1, 6) and sections[1][4] == 64 and sections[1][8] == 16,
         "Read-only executable witness image required")
    need(sections[2][1] == 2 and sections[2][5:] == (120, 3, 1, 8, 24), "Witness symbol table differs")
    need(sections[3][1] == sections[4][1] == 3 and sections[5][1:3] == (1, 0) and sections[5][5] == 0,
         "Unexpected ELF sections")
    for section in sections:
        need(section[4] <= len(raw) and section[5] <= len(raw) - section[4], "ELF section exceeds object")
        need(section[1] not in (4, 9), "Witness must not have relocation sections")
    names = raw[sections[3][4]:sections[3][4] + sections[3][5]]
    actual = []
    for index in range(5):
        value = struct.unpack_from("<IBBHQQ", raw, sections[2][4] + index * 24)
        if index == 0:
            need(value == (0,) * 6, "Null ELF symbol differs")
            continue
        name, info, other, section, offset, size = value
        need(info == 0x12 and other == 0 and section == 1 and offset + size <= sections[1][5],
             "Witness has an undefined or non-function symbol")
        need(name < len(names) and b"\0" in names[name:], "Unterminated ELF symbol")
        actual.append(names[name:names.index(b"\0", name)].decode("ascii"))
    need(tuple(actual) == EXPORTS, "Four witness ABI exports differ")
    return {"format": "ELF64LE", "machine": "x86_64", "type": "ET_REL", "exports": actual,
            "relocation_sections": 0, "undefined_symbols": 0, "payload_bytes": len(raw)}


class WitnessBuild:
    def __init__(self, dependency, output):
        self.dependency = Path(dependency).resolve(strict=True)
        self.output = Path(output).absolute()
        need(self.output.resolve() == self.output and not self.output.exists() and ROOT not in self.output.parents,
             "Fresh canonical evidence outside checkout required")
        self.output.mkdir(parents=True, mode=0o700)
        self.report = {"schema": "trnm.hia.task-kernel.native-witness-build.v1", "status": "FAIL",
                       "finalized": False, "stages": [], "probe_linked_into_final_object": False,
                       "hosted_build_observer": True, "native_witness_runtime_c_dependencies": False}
        self.save()

    def save(self):
        write_json(self.output / "build.json", self.report)

    def stage(self, name, argv, timeout=120):
        argv = list(map(str, argv))
        row = {"name": name, "argv": argv, "cwd": str(ROOT), "timeout_seconds": timeout, "completed": False}
        self.report["stages"].append(row)
        self.save()
        (self.output / (name + ".stdin.raw")).write_bytes(b"")
        started = time.monotonic_ns()
        try:
            process = subprocess.run(argv, input=b"", capture_output=True, cwd=ROOT, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (self.output / (name + ".stdout.raw")).write_bytes(error.stdout or b"")
            (self.output / (name + ".stderr.raw")).write_bytes(error.stderr or b"")
            row.update(error=repr(error), elapsed_ns=time.monotonic_ns() - started)
            self.save()
            raise
        (self.output / (name + ".stdout.raw")).write_bytes(process.stdout)
        (self.output / (name + ".stderr.raw")).write_bytes(process.stderr)
        row.update(completed=True, exit_code=process.returncode, elapsed_ns=time.monotonic_ns() - started)
        self.save()
        process.check_returncode()
        return process.stdout

    def run(self):
        try:
            need(__debug__ and platform.system() == "Linux" and platform.machine() == "x86_64" and
                 sys.byteorder == "little" and struct.calcsize("P") == 8, "Pinned Linux x86-64 required")
            environment_fence(os.environ)
            preflight_paths = [ROOT / name for name in (
                "scripts/project-preflight.sh", "scripts/ci/project_boundary.py", "PROJECT_BOUNDARY.json",
                "PROJECT_ID", "config/portability-inventory-v1.json", "trillionnium/Cargo.toml")]
            members = tomllib.loads((ROOT / "trillionnium/Cargo.toml").read_text())["workspace"]["members"]
            preflight_paths += [ROOT / "trillionnium" / member / "Cargo.toml" for member in members]
            preflight_before = {str(path): identity(path) for path in preflight_paths}
            self.stage("preflight", ["bash", ROOT / "scripts/project-preflight.sh", "--audit"], 60)
            need({str(path): identity(path) for path in preflight_paths} == preflight_before,
                 "Project boundary inputs changed during preflight")
            need(self.dependency.name == "libsqlite3-sys-0.39.1", "Exact locked SQLite dependency required")
            include = self.dependency / "sqlite3"
            amalgamation = include / "sqlite3.c"
            probe = ROOT / "trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c"
            source = HERE / "witness_emitter.hepta"
            paths = [*preflight_paths, amalgamation, include / "sqlite3.h", self.dependency / "build.rs", self.dependency / "Cargo.toml",
                     probe, source, Path(__file__).resolve(), HERE / "build_provider.py", ROOT / "hia/tools/toolchain.py",
                     *[ROOT / "hia" / name for name in PINNED_INPUTS]]
            before = {str(path): identity(path) for path in paths}
            need(all(before[path] == expected for path, expected in preflight_before.items()),
                 "Project boundary source changed before build capture")
            for path, expected in ((amalgamation, (9582521, AMALGAMATION)),
                                   (include / "sqlite3.h", (695729, HEADER)),
                                   (self.dependency / "build.rs", (35413, UPSTREAM_BUILD)),
                                   (self.dependency / "Cargo.toml", (2641, DEPENDENCY_MANIFEST))):
                need(before[str(path)] == dict(zip(("bytes", "sha256"), expected)), "Locked dependency source differs")
            self.report["source_before"] = before
            for index, path in enumerate(paths):
                target = self.output / "source-snapshots" / (str(index) + "-" + path.name)
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(path.read_bytes())
                need(identity(target) == before[str(path)], "Source snapshot differs")
            compiler = Path(shutil.which("cc") or "/unavailable/cc").resolve(strict=True)
            self.report["probe_compiler"] = {"path": str(compiler), **identity(compiler)}
            self.stage("probe-compiler-version", [compiler, "--version"], 30)
            target = self.stage("probe-compiler-target", [compiler, "-dumpmachine"], 30)
            need(target.strip() in (b"x86_64-linux-gnu", b"x86_64-unknown-linux-gnu"), "Foreign C probe target refused")
            need(not any(char in str(amalgamation) for char in '\\"\n\r'), "Probe include cannot be quoted")
            argv = [compiler, "-std=c11", "-O0", "-fPIC", "-fno-common", "-fno-strict-aliasing",
                    "-ffunction-sections", "-fdata-sections", "-I", include, *["-D" + item for item in FLAGS],
                    '-DTRNM_SQLITE_AMALGAMATION="' + str(amalgamation) + '"', "-c", probe, "-o", self.output / "probe.o"]
            self.stage("compile-probe", argv)
            self.stage("link-probe", [compiler, "-shared", "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections",
                       self.output / "probe.o", "-lm", "-ldl", "-lpthread", "-o", self.output / "probe.so"])
            probe_library = ctypes.CDLL(str(self.output / "probe.so"))
            observed = observation(probe_library)
            need(observed["version"] == 3054001 and observed["source_id"] == SOURCE_ID and observed["layout"] == LAYOUT,
                 "Current original C probe does not match the supported SQLite ABI")
            compilers = [option for option in observed["options"] if option.startswith("COMPILER=")]
            need(len(compilers) == 1 and re.fullmatch(r"COMPILER=(gcc|clang)-.+", compilers[0]) and
                 [option for option in observed["options"] if not option.startswith("COMPILER=")] == list(OPTIONS),
                 "Current original C probe does not match the bundled compiler profile")
            write_json(self.output / "observed-identity.json", observed)
            request = frame(observed)
            (self.output / "emitter-input.bin").write_bytes(request)
            self.report["observed_identity"] = observed
            self.report["emitter_input"] = identity(self.output / "emitter-input.bin")
            pinned_toolchain()
            from hepta.hia_agent_assembly import assemble_program
            core = assemble_program(source.read_bytes()).as_dict()
            self.report["function_count"] = len(core["functions"])
            # The pinned compiler's selfhost_elf profile emits ET_REL; function
            # bytes remain exactly those of the canonical HIA source.
            native_source = b"hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n" + source.read_bytes().split(b"\n", 1)[1]
            assemble_program(native_source)
            (self.output / "emitter-compiled.hepta").write_bytes(native_source)
            native = Build(self.output / "pinned-native")
            object_bytes = native.stage(native.compiler, native_source, "compile-witness-emitter")
            (self.output / "witness-emitter.o").write_bytes(object_bytes)
            self.stage("link-witness-emitter", ["ld", "-shared", "-z", "defs", "-z", "noexecstack", "--build-id=none",
                       self.output / "witness-emitter.o", "-o", self.output / "witness-emitter.so"])
            emitter = ctypes.CDLL(str(self.output / "witness-emitter.so"))
            started = time.monotonic_ns()
            code, result = emit(emitter_function(emitter), request)
            need(code == 0, "Native witness emitter refused current probe data")
            length = struct.unpack_from("<Q", result)[0]
            need(0 < length <= len(result) - 8 and result[8 + length:] == bytes([0xA5]) * (len(result) - 8 - length),
                 "Native witness emitter output extent differs")
            payload = result[8:8 + length]
            (self.output / "emitter-output.bin").write_bytes(result[:8 + length])
            (self.output / "witness.o").write_bytes(payload)
            self.report["native_emission"] = {"exit_code": code, "elapsed_ns": time.monotonic_ns() - started,
                                              "input": self.report["emitter_input"],
                                              "output": identity(self.output / "emitter-output.bin")}
            self.report["object"] = inspect_object(payload)
            self.stage("link-witness", ["ld", "-shared", "-z", "defs", "-z", "noexecstack", "--build-id=none",
                       self.output / "witness.o", "-o", self.output / "witness.so"])
            self.stage("witness-symbols", ["nm", "--defined-only", self.output / "witness.o"], 30)
            undefined = self.stage("witness-undefined", ["nm", "-u", self.output / "witness.o"], 30)
            need(not undefined.strip(), "Generated witness has runtime external dependencies")
            actual = observation(ctypes.CDLL(str(self.output / "witness.so")))
            need(actual == observed, "HIA witness differs from current independent original C probe")
            self.report["native_identity"] = actual
            self.report["native_compiler_stages"] = native.stages
            native.check_pin()
            environment_fence(os.environ)
            self.report["source_after"] = {str(path): identity(path) for path in paths}
            need(self.report["source_after"] == before, "Witness build source changed")
            need(identity(compiler) == {key: self.report["probe_compiler"][key] for key in ("bytes", "sha256")},
                 "Original C probe compiler changed")
            names = ("probe.o", "probe.so", "observed-identity.json", "emitter-input.bin", "emitter-output.bin", "emitter-compiled.hepta",
                     "witness-emitter.o", "witness-emitter.so", "witness.o", "witness.so")
            self.report["artifacts"] = {name: identity(self.output / name) for name in names}
            self.report.update(status="PASS", finalized=True)
            self.save()
            return self.output / "witness.o"
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error))
            self.save()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependency", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = WitnessBuild(args.dependency, args.output).run()
    print(json.dumps({"status": "PASS", "witness": str(result), "report": str(args.output / "build.json")}))


if __name__ == "__main__":
    main()

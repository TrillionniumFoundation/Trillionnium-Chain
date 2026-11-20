#!/usr/bin/env python3
"""Build the eight pinned HIA Settlement units and their owned public Engine.

This is a hosted build driver. Every runtime object is emitted by the pinned
native HIA compiler or by the compiled HIA ownership emitter. It does not
implement Settlement decisions, synthesize ISA instructions, or qualify runtime
behavior. The build output contains all actual compiler, linker, object-tool,
Python, source, command, and raw-output evidence needed by a separate reader.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import time
import tomllib
import traceback

SELF = Path(__file__).resolve()
REPO = SELF.parents[3]
HIA = REPO / "hia"
COMPILER_SHA256 = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
TOOLCHAIN_REVISION = "f33d8da316de8fdf27b504371f1a5310997ff548"
BUILD_SECONDS = 30
PUBLIC_SECONDS = 60
CLEANUP_SECONDS = 3
EMITTED_BYTES = 9760
UNITS = (
    ("control", "hia/src/service_settlement/engine_control.hepta"),
    ("receipt", "hia/src/service_settlement/receipt_owned.hepta"),
    ("rollup", "hia/src/service_settlement/rollup.hepta"),
    ("settle", "hia/src/service_settlement/settle.hepta"),
    ("values", "hia/src/service_settlement/values.hepta"),
    ("trust", "hia/src/service_settlement/trust_owned.hepta"),
    ("emitter", "hia/platform/service_settlement/engine_owned.hepta"),
    ("arithmetic", "hia/src/service_settlement/arithmetic.hepta"),
)
LINK_ROLES = ("control", "trust", "receipt", "rollup", "settle", "values")
EXPORTS = (
    "trnm_settlement_engine_new", "trnm_settlement_engine_apply",
    "trnm_settlement_engine_replay", "trnm_settlement_engine_validate_execution",
    "trnm_settlement_engine_clone", "trnm_settlement_owned_clone",
    "trnm_settlement_owned_drop", "trnm_settlement_owned_kind",
    "trnm_settlement_engine_trust", "trnm_settlement_engine_state",
    "trnm_settlement_engine_state_root", "trnm_settlement_engine_history_count",
    "trnm_settlement_engine_state_copy", "trnm_settlement_error_code",
    "trnm_settlement_error_message", "trnm_settlement_error_display",
    "trnm_settlement_bytes_view", "trnm_settlement_consumption_receipt_id",
    "trnm_settlement_consumption_rollup_id",
    "trnm_settlement_settlement_policy_hash", "trnm_settlement_operation_id",
)
BUDGET = {"functions": 128, "instructions": 8192, "blocks": 1536,
          "blocks_per_function": 256, "values_per_function": 2048,
          "parameters_per_block": 16}
SCOPE = {"public_runtime_qualified": False, "whole_engine_or_store_closed": False,
         "whole_service_settlement_native": False, "whole_chain_native": False,
         "old_stack_can_be_removed": False, "production_activation": False}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def regular_bytes(path):
    require(path.is_file() and not path.is_symlink(), "Not a regular input: " + str(path))
    return path.read_bytes()


def relative_path(name):
    require(isinstance(name, str), "A source path must be text")
    p = Path(name)
    require(not p.is_absolute() and ".." not in p.parts and p.as_posix() == name,
            "Noncanonical repository source path: " + name)
    full = REPO / p
    require(full.resolve() == full, "Symlinked repository source path: " + name)
    return full


def function_bytes(raw):
    declared = [name.decode() for name in re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw)]
    matches = list(re.finditer(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw))
    result = {m[1].decode(): m[0] for m in matches}
    require(len(declared) == len(set(declared)) == len(matches) == len(result)
            and set(declared) == set(result), "Ambiguous HIA function boundaries")
    return result


def sealed_executable(raw, label):
    fd = os.memfd_create(label, os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            size = os.write(fd, raw[offset:])
            require(size > 0, "Short sealed executable write")
            offset += size
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        return fd
    except BaseException:
        os.close(fd)
        raise


def section(raw, name):
    require(raw[:6] == b"\x7fELF\x02\x01", "Not ELF64 little-endian")
    offset = struct.unpack_from("<Q", raw, 40)[0]
    width, count, names = struct.unpack_from("<3H", raw, 58)
    require(width == 64 and names < count, "Invalid ELF section table")
    require(offset + width * count <= len(raw), "Truncated ELF section table")
    headers = [struct.unpack_from("<IIQQQQIIQQ", raw, offset + i * width) for i in range(count)]
    string_header = headers[names]
    strings = raw[string_header[4]:string_header[4] + string_header[5]]
    found = [row for row in headers
             if strings[row[0]:].split(b"\0", 1)[0] == name.encode()]
    require(len(found) == 1, "ELF section is missing or ambiguous: " + name)
    row = found[0]
    require(row[4] + row[5] <= len(raw), "Truncated ELF section: " + name)
    return raw[row[4]:row[4] + row[5]]


def execute_emitter(image, wanted_sha, destination):
    """Private subprocess: execute one sealed exact image and retain buffers."""
    require(platform.system() == "Linux", "Emitter requires the Linux target")
    raw = regular_bytes(image)
    require(identity(raw)["sha256"] == wanted_sha, "Emitter image changed before execution")
    destination.mkdir(mode=0o700)
    request, sizes = b"SSOWN001", (8, EMITTED_BYTES + 8, 0)
    buffers = [(ctypes.c_ubyte * (size + 64))() for size in sizes]
    for buffer, fill in zip(buffers, (0xA7, 0x5C, 0x96)):
        ctypes.memset(buffer, fill, len(buffer))
    ctypes.memmove(ctypes.byref(buffers[0], 32), request, len(request))
    before = [bytes(buffer) for buffer in buffers]
    for i, data in enumerate(before):
        (destination / ("before-" + str(i) + ".raw")).write_bytes(data)
    write_json(destination / "request.json", {
        "image": str(image), "image_identity": identity(raw), "input": identity(request),
        "buffer_lengths": sizes, "guard_bytes": 32, "symbol": "f0",
        "signature": "u32(readbuf,mutbuf,mutbuf)", "executing_python": str(Path(sys.executable).resolve()),
        "executing_python_identity": identity(regular_bytes(Path("/proc/self/exe").resolve())),
    })
    fd = sealed_executable(raw, "trnm-settlement-hia-emitter")
    try:
        library = ctypes.CDLL("/proc/self/fd/" + str(fd))
        entry = library.f0
        entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
        entry.restype = ctypes.c_uint32
        start = time.monotonic_ns()
        code = entry(ctypes.byref(buffers[0], 32), sizes[0],
                     ctypes.byref(buffers[1], 32), sizes[1],
                     ctypes.byref(buffers[2], 32), sizes[2])
        elapsed = time.monotonic_ns() - start
        after = [bytes(buffer) for buffer in buffers]
        for i, data in enumerate(after):
            (destination / ("after-" + str(i) + ".raw")).write_bytes(data)
        checks = {
            "return_zero": code == 0,
            "input_unchanged": before[0] == after[0],
            "empty_workspace_unchanged": before[2] == after[2],
            "output_guards_unchanged": before[1][:32] == after[1][:32] and before[1][-32:] == after[1][-32:],
            "exact_length": struct.unpack_from("<Q", after[1], 32)[0] == EMITTED_BYTES,
        }
        obj = after[1][40:-32]
        write_json(destination / "report.json", {
            "status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
            "return_code": code, "elapsed_ns": elapsed, "image": identity(raw),
            "input": identity(request), "object": identity(obj),
            "before": [identity(b) for b in before], "after": [identity(b) for b in after],
            "actual_compiled_hia_execution": True, "authored_reference_used": False,
        })
        require(all(checks.values()) and len(obj) == EMITTED_BYTES, "HIA ownership emitter failed")
        (destination / "engine-owned.o").write_bytes(obj)
    finally:
        os.close(fd)
    require(regular_bytes(image) == raw, "Emitter image changed during execution")


class Build:
    def __init__(self, output):
        require(SELF == REPO / "hia/platform/service_settlement/build.py", "Noncanonical builder location")
        output = output.absolute()
        require(output.resolve() == output and output != REPO and REPO not in output.parents,
                "Output must be a fresh path outside the repository without symlink components")
        require(not output.exists() and not output.is_symlink(), "Build output already exists")
        output.mkdir(mode=0o700)
        self.output = output
        self.report = {"schema": "trnm.hia.service-settlement-engine-build.v1",
                       "status": "INCOMPLETE", "finalized": False, "stages": [],
                       "units": {}, "source_before": {}, "source_after": {},
                       "source_inputs": {}, "tools_before": {}, "tools_after": {},
                       "declared_budget": BUDGET, "unit_roster": dict(UNITS), **SCOPE}
        self.source_bytes = {}
        self.tool_bytes = {}
        self.toolchain_bytes = {}
        self.tools = {}
        self.env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPYCACHEPREFIX": str(output / "python-cache"),
                    "GIT_NO_LAZY_FETCH": "1", "LC_ALL": "C"}
        self.report["invocation"] = {"argv": [sys.executable, *sys.argv], "cwd": str(Path.cwd()),
            "relevant_environment": {name: os.environ.get(name) for name in
                ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256")},
            "parent_environment_is_not_copied_to_children": True}
        sys.dont_write_bytecode = True
        sys.pycache_prefix = str(output / "python-cache")

    def flush(self):
        write_json(self.output / "build.json", self.report)

    def capture_source(self, name):
        raw = regular_bytes(relative_path(name))
        if name in self.source_bytes:
            require(raw == self.source_bytes[name], "Source changed during capture: " + name)
        else:
            self.source_bytes[name] = raw
            path = self.output / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.report["source_before"][name] = identity(raw)
            self.report["source_inputs"][name] = identity(raw)
        return raw

    def capture_tool(self, name, requested):
        path = Path(requested).resolve(strict=True)
        raw = regular_bytes(path)
        dest = self.output / "tools" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        self.tool_bytes[name] = raw
        self.tools[name] = path
        self.report["tools_before"][name] = {
            "requested_path": str(requested), "resolved_path": str(path),
            "snapshot": dest.relative_to(self.output).as_posix(), **identity(raw),
        }

    def stage(self, directory, name, argv, *, data=b"", env=None, pass_fds=(), timeout=BUILD_SECONDS):
        dest = directory / name
        dest.mkdir(mode=0o700)
        actual_env = self.env if env is None else env
        request = {"argv": list(map(str, argv)), "cwd": str(REPO),
                   "environment": actual_env, "pass_fds": list(pass_fds),
                   "timeout_seconds": timeout, "cleanup_seconds": CLEANUP_SECONDS,
                   "stdin": identity(data)}
        write_json(dest / "request.json", request)
        (dest / "stdin.raw").write_bytes(data)
        process = None
        timed = False
        cleanup = None
        failure = None
        start = time.monotonic_ns()
        cleanup_deadline = None

        def terminate_once():
            nonlocal cleanup, cleanup_deadline
            if cleanup_deadline is not None:
                return
            cleanup_start = time.monotonic_ns()
            cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
            try:
                os.killpg(process.pid, signal.SIGKILL)
                outcome = "sent"
            except ProcessLookupError:
                outcome = "already_exited"
            complete = False
            try:
                process.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
                complete = True
            except subprocess.TimeoutExpired:
                pass
            cleanup = {"signal": "SIGKILL", "signal_outcome": outcome, "complete": complete,
                       "elapsed_ns": time.monotonic_ns() - cleanup_start}

        try:
            with (dest / "stdout.raw").open("xb") as stdout, (dest / "stderr.raw").open("xb") as stderr:
                process = subprocess.Popen(request["argv"], stdin=subprocess.PIPE, stdout=stdout,
                    stderr=stderr, cwd=REPO, env=actual_env, pass_fds=pass_fds,
                    start_new_session=True, umask=0o077)
                try:
                    process.communicate(data, timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed = True
                    terminate_once()
        except BaseException:
            failure = traceback.format_exc()
            if process is not None and process.poll() is None:
                terminate_once()
        stdout = (dest / "stdout.raw").read_bytes() if (dest / "stdout.raw").exists() else b""
        stderr = (dest / "stderr.raw").read_bytes() if (dest / "stderr.raw").exists() else b""
        row = {**request, "exit_code": process.poll() if process is not None else None,
               "timed_out": timed, "cleanup": cleanup, "exception": failure,
               "elapsed_ns": time.monotonic_ns() - start,
               "stdout": identity(stdout), "stderr": identity(stderr)}
        write_json(dest / "receipt.json", row)
        self.report["stages"].append({"path": dest.relative_to(self.output).as_posix(), **row})
        self.flush()
        require(not timed and failure is None and row["exit_code"] == 0,
                "Actual build stage failed; retained " + str(dest / "receipt.json"))
        return stdout, row

    def input_graph(self):
        fixed = (
            "AGENTS.md", "PROJECT_ID", "PROJECT_BOUNDARY.json",
            "scripts/project-preflight.sh", "scripts/ci/project_boundary.py",
            "config/portability-inventory-v1.json", "config/hia-migration-v1.json",
            "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
            "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
            "hia/tools/toolchain.py", "hia/toolchain.lock.json", "hia/components.json",
            "hia/qualification/compiler-binding.json",
            "hia/platform/service_settlement/build.py",
            "hia/platform/service_settlement/engine_owned_exports.json",
            "hia/platform/service_settlement/engine_owned.map",
            "hia/platform/service_settlement/engine_owned.h",
        )
        for name in fixed:
            self.capture_source(name)
        cargo = tomllib.loads(self.source_bytes["trillionnium/Cargo.toml"].decode())
        for member in cargo["workspace"]["members"]:
            self.capture_source("trillionnium/" + member + "/Cargo.toml")
        binding = json.loads(self.source_bytes["hia/qualification/compiler-binding.json"],
                             object_pairs_hook=unique_keys)
        require(binding["compiler_sha256"] == COMPILER_SHA256
                and binding["toolchain_revision"] == TOOLCHAIN_REVISION, "Compiler qualification pin differs")
        for field, digest in (("outer_report", "outer_sha256"), ("nested_report", "compressed_sha256")):
            raw = self.capture_source("hia/qualification/" + binding[field])
            require(identity(raw)["sha256"] == binding[digest], "Compiler qualification bytes differ")
        require(json.loads(self.source_bytes["hia/qualification/" + binding["outer_report"]])["status"]
                == "COLD_SELFHOST_REPLAY_PASS", "Compiler cold qualification is not successful")
        self.binding = binding
        self.pin = json.loads(self.source_bytes["hia/toolchain.lock.json"], object_pairs_hook=unique_keys)
        require(self.pin["revision"] == TOOLCHAIN_REVISION
                and self.pin["language_schema"] == "hepta.hia.program.v8"
                and self.pin["target"] == "x86_64-linux-gnu", "Unsupported pinned compiler profile")
        manifest = json.loads(self.source_bytes["hia/components.json"], object_pairs_hook=unique_keys)
        require(set(manifest) == {"schema", "includes"}
                and manifest["schema"] == "trnm.hia.component-includes.v1"
                and isinstance(manifest["includes"], dict), "Unsupported include registry")
        self.includes = manifest["includes"]
        for name in self.includes:
            require(name.startswith(("src/", "platform/", "storage/")) and name.endswith(".hepta"),
                    "Invalid include registry key")
            path = relative_path("hia/" + name)
            require(path.is_file() and not path.is_symlink(), "Missing registered source: " + name)
        self.unit_inputs = {}
        self.function_sources = {}

        def visit(name, ancestors=()):
            require(name not in ancestors, "Cyclic explicit includes")
            raw = self.capture_source("hia/" + name)
            own = function_bytes(raw)
            paths = {"hia/" + name, "hia/components.json"}
            selected = {fn: {"path": "hia/" + name, **identity(body)}
                        for fn, body in own.items()}
            rows = self.includes.get(name, [])
            require(isinstance(rows, list), "Includes are not a list")
            for row in rows:
                require(isinstance(row, dict) and set(row) == {"source", "functions"}
                        and isinstance(row["functions"], list) and row["functions"]
                        and all(isinstance(fn, str) for fn in row["functions"]), "Malformed include row")
                dep = row["source"]
                require(isinstance(dep, str) and dep.startswith(("src/", "platform/", "storage/"))
                        and dep.endswith(".hepta"), "Invalid dependency path")
                dep_paths, _ = visit(dep, (*ancestors, name))
                paths.update(dep_paths)
                available = function_bytes(self.source_bytes["hia/" + dep])
                for fn in row["functions"]:
                    require(fn in available and fn not in selected, "Missing or duplicate direct function: " + fn)
                    selected[fn] = {"path": "hia/" + dep, **identity(available[fn])}
            return paths, selected

        for role, entry in UNITS:
            paths, selected = visit(entry.removeprefix("hia/"))
            self.unit_inputs[role] = paths
            self.function_sources[role] = selected
        self.report["source_graph"] = {
            "derivation": "canonical builder, preflight inputs, workspace manifests, compiler binding, eight fixed entries and recursive explicit admissions",
            "units": {role: {"entry": entry, "admission_sources": sorted(self.unit_inputs[role]),
                             "function_sources": self.function_sources[role]} for role, entry in UNITS},
            "global_registry_key_presence": sorted(self.includes),
        }
        exports = json.loads(self.source_bytes["hia/platform/service_settlement/engine_owned_exports.json"],
                             object_pairs_hook=unique_keys)
        require(set(exports) == {"exports"} and exports["exports"] == list(EXPORTS),
                "Owned public export manifest differs")
        self.report["source_digest"] = hashlib.sha256(json.dumps(self.report["source_inputs"],
            sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        self.flush()

    def prepare_tools(self):
        require(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
                "Build target must be Linux x86-64")
        for name in ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256"):
            require(bool(os.environ.get(name)), "Required explicit build setting: " + name)
        require(os.environ["HIA_NATIVE_COMPILER_SHA256"] == COMPILER_SHA256, "Compiler environment SHA differs")
        for name, path in (
            ("python", Path(sys.executable).resolve()), ("ld", "/usr/bin/ld"),
            ("objcopy", "/usr/bin/objcopy"), ("bash", "/usr/bin/bash"), ("git", "/usr/bin/git"),
            ("compiler", os.environ["HIA_NATIVE_COMPILER"]),
        ):
            self.capture_tool(name, path)
        self.report["tools"] = {("native_compiler" if name == "compiler" else name):
            {"path": str(self.tools[name]), **identity(self.tool_bytes[name])}
            for name in ("compiler", "python", "ld", "objcopy")}
        self.report["limits"] = {"compiler_seconds": BUILD_SECONDS, "compiler_functions": 128,
            "compiler_ops": 8192, "compiler_blocks": 1536, "compiler_blocks_per_function": 256,
            "compiler_parameters_per_block": 16, "compiler_values_per_function": 2048,
            "public_seconds": PUBLIC_SECONDS, "cleanup_seconds": CLEANUP_SECONDS}
        require(self.tool_bytes["python"] == regular_bytes(Path("/proc/self/exe").resolve()),
                "Recorded Python is not the executing interpreter")
        require(identity(self.tool_bytes["compiler"])["sha256"] == COMPILER_SHA256, "Compiler bytes differ")
        self.env["PATH"] = str(self.tools["python"].parent) + ":/usr/bin:/bin"
        require(Path(shutil.which("python3", path=self.env["PATH"])).resolve() == self.tools["python"],
                "Preflight Python does not match the recorded interpreter")
        self.toolchain = Path(os.environ["HIA_TOOLCHAIN_ROOT"]).resolve(strict=True)
        stages = self.output / "stages"
        stages.mkdir()
        head, _ = self.stage(stages, "toolchain-head", [self.tools["git"], "-C", self.toolchain, "rev-parse", "HEAD"])
        dirty, _ = self.stage(stages, "toolchain-status", [self.tools["git"], "-C", self.toolchain,
                                "status", "--porcelain=v1", "--untracked-files=no"])
        require(head.decode().strip() == TOOLCHAIN_REVISION and not dirty, "Pinned upstream is not exact and tracked-clean")
        tree, _ = self.stage(stages, "toolchain-input-tree", [self.tools["git"], "-C", self.toolchain,
                              "ls-tree", "-rz", "--full-tree", TOOLCHAIN_REVISION, "--", "hepta", "pyproject.toml"])
        inventory = {}
        for item in tree.split(b"\0"):
            if not item:
                continue
            meta, name = item.split(b"\t", 1)
            mode, kind, blob = meta.decode().split()
            name = name.decode()
            require(kind == "blob" and mode in {"100644", "100755"}, "Nonregular pinned toolchain input")
            p = self.toolchain / name
            require(p.resolve() == p, "Symlinked toolchain input")
            raw = regular_bytes(p)
            require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == blob,
                    "Toolchain bytes differ from pinned Git: " + name)
            self.toolchain_bytes[name] = raw
            dest = self.output / "tools/toolchain" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            inventory[name] = {"git_blob": blob, **identity(raw)}
        require("hepta/hia_agent_assembly.py" in inventory, "Pinned Core source not captured")
        self.report["toolchain"] = self.pin
        self.report["compiler_qualification_binding"] = self.binding
        self.report["toolchain_sources_before"] = inventory
        self.stage(stages, "preflight-before", [self.tools["bash"], "scripts/project-preflight.sh", "--audit"])
        sys.path.insert(0, str(self.toolchain))
        import hepta
        require(Path(hepta.__file__).resolve().parent == self.toolchain / "hepta", "Foreign hepta package loaded")
        spec = importlib.util.spec_from_file_location("trnm_settlement_build_toolchain", HIA / "tools/toolchain.py")
        self.tc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tc)
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.object_symbols import inspect_object_symbols
        from hepta.elf_shared_abi import inspect_owned_shared_elf
        self.assemble = assemble_program
        self.render = render_assembly
        self.inspect_object = inspect_object_symbols
        self.inspect_shared = inspect_owned_shared_elf

    def build_unit(self, role, entry):
        directory = self.output / "units" / role
        directory.mkdir(parents=True)
        raw, inputs = self.tc.compose_source(REPO / entry)
        actual = {p.relative_to(REPO).as_posix(): data for p, data in inputs}
        require(set(actual) == self.unit_inputs[role], "Independent source closure differs for " + role)
        for name, data in actual.items():
            require(data == self.source_bytes[name], "Composed source changed: " + name)
        available = function_bytes(raw)
        expected = self.function_sources[role]
        require(set(available) == set(expected), "Direct function roster differs for " + role)
        for fn, data in available.items():
            require(identity(data) == {k: expected[fn][k] for k in ("bytes", "sha256")},
                    "Selected function owner/body differs: " + role + ":" + fn)
        checked = self.assemble(raw)
        value = checked.as_dict()
        require(value["schema"] == self.pin["language_schema"], "Core schema differs")
        first = value["functions"][0]
        require(first["name"] == "f0" and [p["type"] for p in first["params"]] == ["readbuf", "mutbuf", "mutbuf"]
                and first["returns"] == ["u32"] and "exports" not in value, "Unexpected borrowed entry")
        blocks = [block for fn in value["functions"] for block in fn["blocks"]]
        shape = {"functions": len(value["functions"]), "ops": sum(len(b["ops"]) for b in blocks),
                 "blocks": len(blocks), "max_blocks_per_function": max(len(fn["blocks"]) for fn in value["functions"]),
                 "max_block_parameters": max(len(b["params"]) for b in blocks)}
        require(shape["functions"] <= 128 and shape["ops"] <= 8192 and shape["blocks"] <= 1536
                and shape["max_blocks_per_function"] <= 256 and shape["max_block_parameters"] <= 16,
                "Original pinned Core budget exceeded")
        value["module"] = "selfhost_elf"
        wire = self.render(value).encode()
        (directory / "composed.hepta").write_bytes(raw)
        write_json(directory / "core.json", value)
        wire_functions = function_bytes(wire)
        owners = {fn: {**row, "compiler_function": identity(wire_functions[fn])} for fn, row in expected.items()}
        fd = sealed_executable(self.tool_bytes["compiler"], "trnm-settlement-compiler-" + role)
        try:
            obj, compile_receipt = self.stage(directory, "native-compile", ["/proc/self/fd/" + str(fd)],
                      data=wire, env={"PATH": ""}, pass_fds=(fd,))
        finally:
            os.close(fd)
        require(compile_receipt["stderr"]["bytes"] == 0, "Compiler emitted diagnostics")
        symbols = self.inspect_object(obj, "ELF64", 62)
        require(symbols["defined"] == frozenset({"f0"}) and symbols["undefined"] <= {"calloc", "free"},
                "Compiled unit import/export inventory differs")
        (directory / "module.o").write_bytes(obj)
        _, link_receipt = self.stage(directory, "link", [self.tools["ld"], "-m", "elf_x86_64", "-shared",
            "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none",
            "--hash-style=both", directory / "module.o", "-lc", "-o", directory / "module.so"])
        library = regular_bytes(directory / "module.so")
        abi = self.inspect_shared(library, ("f0",))
        for name in actual:
            require(regular_bytes(relative_path(name)) == self.source_bytes[name],
                    "Unit input changed during emission: " + name)
        source_inputs = {name: identity(self.source_bytes[name]) for name in sorted(actual)}
        for name in source_inputs:
            dest = directory / "source" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(self.source_bytes[name])
        report = {"schema": "trnm.hia.service-settlement-unit-build.v1",
                  "status": "NATIVE_EMITTED_NOT_EXECUTED", "role": role, "entry": entry,
                  "source_inputs": source_inputs, "function_sources": owners,
                  "object": identity(obj), "artifact": identity(library), "dynamic_abi": abi,
                  "functions": shape["functions"], "shape": shape, "declared_budget": BUDGET,
                  "compiler_sha256": COMPILER_SHA256, "compiler_wire_sha256": identity(wire)["sha256"],
                  "toolchain": self.pin, "tools": self.report["tools_before"],
                  "stages": [compile_receipt, link_receipt], "source_unchanged": True,
                  "compiler_fallback_used": False, "product_implemented_by_python": False, **SCOPE}
        write_json(directory / "build.json", report)
        self.report["units"][role] = {"directory": directory.relative_to(self.output).as_posix(),
                 "build": identity(regular_bytes(directory / "build.json")),
                 "object": identity(obj), "artifact": identity(library), "shape": shape}
        self.flush()

    def public_image(self):
        directory = self.output / "public"
        directory.mkdir()
        report = {"schema": "trnm.hia.service-settlement-public-build.v1", "status": "INCOMPLETE",
                  "source_inputs": {}, "modules": {}, "stages": [],
                  "all_business_decisions_in_canonical_hia": True, **SCOPE}
        try:
            emitter = self.output / "units/emitter"
            image = emitter / "module.so"
            wanted = identity(regular_bytes(image))["sha256"]
            _, receipt = self.stage(directory, "execute-emitter",
                [self.tools["python"], "-B", SELF, "--execute-emitter", "--emitter-image", image,
                 "--emitter-sha256", wanted, "--emitter-output", directory / "emitter-execution"],
                timeout=PUBLIC_SECONDS)
            report["stages"].append(receipt)
            observation = json.loads(regular_bytes(directory / "emitter-execution/report.json"))
            obj = regular_bytes(directory / "emitter-execution/engine-owned.o")
            require(observation["status"] == "PASS" and observation["object"] == identity(obj),
                    "Emitter observation/object differs")
            symbols = self.inspect_object(obj, "ELF64", 62)
            require(symbols["defined"] == frozenset(EXPORTS)
                    and symbols["undefined"] == frozenset({"calloc", "free", "memcpy"}
                        | {"_trnm_settlement_" + name for name in LINK_ROLES}),
                    "Ownership object imports/exports differ")
            (directory / "engine-owned.o").write_bytes(obj)
            report["emitter_execution"] = {
                "status": 0, "input": observation["input"], "object": identity(obj),
                "actual_compiled_hia_execution": True, "authored_reference_used": False,
                "observation": identity(regular_bytes(directory / "emitter-execution/report.json")),
                "directory": str(directory / "emitter-execution"),
            }
            objects = []
            for role in ("emitter", *LINK_ROLES):
                unit = self.output / "units" / role
                unit_bytes = regular_bytes(unit / "build.json")
                row = json.loads(unit_bytes)
                require(row["status"] == "NATIVE_EMITTED_NOT_EXECUTED" and row["source_unchanged"] is True,
                        "Unsuccessful unit used for public link")
                original = regular_bytes(unit / "module.o")
                require(identity(original) == row["object"]
                        and identity(regular_bytes(unit / "module.so")) == row["artifact"], "Unit artifact changed")
                report["modules"][role] = {"directory": str(unit), "build": identity(unit_bytes),
                                           "object": row["object"], "image": row["artifact"]}
                for name, wanted in row["source_inputs"].items():
                    require(identity(self.source_bytes[name]) == wanted, "Unit source manifest changed")
                    report["source_inputs"][name] = wanted
                if role == "emitter":
                    continue
                symbol = "_trnm_settlement_" + role
                renamed = directory / (role + ".o")
                _, rename_receipt = self.stage(directory, "rename-" + role,
                    [self.tools["objcopy"], "--redefine-sym", "f0=" + symbol, unit / "module.o", renamed],
                    timeout=PUBLIC_SECONDS)
                report["stages"].append(rename_receipt)
                converted = regular_bytes(renamed)
                inventory = self.inspect_object(converted, "ELF64", 62)
                require(inventory["defined"] == frozenset({symbol})
                        and inventory["undefined"] <= {"calloc", "free"}, "Renamed unit symbol inventory differs")
                require(section(original, ".text") == section(converted, ".text"),
                        "Object renaming changed runtime instructions")
                report["modules"][role].update(renamed=identity(converted),
                                               machine_code=identity(section(converted, ".text")))
                objects.append(renamed)
            for name in ("engine_owned_exports.json", "engine_owned.map", "engine_owned.h", "build.py"):
                relative = "hia/platform/service_settlement/" + name
                report["source_inputs"][relative] = identity(self.source_bytes[relative])
            for name in report["source_inputs"]:
                dest = directory / "source" / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(self.source_bytes[name])
            _, link_receipt = self.stage(directory, "link",
                [self.tools["ld"], "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                 "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both",
                 "--version-script=" + str(REPO / "hia/platform/service_settlement/engine_owned.map"),
                 directory / "engine-owned.o", *objects, "-lc", "-o", directory / "settlement-engine.so"],
                timeout=PUBLIC_SECONDS)
            report["stages"].append(link_receipt)
            library = regular_bytes(directory / "settlement-engine.so")
            abi = self.inspect_shared(library, tuple(sorted(EXPORTS)))
            report.update(status="PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", exports=list(EXPORTS),
                artifact=identity(library), dynamic_abi=abi, source_unchanged=True,
                raw_hia_functions_exported=False, shared_provider_required=False,
                tools=self.report["tools"], tool_evidence=self.report["tools_before"])
            self.report["artifact"] = identity(library)
        except BaseException:
            report.update(status="FAIL", exception=traceback.format_exc())
            raise
        finally:
            write_json(directory / "build.json", report)
            self.report["public"] = {"directory": "public", "status": report["status"],
                                     "build": identity(regular_bytes(directory / "build.json"))}

    def final_fence(self):
        changed = []
        for name, before in self.source_bytes.items():
            try:
                after = regular_bytes(relative_path(name))
                self.report["source_after"][name] = identity(after)
                if after != before:
                    changed.append(name)
                    dest = self.output / "source-after" / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(after)
            except BaseException:
                changed.append(name)
                self.report["source_after"][name] = {"error": traceback.format_exc()}
        for name, before in self.tool_bytes.items():
            try:
                after = regular_bytes(self.tools[name])
                self.report["tools_after"][name] = {"resolved_path": str(self.tools[name]), **identity(after)}
                if after != before:
                    changed.append("tool:" + name)
                    (self.output / "tools" / (name + ".after")).write_bytes(after)
            except BaseException:
                changed.append("tool:" + name)
                self.report["tools_after"][name] = {"error": traceback.format_exc()}
        after_chain = {}
        for name, before in self.toolchain_bytes.items():
            try:
                after = regular_bytes(self.toolchain / name)
                after_chain[name] = identity(after)
                if after != before:
                    changed.append("toolchain:" + name)
                    dest = self.output / "tools/toolchain-after" / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(after)
            except BaseException:
                changed.append("toolchain:" + name)
                after_chain[name] = {"error": traceback.format_exc()}
        for name in getattr(self, "includes", {}):
            path = relative_path("hia/" + name)
            if not path.is_file() or path.is_symlink():
                changed.append("registered-path:" + name)
        self.report["toolchain_sources_after"] = after_chain
        self.report["changed_inputs"] = changed
        self.report["source_unchanged"] = not changed
        require(not changed, "Captured input bytes changed during build: " + repr(changed))

    def run(self):
        start = time.monotonic_ns()
        error = None
        try:
            self.input_graph()
            self.prepare_tools()
            for role, entry in UNITS:
                self.build_unit(role, entry)
            self.public_image()
            stages = self.output / "stages"
            self.stage(stages, "preflight-after", [self.tools["bash"], "scripts/project-preflight.sh", "--audit"])
            head, _ = self.stage(stages, "toolchain-head-after", [self.tools["git"], "-C", self.toolchain, "rev-parse", "HEAD"])
            dirty, _ = self.stage(stages, "toolchain-status-after", [self.tools["git"], "-C", self.toolchain,
                                   "status", "--porcelain=v1", "--untracked-files=no"])
            require(head.decode().strip() == TOOLCHAIN_REVISION and not dirty, "Pinned toolchain changed")
            require(set(self.report["units"]) == {role for role, _ in UNITS}, "Incomplete eight-unit build")
            self.report.update(status="EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED",
                compiler_fallback_used=False, product_implemented_by_python=False,
                actual_hia_ownership_emitter_executed=True, authored_reference_used=False)
        except BaseException:
            error = traceback.format_exc()
            self.report.update(status="FAIL", exception=error)
        finally:
            try:
                self.final_fence()
            except BaseException:
                self.report.update(status="FAIL", fence_exception=traceback.format_exc())
            self.report.update(finalized=True, elapsed_ns=time.monotonic_ns() - start)
            self.flush()
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--execute-emitter", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--emitter-image", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--emitter-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--emitter-output", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.execute_emitter:
        require(args.output is None and args.emitter_image and args.emitter_sha256 and args.emitter_output,
                "Incomplete private emitter invocation")
        execute_emitter(args.emitter_image, args.emitter_sha256, args.emitter_output)
        return 0
    require(args.output is not None and args.emitter_image is None and args.emitter_sha256 is None
            and args.emitter_output is None, "Use --output NEW_OUTSIDE_REPOSITORY")
    report = Build(args.output).run()
    print(json.dumps({"status": report["status"], "finalized": report["finalized"],
                      "artifact": report.get("artifact"), "report": str(args.output / "build.json")},
                     sort_keys=True), flush=True)
    return 0 if report["status"] == "EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())

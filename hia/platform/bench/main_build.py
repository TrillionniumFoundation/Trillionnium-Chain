"""Source-bound build for the finite Bench Linux process; no host runtime."""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from hia.platform.build import Build, inspect_executable, sha256
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

COMPONENTS = (
    "src/bench/main_cli.hepta",
    "src/bench/workload.hepta",
    "src/executor/schedule.hepta",
    "src/bench/digests.hepta",
    "src/bench/report.hepta",
    "src/bench/profile.hepta",
    "src/bench/environment.hepta",
    "src/bench/main_diagnostics.hepta",
)
EMITTER = "platform/bench/main_emitter.hepta"
ADAPTER_SHA256 = "f8c2f97cb3c6e3a3b4b58c80319405ecc886fe3ce47c834177591b69aafa2b5a"
PREFIX, BASE = 4280, 0x400000


def exact_native_text(data):
    """Only the pinned compiler's resolved import-free f0 entry, with no patching."""
    from hepta.object_symbols import inspect_object_symbols
    inventory = inspect_object_symbols(data, "ELF64", 62)
    if inventory["defined"] != {"f0"} or inventory["undefined"]:
        raise ValueError("Unexpected imports/exports in Bench argument object")
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if h[0][:7] != b"\x7fELF\x02\x01\x01" or h[1] != 1 or h[2] != 62 or h[11] != 64:
        raise ValueError("Expected ELF64 x86-64 relocatable object")
    shapes = [struct.unpack_from("<IIQQQQIIQQ", data, h[6] + 64 * i) for i in range(h[12])]
    names_at, names_len = shapes[h[13]][4:6]
    names = data[names_at:names_at + names_len]
    section = {}
    for row in shapes:
        name_at, typ, _, _, at, n, _, _, _, _ = row
        name = names[name_at:names.index(b"\0", name_at)]
        if typ in (4, 9) or (typ != 8 and at + n > len(data)) or name in section:
            raise ValueError("Unexpected relocations or malformed Bench argument section")
        section[name] = row
    txt, sym = section[b".text"], section[b".symtab"]
    if txt[1:4] != (1, 6, 0) or sym[9] != 24:
        raise ValueError("Unexpected argument code or symbol layout")
    symbols = [struct.unpack_from("<IBBHQQ", data, sym[4] + j)
               for j in range(0, sym[5], 24)]
    global_funcs = [row for row in symbols if row[1] == 0x12]
    if (len(global_funcs) != 1 or shapes[global_funcs[0][3]] != txt
            or global_funcs[0][4] != 0 or not 0 < global_funcs[0][5] <= txt[5]):
        raise ValueError("Argument f0 does not start exact resolved .text")
    return data[txt[4]:txt[4] + txt[5]]


def build(output: Path, *, bind_profile_output=False):
    # The only eligible output authority is this build's private, repo-shaped
    # original Cargo anchor. No path is supplied by any process argv or env.
    root = output.parent / "isolated-source/trillionnium"
    anchor = b""
    if bind_profile_output:
        root = root.absolute()
        if (root != root.resolve(strict=True) or not root.is_dir()
                or root.is_relative_to(HIA_ROOT.parent)
                or (root / "Cargo.lock").read_bytes() != (HIA_ROOT.parent / "trillionnium/Cargo.lock").read_bytes()
                or output.parent.lstat().st_mode & 0o077
                or output.parent.lstat().st_uid != os.geteuid()):
            raise ValueError("Expected private, exact, repo-shaped Bench profile anchor")
        anchor = str(root).encode("utf-8")
        if len(anchor) > 1024 or b"\0" in anchor or b"\n" in anchor:
            raise ValueError("Bench profile anchor is not in the bounded display path domain")
    if not __debug__:
        raise RuntimeError("Optimized Python source qualification refused")
    pinned = Build(output)
    sources, wires, parts, object_receipts = {}, {}, [], {}
    for rel in (*COMPONENTS, EMITTER):
        _, wire, _, _, captured = checked_source(HIA_ROOT / rel)
        sources[rel] = {p.relative_to(HIA_ROOT).as_posix(): sha256(raw) for p, raw in captured}
        wires[rel] = wire
    explicit_object = {"src/bench/main_cli.hepta": "cli", "src/bench/report.hepta": "report",
                       "src/bench/main_diagnostics.hepta": "diagnostics"}
    for rel in COMPONENTS:
        if rel in explicit_object:
            # The fixed-core flat profile refuses these CFGs. The self-host
            # object profile is selected explicitly; there is no host fallback.
            name = explicit_object[rel]
            obj = output / f"{name}.o"
            receipt, _ = build_native(HIA_ROOT / rel, obj, byte_exports=("f0",), kind="object",
                backend="selfhost", compiler=os.environ["HIA_NATIVE_COMPILER"],
                compiler_sha256=os.environ["HIA_NATIVE_COMPILER_SHA256"])
            object_receipts[name] = receipt
            record = output / f"{name}.canonical-input.hepta"
            value = checked_source(HIA_ROOT / rel)[0].as_dict()
            value["module"] = "selfhost_elf"
            from hepta.hia_agent_assembly import render_assembly
            wire = render_assembly(value).encode()
            if sha256(wire) != receipt["compiler_wire_sha256"]:
                raise ValueError("Exact Bench object compiler request changed: " + name)
            record.write_bytes(wire)
            raw = exact_native_text(obj.read_bytes())
        else:
            raw = pinned.stage(pinned.compiler, wires[rel], "compile-" + Path(rel).stem)
        if not raw:
            raise ValueError("Empty native Bench component")
        parts.append(raw)
    addresses = []
    position = BASE + PREFIX + 8 * (len(parts) + 2)
    for raw in parts:
        addresses.append(position)
        position += len(raw)
    payload = struct.pack("<10Q", *addresses[:6], position if anchor else 0, len(anchor),
                          *addresses[6:]) + b"".join(parts)
    if anchor:
        payload += anchor + b"\0"
    if len(payload) > 950272:
        raise ValueError("Native Bench ELF exceeds original filter packing capacity")
    # The larger machine prefix selects the pinned object profile explicitly.
    # A disposable host process transports bytes to the emitted HIA emitter;
    # the packed Bench executable has no loader or host runtime.
    emitter_path = output / "emitter.so"
    emitter_receipt, emitter_canonical = build_native(HIA_ROOT / EMITTER, emitter_path,
        byte_exports=("f0",), kind="shared", backend="selfhost",
        compiler=os.environ["HIA_NATIVE_COMPILER"],
        compiler_sha256=os.environ["HIA_NATIVE_COMPILER_SHA256"])
    emitter_case = output / "emit-bench-main"
    emitter_case.mkdir(mode=0o700)
    (emitter_case / "stdin.raw").write_bytes(payload)
    from hepta.hia_agent_assembly import render_assembly
    emitter_wire = emitter_canonical.copy()
    emitter_wire["module"] = "selfhost_elf"
    rendered = render_assembly(emitter_wire).encode()
    if sha256(rendered) != emitter_receipt["compiler_wire_sha256"]:
        raise ValueError("Emitter compiled request differs")
    (emitter_case / "compiler-input.hepta").write_bytes(rendered)
    runner = """import ctypes as c, sys
library = c.CDLL(sys.argv[1])
entry = library.f0
entry.argtypes = [c.c_void_p,c.c_size_t] * 3
entry.restype = c.c_uint32
source = sys.stdin.buffer.read()
raw = c.create_string_buffer(source)
out = c.create_string_buffer(1 << 20)
scratch = c.create_string_buffer(1)
n = entry(raw,len(source),out,len(out),scratch,len(scratch))
if not 0 < n <= len(out): raise SystemExit(2)
sys.stdout.buffer.write(out.raw[:n])
"""
    result = subprocess.run([sys.executable,"-B","-c",runner,str(emitter_path)],
        input=payload, capture_output=True, env={"PATH": ""}, timeout=30)
    (emitter_case / "stdout.raw").write_bytes(result.stdout)
    (emitter_case / "stderr.raw").write_bytes(result.stderr)
    (emitter_case / "receipt.json").write_text(json.dumps({
        "exit": result.returncode, "payload_sha256": sha256(payload),
        "output_sha256": sha256(result.stdout), "stderr_sha256": sha256(result.stderr),
        "emitter_sha256": sha256(emitter_path.read_bytes())}, indent=2) + "\n")
    if (result.returncode or result.stderr
            or sha256(emitter_path.read_bytes()) != emitter_receipt["artifact_sha256"]):
        raise ValueError("The pinned HIA emitter refused or changed")
    image = result.stdout
    elf = inspect_executable(image)
    if image[PREFIX:] != payload or sha256(image[176:PREFIX]) != ADAPTER_SHA256:
        raise ValueError("Unexpected machine adapter or component output")
    for captured in sources.values():
        for relative, identity in captured.items():
            if sha256((HIA_ROOT / relative).read_bytes()) != identity:
                raise ValueError("Native Bench source changed during construction")
    pinned.check_pin()
    report = {"schema": "trnm.hia.bench-main.build.v5",
              "status": "BUILD_PASS", "compiler_sha256": sha256(pinned.compiler),
              "toolchain_revision": pinned.lock["revision"], "source_inputs": sources,
              "native_elf": {**elf, "sha256": sha256(image), "bytes": len(image)},
              "adapter_sha256": ADAPTER_SHA256, "adapter_bytes": PREFIX - 176,
              "argument_object": object_receipts["cli"], "report_object": object_receipts["report"],
              "diagnostics_object": object_receipts["diagnostics"],
              "emitter_object": emitter_receipt,
              "contained_parts": [{"source": rel, "entry_address": addr, "sha256": sha256(raw),
                                   "bytes": len(raw)}
                                  for rel, addr, raw in zip(COMPONENTS, addresses, parts, strict=True)],
              "stages": pinned.stages, "whole_bench_native_qualified": False,
              "production_entrypoint_activated": False,
              "runtime_rust_or_python_fallback": False,
              "compiled_profile_root": anchor.decode("utf-8") if anchor else None}
    (output / "build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return image, report

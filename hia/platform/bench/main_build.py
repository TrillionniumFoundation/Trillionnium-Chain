"""Source-bound build for the finite no-profile Bench process; no host runtime."""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct

from hia.platform.build import Build, inspect_executable, sha256
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

COMPONENTS = (
    "src/bench/main_cli.hepta",
    "src/bench/workload.hepta",
    "src/executor/schedule.hepta",
    "src/bench/digests.hepta",
    "src/bench/report.hepta",
)
EMITTER = "platform/bench/main_emitter.hepta"
ADAPTER_SHA256 = "aeae25e5824e5a3411369287bce13f3db8c5fb672d64c9024c5056915ee5aa2b"
PREFIX, BASE = 1344, 0x400000


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


def build(output: Path):
    if not __debug__:
        raise RuntimeError("Optimized Python source qualification refused")
    pinned = Build(output)
    sources, wires, parts, cli_receipt = {}, {}, [], None
    for rel in (*COMPONENTS, EMITTER):
        _, wire, _, _, captured = checked_source(HIA_ROOT / rel)
        sources[rel] = {p.relative_to(HIA_ROOT).as_posix(): sha256(raw) for p, raw in captured}
        wires[rel] = wire
    for index, rel in enumerate(COMPONENTS):
        if index == 0:
            # The fixed-core flat profile refuses this CFG. Its pinned object
            # profile is explicitly selected, not a host/direct-emitter fallback.
            obj = output / "cli.o"
            cli_receipt, _ = build_native(HIA_ROOT / rel, obj, byte_exports=("f0",), kind="object",
                backend="selfhost", compiler=os.environ["HIA_NATIVE_COMPILER"],
                compiler_sha256=os.environ["HIA_NATIVE_COMPILER_SHA256"])
            record = output / "cli.canonical-input.hepta"
            value = checked_source(HIA_ROOT / rel)[0].as_dict()
            value["module"] = "selfhost_elf"
            from hepta.hia_agent_assembly import render_assembly
            wire = render_assembly(value).encode()
            if sha256(wire) != cli_receipt["compiler_wire_sha256"]:
                raise ValueError("Exact original argument compiler request changed")
            record.write_bytes(wire)
            raw = exact_native_text(obj.read_bytes())
        else:
            raw = pinned.stage(pinned.compiler, wires[rel], "compile-" + Path(rel).stem)
        if not raw:
            raise ValueError("Empty native Bench component")
        parts.append(raw)
    addresses = []
    position = BASE + PREFIX + len(parts) * 8
    for raw in parts:
        addresses.append(position)
        position += len(raw)
    payload = struct.pack("<5Q", *addresses) + b"".join(parts)
    if len(payload) > 950272:
        raise ValueError("Native Bench ELF exceeds original filter packing capacity")
    emitter = pinned.stage(pinned.compiler, wires[EMITTER], "compile-bench-emitter")
    inspect_executable(emitter)
    image = pinned.stage(emitter, payload, "emit-bench-main")
    elf = inspect_executable(image)
    if image[PREFIX:] != payload or sha256(image[176:PREFIX]) != ADAPTER_SHA256:
        raise ValueError("Unexpected machine adapter or component output")
    for captured in sources.values():
        for relative, identity in captured.items():
            if sha256((HIA_ROOT / relative).read_bytes()) != identity:
                raise ValueError("Native Bench source changed during construction")
    pinned.check_pin()
    report = {"schema": "trnm.hia.bench-no-profile.build.v1",
              "status": "BUILD_PASS", "compiler_sha256": sha256(pinned.compiler),
              "toolchain_revision": pinned.lock["revision"], "source_inputs": sources,
              "native_elf": {**elf, "sha256": sha256(image), "bytes": len(image)},
              "adapter_sha256": ADAPTER_SHA256, "adapter_bytes": PREFIX - 176,
              "argument_object": cli_receipt,
              "contained_parts": [{"source": rel, "entry_address": addr, "sha256": sha256(raw),
                                   "bytes": len(raw)}
                                  for rel, addr, raw in zip(COMPONENTS, addresses, parts, strict=True)],
              "stages": pinned.stages, "whole_bench_native_qualified": False,
              "production_entrypoint_activated": False,
              "runtime_rust_or_python_fallback": False}
    (output / "build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return image, report

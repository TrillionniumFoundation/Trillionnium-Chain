"""Build the offline Linux x86-64 Worker owned-stdin fixture. No install target."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from hia.platform.bench.main_build import exact_native_text
from hia.platform.build import inspect_executable, sha256
from hia.platform.worker_audit.build import fresh_directory
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

HERE = Path(__file__).resolve().parent
EMITTER = HERE / "emitter.hepta"
KERNEL = HIA_ROOT / "src/worker_agent/journal_audit_export_v3.hepta"
FIXED = (Path(__file__).resolve(), HIA_ROOT / "platform/build.py",
         HIA_ROOT / "platform/bench/main_build.py", HIA_ROOT / "tools/toolchain.py",
         HIA_ROOT / "toolchain.lock.json", HIA_ROOT / "qualification/compiler-binding.json")
PREFIX = 856
KERNEL_BYTES = 216324
KERNEL_TEXT_SHA256 = "55b23d2319775cbfa5b50a31b9dfffbfe62e4f491b4481c8e97733898636c461"
ADAPTER_SHA256 = "1edd98d287c7e15278ed27c73498f81f433e1274e170ecfec43ffbfc94a7419e"
WAO_MAX = 1 << 20
RAW_MAX = 1 << 16
SCRATCH_BYTES = 102400

# This subprocess transports bytes into the pinned HIA *build-time* emitter.
# It is not present in the final executable or used to read the journal.
_EMIT = """
import ctypes as c
import sys
entry = c.CDLL(sys.argv[1]).f0
entry.argtypes = [c.c_void_p, c.c_size_t] * 3
entry.restype = c.c_uint32
raw = sys.stdin.buffer.read(216325)
source = c.create_string_buffer(raw)
extent = int(sys.argv[2])
out = c.create_string_buffer(b'\\xa5' * (extent + 8), extent + 8)
scratch = c.create_string_buffer(1)
size = entry(source, len(raw), out, extent, scratch, len(scratch))
if size == 4294967294 and out.raw == b'\\xa5' * len(out):
    raise SystemExit(21)
if size != extent or out.raw[extent:] != b'\\xa5' * 8:
    raise SystemExit(22)
sys.stdout.buffer.write(out.raw[:size])
"""


def build(output: Path):
    """Extract exact kernel text, call the HIA packer, and independently bind it."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Use the locked Linux x86-64 fixture target")
    directory = fresh_directory(output)
    binding = json.loads(FIXED[-1].read_bytes())
    expected = binding["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256") != expected:
        raise ValueError("Use the already qualified native compiler")
    options = {"backend": "selfhost", "compiler": os.environ["HIA_NATIVE_COMPILER"],
               "compiler_sha256": expected, "byte_exports": ("f0",)}
    source_before = {p: sha256(p.read_bytes()) for p in FIXED}
    for path in (KERNEL, EMITTER):
        source_before.update((p, sha256(raw)) for p, raw in checked_source(path)[-1])

    def compile_source(path, name, kind):
        from hepta.hia_agent_assembly import render_assembly

        result = directory / name
        receipt, canonical = build_native(path, result, kind=kind, **options)
        if receipt["claims"].get("fallback_used") or sha256(result.read_bytes()) != receipt["artifact_sha256"]:
            raise ValueError("Unexpected compiler artifact")
        wire = render_assembly({**canonical, "module": "selfhost_elf"}).encode()
        if sha256(wire) != receipt["compiler_wire_sha256"]:
            raise ValueError("Canonical compiler input differs")
        (directory / (result.stem + ".compiler-input.hepta")).write_bytes(wire)
        return result, receipt

    kernel, kernel_receipt = compile_source(KERNEL, "wqx3.o", "object")
    body = exact_native_text(kernel.read_bytes())
    if len(body) != KERNEL_BYTES or sha256(body) != KERNEL_TEXT_SHA256:
        raise ValueError("Prior pinned import-free WQX3 machine body differs")
    emitter, emitter_receipt = compile_source(EMITTER, "emitter.so", "shared")
    extent = PREFIX + len(body)

    def emit(data, capacity):
        return subprocess.run([sys.executable, "-B", "-c", _EMIT, str(emitter), str(capacity)],
                              input=data, capture_output=True, env={"PATH": ""}, timeout=20)

    for data, capacity in ((body[:-1], extent), (body, extent - 1)):
        refusal = emit(data, capacity)
        if (refusal.returncode, refusal.stdout, refusal.stderr) != (21, b"", b""):
            raise ValueError("HIA assembler fixture must refuse without writing on old caps")
    emitted = emit(body, extent)
    if emitted.returncode or emitted.stderr or len(emitted.stdout) != extent:
        raise ValueError(f"Exact native HIA emitter refused: {emitted.returncode}: {emitted.stderr!r}")
    image = emitted.stdout
    elf = inspect_executable(image)
    if image[PREFIX:] != body or sha256(image[176:PREFIX]) != ADAPTER_SHA256:
        raise ValueError("ELF does not contain the reviewed exact adapter and untouched WQX3 body")
    if any(sha256(p.read_bytes()) != before for p, before in source_before.items()):
        raise ValueError("Platform source changed during compilation")
    if sha256(emitter.read_bytes()) != emitter_receipt["artifact_sha256"]:
        raise ValueError("HIA emitter object changed during build")
    (directory / "fixture.elf").write_bytes(image)
    report = {
        "schema": "trnm.worker-owned-sealed-stdin.build.v1",
        "source_sha256": {str(p.relative_to(HIA_ROOT)): h for p, h in sorted(source_before.items())},
        "elf": {**elf, "bytes": len(image), "sha256": sha256(image)},
        "adapter": {"sha256": ADAPTER_SHA256, "end": PREFIX},
        "kernel_text": {"sha256": KERNEL_TEXT_SHA256, "offset": PREFIX, "bytes": KERNEL_BYTES,
                        "dynamic_imports": [], "relocations": False},
        "caps": {"input": RAW_MAX, "output": WAO_MAX, "scratch": SCRATCH_BYTES},
        "compiler_sha256": expected, "kernel": kernel_receipt, "emitter": emitter_receipt,
        "emitter_atomic_cap_controls": 2, "no_assembler_or_linker_runtime": True,
        "production_dispatch": False,
    }
    (directory / "build.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return image, report

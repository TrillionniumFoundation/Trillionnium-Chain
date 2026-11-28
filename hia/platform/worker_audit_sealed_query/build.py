"""Pack a static, selfhost-only private Worker raw-query fixture."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from hia.platform.bench.main_build import exact_native_text
from hia.platform.build import inspect_executable, sha256
from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_journal_audit_stdin.build import ADAPTER_SHA256, PREFIX as ADAPTER_END
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

HERE = Path(__file__).resolve().parent
EMITTER = HERE / "emitter.hepta"
PROGRAMS = {
    "wer": ("audit_export_row_decode", 76377, "8c3602fe048a340d4e339b7820476f021ce79791a18a3e250477d52a42b413f7"),
    "wid": ("audit_index_decode", 81806, "c7285cbfed8516f43717d90c0c665a1ea4c56aa63a32515bdf80a0f9ddfe3684"),
    "wtq": ("audit_task_query_pretty", 135360, "59454b551b4be185066193e4fcac91fd6fec9d8a73731b39c9048da3e46a50d1"),
}
THUNK_SHA256 = "5b9b69443510ba7809eca79b1a797d1194373ff3ded1075ed4e58c91dbeb4107"
THUNK_END = 1304
IMAGE_N = 294847
RAW_MAX = 65536
OUT_MAX = 1048576
SCRATCH = 102400
FIXED = (
    Path(__file__).resolve(), HIA_ROOT / "platform/worker_journal_audit_stdin/build.py",
    HIA_ROOT / "platform/build.py", HIA_ROOT / "platform/bench/main_build.py",
    HIA_ROOT / "tools/toolchain.py", HIA_ROOT / "toolchain.lock.json",
    HIA_ROOT / "qualification/compiler-binding.json",
)

# Build-only byte transport into an HIA emitter. No runtime parsing or routing.
_EMIT = """
import ctypes as c
import sys
fn = c.CDLL(sys.argv[1]).f0
fn.argtypes = [c.c_void_p,c.c_size_t] * 3
fn.restype = c.c_uint32
source = sys.stdin.buffer.read(293544)
raw = c.create_string_buffer(source)
extent = int(sys.argv[2])
out = c.create_string_buffer(b'\\xa5' * (extent + 8), extent+8)
scratch = c.create_string_buffer(1)
result = fn(raw,len(source),out,extent,scratch,len(scratch))
if result == 0xfffffffe and out.raw == b'\\xa5' * len(out):
    raise SystemExit(21)
if result != extent or out.raw[extent:] != b'\\xa5' * 8:
    raise SystemExit(22)
sys.stdout.buffer.write(out.raw[:result])
"""


def guard_space(path):
    fs = os.statvfs(path)
    if fs.f_bavail * fs.f_frsize < 153 * 1024 * 1024:
        raise RuntimeError("Stop before the 150 MiB workspace floor")


def build(output):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Only the locked Linux x86-64 fixture")
    guard_space(output.parent)
    directory = fresh_directory(output)
    binding = json.loads(FIXED[-1].read_bytes())
    expected = binding["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256") != expected:
        raise ValueError("Use the exact qualified selfhost compiler")
    opts = {"backend": "selfhost", "compiler": os.environ["HIA_NATIVE_COMPILER"],
            "compiler_sha256": expected, "byte_exports": ("f0",)}

    paths = {name: HIA_ROOT / ("src/worker_agent/" + f + ".hepta")
             for name, (f, _, _) in PROGRAMS.items()}
    captured = {p: sha256(p.read_bytes()) for p in FIXED}
    for source in (*paths.values(), EMITTER):
        captured.update((p, sha256(b)) for p, b in checked_source(source)[-1])

    def compiled(source, name, kind):
        from hepta.hia_agent_assembly import render_assembly

        guard_space(directory)
        dest = directory / name
        receipt, document = build_native(source, dest, kind=kind, **opts)
        recorded = dest.read_bytes()
        canonical = render_assembly({**document, "module": "selfhost_elf"}).encode()
        if (receipt["claims"].get("fallback_used") or sha256(canonical) != receipt["compiler_wire_sha256"]
                or sha256(recorded) != receipt["artifact_sha256"]):
            raise ValueError("Native provenance differs")
        (directory / (dest.stem + ".compiler-input.hepta")).write_bytes(canonical)
        return recorded, receipt

    bodies, receipts = {}, {}
    starts, at = {}, THUNK_END
    for role, path in paths.items():
        obj, receipts[role] = compiled(path, role+".o", "object")
        body = exact_native_text(obj)
        _, size, digest = PROGRAMS[role]
        if len(body) != size or sha256(body) != digest:
            raise ValueError("Strict pinned object text differs: " + role)
        bodies[role] = body
        starts[role] = at
        at += size
    if at != IMAGE_N:
        raise ValueError("Exact native image geometry changed")

    _, emitter = compiled(EMITTER, "emitter.so", "shared")
    payload = b"".join(bodies.values())

    def emit(raw, n):
        return subprocess.run([sys.executable, "-B", "-c", _EMIT,
                               str(directory/"emitter.so"), str(n)],
                              input=raw, capture_output=True, env={"PATH": ""}, timeout=20)

    for raw, capacity in ((payload[:-1], IMAGE_N), (payload, IMAGE_N-1)):
        refusal = emit(raw, capacity)
        if (refusal.returncode, refusal.stdout, refusal.stderr) != (21, b"", b""):
            raise ValueError("HIA emitter does not atomically refuse bad geometry")
    result = emit(payload, IMAGE_N)
    if result.returncode or result.stderr or len(result.stdout) != IMAGE_N:
        raise ValueError(f"HIA image pack refused: {result.returncode}: {result.stderr!r}")
    image = result.stdout
    elf = inspect_executable(image)
    if (sha256(image[176:ADAPTER_END]) != ADAPTER_SHA256
            or sha256(image[ADAPTER_END:THUNK_END]) != THUNK_SHA256
            or image[THUNK_END:] != payload
            or any(sha256(p.read_bytes()) != digest for p, digest in captured.items())):
        raise ValueError("Changed old adapter, reviewed thunk, exact object text or repository source")
    if sha256((directory/"emitter.so").read_bytes()) != emitter["artifact_sha256"]:
        raise ValueError("Emitter binary changed")
    (directory/"sealed-worker-task-query.elf").write_bytes(image)
    receipt = {
        "schema": "trnm.hia.worker-sealed-task-query.fixture.v1",
        "compiler_sha256": expected,
        "backend": "selfhost",
        "elf": {**elf, "sha256": sha256(image), "bytes": IMAGE_N},
        "kernel_text": {r: {"at":starts[r], "bytes":len(data), "sha256":sha256(data),
                            "imports":[], "relocations":False} for r,data in bodies.items()},
        "earlier_fd_adapter": {"sha256": ADAPTER_SHA256, "start": 176, "end": ADAPTER_END},
        "query_thunk": {"sha256": THUNK_SHA256, "start": ADAPTER_END, "end": THUNK_END},
        "pins": {str(p.relative_to(HIA_ROOT)):digest for p,digest in sorted(captured.items())},
        "compiler": receipts,
        "emitter": emitter,
        "emitter_refusal_controls": 2,
        "caps": {"physical_frame":RAW_MAX, "typed_frame":RAW_MAX, "stdout":OUT_MAX, "scratch":SCRATCH},
        "production_dispatch":False,
        "direct_backend_qualified_for_named_target":False,
    }
    (directory/"build.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
    return image,receipt



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    a = parser.parse_args()
    _, receipt = build(a.output.absolute())
    print(json.dumps({"artifact": "sealed-worker-task-query.elf", "elf": receipt["elf"],
                      "backend": receipt["backend"], "installed": False}, sort_keys=True))


if __name__ == "__main__":
    main()

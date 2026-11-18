"""Isolated native RS46 calls with the original 4 MiB chunk extent.

This is qualification infrastructure. The child loads only an immutable native
artifact; HIA implements the codec, hash, and rejection decisions. Each buffer
has 64-byte guards and explicit size checks. No production limit is widened.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

if __name__ != "__main__":
    try:
        from .native_support import NativeCall, NativeModule
    except ImportError:
        from native_support import NativeCall, NativeModule
else:
    # The isolated child has no build-driver dependency or import search path.
    NativeModule = object

MAX_SOURCE = 4 * 1024 * 1024
MAX_WIRE = 6 * (81 + MAX_SOURCE // 4)
MAX_INPUT = MAX_WIRE + 80
MAX_SCRATCH = MAX_SOURCE + 4096
SOURCE = Path(__file__).resolve().parents[1] / "src/data_availability/rs46.hepta"


class RS46Native(NativeModule):
    def __init__(self, source=SOURCE):
        super().__init__(source, byte_exports=("f0",))

    def call(self, request, output_length, *, scratch_length=None, timeout=60):
        return self.call_many([(request, output_length, scratch_length)], timeout=timeout)[0]

    def call_many(self, cases, *, timeout=60):
        if not 0 < timeout <= 240:
            raise ValueError("RS46 test timeout must be in (0,240] seconds")
        rows = []
        originals = []
        for case in cases:
            raw, output_length, *optional = case
            scratch_length = optional[0] if optional else None
            if type(raw) not in (bytes, bytearray) or len(raw) > MAX_INPUT + 1:
                raise ValueError("RS46 test input extent")
            if type(output_length) is not int or not 0 <= output_length <= MAX_WIRE + 1:
                raise ValueError("RS46 test output extent")
            if scratch_length is None:
                source_size = int.from_bytes(raw[44:48], "little") if len(raw) >= 48 else 0
                scratch_length = 4096 + 4 * ((min(source_size, MAX_SOURCE) + 3) // 4)
            if type(scratch_length) is not int or not 0 <= scratch_length <= MAX_SCRATCH + 1:
                raise ValueError("RS46 test scratch extent")
            rows.append({"input": base64.b64encode(raw).decode(), "output_length": output_length,
                         "scratch_length": scratch_length})
            originals.append(bytes(raw))
        request = {"library": str(self.library), "sha256": self.artifact_sha256,
                   "cases": rows, "cpu_seconds": max(1, int(timeout))}
        try:
            result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                                     "--worker"], input=json.dumps(request), capture_output=True,
                                    text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return [NativeCall("timeout", None) for _ in rows]
        if result.returncode:
            category = "trapped" if result.returncode in (-signal.SIGABRT, -signal.SIGILL) else "faulted"
            if len(rows) != 1:
                category = "batch_failed"
            return [NativeCall(category, result.returncode, stderr=result.stderr) for _ in rows]
        try:
            observed = json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise AssertionError("RS46 native child returned no complete observation") from error
        if (observed.get("artifact_sha256") != self.artifact_sha256
                or observed.get("host_compiler_modules_loaded") != []
                or len(observed.get("cases", [])) != len(rows)):
            raise AssertionError("RS46 native artifact/result identity differs")
        results = []
        for raw, sent, got in zip(originals, rows, observed["cases"]):
            output = base64.b64decode(got["output"], validate=True)
            if (got["input_sha256"] != hashlib.sha256(raw).hexdigest()
                    or len(output) != sent["output_length"] or got["guards_preserved"] is not True
                    or got["scratch_length"] != sent["scratch_length"]):
                raise AssertionError("RS46 native call changed immutable input, extent, or guards")
            results.append(NativeCall("returned", 0, got["value"], got["abi_status"],
                                      [raw, output, got["scratch_sha256"]], result.stderr))
        return results


def _worker():
    import ctypes
    import fcntl
    import resource
    request = json.load(sys.stdin)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (request["cpu_seconds"], request["cpu_seconds"]))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "disable core dumps")
    artifact = Path(request["library"]).read_bytes()
    digest = hashlib.sha256(artifact).hexdigest()
    if digest != request["sha256"]:
        raise ValueError("Changed RS46 native artifact")
    fd = os.memfd_create("trnm-rs46-test", os.MFD_ALLOW_SEALING)
    try:
        position = 0
        while position < len(artifact):
            written = os.write(fd, artifact[position:])
            if written <= 0:
                raise OSError("short RS46 native artifact capture")
            position += written
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        library = ctypes.CDLL("/proc/self/fd/" + str(fd))
    finally:
        os.close(fd)
    fn = library.f0
    fn.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    fn.restype = ctypes.c_uint64
    guard = bytes(range(64))
    answers = []
    for row in request["cases"]:
        data = base64.b64decode(row["input"], validate=True)
        outlen, worklen = row["output_length"], row["scratch_length"]
        if not (len(data) <= MAX_INPUT + 1 and 0 <= outlen <= MAX_WIRE + 1
                and 0 <= worklen <= MAX_SCRATCH + 1):
            raise ValueError("RS46 child input extent")
        bufs = [ctypes.create_string_buffer(guard + data + guard),
                ctypes.create_string_buffer(guard + b"\xa5" * outlen + guard),
                ctypes.create_string_buffer(guard + b"\x5a" * worklen + guard)]
        sizes = [len(data), outlen, worklen]
        argv = []
        for buf, size in zip(bufs, sizes):
            argv.extend([ctypes.addressof(buf) + 64, size])
        result = fn(*argv)
        intact = all(buf.raw[:64] == guard and buf.raw[64 + size:128 + size] == guard
                     for buf, size in zip(bufs, sizes))
        if bufs[0].raw[64:64 + len(data)] != data:
            raise ValueError("Native RS46 changed immutable input")
        answers.append({"value": result & 0xffffffff, "abi_status": result >> 32,
                        "input_sha256": hashlib.sha256(data).hexdigest(),
                        "output": base64.b64encode(bufs[1].raw[64:64 + outlen]).decode(),
                        "guards_preserved": intact, "scratch_length": worklen,
                        "scratch_sha256": hashlib.sha256(bufs[2].raw[64:64 + worklen]).hexdigest()})
    loaded = sorted(name for name in sys.modules if name == "hepta" or name.startswith("hepta."))
    print(json.dumps({"artifact_sha256": digest, "host_compiler_modules_loaded": loaded,
                      "cases": answers}, separators=(",", ":")))


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("RS46 native test worker requires --worker")
    _worker()

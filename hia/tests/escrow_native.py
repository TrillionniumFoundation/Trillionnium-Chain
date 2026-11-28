"""Isolated native execution of private HIA vault sessions.

This runner supplies public method frames only. It cannot see, initialize,
restore, or mutate a native balance, lock, event, or owner arena.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

if __name__ != "__main__":
    from .native_support import NativeModule
else:
    NativeModule = object

SOURCE = Path(__file__).resolve().parents[1] / "src/escrow/vault.hepta"
# Qualification runner resource bounds, not limits of a vault or its ABI.
MAX_BYTES = 64 * 1024 * 1024


class EscrowNative(NativeModule):
    def __init__(self):
        super().__init__(SOURCE, byte_exports=("f0",))
        configured = os.environ.get("TRNM_HIA_ESCROW_OUTPUT")
        self.capture_directory = Path(configured).absolute() if configured else None
        self.capture_sequence = 0

    def sessions(self, cases, *, fault_library=None, timeout=120):
        if not 0 < timeout <= 240:
            raise ValueError("Vault runner requires a bounded deadline")
        rows = []
        for case in cases:
            data, output_size, *options = case
            fail_at = options[0] if options else 0
            if (not isinstance(data, bytes) or len(data) > MAX_BYTES
                    or type(output_size) is not int or not 0 <= output_size <= MAX_BYTES
                    or type(fail_at) is not int or not 0 <= fail_at <= 100000):
                raise ValueError("Invalid vault runner extent/fault index")
            rows.append({"input": base64.b64encode(data).decode(),
                         "output_size": output_size, "fail_at": fail_at})
        request = {"library": str(self.library), "sha256": self.artifact_sha256,
                   "cases": rows, "fault_library": str(fault_library) if fault_library else None,
                   "cpu_seconds": int(timeout)}
        env = dict(os.environ)
        if fault_library:
            env["LD_PRELOAD"] = str(fault_library)
        argv = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker"]
        request_raw = json.dumps(request)
        result = subprocess.run(argv, input=request_raw, capture_output=True,
                                text=True, timeout=timeout, env=env, check=False)
        if self.capture_directory is not None:
            stem = f"native-call-{self.capture_sequence:04d}"
            self.capture_sequence += 1
            files = {"request.json": request_raw.encode(), "stdout.raw": result.stdout.encode(),
                     "stderr.raw": result.stderr.encode()}
            for suffix, data in files.items():
                with (self.capture_directory / (stem + "." + suffix)).open("xb") as stream:
                    stream.write(data)
            with (self.capture_directory / (stem + ".execution.json")).open("x") as stream:
                json.dump({"argv": argv, "returncode": result.returncode,
                           "timeout_seconds": timeout, "artifact_sha256": self.artifact_sha256,
                           "fault_library": request["fault_library"],
                           "files": {suffix: {"bytes": len(data),
                               "sha256": hashlib.sha256(data).hexdigest()}
                               for suffix,data in files.items()}}, stream, sort_keys=True)
                stream.write("\n")
        if result.returncode:
            raise AssertionError(("vault native worker failed", result.returncode, result.stderr))
        observed = json.loads(result.stdout)
        if (observed.get("artifact_sha256") != self.artifact_sha256
                or observed.get("host_compiler_modules_loaded") != []
                or len(observed.get("cases", [])) != len(rows)):
            raise AssertionError("Vault artifact or complete call roster differs")
        for source, sent, got in zip(cases, rows, observed["cases"]):
            got["output"] = base64.b64decode(got["output"], validate=True)
            if (got["input_sha256"] != hashlib.sha256(source[0]).hexdigest()
                    or len(got["output"]) != sent["output_size"]
                    or got["guards_preserved"] is not True
                    or got["scratch_unchanged"] is not True
                    or got["abi_status"] != 0):
                raise AssertionError("Vault borrowed boundary or immutable input differs")
        return observed


# Test-only allocator interposition. It implements no vault operation or
# success value. The only changed behavior is an actual selected calloc NULL.
FAULT_SOURCE = r'''
#include <stddef.h>
#include <stdint.h>
extern void *__libc_calloc(size_t, size_t);
extern void __libc_free(void *);
static _Thread_local int active;
static _Thread_local uint64_t calls, fail_at, denied, alive, peak, invalid;
static _Thread_local void *owned[64];
void *calloc(size_t n, size_t m) {
    if (active) {
        calls++;
        if (calls == fail_at) { denied++; return NULL; }
    }
    void *p = __libc_calloc(n,m);
    if (active && p) {
        int saved=0;
        for (size_t i=0;i<64;i++) if (!owned[i]) {owned[i]=p;saved=1;break;}
        if (!saved) invalid++;
        alive++; if (alive>peak) peak=alive;
    }
    return p;
}
void free(void *p) {
    if (active && p) {
        int found=0;
        for (size_t i=0;i<64;i++) if (owned[i]==p) {owned[i]=NULL;found=1;break;}
        if (found) alive--; else invalid++;
    }
    __libc_free(p);
}
typedef uint64_t (*entry)(const void *, uint64_t, void *, uint64_t, void *, uint64_t);
uint64_t vault_fault_invoke(entry f,const void *in,uint64_t ni,void *out,uint64_t no,
                           void *scratch,uint64_t ns,uint64_t selected) {
    calls=denied=alive=peak=invalid=0;fail_at=selected;
    for (size_t i=0;i<64;i++) owned[i]=NULL;
    active=1;uint64_t result=f(in,ni,out,no,scratch,ns);active=0;return result;
}
uint64_t vault_fault_calls(void) {return calls;}
uint64_t vault_fault_denied(void) {return denied;}
uint64_t vault_fault_alive(void) {return alive;}
uint64_t vault_fault_peak(void) {return peak;}
uint64_t vault_fault_invalid(void) {return invalid;}
'''


def _worker():
    import ctypes
    import fcntl
    import resource

    request = json.load(sys.stdin)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (request["cpu_seconds"], request["cpu_seconds"]))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "disable core dumps")
    raw = Path(request["library"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != request["sha256"]:
        raise ValueError("Changed vault artifact")
    fd = os.memfd_create("trnm-private-vault", os.MFD_ALLOW_SEALING)
    try:
        position = 0
        while position < len(raw):
            size = os.write(fd, raw[position:])
            if size <= 0:
                raise OSError("Short artifact capture")
            position += size
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        library = ctypes.CDLL("/proc/self/fd/" + str(fd))
    finally:
        os.close(fd)
    entry = library.f0
    entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    entry.restype = ctypes.c_uint64
    fault = None
    if request["fault_library"]:
        fault = ctypes.CDLL(request["fault_library"])
        fault.vault_fault_invoke.argtypes = [ctypes.c_void_p] + entry.argtypes + [ctypes.c_uint64]
        fault.vault_fault_invoke.restype = ctypes.c_uint64
        for name in ("calls", "denied", "alive", "peak", "invalid"):
            getattr(fault, "vault_fault_" + name).restype = ctypes.c_uint64
    guard = bytes(range(64))
    answers = []
    for row in request["cases"]:
        data = base64.b64decode(row["input"], validate=True)
        outsize = row["output_size"]
        if len(data) > MAX_BYTES or not 0 <= outsize <= MAX_BYTES:
            raise ValueError("Child vault extent")
        scratch = b"\x73" * 137
        values = [data, b"\xa5" * outsize, scratch]
        # Misaligned real pointers, independently guarded exact public extents.
        prefix = guard + b"!"
        buffers = [ctypes.create_string_buffer(prefix + value + guard) for value in values]
        argv = []
        for buffer, value in zip(buffers, values):
            argv.extend([ctypes.addressof(buffer) + len(prefix), len(value)])
        result = (fault.vault_fault_invoke(ctypes.cast(entry, ctypes.c_void_p), *argv, row["fail_at"])
                  if fault else entry(*argv))
        pristine = all(buffer.raw[:len(prefix)] == prefix
                       and buffer.raw[len(prefix)+len(value):len(prefix)+len(value)+64] == guard
                       for buffer, value in zip(buffers, values))
        if buffers[0].raw[len(prefix):len(prefix)+len(data)] != data:
            raise AssertionError("Vault changed read-only public method bytes")
        output = buffers[1].raw[len(prefix):len(prefix)+outsize]
        answers.append({"value": result & 0xffffffff, "abi_status": result >> 32,
                        "input_sha256": hashlib.sha256(data).hexdigest(),
                        "output": base64.b64encode(output).decode(), "guards_preserved": pristine,
                        "scratch_unchanged": buffers[2].raw[len(prefix):len(prefix)+len(scratch)] == scratch,
                        "allocator": None if not fault else {name: getattr(fault,"vault_fault_"+name)()
                            for name in ("calls", "denied", "alive", "peak", "invalid")}})
    loaded = sorted(name for name in sys.modules if name == "hepta" or name.startswith("hepta."))
    print(json.dumps({"artifact_sha256": request["sha256"], "host_compiler_modules_loaded": loaded,
                      "cases": answers}, separators=(",", ":")))


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("Vault test worker requires --worker")
    _worker()

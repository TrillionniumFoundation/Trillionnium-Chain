"""Real native-machine test runner; each batch owns a disposable process.

The Python code builds artifacts and supplies test inputs. HIA machine code
implements the tested functions. A signal, timeout or missing output never
becomes a successful observation. This is test infrastructure, not a node.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

MAX_EXTENT = 1 << 20
MAX_SELFHOST_PRIVATE_INPUT = 17 << 20


def unlinked_path(value, *, directory=False):
    """Preserve lexical provenance; resolving first would hide a linked input."""
    if isinstance(value, str) and Path(value).as_posix() != value:
        raise ValueError("Noncanonical native provenance path")
    path = Path(value).absolute()
    if ".." in path.parts:
        raise ValueError("Traversing native provenance path")
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("Linked native provenance path")
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError("Missing native provenance input")
    return path


@dataclass
class NativeCall:
    status: str
    returncode: int | None
    value: int | bool | None = None
    abi_status: int | None = None
    arguments: list | None = None
    stderr: str = ""

    def require_returned(self):
        if self.status != "returned" or self.returncode != 0 or self.abi_status not in (None, 0):
            raise AssertionError(self)
        return self


class NativeModule:
    def __init__(self, source, *, byte_exports=(), backend="selfhost", fixture_owner=None,
                 max_input_extent=MAX_EXTENT):
        # The stock Selfhost f0 takes caller-owned disjoint spans; unlike the
        # direct wrapper it does not impose the test runner's default 1 MiB.
        # Keep explicit fixture opt-in and do not widen any mutable span.
        if (type(max_input_extent) is not int or not MAX_EXTENT <= max_input_extent <= MAX_SELFHOST_PRIVATE_INPUT
                or max_input_extent != MAX_EXTENT and (backend != "selfhost" or tuple(byte_exports) != ("f0",))):
            raise ValueError("Invalid private native input extent/profile")
        self.max_input_extent = max_input_extent
        # Namespace-package import also works with unittest's -s hia/tests.
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from hia.tools.toolchain import HIA_ROOT, build_native
        self.source = unlinked_path(source)
        self.source_root = unlinked_path(HIA_ROOT, directory=True)
        self.fixture_owner = None if fixture_owner is None else unlinked_path(fixture_owner)
        self._temporary = tempfile.TemporaryDirectory(prefix="trnm-hia-native-")
        self.library = Path(self._temporary.name) / "module.so"
        self.byte_exports = tuple(byte_exports)
        options = {}
        if backend == "selfhost":
            options = {"compiler": os.environ.get("HIA_NATIVE_COMPILER"),
                       "compiler_sha256": os.environ.get("HIA_NATIVE_COMPILER_SHA256")}
        try:
            self.receipt, self.document = build_native(self.source, self.library,
                byte_exports=self.byte_exports, backend=backend, **options)
        except BaseException:
            self._temporary.cleanup()
            raise
        self.functions = {fn["name"]: fn for fn in self.document["functions"]}
        self.exports = frozenset(self.receipt["exports"])
        self.artifact_sha256 = hashlib.sha256(self.library.read_bytes()).hexdigest()

    def close(self):
        self._temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def call(self, function, arguments, *, timeout=30):
        return self.call_many([(function, arguments)], timeout=timeout)[0]

    def call_many(self, cases, *, timeout=30):
        if not 0 < timeout <= 60:
            raise ValueError("Test process timeout must be in (0,60] seconds")
        rows = []
        from hepta.hia_program import scalar_value_valid
        for function, arguments in cases:
            if function not in self.exports:
                raise ValueError("Function is not an artifact export: " + function)
            fn = self.functions[function]
            if len(arguments) != len(fn["params"]):
                raise ValueError("Wrong argument count")
            encoded = []
            for param, arg in zip(fn["params"], arguments):
                typ = param["type"]
                if typ in {"readbuf", "mutbuf"}:
                    extent = self.max_input_extent if typ == "readbuf" else MAX_EXTENT
                    if type(arg) not in {bytes, bytearray} or len(arg) > extent:
                        raise ValueError("Borrowed arguments must be private bytes within the fixture extent")
                    encoded.append({"type": typ, "bytes": base64.b64encode(arg).decode()})
                else:
                    if not scalar_value_valid(arg, typ):
                        raise ValueError("Scalar does not fit its Core type")
                    encoded.append({"type": typ, "value": arg})
            rows.append({"function": function, "arguments": encoded,
                         "returns": fn["returns"], "byte_abi": function in self.byte_exports})
        request = {"library": str(self.library), "sha256": self.artifact_sha256,
                   "cases": rows, "cpu_seconds": max(1, int(timeout))}
        try:
            result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                                     "--worker"], input=json.dumps(request), capture_output=True,
                                    text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            # subprocess.run kills and reaps its child before raising.
            return [NativeCall("timeout", None) for _ in rows]
        if result.returncode:
            category = "trapped" if result.returncode in {-signal.SIGABRT, -signal.SIGILL} else "faulted"
            if len(rows) != 1:
                # The batch protocol publishes only a complete terminal record.
                # A signal cannot identify which individual cases ran or trapped.
                category = "batch_failed"
            return [NativeCall(category, result.returncode, stderr=result.stderr) for _ in rows]
        try:
            observed = json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise AssertionError("Native test child did not return a complete observation") from error
        if (observed.get("artifact_sha256") != self.artifact_sha256
                or observed.get("host_compiler_modules_loaded") != []
                or len(observed.get("cases", [])) != len(rows)):
            raise AssertionError("Native test artifact or result identity differs")
        answers = []
        for sent, got in zip(rows, observed["cases"]):
            if got.get("function") != sent["function"] or len(got.get("arguments", [])) != len(sent["arguments"]):
                raise AssertionError("Native case identity differs")
            output = []
            for before, after in zip(sent["arguments"], got["arguments"]):
                if "bytes" in before:
                    decoded = base64.b64decode(after["bytes"], validate=True)
                    original = base64.b64decode(before["bytes"])
                    if len(decoded) != len(original) or before["type"] == "readbuf" and decoded != original:
                        raise AssertionError("Native invocation changed read-only bytes or buffer extent")
                    output.append(decoded)
                else:
                    if after != before:
                        raise AssertionError("Native invocation changed scalar input observations")
                    output.append(after["value"])
            answers.append(NativeCall("returned", 0, got["value"], got["abi_status"], output, result.stderr))
        return answers


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
    with open(request["library"], "rb") as stream:
        raw = stream.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != request["sha256"]:
        raise ValueError("Changed native artifact")
    fd = os.memfd_create("trnm-hia-test", os.MFD_ALLOW_SEALING)
    try:
        position = 0
        while position < len(raw):
            written = os.write(fd, raw[position:])
            if written <= 0:
                raise OSError("short native artifact capture")
            position += written
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        library = ctypes.CDLL("/proc/self/fd/" + str(fd))
    finally:
        os.close(fd)
    types = {"u8": ctypes.c_uint8, "u16": ctypes.c_uint16, "u32": ctypes.c_uint32,
             "u64": ctypes.c_uint64, "usize": ctypes.c_uint64, "i8": ctypes.c_int8,
             "i16": ctypes.c_int16, "i32": ctypes.c_int32, "i64": ctypes.c_int64,
             "isize": ctypes.c_int64, "bool": ctypes.c_uint8}
    results = []
    for case in request["cases"]:
        fn = getattr(library, case["function"])
        arguments, signature, copies = [], [], []
        for arg in case["arguments"]:
            if "bytes" in arg:
                data = base64.b64decode(arg["bytes"], validate=True)
                copied = ctypes.create_string_buffer(data, max(1, len(data)))
                copies.append((copied, len(data)))
                arguments.extend((copied, len(data)))
                signature.extend((ctypes.c_void_p, ctypes.c_uint64))
            else:
                copies.append(None)
                arguments.append(arg["value"])
                signature.append(types[arg["type"]])
        fn.argtypes = signature
        returns = case["returns"]
        fn.restype = ctypes.c_uint64 if case["byte_abi"] else (
            None if not returns or returns == ["unit"] else types[returns[0]])
        value = fn(*arguments)
        abi = (value >> 32) if case["byte_abi"] else None
        if case["byte_abi"]:
            value &= 0xffffffff
        out = []
        for original, copied in zip(case["arguments"], copies):
            out.append(original if copied is None else {"type": original["type"],
                "bytes": base64.b64encode(copied[0].raw[:copied[1]]).decode()})
        results.append({"function": case["function"], "value": value, "abi_status": abi, "arguments": out})
    print(json.dumps({"artifact_sha256": digest, "cases": results,
                      "host_compiler_modules_loaded": [name for name in sys.modules if name.startswith("hepta")]}))


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("This test helper only accepts --worker")
    _worker()

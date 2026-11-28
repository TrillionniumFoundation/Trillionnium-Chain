"""Execute a compiled HIA emitter and preserve its actual output, without ISA synthesis."""
from pathlib import Path
import ctypes
import json
import struct
import sys

base, name, tag = Path(sys.argv[1]), sys.argv[2], sys.argv[3].encode()
library = ctypes.CDLL(str(base / (name + "-emitter.so")))
entry = library.f0
entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
entry.restype = ctypes.c_uint32
source = ctypes.create_string_buffer(tag)
output = ctypes.create_string_buffer(65536)
scratch = ctypes.create_string_buffer(262144)
code = entry(source, len(tag), output, len(output), scratch, len(scratch))
(base / (name + ".actual-output.raw")).write_bytes(output.raw)
if code != 0:
    raise RuntimeError("HIA emitter returned " + str(code))
size = struct.unpack_from("<Q", output.raw)[0]
if size > len(output) - 8:
    raise RuntimeError("HIA emitter output extent differs")
actual = output.raw[8:8 + size]
if not actual.startswith(b"\x7fELF\x02\x01"):
    raise RuntimeError("HIA emitter did not emit ELF64LE")
(base / (name + ".o")).write_bytes(actual)
print(json.dumps({"code": code, "bytes": size, "source_unchanged": source.raw[:len(tag)] == tag}))

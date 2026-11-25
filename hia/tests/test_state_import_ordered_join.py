"""Original post-finality root/ordered-digest join over known valid ordered rows."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_header import original_dependency
from hia.tests.test_state_import_header_admission import oracle_defs
from hia.tests.test_state_import_merkle import independent as independent_root

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/export_ordered_root_join.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_state_import_ordered_join_reference.rs"
WORK = 1400
ABI_LIMIT = 1 << 20
MAX_LEAVES = (ABI_LIMIT - WORK) // 32
DOMAIN = b"trnm.migration.ordered-rows.v0"

# Owned anonymous memory only; a stock borrowed ABI defensive no-write check.
# Test the emitted library in a bounded process (not another policy or verifier).
ALIAS_WORKER = r"""
import ctypes, fcntl, hashlib, json, os, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
with open(sys.argv[1], 'rb') as stream:
    image = stream.read()
if hashlib.sha256(image).hexdigest() != sys.argv[2]:
    raise ValueError('native image receipt mismatch')
fd = os.memfd_create('trnm-hia-join-alias', os.MFD_ALLOW_SEALING)
with os.fdopen(fd, 'wb', closefd=False) as stream:
    stream.write(image)
fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
try:
    entry = ctypes.CDLL('/proc/self/fd/' + str(fd)).f0
finally:
    os.close(fd)
entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
entry.restype = ctypes.c_uint64
results = []
for i, o, w in ((16, 48, 160), (16, 160, 48), (16, 160, 176)):
    buffer = ctypes.create_string_buffer(b'\xa5' * 2048)
    base = ctypes.addressof(buffer)
    before = buffer.raw
    returned = entry(base+i, 64, base+o, 32, base+w, 1432)
    results.append((returned >> 32, returned & 0xffffffff, before == buffer.raw))
print(json.dumps(results))
"""


def actual_original(requests):
    artifact = original_dependency()
    sha = hashlib.sha256(artifact.read_bytes()).digest()
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-post-finality-") as tmp:
        source, exe = Path(tmp) / "oracle.rs", Path(tmp) / "oracle"
        source.write_bytes(oracle_defs(ORIGINAL.read_bytes()) + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        build = subprocess.run([rustc, "--edition=2024", "-O", "--extern", "sha2=" + str(artifact),
                                "-L", "dependency=" + str(artifact.parent), str(source), "-o", str(exe)],
                               capture_output=True, timeout=60)
        if build.returncode:
            raise ValueError(build.stderr.decode())
        done = subprocess.run([str(exe)], input=b"".join(struct.pack("<III", *r) for r in requests),
                              check=True, capture_output=True, timeout=30)
    if done.stderr or hashlib.sha256(artifact.read_bytes()).digest() != sha:
        raise ValueError("incomplete or changed original batch observation")
    raw = done.stdout
    results = []
    for requested in requests:
        end = 33 + 32 * (requested[0] + 1)
        if len(raw) < end:
            raise ValueError("short original batch observation")
        results.append((raw[0], raw[1:33], raw[33:end]))
        raw = raw[end:]
    if raw:
        raise ValueError("trailing original batch observation bytes")
    return results


def fixtures():
    requests = [(n, 0xE019BBDF ^ n, 32) for n in range(1, 66)]
    requests += [(n, 0x619168, 32) for n in (127, 128, 129, 255, 256, 257, 1023, 1024, 1025, MAX_LEAVES)]
    requests += [(1 + (i % 11), i + 967, i) for i in range(32)]
    return requests


class StateImportOrderedRootJoin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    def test_original_ordered_digest_and_root_error_for_locally_verified_rows(self):
        requests = fixtures()
        results = actual_original(requests)
        self.assertEqual(len(results), len(requests))
        for (count, _, mutation), (code, result, raw) in zip(requests, results):
            self.assertEqual(len(raw), 32 * (count + 1))
            has_matching_root = independent_root(raw[:-32]) == raw[-32:]
            self.assertEqual(has_matching_root, mutation == 32)
            self.assertEqual(code, 0 if has_matching_root else 108)
            self.assertEqual(result, hashlib.sha256(DOMAIN + raw[:-32]).digest() if code == 0 else bytes(32))
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                for start in range(0, len(results), 16):
                    batch = results[start:start + 16]
                    args = [[raw, b"\xa5" * 39, b"\x6d" * min(ABI_LIMIT, WORK + len(raw) - 32 + 8)]
                            for _, _, raw in batch]
                    for i, (got, sent) in enumerate(zip(
                            module.call_many([("f0", a) for a in args], timeout=45), args)):
                        code, digest, raw = batch[i]
                        self.assertEqual(got.require_returned().value, code, start + i)
                        output = digest + b"\xa5" * 7 if code == 0 else sent[1]
                        self.assertEqual(got.arguments[:2], [raw, output])
                        bound = WORK + len(raw) - 32
                        self.assertEqual(got.arguments[2][bound:], sent[2][bound:])

    def test_exact_extent_capacity_and_live_nonoverlap_contract(self):
        raw = bytes(64)
        cases = [(b"", 0, 0, 100), (bytes(32), 32, WORK, 100),
                 (bytes(65), 32, WORK + 32, 100), (raw, 31, WORK + 32, 102),
                 (raw, 32, WORK + 31, 102),
                 (bytes((MAX_LEAVES + 2) * 32), 32, ABI_LIMIT, 102)]
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                args = [[r, b"\xa5" * o, b"\x6d" * w] for r, o, w, _ in cases]
                for i, got in enumerate(module.call_many([("f0", a) for a in args])):
                    self.assertEqual((got.require_returned().value, got.arguments), (cases[i][3], args[i]))
                one = bytes(range(32))
                minimal = [one + one, bytes(32), bytes(WORK + 32)]
                success = module.call("f0", minimal).require_returned()
                self.assertEqual((success.value, success.arguments[:2]),
                                 (0, [one + one, hashlib.sha256(DOMAIN + one).digest()]))
                if backend == "direct":
                    aliases = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", ALIAS_WORKER,
                                              str(module.library), module.artifact_sha256],
                                             check=True, capture_output=True, timeout=20)
                    self.assertEqual(json.loads(aliases.stdout), [[4, 0, True]] * 3)

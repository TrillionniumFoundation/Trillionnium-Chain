"""Real native StoreOwner qualification; absence of a compiler is explicit."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from hia.storage.build import HIA
from hia.tests.native_support import NativeModule


class StorageCliTests(unittest.TestCase):
    def test_absolute_scripts_start_without_import_environment(self):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        with tempfile.TemporaryDirectory(prefix="trnm-storage-cli-cwd-") as directory:
            for relative in ("tools/qualify_storage.py", "storage/build.py"):
                with self.subTest(script=relative):
                    script = (HIA / relative).resolve(strict=True)
                    result = subprocess.run([sys.executable, "-B", str(script), "--help"],
                                            cwd=Path(directory), env=environment,
                                            text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("usage:", result.stdout)


class StorageNativeTests(unittest.TestCase):
    def setUp(self):
        missing = [name for name in ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256")
                   if not os.environ.get(name)]
        if missing:
            self.skipTest("Native storage qualification NOT_RUN: missing " + ", ".join(missing))

    def test_native_policy_rejects_all_bad_buffer_shapes_before_effects(self):
        module = NativeModule(HIA / "storage/owner_policy.hepta", byte_exports=("f0",))
        self.addCleanup(module.close)
        cases = []
        originals = []
        for index, sizes in enumerate(((0, 63, 65), (0, 65535, 65537), (0, 196607, 196609))):
            for size in sizes:
                lengths = [64, 65536, 196608]
                lengths[index] = size
                arguments = [bytes([0x31 + i]) * length for i, length in enumerate(lengths)]
                originals.append(arguments)
                cases.append(("f0", arguments))
        results = module.call_many(cases)
        for result, original in zip(results, originals):
            result.require_returned()
            self.assertEqual(result.value, 64)
            self.assertEqual(result.abi_status, 0)
            self.assertEqual(result.arguments, original)

    def test_native_required_file_open_commands_are_nonblocking(self):
        # These are HIA command-contract controls. Real FIFO rejection and
        # regular-file recovery run in the mandatory standalone qualifier.
        module = NativeModule(HIA / "storage/owner_policy.hepta", byte_exports=("f0",))
        self.addCleanup(module.close)
        cases = []
        for phase in (9, 33, 37, 44, 61):
            event, command, state = bytearray(64), bytearray(65536), bytearray(196608)
            struct.pack_into("<QQ", event, 0, 64 if phase == 61 else 0, phase)
            struct.pack_into("<Q", state, 140000, phase)
            struct.pack_into("<Q", state, 140008, 2)  # existing namespace
            struct.pack_into("<Q", state, 140016, 7)  # private directory proposal
            struct.pack_into("<Q", state, 140056, 2)  # current sequence
            struct.pack_into("<Q", state, 140112, 2)  # recovery sequence
            if phase == 61:
                struct.pack_into("<Q", command, 24, 64)
                struct.pack_into("<8sQQQ32s", command, 128, b"HIACMD02", 2, 0, 2, bytes(32))
            cases.append(("f0", [bytes(event), bytes(command), bytes(state)]))
        results = module.call_many(cases)
        self.assertEqual(len(results), 5)
        for result in results:
            result.require_returned()
            self.assertEqual(result.value, 0)
            self.assertEqual(result.abi_status, 0)
            command = result.arguments[1]
            self.assertEqual(struct.unpack_from("<Q", command, 0)[0], 257)  # openat
            self.assertEqual(struct.unpack_from("<Q", command, 24)[0], 657408)
            self.assertEqual(struct.unpack_from("<Q", command, 56)[0], 2)

    def test_native_exact_addressing_and_sequence_contracts(self):
        # Actual HIA command contracts, not physical exabyte/U64_MAX histories.
        module = NativeModule(HIA / "storage/owner_policy.hepta", byte_exports=("f0",))
        self.addCleanup(module.close)
        maximum = (1 << 63) - 1 - 128
        last = (1 << 64) - 1
        subjects = ((0, maximum, 0), (0, maximum + 1, 68), (0, last, 68),
                    (last, 0, 68), (last - 1, 0, 0), (4096, 16 * 1024 * 1024 + 1, 0))
        cases = []
        for sequence, length, expected in subjects:
            event, command, state = bytearray(64), bytearray(65536), bytearray(196608)
            struct.pack_into("<QQ", event, 0, 64, 61)
            struct.pack_into("<Q", command, 24, 64)
            struct.pack_into("<8sQQQ32s", command, 128, b"HIACMD02", 1, length, sequence, bytes(32))
            struct.pack_into("<Q", state, 140000, 61)
            struct.pack_into("<Q", state, 140016, 7)
            struct.pack_into("<Q", state, 140056, sequence)
            cases.append(("f0", [bytes(event), bytes(command), bytes(state)]))
        for (sequence, length, expected), result in zip(subjects, module.call_many(cases)):
            result.require_returned()
            self.assertEqual(result.value, expected, (sequence, length))
            if expected == 0:
                self.assertEqual(struct.unpack_from("<Q", result.arguments[1], 0)[0], 263)
                self.assertEqual(struct.unpack_from("<Q", result.arguments[2], 140096)[0], sequence + 1)
            else:
                self.assertEqual(struct.unpack_from("<Q", result.arguments[1], 72)[0], expected)

    def test_native_storage_sha_framing_against_hashlib_and_canaries(self):
        module = NativeModule(HIA / "storage/sha256_framing.hepta", byte_exports=("f0",))
        self.addCleanup(module.close)
        lengths = (*range(140), 511, 512, 513, 1024, 32768, 32815, 32816)
        for start in range(0, len(lengths), 16):
            payloads = [bytes((i * 31 + 7) & 255 for i in range(n)) for n in lengths[start:start + 16]]
            cases = [("f0", [raw, bytes([0xA5]) * 39, bytes([0xC3]) * 132263]) for raw in payloads]
            for raw, result in zip(payloads, module.call_many(cases)):
                result.require_returned()
                self.assertEqual(result.value, 32)
                self.assertEqual(result.arguments[0], raw)
                self.assertEqual(result.arguments[1], hashlib.sha256(raw).digest() + bytes([0xA5]) * 7)
                scratch = result.arguments[2]
                for left, right in ((0, 128), (192, 256), (512, 65536),
                                    (65536 + len(raw), 131136), (131168, 132263)):
                    self.assertEqual(scratch[left:right], bytes([0xC3]) * (right - left))
        refusals = [(bytes(32817), bytes([0xA5]) * 32, bytes([0xC3]) * 132256),
                    (b"a", bytes([0xA5]) * 31, bytes([0xC3]) * 132256),
                    (b"a", bytes([0xA5]) * 32, bytes([0xC3]) * 132255)]
        for arguments, result in zip(refusals, module.call_many([("f0", list(row)) for row in refusals])):
            result.require_returned()
            self.assertEqual(result.value, 100)
            self.assertEqual(result.arguments, list(arguments))


if __name__ == "__main__":
    unittest.main()

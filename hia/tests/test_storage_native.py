"""Real native StoreOwner qualification; absence of a compiler is explicit."""
import os
import struct
import unittest

from hia.storage.build import HIA
from hia.tests.native_support import NativeModule


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
                struct.pack_into("<8sQQQ32s", command, 128, b"HIACMD01", 2, 0, 2, bytes(32))
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


if __name__ == "__main__":
    unittest.main()

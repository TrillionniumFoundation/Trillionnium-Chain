"""Real offline standard certificate verification, not node admission."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/availability_certificate_verify.hepta"
ADAPTER = Path(__file__).with_name("rust_da_availability_certificate_verify_reference.rs")
WORK = 262912
MAX_PRIVATE = 65536
RESULT = b"\x73" * 17
SCRATCH = b"\x91" * (WORK + 23)


def unpack_records(raw):
    offset = 0
    while offset < len(raw):
        status, count = struct.unpack_from("<BI", raw, offset)
        offset += 5
        value = raw[offset:offset + count]
        if len(value) != count:
            raise ValueError("Truncated actual original certificate result")
        yield value, status
        offset += count


class AvailabilityCertificateVerification(unittest.TestCase):
    def test_actual_standard_original_and_both_pinned_verifiers(self):
        with tempfile.TemporaryDirectory(prefix="trnm-da-cert-original-") as tmp:
            observation = locked_reference(Path(tmp), b"", caller=ADAPTER,
                                           extra_externs=("ed25519_dalek",))
        original = list(unpack_records(observation))
        self.assertEqual([status for _, status in original],
                         [0, 0, 231, 231, 232, 232, 232, 224, 222])
        known = original[0][0]
        cases = [(wire, status, len(SCRATCH)) for wire, status in original] + [
            (known, 0, WORK), (known, 102, WORK - 1),
            (known[:-1], 100, WORK), (known + b"\x00", 100, WORK),
            (b"", 100, 0), (known[:-4] + b"\xff"*4, 100, WORK),
            (b"\x00"*MAX_PRIVATE, 100, WORK),
            (b"\x00"*(MAX_PRIVATE+1), 100, 0),
        ]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                replies = native.call_many([("f0", [wire, RESULT, SCRATCH[:work]])
                                            for wire, _, work in cases], timeout=60)
                for row, ((wire, expected, work), observed) in enumerate(zip(cases, replies, strict=True)):
                    self.assertEqual(observed.require_returned().value, expected, (backend, row))
                    self.assertEqual(observed.arguments[:2], [wire, RESULT], (backend, row))
                    self.assertEqual(observed.arguments[2][WORK:], SCRATCH[WORK:work], (backend, row))


if __name__ == "__main__":
    unittest.main()

"""Canonical schema-1 offline author verification, with a real locked Rust oracle."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/batch_author_verify.hepta"
ADAPTER = Path(__file__).with_name("rust_da_batch_author_verify_reference.rs")
WORK = 262784
OUT = b"\xc4" * 23
SCRATCH = b"\xbd" * (WORK + 17)


def records(raw):
    at = 0
    while at < len(raw):
        status, extent = struct.unpack_from("<BI", raw, at)
        at += 5
        wire = raw[at:at + extent]
        if len(wire) != extent or status not in (0, 201):
            raise ValueError("incomplete original signed-author observation")
        yield wire, status
        at += extent


class DaBatchAuthorVerify(unittest.TestCase):
    def test_original_standard_author_and_ordinary_refusals(self):
        with tempfile.TemporaryDirectory(prefix="trnm-da-batch-author-verify-") as tmp:
            original = list(records(locked_reference(Path(tmp), b"", caller=ADAPTER,
                                                      extra_externs=("ed25519_dalek",))))
        self.assertEqual([status for _, status in original], [0, 201, 201, 201, 201, 201] * 2)
        canonical = original[0][0]
        envelope, = struct.unpack_from("<I", canonical, len(canonical) - 4)
        # The unsupported-schema control intentionally uses the already rejected
        # empty-signature fixture, never a valid alternate-schema signed object.
        unsigned = original[3][0]
        unsupported = unsigned[:envelope] + b"\x02\x00" + unsigned[envelope + 2:]
        local = [
            (canonical, 0, WORK), (canonical, 102, WORK - 1),
            (unsigned, 201, 0), (unsupported, 101, 0),
            (b"", 100, 0), (canonical[:-1], 100, 0),
            (canonical + b"\x00", 100, 0), (b"\x00" * MAX_EXTENT, 100, 0),
            (canonical[:-4] + b"\xff" * 4, 100, 0),
        ]
        for backend in ("direct", "selfhost"):
            cases = [(wire, status, len(SCRATCH)) for wire, status in original] + local
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as module:
                replies = module.call_many([("f0", [wire, OUT, SCRATCH[:work]])
                                            for wire, _, work in cases], timeout=60)
                for index, ((wire, status, work), reply) in enumerate(zip(cases, replies, strict=True)):
                    self.assertEqual(reply.require_returned().value, status, (backend, index))
                    self.assertEqual(reply.arguments[:2], [wire, OUT], (backend, index))
                    self.assertEqual(reply.arguments[2][WORK:], SCRATCH[WORK:work], (backend, index))


if __name__ == "__main__":
    unittest.main()

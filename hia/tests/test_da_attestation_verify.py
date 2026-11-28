"""Compare real locked original strict attestation verification, never live keys."""
from pathlib import Path
import tempfile
import unittest
from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/attestation_verify.hepta"
ADAPTER = Path(__file__).with_name("rust_da_attestation_verify_reference.rs")
WORK = 262784
W = b"\x4a" * (WORK + 13)
OUT = b"\x6c" * 17


def packets(raw):
    at = 0
    while at < len(raw):
        status = raw[at]
        n = int.from_bytes(raw[at+1:at+5], "little")
        wire = raw[at+5:at+5+n]
        if len(wire) != n:
            raise ValueError("truncated original verification")
        yield wire, status
        at += 5+n


class DaAttestationVerify(unittest.TestCase):
    def test_original_valid_and_invalid_attestations_on_both_backends(self):
        with tempfile.TemporaryDirectory(prefix="trnm-da-verify-private-") as directory:
            reference = list(packets(locked_reference(Path(directory), b"", caller=ADAPTER,
                extra_externs=("ed25519_dalek", "sha2"))))
        ordinary = [0, 222, 222, 224, 225, 225, 223, 222, 214, 221, 212]
        self.assertEqual([s for _, s in reference], [*ordinary, 0, 0, *ordinary])
        self.assertEqual([len(r) for r, _ in reference[11:13]], [MAX_EXTENT, MAX_EXTENT+1])
        wire = reference[0][0]
        cases = [(r, s, len(W)) for r, s in reference if len(r) <= MAX_EXTENT] + [
            (wire, 102, WORK-1), (wire, 0, WORK), (wire[:-1], 100, len(W)),
            (wire+b"\0", 100, len(W)), (b"", 100, 0),
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                actual = native.call_many([("f0", [r, OUT, W[:size]])
                                           for r, _, size in cases], timeout=60)
                for i, ((r, status, size), observed) in enumerate(zip(cases, actual, strict=True)):
                    self.assertEqual(observed.require_returned().value, status, (backend,i))
                    self.assertEqual(observed.arguments[:2], [r, OUT], (backend,i))
                    self.assertEqual(observed.arguments[2][WORK:], W[WORK:size], (backend,i))


if __name__ == "__main__":
    unittest.main()

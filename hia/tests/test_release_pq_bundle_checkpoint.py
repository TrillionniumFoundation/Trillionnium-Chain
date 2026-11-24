"""Mechanical checkpoint proposal only, not a reusable verification result."""
from __future__ import annotations

import hashlib
import struct
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_pq_bundle_state import CONTENT, OLD, TIP, snapshot
from hia.tests.test_release_pq_signing import DIR, message

DOMAIN = b"TRNM/Release/PQ/Checkpoint/v1\x00"
SNAPSHOT_DOMAIN = b"TRNM/HIA/PQ/BundleShadowSnapshot/v1\x00"
OUTPUT, WORK = 64, 1504


def snapshot_identity(frame):
    return hashlib.sha256(SNAPSHOT_DOMAIN + frame).digest()


def expected_proposal(frame):
    transcript = message(frame[:155])
    observed_at = struct.unpack_from("<Q", frame, 316)[0]
    sequence = frame[235:267] + struct.pack(">QQ", observed_at, len(transcript)) + transcript
    return hashlib.sha256(DOMAIN + sequence).digest() + snapshot_identity(frame)


class ReleasePqBundleCheckpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backends = {backend: cls.enterClassContext(NativeModule(
            DIR / "pq_bundle_checkpoint.hepta", backend=backend, byte_exports=("f0",)))
            for backend in ("direct", "selfhost")}
        if cls.backends["direct"].artifact_sha256 == cls.backends["selfhost"].artifact_sha256:
            raise ValueError("both independent HIA emitters are required")

    def check(self, rows):
        for mode, backend in self.backends.items():
            inputs = [[frame, b"\x37" * out, b"\xa2" * scratch]
                      for frame, _, out, scratch in rows]
            cases = [("f0", args) for args in inputs]
            for row, args, raw in zip(rows, inputs, backend.call_many(cases, timeout=40), strict=True):
                frame, result, out, scratch = row
                with self.subTest(mode=mode, result=result, out=out, scratch=scratch):
                    raw.require_returned()
                    self.assertEqual(raw.value, result)
                    self.assertEqual(raw.arguments[0], frame)
                    self.assertEqual(raw.arguments[1],
                                     args[1] if result else expected_proposal(frame) + args[1][OUTPUT:])
                    self.assertEqual(raw.arguments[2] if result else raw.arguments[2][WORK:],
                                     args[2] if result else args[2][WORK:])

    def test_same_bytes_historical_snapshot_and_word_order(self):
        stamp = 0x1234_5678_9ABC_DEF0
        source = snapshot(now=stamp, floor=stamp - 1, root_expiry=stamp + 5,
                          offered_expiry=stamp + 4, previous=OLD, current=OLD,
                          history=((1, OLD), (2, TIP)))
        # Two independent state snapshots can legitimately produce identical proposed
        # checkpoint bytes. The second, domain-separated output still distinguishes them.
        alternate = snapshot(now=stamp, floor=stamp - 1, root_expiry=stamp + 5,
                             offered_expiry=stamp + 4, previous=OLD, current=OLD,
                             history=((1, OLD), (2, TIP), (4, TIP)))
        self.assertEqual(expected_proposal(source)[:32], expected_proposal(alternate)[:32])
        self.assertNotEqual(snapshot_identity(source), snapshot_identity(alternate))
        history = ((1, CONTENT),) + tuple((2, i.to_bytes(32, "big")) for i in range(4095))
        max_history = snapshot(previous=CONTENT, current=CONTENT, history=history)
        self.check([(source, 0, OUTPUT, WORK), (alternate, 0, OUTPUT + 8, WORK + 13),
                    (max_history, 0, OUTPUT, WORK),
                    (snapshot(content=OLD, history=history), 201, OUTPUT, WORK)])

    def test_no_proposal_on_invalid_policy_or_capacity(self):
        good = snapshot()
        self.check([(good, 102, OUTPUT - 1, WORK), (good, 102, OUTPUT, WORK - 1),
                    (snapshot(trusted_tip=OLD, offered_expiry=1), 111, OUTPUT - 1, WORK - 1),
                    (snapshot(offered_expiry=1, offered_generation=10), 203, OUTPUT, WORK),
                    (snapshot(offered_tip=OLD, offered_version=1), 205, OUTPUT, WORK),
                    (snapshot(history=((1, CONTENT),)), 208, OUTPUT, WORK),
                    (good + b"\x00", 100, OUTPUT, WORK)])


if __name__ == "__main__":
    unittest.main()

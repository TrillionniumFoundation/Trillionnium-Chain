"""Compare real original generated DA chunk commitments on the emitted images."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_batch_author_transcript import authored
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/chunk_commitments.hepta"
ADAPTER = Path(__file__).with_name("rust_da_chunk_commitments_reference.rs")
CODEC = ROOT / "trillionnium/crates/trnm-data-availability/src/codec.rs"
WORK = 1296
OUT = b"\xa5" * 79
W = b"\x6d" * (WORK + 9)


def records(raw):
    cursor = 0
    while cursor < len(raw):
        tag, i, midpoint, n = struct.unpack_from("<4I", raw, cursor)
        cursor += 16
        wire = raw[cursor:cursor+n]
        cursor += n
        proof = raw[cursor:cursor+64]
        cursor += len(proof)
        if len(wire) != n or len(proof) != 64 or not 175 <= midpoint < n:
            raise ValueError("invalid original observation")
        yield tag, i, midpoint, wire, proof
    if cursor != len(raw):
        raise ValueError("missing original commitment bytes")


class DaChunkCommitments(unittest.TestCase):
    def test_actual_generated_transactions_and_two_native_emitters(self):
        digest = hashlib.sha256(CODEC.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-chunk-") as tmp:
            results = list(records(locked_reference(Path(tmp), b"", caller=ADAPTER)))
        self.assertEqual(hashlib.sha256(CODEC.read_bytes()).digest(), digest)
        self.assertEqual(len(results), 23)
        seen = {(tag, i): (midpoint, wire, proof) for tag, i, midpoint, wire, proof in results}
        for _, i, midpoint, wire, proof in results:
            self.assertEqual(struct.unpack_from("<I", wire, midpoint-12), (i,))
            self.assertEqual(proof, authored(b"trnm.portable.v2.da-chunk-id.v1", wire[:midpoint])
                             + authored(b"trnm.portable.v2.da-chunk-bytes.v1", wire[midpoint:]))
        self.assertEqual(seen[1, 0][2][:32], seen[2, 0][2][:32])
        self.assertNotEqual(seen[1, 0][2][32:], seen[2, 0][2][32:])
        self.assertNotEqual(seen[1, 0][2][:32], seen[3, 0][2][:32])
        self.assertEqual(seen[1, 0][2][32:], seen[3, 0][2][32:])
        self.assertEqual([len(x[3]) for x in results[-2:]], [MAX_EXTENT, MAX_EXTENT+1])
        self.assertEqual({len(seen[tag, 1][1]) - seen[tag, 1][0] - 4 for tag in (1, 4, 5)}, {1, 2, 3})
        cap, wire, known = seen[1, 0]
        private = [
            (b"", 100, b"", 0, 0), (wire[:176], 100, b"", 79, WORK),
            (wire[:-1], 100, b"", 79, WORK), (wire+b"\0", 100, b"", 79, WORK),
            (wire[:36]+b"\xff"*4+wire[40:], 100, b"", 79, WORK),
            (wire[:118]+b"\xff"*4+wire[122:], 100, b"", 79, WORK),
            (wire[:40]+b"\xff"+wire[41:], 100, b"", 79, WORK),
            (wire[:cap]+b"\xff"*4+wire[cap+4:], 100, b"", 79, WORK),
            (wire[:cap-8]+b"\0"*8+wire[cap:], 6, b"", 79, WORK),
            (wire[:cap-8]+b"\0"*12, 6, b"", 79, WORK),
            (wire, 102, b"", 79, WORK-1), (wire, 102, b"", 63, WORK),
            (wire, 0, known, 64, WORK),
        ]
        panel = [(r, 0, v, len(OUT), len(W)) for _, _, _, r, v in results[:-1]] + private
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                records_out = native.call_many([("f0", [r, OUT[:o], W[:w]]) for r, _, _, o, w in panel],
                                               timeout=60)
                for i, ((r, status, v, o, w), record) in enumerate(zip(panel, records_out, strict=True)):
                    self.assertEqual(record.require_returned().value, status, i)
                    self.assertEqual(record.arguments[:2], [r, v+OUT[len(v):o]], i)
                    self.assertEqual(record.arguments[2][WORK:], W[WORK:w], i)

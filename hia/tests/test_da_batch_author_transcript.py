"""Real original unsigned DA envelope and stock HIA transcript differential."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/batch_author_transcript.hepta"
ADAPTER = Path(__file__).with_name("rust_da_batch_author_transcript_reference.rs")
CODEC = ROOT / "trillionnium/crates/trnm-data-availability/src/codec.rs"
WORK = 1296
OUT = b"\xa5" * 71
SCRATCH = b"\x6d" * (WORK + 11)


def authored(domain, body):
    return hashlib.sha256(struct.pack("<I", len(domain)) + domain + body).digest()


def records(raw):
    cursor = 0
    while cursor < len(raw):
        status, n = struct.unpack_from("<BI", raw, cursor)
        if status not in {0, 2, 3, 4, 5, 6, 100}:
            raise ValueError("uncaptured Rust status")
        cursor += 5
        wire = raw[cursor:cursor+n]
        cursor += n
        value = raw[cursor:cursor+64] if status == 0 else b""
        cursor += len(value)
        if len(wire) != n or (status == 0 and len(value) != 64):
            raise ValueError("truncated original observation")
        yield wire, status, value
    if cursor != len(raw):
        raise ValueError("malformed original stream")


class DaBatchAuthorTranscript(unittest.TestCase):
    def test_real_unsigned_batch_envelope_and_two_native_backends(self):
        codec_sha = hashlib.sha256(CODEC.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-batch-root-") as tmp:
            original = list(records(locked_reference(Path(tmp), b"", caller=ADAPTER)))
        self.assertEqual(hashlib.sha256(CODEC.read_bytes()).digest(), codec_sha)
        self.assertEqual(len(original), 37)
        self.assertEqual(set(status for _, status, _ in original), {0, 2, 3, 4, 5, 6, 100})
        for raw, status, value in original:
            if status == 0:
                batch = authored(b"trnm.portable.v2.da-batch.v1", raw)
                c, = struct.unpack_from("<I", raw, 36)
                a, = struct.unpack_from("<I", raw, 117+c)
                statement = raw[:129+c+a] + batch
                self.assertEqual(value, batch + authored(
                    b"trnm.portable.v2.da-batch-author-signature.v1", statement))
        # Actual changes of item bytes and author sequence both affect both roots.
        for alternate in (1, 2):
            for i in (0, 32):
                self.assertNotEqual(original[0][2][i:i+32], original[alternate][2][i:i+32])
        self.assertEqual([len(x[0]) for x in original[-2:]], [MAX_EXTENT, MAX_EXTENT+1])
        self.assertEqual([x[1] for x in original[-2:]], [0, 0])
        ordinary, _, known = original[0]
        base_panel = [(wire, rc, value, len(OUT), len(SCRATCH))
                      for wire, rc, value in original[:-1]]
        base_panel += [
            (b"", 100, b"", 10, 0), (ordinary[:282], 100, b"", 64, 0),
            (ordinary[:36]+b"\xff"*4+ordinary[40:], 100, b"", 64, WORK),
            (ordinary[:118]+b"\xff"*4+ordinary[122:], 100, b"", 64, WORK),
            (ordinary, 102, b"", 63, WORK), (ordinary, 0, known, 64, WORK),
            (ordinary, 102, b"", 64, WORK-1), (original[19][0], 5, b"", 0, 0),
        ]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                replies = native.call_many([("f0", [r, OUT[:out], SCRATCH[:w]])
                                              for r, _, _, out, w in base_panel], timeout=60)
                for i, ((frame, status, result, out, w), reply) in enumerate(
                        zip(base_panel, replies, strict=True)):
                    self.assertEqual(reply.require_returned().value, status, i)
                    self.assertEqual(reply.arguments[:2],
                                     [frame, result+OUT[len(result):out]], i)
                    self.assertEqual(reply.arguments[2][WORK:], SCRATCH[WORK:w], i)

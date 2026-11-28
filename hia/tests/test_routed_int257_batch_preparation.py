"""Observe only the original Int257 public input digest using fixed synthetic fixtures."""
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_model_commitment as model
from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests.native_support import NativeModule

SOURCE = ordinary.SOURCE.with_name("routed_int257_batch_preparation.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_batch_preparation_reference.rs")
DOMAIN = b"pon-routed-int257-grouped-input-v0"
PREIMAGE = 1208
CONTEXT = bytes(range(128))
LIMIT = (1 << 64) - 1
MATRIX = [0] * ordinary.PARAMS
MATRIX[1] = 7
MODEL = hashlib.sha256(model.reference_preimage(bytes([197]) * 32, MATRIX)).digest()
MODEL_ALT = hashlib.sha256(model.reference_preimage(bytes([198]) * 32, MATRIX)).digest()
CANARY = 0xD3


@dataclass(frozen=True)
class Row:
    identity: bytes
    scope: bytes
    arrival: int
    deadline: int
    values: tuple

    def frame(self):
        return self.identity + self.scope + struct.pack("<QQ257i", self.arrival, self.deadline, *self.values)

    def body(self):
        return self.identity + self.scope + struct.pack(">QQ257q", self.arrival, self.deadline, *self.values)


def row(i):
    return Row(bytes(31) + bytes([i]), bytes([241 - i]) * 32, 5, 20,
               tuple(ordinary.features((0, -8), (i + 2, i % 17 - 8))))


def wire(now, context, rows, commitment=MODEL):
    return struct.pack("<IQ", len(rows), now) + commitment + context + b"".join(r.frame() for r in rows)


def transcript(context, rows, commitment=MODEL):
    body = context + struct.pack(">Q", len(rows)) + b"".join(r.body() for r in rows)
    fields = (DOMAIN, model.PROFILE, commitment, body)
    return b"trnm.domain.hash.v1" + b"".join(struct.pack(">Q", len(p)) + p for p in fields)


class RoutedInt257BatchPreparation(unittest.TestCase):
    def test_real_original_and_both_stock_typed_input_commitment(self):
        a, b = row(0), row(1)
        wrong = replace(b, values=tuple(ordinary.features((255, 9))))
        bias = replace(b, values=tuple(ordinary.features(bias=-8)))
        first = [a]
        rows = [row(i) for i in range(64)]
        # Corner combinations distinguish original per-row refusal priority,
        # exact unsigned time comparisons, and ID equality across 32 bytes.
        malformed_repeat = replace(wrong, identity=a.identity, deadline=10)
        panel = [
            (10, CONTEXT, first, 0), (5, CONTEXT, first, 0), (19, CONTEXT, first, 0),
            (10, CONTEXT, [a, b], 0), (10, CONTEXT, [b, a], 0),
            (10, CONTEXT, [replace(a, scope=bytes(32)), b], 0),
            (10, CONTEXT, [replace(a, identity=bytes([1])+bytes(31)), b], 0),
            (10, CONTEXT, [replace(a, arrival=10), b], 0),
            (10, CONTEXT, [replace(a, deadline=21), b], 0),
            (10, CONTEXT, [replace(a, values=tuple(ordinary.features((0, 8)))), b], 0),
            (LIMIT - 1, CONTEXT, [replace(a, arrival=LIMIT - 1, deadline=LIMIT)], 0),
            (0, CONTEXT, [replace(a, arrival=0, deadline=1)], 0),
            (10, CONTEXT, rows, 0), (10, CONTEXT, rows[::-1], 0),
            (10, CONTEXT, [], 4), (10, CONTEXT, rows + [row(64)], 4),
            (20, CONTEXT, first, 5), (4, CONTEXT, first, 5),
            (5, CONTEXT, [replace(a, arrival=5, deadline=5)], 5),
            (5, CONTEXT, [replace(a, arrival=12, deadline=0)], 5),
            (LIMIT, CONTEXT, [replace(a, arrival=LIMIT - 1, deadline=LIMIT)], 5),
            (10, CONTEXT, [a, malformed_repeat], 6),
            (10, CONTEXT, [a, replace(wrong, deadline=10)], 5),
            (10, CONTEXT, [wrong, replace(a, deadline=10)], 7),
            (10, CONTEXT, [a, bias], 7),
            (10, CONTEXT, rows[:-1] + [replace(wrong, identity=rows[-1].identity)], 7),
            (10, CONTEXT, rows[:-1] + [replace(rows[-1], identity=rows[0].identity)], 6),
        ]
        for i in range(4):
            shifted = bytearray(CONTEXT)
            shifted[i * 32 + 31] ^= 0xff
            panel.append((10, bytes(shifted), first, 0))
        panel.append((10, CONTEXT, first, 0))
        models = [MODEL] * (len(panel) - 1) + [MODEL_ALT]
        raw_frames = [wire(now, context, reqs, m)
                      for (now, context, reqs, _), m in zip(panel, models, strict=True)]
        original_wire = b"".join(struct.pack("<I", len(frame)) + frame for frame in raw_frames)
        with tempfile.TemporaryDirectory(prefix="trnm-int257-input-original-") as tmp:
            with patch.object(ordinary, "CALLER", CALLER):
                exact = ordinary.locked_ordinary(Path(tmp), original_wire)
        probes = []
        position = 0
        first_digest = None
        for i, (raw, (_, ctx, reqs, status), m) in enumerate(zip(raw_frames, panel, models, strict=True)):
            self.assertEqual(exact[position], status, i)
            position += 1
            preimage = b"" if status else transcript(ctx, reqs, m)
            digest = b"" if status else exact[position:position+32]
            position += len(digest)
            needed = PREIMAGE + len(preimage)
            if not status:
                self.assertEqual(len(preimage), 290 + len(reqs) * 2136, i)
                self.assertEqual(digest, hashlib.sha256(preimage).digest(), i)
                if i == 0:
                    first_digest = digest
                if i < 3:
                    self.assertEqual(digest, first_digest, i)
                if m == MODEL_ALT:
                    self.assertNotEqual(digest, first_digest, i)
            probes.append((raw, status, digest, preimage, 37, needed + 5))
        self.assertEqual(position, len(exact))
        raw = raw_frames[0]
        preimage = transcript(CONTEXT, first)
        needed = PREIMAGE + len(preimage)
        probes += [
            (b"", 100, b"", b"", 0, 0),
            (raw[:171], 100, b"", b"", 37, needed),
            (raw[:-1], 100, b"", b"", 37, needed),
            (raw+b"\0", 100, b"", b"", 37, needed),
            (b"\xff"*4+raw[4:], 100, b"", b"", 37, needed),
            (raw, 102, b"", b"", 31, needed),
            (raw, 102, b"", b"", 32, needed-1),
            (raw_frames[21], 6, b"", b"", 0, 0),
            (raw, 0, first_digest, preimage, 32, needed),
        ]
        maximum = probes[12]
        self.assertEqual(len(maximum[0]), 71084)
        self.assertEqual(PREIMAGE+len(maximum[3]), 138202)
        probes.extend([
            (*maximum[:4], 32, 138202),
            (maximum[0], 102, b"", b"", 32, 138201),
        ])
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                for start in range(0, len(probes), 4):
                    selected = probes[start:start+4]
                    ans = native.call_many(
                        [("f0", [f, b"\xA5"*o, bytes([CANARY])*w]) for f, _, _, _, o, w in selected],
                        timeout=60)
                    for i, ((raw, s, digest, preimage, out, work), ret) in enumerate(
                            zip(selected, ans, strict=True), start):
                        self.assertEqual(ret.require_returned().value, s, (backend, i))
                        self.assertEqual(ret.arguments[:2], [raw, digest+b"\xA5"*(out-len(digest))], i)
                        scratch = ret.arguments[2]
                        if s:
                            self.assertEqual(scratch, bytes([CANARY])*work, i)
                        else:
                            stop = PREIMAGE+len(preimage)
                            self.assertEqual(scratch[PREIMAGE:stop], preimage, i)
                            self.assertEqual(scratch[stop:], bytes([CANARY])*(work-stop), i)

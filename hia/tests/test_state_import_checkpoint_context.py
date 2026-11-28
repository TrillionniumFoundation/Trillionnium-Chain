"""Original SourceCheckpointContextV0 deterministic shape, without issuing trust."""
import hashlib
from pathlib import Path
import random
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/src/state_import/checkpoint_context.hepta"
REFERENCE = ROOT / "hia/tests/rust_state_import_checkpoint_context_reference.rs"
WIDTHS = (32, 32, 32, 32, 8, 8, 32, 32, 32)


def canonical_digest(raw):
    domain = b"trnm.migration.source-checkpoint-context.v0"
    pieces, offset = [domain], 0
    for width in WIDTHS:
        pieces.append(raw[offset:offset + width])
        offset += width
    assert offset == len(raw)
    return hashlib.sha256(b"".join(len(p).to_bytes(8, "big") + p for p in pieces)).digest()


class StateImportCheckpointContext(unittest.TestCase):
    def test_original_pure_context_digest_and_pre_finality_shape(self):
        rng = random.Random(0x484941)
        rows = []
        for h, e in ((1, 0), (1 << 40, 1 << 56), ((1 << 64) - 1, (1 << 64) - 1)):
            baseline = rng.randbytes(128) + h.to_bytes(8, "big") + e.to_bytes(8, "big") + rng.randbytes(96)
            rows.append((baseline, 0))
            offset = 0
            for width in WIDTHS:
                rows.append((baseline[:offset] + bytes(width) + baseline[offset + width:], 0 if offset == 136 else 101))
                for p in {offset, offset + width - 1}:
                    mutated = baseline[:p] + bytes([baseline[p] ^ 1]) + baseline[p + 1:]
                    height = int.from_bytes(mutated[128:136], "big")
                    rows.append((mutated, 0 if height else 101))
                offset += width
        repeated = b"E" * 128 + (1).to_bytes(8, "big") + bytes(8) + b"E" * 96
        rows.append((repeated, 0))
        original_src = CRATE / "src/lib.rs"
        source_before = hashlib.sha256(original_src.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="trnm-m13-checkpoint-context-") as path:
            original, _ = _build_original(Path(path), REFERENCE)
            out = _run([original], input=b"".join(frame for frame, _ in rows)).stdout
        self.assertEqual(hashlib.sha256(original_src.read_bytes()).digest(), source_before)
        self.assertEqual(len(out), 33 * len(rows))
        baselines = [out[p:p + 33] for p in range(0, len(out), 33)]
        for (frame, expected), answer in zip(rows, baselines, strict=True):
            self.assertEqual(answer, bytes([expected]) + canonical_digest(frame))
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(OWNER, byte_exports=("f0",), backend=backend) as native:
                for start in range(0, len(rows), 12):
                    for checked in (False, True):
                        group = rows[start:start + 12]
                        args = [(frame + b"\1" if checked else frame, b"\xa5" * 39, b"\x6d" * 1579)
                                for frame, _ in group]
                        calls = native.call_many([("f0", list(a)) for a in args])
                        for (frame, expected), a, got in zip(group, args, calls, strict=True):
                            status = expected if checked else 0
                            self.assertEqual(got.require_returned().value, status)
                            self.assertEqual(got.arguments[0], a[0])
                            self.assertEqual(got.arguments[1], a[1] if status else canonical_digest(frame) + a[1][32:])
                            self.assertEqual(got.arguments[2][1572:], a[2][1572:])
                frame = rows[0][0]
                exact = native.call("f0", [frame + b"\1", bytes(32), bytes(1572)]).require_returned()
                self.assertEqual((exact.value, exact.arguments[1]), (0, canonical_digest(frame)))
                guards = [(frame[:-1], 32, 1572, 100), (frame + b"\0", 32, 1572, 100),
                          (frame + b"\1\0", 32, 1572, 100), (frame, 31, 1572, 102),
                          (frame + b"\1", 32, 1571, 102)]
                for raw, size, scratch, status in guards:
                    args = [raw, b"\x35" * size, b"\x7c" * scratch]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (status, args))

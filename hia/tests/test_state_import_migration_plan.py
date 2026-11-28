"""Complete original deterministic MigrationPlanV0 vs both native ELF backends."""
import hashlib
from pathlib import Path
import random
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, _build_original, _run
from hia.tests.test_state_import_sqlite_handoff_read import retained_fixture

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "hia/tests/rust_state_import_migration_plan_reference.rs"
SOURCE = ROOT / "hia/src/state_import/migration_plan.hepta"
WIDTHS = (32, 32, 32, 8, 32, 32, 32, 32, 32, 1, 1)
OFFSETS = tuple(sum(WIDTHS[:n]) for n in range(len(WIDTHS)))


def canonical_independent(plan):
    fields = [plan[p:p+w] for p, w in zip(OFFSETS, WIDTHS)]
    return hashlib.sha256(b"".join(struct.pack(">Q", len(f)) + f for f in
                                   [b"trnm.migration.plan.v0", *fields])).digest()


def replace(data, pos, part):
    return data[:pos] + part + data[pos + len(part):]


class StateImportMigrationPlan(unittest.TestCase):
    def test_original_accepted_and_every_rejected_plan_condition(self):
        rust = CRATE / "src/lib.rs"
        source_before = hashlib.sha256(rust.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="m13-migration-plan-original-") as tmp:
            root = Path(tmp).resolve()
            adapter = root / "original-plan.rs"
            adapter.write_bytes(retained_fixture(rust.read_bytes()) + ADAPTER.read_bytes())
            executable, _ = _build_original(root, adapter, ("sha2",))
            raw_exports = _run([executable, "--exports"]).stdout
            self.assertEqual(len(raw_exports), 3 * 136)
            exports = [raw_exports[i:i+136] for i in range(0, len(raw_exports), 136)]
            self.assertEqual([int.from_bytes(e[96:104], "big") for e in exports], [100, 1, (1 << 64)-1])
            cases = []

            def add(index, plan, marker, claimed=None):
                given = canonical_independent(plan) if claimed is None else claimed
                self.assertEqual((len(plan), len(given)), (266, 32))
                cases.append((index, plan, given, marker))

            rng = random.Random(0x4d3133504c414e)
            for index, exp in enumerate(exports):
                baseline = exp + rng.randbytes(128) + b"\1\1"
                add(index, baseline, True)
                # Target properties may equal corresponding source values except chain.
                add(index, replace(baseline, 168, exp[32:64] + exp[64:96]), True)
                # Every individual source binding and target required field changes separately.
                for pos in OFFSETS:
                    add(index, replace(baseline, pos, bytes((baseline[pos] ^ 1,))), pos in (136, 168, 200, 232))
                for pos in (0, 32, 64, 136, 168, 200, 232):
                    add(index, replace(baseline, pos, bytes(32)), False)
                add(index, replace(baseline, 136, exp[:32]), False)
                add(index, baseline, False, bytes(32))
                bad_digest = canonical_independent(baseline)
                add(index, baseline, False, bytes((bad_digest[0] ^ 128,)) + bad_digest[1:])
                add((index + 1) % 3, baseline, False)
            wire = b"".join(bytes((i,)) + body + submitted for i, body, submitted, _ in cases)
            result = _run([executable], input=wire).stdout
        self.assertEqual(len(result), 33 * len(cases))
        self.assertEqual(hashlib.sha256(rust.read_bytes()).digest(), source_before)
        parsed = [result[i:i+33] for i in range(0, len(result), 33)]
        for (_, body, _, admitted), rust_reply in zip(cases, parsed):
            self.assertEqual(rust_reply, bytes((0 if admitted else 101,)) + canonical_independent(body))
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as artifact:
                for at in range(0, len(cases), 12):
                    rows, gold = cases[at:at+12], parsed[at:at+12]
                    for checked in (False, True):
                        args = [[p + tok + exports[i] if checked else p, b"\xa5" * 39, b"\x6d" * 1599]
                                for i, p, tok, _ in rows]
                        for given, got, answer in zip(args, artifact.call_many([("f0", a) for a in args]), gold):
                            expected = answer[0] if checked else 0
                            self.assertEqual((got.require_returned().value, got.arguments[0]), (expected, given[0]))
                            self.assertEqual(got.arguments[1], (answer[1:] + b"\xa5" * 7) if not expected else given[1])
                            self.assertEqual(got.arguments[2][1592:], b"\x6d" * 7)
                body = cases[0][1]
                full = body + cases[0][2] + exports[0]
                malformed = [(body[:-1], 100, 39, 1592), (body + b"\0", 100, 39, 1592),
                             (full[:-1], 100, 39, 1592), (full + b"\0", 100, 39, 1592),
                             (replace(full, 264, b"\2"), 100, 39, 1592),
                             (replace(body, 265, b"\xff"), 100, 39, 1592),
                             (full, 102, 31, 1592), (body, 102, 32, 1591)]
                spans = [[raw, b"\xa5" * o, b"\x6d" * w] for raw, _, o, w in malformed]
                for case, args, native in zip(malformed, spans, artifact.call_many([("f0", a) for a in spans])):
                    self.assertEqual((native.require_returned().value, native.arguments), (case[1], args))

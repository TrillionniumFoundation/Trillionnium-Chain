"""Observe the actual locked original prefix before any attestation signature."""
from pathlib import Path
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_attestation_coordinate import changed, fields, num, vector
from hia.tests.test_da_batch_author_transcript import authored
from hia.tests.test_da_committee_definition import member
from hia.tests.test_da_committee_id import descriptor
from hia.tests.test_da_protocol_context import locked_reference

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/attestation_context_binding.hepta"
ADAPTER = Path(__file__).with_name("rust_da_attestation_context_binding_reference.rs")
DOMAIN = b"trnm.portable.v2.da-committee.v1"
WORK = 141536
CANARY = b"\x5a" * (WORK + 11)


def committee(parts, rows=None, **kw):
    kwargs = {"ctx": b"".join(parts[1:6]), "epoch": 29, **kw}
    return descriptor([member()] if rows is None else rows, **kwargs)


def frame(parts, c, recalc=True):
    if recalc:
        parts = changed(parts, 8, authored(DOMAIN, c))
    return c + b"".join(parts) + num(4, len(c))


class DaAttestationContextBinding(unittest.TestCase):
    def test_original_validation_prefix_and_both_locked_native_emitters(self):
        baseline = fields()
        c = committee(baseline)
        chain_case = fields(b"A"*128)
        invalid_member = member(weight=0)
        invalid_threshold = committee(baseline, threshold=9)
        cases = [
            (frame(baseline, c), 0),
            (frame(chain_case, committee(chain_case)), 0),
            (frame(changed(baseline, 1, num(2, 2)), invalid_threshold), 208),
            (frame(changed(baseline, 4, num(4, 4)), invalid_threshold), 208),
            (frame(fields("界".encode()), invalid_threshold), 209),
            (frame(fields(b""), invalid_threshold), 209),
            (frame(fields(b"x"*129), invalid_threshold), 209),
            (frame(changed(baseline, 6, b"\x01"), invalid_threshold), 213),
            (frame(changed(baseline, 6, b"\xff"), invalid_threshold), 214),
            (frame(changed(baseline, 0, num(2, 2)), invalid_threshold), 221),
            (frame(changed(baseline, 7, num(8, 28)), invalid_threshold), 221),
            (frame(changed(baseline, 5, b"x"*32), invalid_threshold), 221),
            (frame(fields(b"a-different-chain"), invalid_threshold), 221),
            (frame(baseline, committee(baseline, rows=[])), 204),
            (frame(baseline, committee(baseline, namespace=1)), 213),
            (frame(baseline, committee(baseline, namespace=2)), 214),
            (frame(baseline, committee(baseline, schema=2)), 210),
            (frame(changed(baseline, 14, vector(b"")), invalid_threshold), 212),
            (frame(changed(baseline, 15, num(8, 0)),
                   committee(baseline, rows=[invalid_member])), 201),
            (frame(baseline, c, recalc=False), 221),
            (frame(changed(baseline, 14, vector(b"")), c), 221),
            (frame(changed(baseline, 15, num(8, 0)), c), 221),
            (frame(changed(baseline, 16, num(8, 0)), c), 221),
            (frame(changed(baseline, 12, num(8, 29)), c), 221),
            (frame(changed(baseline, 12, num(8, 28)), c), 221),
        ]
        for i in (9, 10, 11, 17):
            cases.append((frame(changed(baseline, i, b"x"*32), c), 0))
        edge_author = MAX_EXTENT - len(cases[0][0]) + len(b"fixture-author")
        cases += [(frame(fields(author=b"x"*n), c), 0) for n in (edge_author, edge_author+1)]
        self.assertEqual([len(w) for w, _ in cases[-2:]], [MAX_EXTENT, MAX_EXTENT+1])
        with tempfile.TemporaryDirectory(prefix="trnm-da-attestation-context-") as directory:
            result = locked_reference(Path(directory), b"".join(vector(w) for w, _ in cases), caller=ADAPTER)
        self.assertEqual(result, bytes(s for _, s in cases))
        normal = cases[0][0]
        checks = [(w, status, len(CANARY)) for w, status in cases[:-1]] + [
            (b"", 100, 0), (normal[:-1], 100, len(CANARY)), (normal+b"\0", 100, len(CANARY)),
            (normal[:-4]+b"\xff"*4, 100, len(CANARY)), (normal, 102, WORK-1), (normal, 0, WORK),
        ]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                actual = native.call_many(
                    [("f0", [wire, b"\xa5"*17, CANARY[:size]]) for wire, _, size in checks], timeout=60)
                for i, ((wire, status, size), call) in enumerate(zip(checks, actual, strict=True)):
                    self.assertEqual(call.require_returned().value, status, (backend, i))
                    self.assertEqual(call.arguments[0], wire, (backend, i))
                    self.assertEqual(call.arguments[1], b"\xa5"*17, (backend, i))
                    self.assertEqual(call.arguments[2][WORK:], CANARY[WORK:size], (backend, i))


if __name__ == "__main__":
    unittest.main()

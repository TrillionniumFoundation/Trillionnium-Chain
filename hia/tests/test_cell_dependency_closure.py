"""Exact original TCD1 byte metadata. No filesystem paths or payload are opened."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import CLOSURE, ENV, build, sha
from hia.tests.test_cell_manifest import MAX_CELL, MARK, ROOT, SCRATCH, NativeManifestChecks, change
from hia.tests.test_cell_release_manifest import CAP, DOMAIN as RELEASE_DOMAIN, ident, release

SRC = ROOT / "hia/src/data_availability/cell_dependency_closure.hepta"
DOMAIN = b"trnm.cell-dependency-closure.v1\0"
WORK = 13944
PROFILE = ident(123)


def idx(items):
    items = tuple(items)
    return struct.pack(">H", len(items)) + b"".join(struct.pack(">H", item) for item in items)


def row(path, identity, *, role=1, payload=ident(99), size=5, dependencies=()):
    return (struct.pack(">H", len(path)) + path + bytes([role]) + ident(identity) + payload
            + struct.pack(">Q", size) + idx(dependencies))


def closure(*rows, generation=2, profile=PROFILE, roots=(0,), cells=(1,), nested=None):
    inner = release(cells=[ident(i) for i in cells]) if nested is None else nested
    return (b"TCD1" + struct.pack(">Q", generation) + profile + struct.pack(">I", len(inner))
            + inner + idx(roots) + struct.pack(">H", len(rows)) + b"".join(rows))


def result(wire, count):
    nested_len, = struct.unpack_from(">I", wire, 44)
    return (hashlib.sha256(DOMAIN + wire).digest()
            + hashlib.sha256(RELEASE_DOMAIN + wire[48:48+nested_len]).digest()
            + struct.pack("<II", count, count))


def graph(dependency_rows, roots):
    rows = [row(f"cell{i:03}.dat".encode(), i+1, role=(i % 6) + 1, dependencies=deps)
            for i, deps in enumerate(dependency_rows)]
    return closure(*rows, roots=roots, cells=range(1, len(rows)+1))


def chain(count):
    return [(() if i == count-1 else (i+1,)) for i in range(count)]


def cases():
    a = row(b"Base.dat", 1)
    ab = row(b"Weights/Base.dat", 2, role=5, size=MAX_CELL)
    good = closure(a)
    position = 48 + len(release(cells=[ident(1)]))
    records = position + 6
    shared = graph([(1, 2), (3,), (3,), ()], (0,))
    near = graph(chain(16), (0,))
    max_set = graph([()] * 256, range(256))
    dense = graph([tuple(range((i//16+1)*16, (i//16+2)*16)) if i < 240 else ()
                   for i in range(256)], range(16))
    rows = [
        (dense, 0, 256), (good, 0, 1), (shared, 0, 4), (near, 0, 16), (max_set, 0, 256),
        (closure(row(b"README.md", 4), ab, cells=(2, 4), roots=(0, 1)), 0, 2),
        (closure(row(b"COM0.dat", 1)), 0, 1),
        (closure(row(b"A/B/C/D/E/F/G/" + b"H" * 64, 1)), 0, 1),
        (closure(row(b"A" * 64 + b"/" + b"B" * 64 + b"/" + b"C" * 64 + b"/" + b"D" * 60, 1)), 0, 1),
    ]
    bad = [
        (b"XXXX", 3), (good[:4], 2), (good[:47], 2),
        (change(good, 44, struct.pack(">I", CAP+1)), 4),
        (change(good, 44, struct.pack(">I", len(good))), 4),
        (closure(a, nested=b""), 34),
        (closure(a, nested=b"TCR1"), 2),
        (closure(a, nested=release(family=b"")), 36),
        (closure(a, nested=release(family=b"\xff")), 37),
        (closure(a, nested=release(family=b"+", context=bytes(160))), 38),
        (closure(a, nested=release(context=bytes(160))), 39),
        (closure(a, nested=release(cells=[])), 40),
        (closure(a, nested=release(cells=[ident(1)])+b" "), 41),
        (closure(a, nested=release(cells=[ident(1), ident(1)])), 42),
        (closure(a, nested=release(cells=[bytes(32)])), 43),
        (good[:position+1], 2),
        (change(good, position, struct.pack(">H", 257)), 5),
        (good[:position+3], 2),
        (closure(), 6),
        (change(good, position+4, struct.pack(">H", 257)), 6),
        (change(good, records, bytes(2)), 7),
        (change(good, records, struct.pack(">H", 256)), 7),
        (closure(row(b"\xf0\x80", 1, role=7)), 8),
        (closure(row(b"X", 1, role=7))[:-2], 9),
        (good[:records+2+len(b"Base.dat")], 2),
        (good[:-1], 2),
        (change(good, len(good)-2, struct.pack(">H", 257)), 5),
        (good+b"x", 10),
        (closure(a, generation=0, profile=bytes(32), roots=())+b"x", 10),
        (closure(a, generation=0, profile=bytes(32), roots=()), 11),
        (closure(a, profile=bytes(32), roots=()), 12),
        (closure(a, roots=()), 13),
        (closure(a, roots=(1,)), 13),
        (closure(a, roots=(0, 0)), 13),
        (closure(a, ab, roots=(1, 0), cells=(1, 2)), 13),
        (closure(ab, a, cells=(1, 2)), 14),
        (closure(a, a, cells=(1, 2)), 14),
        (closure(a, row(b"base.dat", 2), cells=(1, 2)), 15),
        (closure(a, row(b"Base.dat/sub", 2), cells=(1, 2)), 20),
        (closure(a, row(b"base.dat/sub", 2), cells=(1, 2)), 20),
        (closure(row(b"Data+Value.dat", 1)), 16),
        (closure(row("Dataé.dat".encode(), 1)), 16),
        (closure(row(b"/A/B/C/D/E/F/G/H", 1)), 17),
        (closure(row(b"X/" + b"/" + b"Y", 1)), 18),
        (closure(row(b".Hidden", 1)), 18),
        (closure(row(b"Suffix.", 1)), 18),
        (closure(row(b"A" * 65, 1)), 18),
        (closure(row(b"X/cOn.dat", 1)), 19),
        (closure(row(b"X/Com1.dat", 1)), 19),
        (closure(row(b"X/nuL", 1)), 19),
        (closure(row(b"X/LPT9", 1)), 19),
        (closure(row(b"X", 1, payload=bytes(32))), 21),
        (closure(row(b"X", 1, size=0)), 21),
        (closure(row(b"X", 1, size=MAX_CELL+1)), 21),
        (closure(a, row(b"Z", 1, dependencies=(5,)), cells=(1, 2)), 22),
        (closure(row(b"X", 1, dependencies=(0, 1))), 23),
        (closure(row(b"X", 1, dependencies=(0, 0))), 23),
        (closure(row(b"X", 1, dependencies=(0,))), 24),
        (closure(a, cells=(2,)), 25),
        (closure(a, cells=(1, 2)), 25),
        (closure(row(b"A", 1, dependencies=(1,)), row(b"B", 2, dependencies=(0,)), cells=(1, 3)), 25),
        (graph(chain(17), (0,)), 26),
        (graph([(1,), (0,)], (0,)), 27),
        (graph([(), (2,), (1,)], (0,)), 28),
        # Memoized previous 16-height branch still raises the exact parent
        # height diagnostic when a later root adds another edge.
        (graph(chain(16)+[(0,)], (0, 16)), 26),
        (b"\0"*CAP, 3),
    ]
    return rows + [(data, code, 0) for data, code in bad]


class CellDependencyClosure(NativeManifestChecks, unittest.TestCase):
    source = SRC

    def check_panel(self, rows):
        for emitter, module in self.modules.items():
            for j, (data, code, payload, out_len, work_len) in enumerate(rows):
                with self.subTest(emitter=emitter, row=j):
                    before_out, before_work = MARK*out_len, SCRATCH*work_len
                    got = module.call("f0", [data, before_out, before_work], timeout=35).require_returned()
                    self.assertEqual(got.value, code)
                    self.assertEqual(got.arguments[0], data)
                    self.assertEqual(got.arguments[1], payload+before_out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:], before_work[WORK:])
                    if code in (*range(1, 14), *range(33, 44), 102):
                        self.assertEqual(got.arguments[2], before_work)

    def test_exact_candidate_metadata_and_no_premature_output(self):
        self.check_panel([(data, code, result(data,count) if not code else b"", 81, WORK+3)
                          for data,code,count in cases()])

    def test_private_bounds(self):
        good = closure(row(b"A", 1))
        self.check_panel([
            (good, 0, result(good, 1), 72, WORK),
            (good, 102, b"", 71, WORK),
            (good, 102, b"", 72, WORK-1),
            (b"", 2, b"", 0, 0),
            (good+b"x", 10, b"", 0, 0),
        ])

    @unittest.skipUnless(os.environ.get(ENV), "requires genuine locked Rust+SHA-256")
    def test_original_closure_byte_roundtrip_and_diagnostic_order(self):
        rows = cases()
        over = bytes(CAP+1)
        frame = b"".join(struct.pack("<I", len(data))+data for data,_,_ in rows+[(over,1,0)])
        with tempfile.TemporaryDirectory(prefix="trnm-tcd1-original-") as d:
            binary, proof = build(Path(d), with_closure=True)
            observed = subprocess.run([binary], input=frame, check=True,
                                      capture_output=True, timeout=55)
        self.assertEqual(proof["mode"], "verified-prebuilt-original-sha2")
        self.assertEqual(proof["original_closure_source_sha256"], sha(CLOSURE.read_bytes()))
        self.assertEqual(observed.stderr, b"")
        expected = b"".join(bytes([code]) + (result(data,count) if not code else b"")
                            for data,code,count in rows) + b"\x01"
        self.assertEqual(observed.stdout, expected)
        # The generic ABI driver has a 1-MiB input extent. Only original Rust
        # observes the extra byte over that use ceiling.
        extracted = []
        pos = 0
        for data, code, _ in rows:
            end = pos + (1 if code else 73)
            extracted.append((data, observed.stdout[pos], observed.stdout[pos+1:end], 81, WORK+3))
            pos = end
        self.check_panel(extracted)

"""Real bounded original Int257 factor comparison on an offline matrix fixture."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests.native_support import NativeModule

SOURCE = ordinary.SOURCE.with_name("routed_int257_factor_preparation.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_factor_preparation_reference.rs")
DIM = ordinary.DIM
SLOT = 8336
BASE = 15452
M = 32767


def lawful(ranks, *, large_cancellation=False):
    matrices = [0] * ordinary.PARAMS
    blocks = []
    for e, rank in enumerate(ranks):
        up = [[(e*3+r*5+k*7) % 11-5 for k in range(rank)] for r in range(3)]
        down = [[(e+k*3+c*5) % 13-6 for c in range(DIM)] for k in range(rank)]
        if large_cancellation:
            assert rank == 8
            # First four products add beyond signed i32; later four cancel.
            up = [[M] * rank for _ in range(3)]
            down = [[M if k < 4 else -M] * DIM for k in range(rank)]
            down[-1][-1] += 1  # all last cells become exactly +32767
        for row in range(3):
            for col in range(DIM):
                z = (6+e*3+row)*DIM+col
                matrices[z] = sum(up[row][k]*down[k][col] for k in range(rank))
        data = struct.pack("<IIII", rank, rank, rank, rank)
        for row in up:
            data += struct.pack("<8i", *row, *([-1 << 31] * (8-rank)))
        for j in range(8):
            data += struct.pack("<257i", *(down[j] if j < rank else [-1 << 31]*DIM))
        assert len(data) == SLOT
        blocks.append(data)
    return bytes(range(32)) + struct.pack(f"<{ordinary.PARAMS}i", *matrices) + b"".join(blocks)


def modify(src, *edits):
    out = bytearray(src)
    for offset, value in edits:
        struct.pack_into("<i", out, offset, value)
    return bytes(out)


def delta(expert, row, col):
    return 32 + ((6+expert*3+row)*DIM+col)*4


class RoutedInt257FactorPreparation(unittest.TestCase):
    def test_public_original_exact_factor_positions_and_both_stock_backends(self):
        smallest = lawful((1, 1, 1))
        mixed = lawful((1, 3, 8))
        wide = lawful((8, 8, 8), large_cancellation=True)
        first = BASE
        second = BASE + SLOT
        third = BASE + SLOT*2
        panel = [(smallest, 0, (1, 1, 1)), (mixed, 0, (1, 3, 8)),
                 (wide, 0, (8, 8, 8)), (lawful((8, 2, 5)), 0, (8, 2, 5)),
                 (modify(smallest, (32, M), (32 + 3*DIM*4, -M)), 0, (1, 1, 1))]
        for slot in (first, second, third):
            panel.extend([
                (modify(mixed, (slot, 0), (slot+4, 0)), 9, None),
                (modify(mixed, (slot, 9)), 9, None),
                (modify(mixed, (slot+4, 9), (slot+16, M+1)), 10, None),
                (modify(mixed, (slot+8, 0)), 10, None),
                (modify(mixed, (slot+12, 0)), 10, None),
                (modify(mixed, (slot+16+64, M+1)), 8, None),
                (modify(wide, (slot+112 + (8*DIM-1)*4, -M-1)), 8, None),
            ])
        for e, row, c in ((0,0,0),(1,1,33),(2,2,256)):
            at = delta(e,row,c)
            old = struct.unpack_from("<i", mixed, at)[0]
            panel.append((modify(mixed, (at, old+1)), 11, None))
        # Exact 2^32 would alias the matching original zero if the native
        # contraction were i32. The first compared cell of expert two differs.
        u = [M]*5 + [1,0,0]
        v = [M]*4 + [8,4,0,0]
        self.assertEqual(sum(a*b for a,b in zip(u,v,strict=True)),1<<32)
        wrap = modify(
            wide,
            *((third+16+r*32+k*4,x) for r in range(3) for k,x in enumerate(u)),
            *((third+112+(k*DIM+c)*4,x if not c else 0)
              for k,x in enumerate(v) for c in range(DIM)),
            *((delta(2,r,DIM-1),0) for r in range(3)),
        )
        panel.extend([
            (wrap, 11, None),
            (modify(mixed, (delta(0,0,0), -M), (second, 0)), 11, None),
            (modify(mixed, (delta(0,0,0), -M), (first+112+8, M+1)), 8, None),
            (modify(mixed, (third, 0), (delta(2,2,256), M+1)), 3, None),
            (modify(smallest, (32 + 3*DIM*4, -M-1)), 3, None),
        ])
        with tempfile.TemporaryDirectory(prefix="trnm-int257-factors-original-") as tmp:
            with patch.object(ordinary, "CALLER", CALLER):
                raw = ordinary.locked_ordinary(Path(tmp), b"".join(x[0] for x in panel))
        cursor = 0
        probes = []
        for i, (frame, status, ranks) in enumerate(panel):
            self.assertEqual(len(frame), 40460, i)
            self.assertEqual(raw[cursor], status, i)
            cursor += 1
            payload = b""
            if ranks:
                payload = raw[cursor:cursor+11]
                cursor += 11
                self.assertEqual(payload, struct.pack("<QBBB", 771*sum(ranks), *ranks), i)
            probes.append((frame, status, payload, 17))
        self.assertEqual(cursor, len(raw))
        probes.extend([
            (b"",100,b"",0),
            (wide[:-1],100,b"",17),
            (wide+b"\0",100,b"",17),
            (mixed,102,b"",10),
            (panel[-1][0],3,b"",0),
            (panel[-2][0],3,b"",10),
            (modify(mixed, (third, 0)),9,b"",0),
            (wide,0,struct.pack("<QBBB",18504,8,8,8),11),
        ])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                for begin in range(0,len(probes),5):
                    group = probes[begin:begin+5]
                    work = [b"" if n == 11 else b"\xE1"*7 for _,_,_,n in group]
                    results = native.call_many(
                        [("f0",[f,b"\xD5"*n,w]) for (f,_,_,n),w in zip(group,work,strict=True)],
                        timeout=60)
                    for i, ((frame,s,data,n), w, ans) in enumerate(zip(group,work,results,strict=True),begin):
                        self.assertEqual(ans.require_returned().value,s,(backend,i))
                        self.assertEqual(ans.arguments,[frame,data+b"\xD5"*(n-len(data)),w],i)

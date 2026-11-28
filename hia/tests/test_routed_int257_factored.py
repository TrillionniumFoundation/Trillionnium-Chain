"""Isolated Int257 true factored arithmetic, compared to unchanged public Rust."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_factor_preparation as factors
from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests.native_support import NativeModule

SOURCE = ordinary.SOURCE.with_name("routed_int257_factored.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_factored_reference.rs")
DIM = ordinary.DIM


def feed(owned_model_and_factors, rows):
    return owned_model_and_factors + struct.pack("<I", len(rows)) + b"".join(
        struct.pack("<257i", *row) for row in rows)


def routed(ranks):
    buf = factors.lawful(ranks)
    base = [(32 + 4 * (r * DIM + c), (r * 13 + c * 2) % 19 - 9)
            for r in range(3) for c in range(DIM)]
    router = [(32 + 4 * ((3 + r) * DIM + r), 1) for r in range(3)]
    return factors.modify(buf, *base, *router)


def extreme(sign):
    m = factors.M * sign
    matrix = [m] * (3 * DIM) + [0] * (3 * DIM) + [m] * (9 * DIM)
    model = bytes(range(32)) + struct.pack("<3855i", *matrix)
    header = struct.pack("<IIII", 1, 1, 1, 1)
    up = struct.pack("<8i", m, *([-(1 << 31)] * 7))
    down = struct.pack("<257i", *([1] * DIM))
    pad = struct.pack("<257i", *([-(1 << 31)] * DIM))
    return model + (header + up * 3 + down + pad * 7) * 3


class RoutedInt257Factored(unittest.TestCase):
    def test_fresh_same_frame_actual_factored_inference_and_original_positions(self):
        ranked = routed((1, 3, 8))
        blocked = factors.lawful((8, 8, 8), large_cancellation=True)
        first = ordinary.features((0,8), (1,8), (2,8), (64,-8))
        mid = ordinary.features((1,7), (0,-8), (255,-7))
        end = ordinary.features((2,8), (1,8), (0,-8), (253,3))
        only_last = ordinary.features((0,-8),(1,-8),(2,8),(255,8))
        rows64 = [first, mid, only_last, end] * 16
        plus = [8] * DIM
        minus = [-8] * (DIM-1) + [8]
        rows = [
            (ranked, [first], 0, (1,3,8), [0]),
            (ranked, [mid], 0, (1,3,8), [1]),
            (ranked, [only_last], 0, (1,3,8), [2]),
            (ranked, [only_last, mid, first, end, mid, only_last], 0,
             (1,3,8), [2,1,0,1,1,2]),
            (ranked, rows64, 0, (1,3,8), [0,1,2,1]*16),
            (routed((8,2,1)), [first,mid,only_last], 0, (8,2,1), [0,1,2]),
            (blocked, [plus,minus], 0, (8,8,8), [0,0]),
            (extreme(1), [plus, minus], 0, (1,1,1), [0,0]),
            (extreme(-1), [plus, minus], 0, (1,1,1), [0,0]),
            (ranked, [], 4, (), []),
            (ranked, rows64+[mid], 4, (), []),
            (ranked, rows64[:-1]+[ordinary.features(bias=7)], 7, (), []),
            (ranked, [ordinary.features((255,-9))], 7, (), []),
        ]
        third = factors.BASE + factors.SLOT*2
        target = factors.delta(2,2,256)
        old = struct.unpack_from("<i", ranked, target)[0]
        late = factors.modify(ranked,(target,old+1))
        rows.extend([
            (late, [first], 11, (), []),  # Unselected expert's last cell still checked.
            (late, [ordinary.features(bias=0)], 11, (), []),
            (factors.modify(ranked,(third,9)), [], 9, (), []),
            (factors.modify(ranked,(third+12,9)), [first], 10, (), []),
            (factors.modify(ranked,(third+112+4*(8*DIM-1),32768)), [first], 8, (), []),
            (factors.modify(ranked,(32+4*DIM,32768),(third,0)), [first], 3, (), []),
        ])
        frames = [feed(m,x) for m,x,_,_,_ in rows]
        raw_in = b"".join(struct.pack("<I",len(x))+x for x in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-int257-factored-original-") as tmp:
            with patch.object(ordinary,"CALLER",CALLER):
                exact = ordinary.locked_ordinary(Path(tmp),raw_in)
        pos = 0
        probes = []
        for i,(frame,(_,x,s,ranks,routes)) in enumerate(zip(frames,rows,strict=True)):
            status, count = struct.unpack_from("<BI",exact,pos)
            pos += 5
            payload = exact[pos:pos+count]
            pos += count
            self.assertEqual(status,s,i)
            if s:
                self.assertEqual(payload,b"",i)
            else:
                n = len(x)
                self.assertEqual(count,88+51*n,i)
                g = [[j for j,route in enumerate(routes) if route == e] for e in range(3)]
                self.assertEqual(struct.unpack_from("<6Q",payload),
                                 (1542*n,0,sum(bool(a) for a in g),*(len(a) for a in g)),i)
                self.assertEqual([payload[48+j*50+48] for j in range(n)],routes,i)
                self.assertEqual(payload[48+50*n:48+51*n],bytes(j for a in g for j in a),i)
                adapter = sum(ranks[e] for e in routes)*260
                self.assertEqual(struct.unpack_from("<5Q",payload,48+51*n),
                                 (771*n,771*n,adapter,3*n,1542*n+adapter),i)
                if i in (7,8):
                    bound = 134_737_904 if i == 7 else -134_737_904
                    self.assertEqual(struct.unpack_from("<3q",payload,72),(bound,)*3,i)
                    self.assertEqual(payload[97],0,i)  # exact prediction tie, lowest index
            probes.append((frame,s,payload,88+51*len(x)+5,264+50*len(x)+7))
        self.assertEqual(pos,len(exact))
        f,s,p,o,w = probes[4]
        self.assertEqual(len(f),106256)
        probes.extend([
            (f,s,p,o-5,w-7),
            (f,102,b"",o-6,w-7),
            (f,102,b"",o-5,w-8),
            (f[:-1],100,b"",o,w),
            (f+b"\0",100,b"",o,w),
            (f[:40460]+b"\xff"*4+f[40464:],100,b"",0,0),
            (b"",100,b"",0,0),
            (probes[13][0],11,b"",0,0),
            (probes[11][0],7,b"",0,0),
        ])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as native:
                for start in range(0,len(probes),4):
                    group = probes[start:start+4]
                    actual = native.call_many(
                        [("f0",[raw,b"\xa5"*out,b"\xc7"*work]) for raw,_,_,out,work in group],
                        timeout=60)
                    for i,((raw,s,data,out,work),ans) in enumerate(zip(group,actual,strict=True),start):
                        self.assertEqual(ans.require_returned().value,s,(backend,i))
                        self.assertEqual(ans.arguments[:2],[raw,data+b"\xa5"*(out-len(data))],i)
                        scratch = ans.arguments[2]
                        if s:
                            self.assertEqual(scratch,b"\xc7"*work,i)
                        else:
                            n = (len(raw)-40464)//1028
                            bound = 264+50*n
                            self.assertEqual(scratch[264:bound],data[48:48+50*n],i)
                            # Independent A×x scratch panel: later selected lower ranks
                            # consume only their prefix; unused cells retain earlier data.
                            hidden = [b"\xc7"*8] * 8
                            for j in range(n):
                                route = data[48+j*50+48]
                                slot = factors.BASE+route*factors.SLOT
                                rank = struct.unpack_from("<I",raw,slot)[0]
                                feature = struct.unpack_from("<257i",raw,40464+1028*j)
                                for k in range(rank):
                                    down = struct.unpack_from("<257i",raw,slot+112+1028*k)
                                    hidden[k] = struct.pack("<q",sum(a*b for a,b in zip(down,feature,strict=True)))
                            self.assertEqual(scratch[200:264],b"".join(hidden),i)
                            self.assertEqual(scratch[195:200],b"\xc7"*5,i)
                            self.assertEqual(scratch[bound:],b"\xc7"*(work-bound),i)

"""Pure direct Int257 diagnostics, original Product with no statement/work path."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests.native_support import NativeModule
from hia.tests.routed_int257_direct_derivation import BEGIN, derive

SOURCE = ordinary.SOURCE.with_name("routed_int257_direct.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_direct_reference.rs")
HEADER = struct.Struct("<QQQQQQ")
ROW = struct.Struct("<qqqBBqqq")
WORK = 195
SCRATCH = b"\x57" * (WORK + 7)


def parse(data, n):
    macs, padded, live, *counts = HEADER.unpack_from(data)
    if len(data) != HEADER.size + (ROW.size+1)*n or sum(counts) != n:
        raise ValueError("Invalid direct product extent")
    rows = list(ROW.iter_unpack(data[HEADER.size:HEADER.size+ROW.size*n]))
    cursor = HEADER.size+ROW.size*n
    groups = []
    for count in counts:
        groups.append(tuple(data[cursor:cursor+count]))
        cursor += count
    return macs, padded, live, rows, groups


class RoutedInt257Direct(unittest.TestCase):
    def test_locked_public_direct_with_both_stock_and_canonical_group_order(self):
        original_source = ordinary.SOURCE.read_bytes()
        emitted = SOURCE.read_text()
        self.assertEqual(emitted[emitted.index(BEGIN):], derive(original_source))
        with self.assertRaisesRegex(ValueError, "ordinary row source differs"):
            derive(original_source+b"\n")
        dim, count = ordinary.DIM, ordinary.PARAMS
        model = [((i*13+i//dim*11) % 29)-14 for i in range(count)]
        model[3*dim:6*dim] = [0]*(3*dim)
        for j in range(3):
            model[(3+j)*dim+j] = 19
        features = ordinary.features
        selectors = [features((j,8)) for j in range(3)]
        uneven = [selectors[j] for j in (2,0,2,0,0,2)]
        long = [selectors[(i*7+i//3) % 3] for i in range(64)]
        tie = features((0,5),(1,5))
        high_select = features((0,-8),(1,1),(2,1))
        # One router coordinate at the implicit bias: route 1 for all rows.
        route1 = [0]*count
        route1[5*dim-1] = 7
        extrema = [8]*dim
        one = selectors[0]
        panel = [
            ([0]*count,[one],0),
            (model,uneven,0),(model,long,0),(model,[tie,high_select],0),
            (route1,[one]*64,0),
            ([32767]*count,[extrema],0),([-32767]*count,[extrema],0),
            (model,[selectors[1]],0),(model,[selectors[2]],0),
            (model,[],4),(model,long+[one],4),
            (ordinary.change(model,0,-32768),[],3),
            (ordinary.change(model,count-1,32768),[one],3),
            (model,[features(bias=7)],5),
            (model,[one,features((255,-9))],5),
            (model,[*long[:-1],features((1,9))],5),
        ]
        frames = [ordinary.frame(m, rows) for m,rows,_ in panel]
        stream = b"".join(struct.pack("<I",len(raw))+raw for raw in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-direct-original-") as tmp:
            path = Path(tmp)
            # Reuse the already-qualified locked library attestation, selecting
            # only this dedicated public direct Rust fixture as the caller.
            with patch.object(ordinary, "CALLER", CALLER):
                exact = list(ordinary.records(ordinary.locked_ordinary(path,stream), len(panel)))
        self.assertEqual([s for s,_ in exact], [s for _,_,s in panel])
        for (_, rows, s), (_, raw) in zip(panel, exact, strict=True):
            if s:
                continue
            n = len(rows)
            useful,padded,active,rr,gg = parse(raw,n)
            self.assertEqual((useful,padded), (1542*n,0))
            self.assertEqual(active, sum(bool(g) for g in gg))
            self.assertEqual(sorted(index for g in gg for index in g),list(range(n)))
            self.assertEqual(gg,[tuple(i for i,row in enumerate(rr) if row[3]==g) for g in range(3)])
            for a,b,c,route,pred,p,q,r in rr:
                self.assertEqual(route,(p,q,r).index(max(p,q,r)))
                self.assertEqual(pred,(a,b,c).index(max(a,b,c)))
        self.assertEqual(parse(exact[1][1],6)[4],[(1,3,4),(),(0,2,5)])
        self.assertEqual(parse(exact[4][1],64)[4],[(),tuple(range(64)),()])
        self.assertEqual([row[3] for row in parse(exact[3][1],2)[3]], [0,1])
        self.assertEqual(parse(exact[5][1],1)[3][0][:3],(ordinary.MAX_LOGIT,)*3)
        self.assertEqual(parse(exact[6][1],1)[3][0][:3],(-ordinary.MAX_LOGIT,)*3)
        self.assertEqual(ordinary.SOURCE.read_bytes(), original_source)
        good = frames[0]
        result = exact[0][1]
        probes = [(raw,s,value,max(60,len(value)+7),len(SCRATCH))
                  for raw,(s,value) in zip(frames,exact,strict=True)]
        probes += [
            (b"",100,b"",0,0),(good[:-1],100,b"",100,WORK),
            (good+b"\0",100,b"",100,WORK),(b"\xff"*4+good[4:],100,b"",100,WORK),
            (good,102,b"",98,WORK),(good,102,b"",99,WORK-1),
            (good,0,result,99,WORK),(frames[2],102,b"",3311,WORK),
            (frames[-1],5,b"",0,0),
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                for at in range(0,len(probes),5):
                    rows = probes[at:at+5]
                    observed = native.call_many(
                        [("f0",[raw,b"\xa5"*out,SCRATCH[:w]]) for raw,_,_,out,w in rows],
                        timeout=60)
                    for i, ((raw,s,value,out,w),actual) in enumerate(zip(rows,observed,strict=True),at):
                        self.assertEqual(actual.require_returned().value,s,i)
                        self.assertEqual(actual.arguments[:2],[raw,value+b"\xa5"*(out-len(value))],i)
                        if s:
                            self.assertEqual(actual.arguments[2],SCRATCH[:w],i)
                        else:
                            self.assertEqual(actual.arguments[2][WORK:],SCRATCH[WORK:w],i)

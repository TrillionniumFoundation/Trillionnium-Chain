"""Exact original grouped Product and observable compact scratch; no timing claim."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests import test_routed_int257_direct as direct
from hia.tests.native_support import NativeModule

SOURCE = ordinary.SOURCE.with_name("routed_int257_grouped.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_grouped_reference.rs")
WORK = 67536
SUMS = 200
GATHER = 1744
SCRATCH = b"\x57" * (WORK + 7)


def scratch_after(initial, product, features):
    """Independently compute final scratch while leaving every padding byte alone."""
    a = bytearray(initial)
    _,_,_,rows,groups = direct.parse(product,len(features))
    a[:3] = bytes(map(len,groups))
    for expert, members in enumerate(groups):
        if not members:
            continue
        begin = 3 + expert*64
        a[begin:begin+len(members)] = bytes(members)
        packed = [features[i][k] for k in range(ordinary.DIM) for i in members]
        sums = [rows[i][k] for k in range(3) for i in members]
        a[GATHER:GATHER+4*len(packed)] = struct.pack(f"<{len(packed)}i",*packed)
        a[SUMS:SUMS+8*len(sums)] = struct.pack(f"<{len(sums)}q",*sums)
    return bytes(a)


class RoutedInt257Grouped(unittest.TestCase):
    def test_locked_public_grouped_products_compact_gather_scatter_and_atomicity(self):
        dim,count = ordinary.DIM,ordinary.PARAMS
        model = [((i*13+i//dim*11)%29)-14 for i in range(count)]
        model[3*dim:6*dim] = [0]*(3*dim)
        for j in range(3):
            model[(3+j)*dim+j] = 19
        mk = ordinary.features
        choose = lambda j,k: mk((j,8),(3+k%251,-8+k%17),(255,((3*k)%17)-8))
        same = [choose(1,k) for k in range(64)]
        varied = [choose((k*7+k//3)%3,k) for k in range(64)]
        unequal = [choose(j,k) for k,j in enumerate((2,0,2,0,0,2,0,0,0))]
        small = [choose(j,k) for k,j in enumerate((1,0,1))]
        extremes = [8]*dim
        panel = [
            ([0]*count,[mk((0,3))],0),
            (model,unequal,0),(model,same,0),(model,varied,0),(model,small,0),
            (model,[mk((0,6),(1,6)),mk((0,-6),(1,2),(2,2))],0),
            ([32767]*count,[extremes],0),([-32767]*count,[extremes],0),
            (model,[choose(2,3)],0),
            (model,[],4),(model,[*varied,choose(0,0)],4),
            (ordinary.change(model,0,-32768),[],3),
            (ordinary.change(model,count-1,32768),[choose(0,0)],3),
            (model,[mk(bias=0)],5),(model,[mk((255,-9))],5),
            (model,[*varied[:-1],mk((1,9))],5),
        ]
        frames = [ordinary.frame(m,rows) for m,rows,_ in panel]
        items = b"".join(struct.pack("<I",len(raw))+raw for raw in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-grouped-original-") as tmp:
            with patch.object(ordinary,"CALLER",CALLER):
                exact = list(ordinary.records(ordinary.locked_ordinary(Path(tmp),items),len(panel)))
        self.assertEqual([s for s,_ in exact],[s for _,_,s in panel])
        self.assertEqual(direct.parse(exact[1][1],9)[4],[(1,3,4,6,7,8),(),(0,2,5)])
        self.assertEqual(direct.parse(exact[2][1],64)[4],[(),tuple(range(64)),()])
        self.assertEqual(direct.parse(exact[6][1],1)[3][0][:3],(ordinary.MAX_LOGIT,)*3)
        self.assertEqual(direct.parse(exact[7][1],1)[3][0][:3],(-ordinary.MAX_LOGIT,)*3)
        self.assertEqual([row[3] for row in direct.parse(exact[5][1],2)[3]],[0,1])
        for (_,rows,s),(_,payload) in zip(panel,exact,strict=True):
            if s:
                continue
            useful,padded,active,values,groups = direct.parse(payload,len(rows))
            self.assertEqual((useful,padded,active),(1542*len(rows),0,sum(bool(g) for g in groups)))
            self.assertEqual(groups,[tuple(i for i,row in enumerate(values) if row[3]==g) for g in range(3)])
        probes = [(raw,s,val,max(len(val)+7,100),len(SCRATCH),features)
                  for raw,(s,val),(_,features,_) in zip(frames,exact,panel,strict=True)]
        a1 = frames[0]
        probes += [
            (b"",100,b"",0,0,[]),(a1[:-1],100,b"",100,WORK,[]),
            (a1+b"\0",100,b"",100,WORK,[]),(b"\xff"*4+a1[4:],100,b"",100,WORK,[]),
            (a1,102,b"",98,WORK,[]),(a1,102,b"",99,WORK-1,[]),
            (frames[2],102,b"",3311,WORK,[]),
            (frames[2],0,exact[2][1],3312,WORK,same),
            (frames[-1],5,b"",0,0,[]),
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as kernel:
                for start in range(0,len(probes),4):
                    sub = probes[start:start+4]
                    measured = kernel.call_many(
                        [("f0",[raw,b"\xa5"*out,SCRATCH[:work]]) for raw,_,_,out,work,_ in sub],
                        timeout=60)
                    for i, ((raw,s,val,out,work,features),actual) in enumerate(zip(sub,measured,strict=True),start):
                        self.assertEqual(actual.require_returned().value,s,i)
                        self.assertEqual(actual.arguments[:2],[raw,val+b"\xa5"*(out-len(val))],i)
                        expected = SCRATCH[:work] if s else scratch_after(SCRATCH[:work],val,features)
                        self.assertEqual(actual.arguments[2],expected,i)

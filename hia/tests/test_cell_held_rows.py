"""Original frozen execute held recurrence, stock dual and immutable trainer rows."""
from functools import lru_cache
from pathlib import Path
import random
import struct
import tempfile
import unittest

from hia.tests.cell_held_rows_original import locked_original
from hia.tests.native_support import NativeModule

SOURCE=Path(__file__).parents[1]/"src/state/cell_held_rows.hepta"
PRODUCT=67368952
LOGIT=134746096
ROW=2192
TRAIN=2096
FIT=48+64*ROW
PROJECT=40+64*(TRAIN+24)
MARK=b"\xad"
SCRATCH=b"\xa9\x13\xfd"


def fields(mask=7,label=0,base=(0,0,0),router=(0,0,0),delta=((0,0,0),)*3,features=(0,)*256+(8,)):
    return struct.pack("<2Q272q",mask,label,*base,*router,*(v for d in delta for v in d),*features)


def wire(rem,memory,rows):
    return b"CTRW0001"+struct.pack("<2Q3q",len(rows),rem,*memory)+b"".join(rows)


def trainer(w,n):
    return struct.unpack_from("<2Q3q",w,40+n*TRAIN)


@lru_cache(maxsize=1)
def cases():
    z=fields()
    b=PRODUCT
    choices=tuple(fields(mask=m,label=m%3,router=(-6,-6,-6),
         delta=((11,12,13),(21,22,23),(31,32,33))) for m in range(1,8))
    bounds=(fields(mask=4,label=2,base=(b,-b,0),router=(b,b,-b),delta=((0,0,0),(0,0,0),(b,-b,0))),
            fields(mask=4,label=1,base=(-b,b,0),router=(b,b,-b),delta=((0,0,0),(0,0,0),(-b,b,0))))
    negative_floor=fields(mask=2,label=1,base=(1,-1,0),router=(9,-8,9))
    output=[
        ("zero_remaining",wire(0,(-8192,-1,8192),(z,choices[-1]))),
        ("active_ties",wire(7,(0,0,0),choices)),
        ("mask_and_bounds",wire((1<<64)-1,(8192,-8192,0),bounds)),
        ("negative_floor",wire(2,(-1,1,-2),(negative_floor,z))),
        ("prefix_then_inactive",wire(1,(-1,1,-2),(negative_floor,choices[-1],bounds[0]))),
        ("only_one",wire(4,(3,-4,5),(fields(mask=6,router=(9,-2,6),label=1),))),
    ]
    rng=random.Random(2297)
    full=tuple(fields(mask=1+(j%7),label=j%3,base=(b if j%2 else -b,-b if j%2 else b,j-37),
         router=(b-j,-b+j,b-j),delta=((b,-b,-7),(-b,b,22),(b,-b,-38)),
         features=((8,-8)*64+(0,)*128+(8,))) for j in range(64))
    output.append(("physical_max",wire((1<<64)-1,(-8192,8192,-1),full)))
    for k in range(15):
        rows=[]
        n=1+rng.randrange(13)
        for i in range(n):
            words=lambda n:tuple(rng.randint(-b,b) for _ in range(n))
            f=[0]*256
            for j in rng.sample(range(256),8):
                f[j]=rng.randint(-8,8)
            rows.append(fields(mask=rng.randint(1,7),label=rng.randint(0,2),base=words(3),router=words(3),
                               delta=(words(3),words(3),words(3)),features=(*f,8)))
        output.append((f"bounded-{k:02d}",wire(rng.randrange(n+4),tuple(rng.randint(-8192,8192) for _ in range(3)),rows)))
    return output


@lru_cache(maxsize=1)
def original_cases():
    requests=cases()
    data=b"".join(struct.pack("<I",len(w))+w for _,w in requests)
    with tempfile.TemporaryDirectory(prefix="trnm-cell-held-rows-") as temp:
        encoded,pins=locked_original(Path(temp),data)
    at=0
    obs=[]
    for tag,w in requests:
        [n]=struct.unpack_from("<I",encoded,at)
        at+=4
        obs.append((tag,w,encoded[at:at+n]))
        at+=n
    if at!=len(encoded):
        raise ValueError("Extra original observation")
    return obs,pins


class CellHeldRowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.machines={role:cls.enterClassContext(NativeModule(SOURCE,backend=role,byte_exports=("f0",)))
                      for role in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.machines.values()})!=2:
            raise ValueError("Both stock backends require actual emitted artifacts")

    def invoke(self,m,frame,want=b"",code=0,*,n=None,w=SCRATCH):
        o=MARK*(len(want)+7 if n is None else n)
        x=m.call("f0",[frame,o,w],timeout=30).require_returned()
        self.assertEqual((x.abi_status,x.value,x.arguments),(0,code,[frame,want+o[len(want):],w]))

    def test_original_full_execute_recurrence_and_trainer_projection(self):
        rows,pins=original_cases()
        self.assertEqual(len(pins["frozen_execution"]),64)
        saved={tag:value for tag,_,value in rows}
        self.assertEqual(struct.unpack("<2Q3q",saved["zero_remaining"]),(0,0,-8192,-1,8192))
        self.assertEqual([trainer(saved["active_ties"],i)[0] for i in range(7)],[0,1,0,2,0,1,0])
        self.assertEqual(trainer(saved["mask_and_bounds"],0),(2,2,LOGIT,-LOGIT,0))
        neg=saved["negative_floor"]
        trace=40+2*TRAIN
        self.assertEqual(trainer(neg,0),(1,1,0,0,-2))
        self.assertEqual(struct.unpack_from("<3q",neg,trace),(-1,0,-2050))
        pre=saved["prefix_then_inactive"]
        self.assertEqual(struct.unpack_from("<2Q3q",pre),(1,0,-1,0,-2050))
        self.assertEqual(len(pre),40+TRAIN+24)
        self.assertEqual(len(saved["physical_max"]),PROJECT)
        for tag,frame,value in rows:
            for role,m in self.machines.items():
                with self.subTest(tag=tag,stock=role):
                    self.invoke(m,frame,value)

    def test_private_domains_and_physical_capacity_are_atomic(self):
        obs,_=original_cases()
        _,full,result=next(x for x in obs if x[0]=="physical_max")
        self.assertEqual((len(full),len(result)),(FIT,PROJECT))
        def patch(f,pos,v):
            return f[:pos]+struct.pack("<Q",v&((1<<64)-1))+f[pos+8:]
        zero=next(f for t,f,_ in obs if t=="zero_remaining")
        bad=[full[:47],full[:-1],full+b"x",b"INVALID!"+full[8:],patch(full,8,65),wire(0,(0,0,0),()),
             patch(full,24,-8193),patch(full,40,8193),patch(full,48,0),patch(full,48,8),patch(full,56,3),
             patch(full,64,-PRODUCT-1),patch(full,72,PRODUCT+1),patch(full,48+136,9),
             patch(full,48+136+128*8,1),patch(full,len(full)-8,7),patch(zero,len(zero)-8,7),
             patch(zero,48+ROW+16,PRODUCT+1)]
        for m in self.machines.values():
            self.invoke(m,full,result,n=PROJECT,w=b"")
            self.invoke(m,full,code=102,n=PROJECT-1,w=b"")
            self.invoke(m,zero,code=102,n=39,w=b"")
            for malformed in bad:
                self.invoke(m,malformed,code=100,n=19)

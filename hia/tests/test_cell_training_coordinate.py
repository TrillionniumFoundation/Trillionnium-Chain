"""The actual frozen masked training update versus both stock native emitters."""
from functools import lru_cache
from pathlib import Path
import random
import struct
import tempfile
import unittest

from hia.tests.cell_training_coordinate_original import reference
from hia.tests.native_support import NativeModule

SOURCE=Path(__file__).parents[1]/"src/model/cell_training_coordinate.hepta"
WIRE=struct.Struct("<QQqqqQQQQQ")
RESULT=struct.Struct("<Qqqqqq")
STEP_MAX=(1<<64)-1
M=(1<<63)-1
G=137988390912
P=32767
MARK=b"\xa5"
SCRATCH=b"\xc1\x7e\x54"
THRESH=65535*4096-1


def frame(*, mask=1, step=17, weight=0, old=0, raw=0, lr=1, den=1,
          mom=0, mden=1, clip=1<<40):
    return WIRE.pack(mask,step,weight,old,raw,lr,den,mom,mden,clip)


def out(weight,moment,raw,clipped,delta,step=18):
    return RESULT.pack(step,weight,moment,raw,clipped,delta)


@lru_cache(maxsize=1)
def cases():
    controls=[
        (frame(mask=0,step=STEP_MAX-1,weight=-32767,old=-M,raw=G,lr=1<<20,
               den=1,mom=65535,mden=65536,clip=1),
         0,out(-32767,-M,0,0,0,STEP_MAX)),
        (frame(mask=0,step=STEP_MAX,weight=32767,old=M,raw=-G),201,b""),
        (frame(step=STEP_MAX,weight=32767,old=-M,raw=-G,mom=65535,mden=65536),201,b""),
        (frame(old=-5,raw=-2,clip=1,mom=1,mden=2,lr=1,den=2),
         0,out(1,-3,-2,-1,-1)),
        (frame(old=5,raw=2,clip=1,mom=1,mden=2,lr=1,den=2),
         0,out(-1,3,2,1,1)),
        (frame(old=-3,raw=2,mom=2,mden=3),0,out(0,0,2,2,0)),
        (frame(old=3,raw=-2,mom=2,mden=3),0,out(0,0,-2,-2,0)),
        (frame(weight=-32766,old=5,mom=1,mden=2,lr=3,den=4),0,out(-32767,2,0,0,1)),
        (frame(weight=-32766,old=7,mom=1,mden=2,lr=3,den=4),203,b""),
        (frame(weight=32766,old=-5,mom=1,mden=2,lr=3,den=4),0,out(32767,-2,0,0,-1)),
        (frame(weight=32766,old=-7,mom=1,mden=2,lr=3,den=4),203,b""),
        (frame(weight=-P,old=3,mom=1,mden=2,lr=1,den=2),0,out(-P,1,0,0,0)),
        (frame(weight=-P,old=4,mom=1,mden=2,lr=1,den=2),203,b""),
        (frame(weight=P,old=-3,mom=1,mden=2,lr=1,den=2),0,out(P,-1,0,0,0)),
        (frame(weight=P,old=-4,mom=1,mden=2,lr=1,den=2),203,b""),
        (frame(weight=P,old=2,raw=THRESH-1,lr=1<<20,den=1<<32,mom=1,mden=2),
         0,out(-P,THRESH,THRESH-1,THRESH-1,2*P)),
        (frame(weight=P,raw=THRESH+1,lr=1<<20,den=1<<32),203,b""),
        (frame(weight=-P,old=-2,raw=-(THRESH-1),lr=1<<20,den=1<<32,mom=1,mden=2),
         0,out(P,-THRESH,-(THRESH-1),-(THRESH-1),-2*P)),
        (frame(weight=-P,raw=-(THRESH+1),lr=1<<20,den=1<<32),203,b""),
        (frame(old=M,raw=G,lr=0,mom=65535,mden=65536),
         0,out(0,M*65535//65536+G,G,G,0)),
        (frame(old=-M,raw=-G,lr=0,mom=65535,mden=65536),
         0,out(0,-(M*65535//65536+G),-G,-G,0)),
        (frame(old=M,raw=0,lr=1<<20,den=1<<32,mom=65535,mden=65536),203,b""),
        (frame(old=-M,raw=0,lr=1<<20,den=1<<32,mom=65535,mden=65536),203,b""),
        (frame(),0,out(0,0,0,0,0)),
        (frame(weight=1,old=44,raw=4,clip=3,mom=0,mden=65536,lr=0),0,out(1,3,4,3,0)),
    ]
    rng=random.Random(0x719C7)
    corpus=[]
    for _ in range(64):
        md=rng.randrange(1,65537)
        raw=2*rng.randrange(-40000000,40000001)
        corpus.append((frame(mask=rng.choice((0,1,1,1)),step=rng.getrandbits(64),
                         weight=rng.randrange(-P,P+1),old=rng.randrange(-M,M+1)
                         if rng.randrange(4)==0 else rng.randrange(-200000000,200000001),
                         raw=raw,lr=rng.choice((0,1,7,1<<20)),den=rng.choice((1,997,1<<32)),
                         mom=rng.randrange(md),mden=md,clip=rng.choice((1,7,1093,1<<40))),
                       None,None))
    return controls+corpus


def original_cases():
    with tempfile.TemporaryDirectory(prefix="trnm-train-coordinate-rust-") as temp:
        return reference(Path(temp),b"".join(f for f,_,_ in cases()))


class CellTrainingCoordinateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native={k:cls.enterClassContext(NativeModule(SOURCE,backend=k,byte_exports=("f0",)))
                    for k in ("direct","selfhost")}
        if len({v.artifact_sha256 for v in cls.native.values()})!=2:
            raise ValueError("Both genuine stock emitters required")

    def verify(self,native,items,capacity=53):
        for values in (items[i:i+32] for i in range(0,len(items),32)):
            args=[("f0",[f,MARK*capacity,SCRATCH]) for f,_,_ in values]
            for call,(f,code,want) in zip(native.call_many(args),values,strict=True):
                g=call.require_returned()
                self.assertEqual((g.abi_status,g.value),(0,code))
                self.assertEqual(g.arguments,[f,want+MARK*(capacity-len(want)),SCRATCH])

    def test_original_frozen_training_update_on_both_stock_backends(self):
        raw,info=original_cases()
        self.assertEqual(len(info["original_train_sha256"]),64)
        at=0
        rows=[]
        for f,known,want in cases():
            code=raw[at]
            at+=1
            n=RESULT.size if code==0 else 0
            value=raw[at:at+n]
            at+=n
            if known is not None:
                self.assertEqual((code,value),(known,want))
            rows.append((f,code,value))
        self.assertEqual(at,len(raw))
        self.assertTrue({0,201,203}<=set(status for _,status,_ in rows))
        for key,native in self.native.items():
            with self.subTest(stock=key):
                self.verify(native,rows)

    def test_typed_domains_precedence_canaries_and_no_scratch(self):
        legal=frame()
        invalid=[legal[:-1],legal+b"x",frame(mask=2),frame(weight=P+1),frame(weight=-P-1),
                 frame(old=-M-1),frame(raw=G+2),frame(raw=-G-2),frame(raw=3),frame(raw=-3),
                 frame(lr=(1<<20)+1),frame(den=0),frame(den=(1<<32)+1),frame(mom=1,mden=1),
                 frame(mden=0),frame(mden=65537),frame(clip=0),frame(clip=(1<<40)+1),
                 frame(mask=2,step=STEP_MAX)]
        for native in self.native.values():
            self.verify(native,[(f,100,b"") for f in invalid])
            self.verify(native,[(legal,102,b""),(frame(step=STEP_MAX),201,b""),
                                (frame(weight=P,raw=-2),203,b"")],capacity=47)
            packed=out(0,0,0,0,0)
            got=native.call("f0",[legal,MARK*48,b""]).require_returned()
            self.assertEqual((got.abi_status,got.value,got.arguments),(0,0,[legal,packed,b""]))

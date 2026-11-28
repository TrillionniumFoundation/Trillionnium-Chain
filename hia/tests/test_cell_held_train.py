"""One native held-row training call versus the complete frozen execute body."""
from functools import lru_cache
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import cell_held_rows_original as source
from hia.tests.native_support import NativeModule
from hia.tests.test_cell_held_rows import fields, PRODUCT

HERE=Path(__file__).parent
SOURCE=HERE.parent/"src/state/cell_held_train.hepta"
HARNESS=HERE/"rust_cell_held_train_reference.rs"
E=3084
START=74128
TRAIN_AT=262144
MAX_IN=214416
MAX_OUT=160936
MAX_ARENA=396288
OUT=b"\x71"
WORK=b"\x92"
UMAX=(1<<64)-1
GMAX=137988390912


def frame(remaining, memory, rows, *, step=None, weights=(), moments=(), masks=(), settings=(1,2,1,2,1)):
    values=[[0]*E for _ in range(3)]
    for plane,records in zip(values,(weights,moments,masks),strict=True):
        for pos,v in records:
            plane[pos]=v
    return (b"CTRX0001"+struct.pack("<9Q",len(rows),0,int(step is not None),0 if step is None else step,*settings)
            +struct.pack(f"<{3*E}q",*(v for plane in values for v in plane))
            +struct.pack("<Q3q",remaining,*memory)+b"".join(rows))


@lru_cache(maxsize=1)
def fixtures():
    first=fields(mask=7,label=0,base=(8193,0,0),router=(5,5,-11),features=(1,)+(0,)*255+(8,))
    last=fields(mask=7,label=2,base=(-2048,0,8191),router=(-3,-3,6))
    moments=((0,5),(E-1,-5),(3*257+7,-77))
    masks=((0,1),(E-1,1))
    p=PRODUCT
    full=tuple(fields(mask=1<<(j%3),label=0,base=(-p,p,0),router=(p,p,p),
        delta=((-p,p,0),)*3,features=(8,-8)+(0,)*254+(8,)) for j in range(64))
    return [
        ("signed-carry",frame(2,(0,0,0),(first,last),step=(1<<63)-1,
            weights=((0,-32766),(E-1,32766)),moments=moments,masks=masks)),
        ("late-weight",frame(2,(0,0,0),(first,last),step=20,
            weights=((0,-32766),(E-1,32767)),moments=moments,masks=masks)),
        ("early-step",frame(2,(0,0,0),(first,last),step=UMAX,
            weights=((0,-32766),(E-1,32767)),moments=moments,masks=masks)),
        ("dry-some",frame(0,(-8192,-1,8192),(first,last),step=UMAX,
            weights=((0,-32766),(E-1,32767)),moments=moments,masks=masks)),
        ("dry-none",frame(0,(-1,1,-2),(first,last),weights=((0,90),))),
        ("negative-floor-prefix",frame(1,(-1,1,-2),(
            fields(mask=2,label=1,base=(1,-1,0),router=(9,-8,9)),last))),
        ("initialize",frame(1,(0,0,0),(first,),masks=((0,1),))),
        ("full-64",frame(UMAX,(-8192,8192,-1),full,step=UMAX-1,
            moments=((0,-((1<<63)-1)),(1,(1<<63)-1)),masks=((0,1),(1,1)),
            settings=(0,1<<32,65535,65536,1<<40))),
    ]


@lru_cache(maxsize=1)
def original_cases():
    frames=fixtures()
    stream=b"".join(struct.pack("<I",len(f))+f for _,f in frames)
    with tempfile.TemporaryDirectory(prefix="trnm-held-cell-train-") as d, patch.object(source,"HARNESS",HARNESS):
        data,pin=source.locked_original(Path(d),stream)
    at=0
    out=[]
    for tag,f in frames:
        code=data[at]
        at+=1
        report=rows=b""
        if code==0:
            n,rn=struct.unpack_from("<II",data,at)
            at+=8
            report=data[at:at+n]
            at+=n
            rows=data[at:at+rn]
            at+=rn
        out.append((tag,f,code,report,rows))
    assert at==len(data)
    return out,pin


def size(active):
    return 154280+104*active


def arena_size(active):
    return TRAIN_AT+2096*active if active else size(0)


class CellHeldTrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock={role:cls.enterClassContext(NativeModule(SOURCE,backend=role,byte_exports=("f0",)))
                   for role in ("direct","selfhost")}
        if len({v.artifact_sha256 for v in cls.stock.values()})!=2:
            raise ValueError("Both stock backends require genuine machine artifacts")

    def invoke(self,m,f,code,expected,*,out,work):
        o=OUT*out
        w=WORK*work
        result=m.call("f0",[f,o,w],timeout=30).require_returned()
        self.assertEqual((result.abi_status,result.value),(0,code))
        self.assertEqual(result.arguments[:2],[f,expected+o[len(expected):]])
        return result.arguments[2]

    def test_frozen_full_execute_matches_same_loan_active_projection_and_update(self):
        rows,pin=original_cases()
        self.assertEqual(len(pin["frozen_execution"]),64)
        self.assertEqual(len(rows),8)
        observed={tag:(f,c,r,a) for tag,f,c,r,a in rows}
        self.assertEqual({c for _,_,c,_,_ in rows},{0,201,203})
        _,_,mirrored,prepared=observed["signed-carry"]
        bw=30848+2*80
        self.assertEqual(struct.unpack_from("<q",mirrored,0),(2,))
        self.assertEqual(struct.unpack_from("<4Q",mirrored,bw),(1,1<<63,1,1))
        self.assertEqual(struct.unpack_from("<5q",mirrored,bw+32),(-32767,3,2,1,1))
        self.assertEqual(struct.unpack_from("<5q",mirrored,bw+123392-40),(32767,-3,-16,-1,-1))
        self.assertEqual(struct.unpack_from("<2Q3q",mirrored,bw+123392),(2,0,1536,0,2048))
        self.assertEqual(struct.unpack_from("<2Q3q",prepared,0),(0,0,8193,0,0))
        self.assertEqual(struct.unpack_from("<2Q3q",prepared,2096),(2,2,0,0,8191))
        self.assertEqual(struct.unpack_from("<4Q",observed["dry-some"][2],30848),(1,UMAX,0,0))
        self.assertEqual(struct.unpack_from("<4Q",observed["dry-none"][2],30848),(0,0,0,0))
        full,_,full_report,full_rows=observed["full-64"]
        self.assertEqual((len(full),len(full_report),len(full_rows)),(MAX_IN,MAX_OUT,64*2096))
        self.assertEqual(struct.unpack_from("<2q",full_report,8),(-GMAX,GMAX))
        for tag,f,code,report,a in rows:
            count=({ "late-weight":2,"early-step":2}.get(tag,len(a)//2096))
            for backend,m in self.stock.items():
                with self.subTest(case=tag,stock=backend):
                    work=arena_size(count)
                    scratch=self.invoke(m,f,code,report,out=size(count)+11,work=work+13)
                    self.assertEqual(scratch[work:],WORK*13)
                    if code==0:
                        self.assertEqual(scratch[:len(report)],report)
                        if count:
                            self.assertEqual(scratch[len(report):TRAIN_AT],WORK*(TRAIN_AT-len(report)))
                            self.assertEqual(scratch[TRAIN_AT:work],a)
                    elif code==201:
                        self.assertEqual(scratch,WORK*(work+13))
                    else:
                        self.assertEqual(scratch[:bw],mirrored[:bw])
                        self.assertEqual(scratch[bw+32:bw+72],mirrored[bw+32:bw+72])
                        self.assertEqual(scratch[bw+123392-40:bw+123392],WORK*40)
                        self.assertEqual(scratch[TRAIN_AT:work],prepared)

    def test_exact_disjoint_regions_and_refusal_priority(self):
        observed={tag:(f,c,r,a) for tag,f,c,r,a in original_cases()[0]}
        full,_,report,prepared=observed["full-64"]
        late=observed["late-weight"][0]
        step=observed["early-step"][0]
        dry,_,dry_report,_=observed["dry-none"]
        def replace(f,i,x):
            return f[:i]+struct.pack("<Q",x&UMAX)+f[i+8:]
        invalid=[full[:START-1],full[:-1],full+b"x",replace(full,8,65),
                 replace(full,16,1),replace(full,len(full)-8,7),replace(dry,32,9),
                 replace(dry,80+8*E,1),replace(full,74104,-8193),replace(step,80+16*E,2)]
        for m in self.stock.values():
            actual=self.invoke(m,full,0,report,out=MAX_OUT,work=MAX_ARENA)
            self.assertEqual(actual[TRAIN_AT:],prepared)
            self.assertEqual(self.invoke(m,dry,0,dry_report,out=size(0),work=size(0)),dry_report)
            for f in invalid:
                self.assertEqual(self.invoke(m,f,100,b"",out=17,work=19),WORK*19)
            self.assertEqual(self.invoke(m,step,201,b"",out=17,work=19),WORK*19)
            self.assertEqual(self.invoke(m,full,102,b"",out=MAX_OUT,work=MAX_ARENA-1),WORK*(MAX_ARENA-1))
            self.assertEqual(self.invoke(m,full,102,b"",out=MAX_OUT-1,work=MAX_ARENA)[:MAX_OUT],report)
            self.invoke(m,late,203,b"",out=size(2)-1,work=arena_size(2))

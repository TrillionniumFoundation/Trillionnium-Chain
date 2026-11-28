"""Shared dense Grouped tile versus original unchanged sequential grouped outputs."""
import hashlib
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests import test_routed_int257_grouped as grouped
from hia.tests import test_routed_int257_direct as direct
from hia.tests.native_support import NativeModule

SOURCE = ordinary.SOURCE.with_name("routed_int257_grouped_multibatch.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_grouped_multibatch_reference.rs")
STAGE = grouped.WORK


def shim(source, target):
    # Preserve old source and machine identity; derive only the exact ABI
    # redirection needed to use one mutable scratch loan for staging.
    name = "rig_" + target
    text = re.search(r"(?ms)^fn "+name+r"\(.*?^end\n",source)[0]
    text = re.sub(r"\bo(?:_initial|[12])?(?::mutbuf)?,","",text)
    text = text.replace("rig_experts","rgm_experts").replace("rig_scatter","rgm_scatter")
    if target == "scatter":
        for n in ("dst","pos_y","pos_z"):
            text = text.replace(f"call({n},",f"call(w1,{n},")
        text = text.replace("buffer.store(d_us,","buffer.store(w1,d_us,").replace(
            '{"value":48}','{"value":67536}')
    return text


def frame(model, children):
    lengths = [len(x) for x in children]
    return ordinary.frame(model,[r for child in children for r in child])+struct.pack(
        "<5I",len(lengths),*lengths,*([0]*(4-len(lengths))))


def segments(data,children):
    sizes = struct.unpack_from("<4Q",data)
    assert sizes == tuple([48+51*len(x) for x in children]+[0]*(4-len(children)))
    at=32
    out=[]
    for n in sizes[:len(children)]:
        out.append(data[at:at+n])
        at+=n
    assert at==len(data)
    return out


def global_product(children,products):
    local = [direct.parse(p,len(x))[3] for x,p in zip(children,products,strict=True)]
    all_rows = [r for b in local for r in b]
    groups = [tuple(i for i,v in enumerate(all_rows) if v[3] == e) for e in range(3)]
    return (struct.pack("<6Q",1542*len(all_rows),0,sum(map(bool,groups)),*map(len,groups))+
            b"".join(direct.ROW.pack(*v) for v in all_rows)+bytes(i for g in groups for i in g))


class RoutedInt257GroupedMultibatch(unittest.TestCase):
    def test_exact_original_per_child_grouped_and_one_shared_feature_major_tile(self):
        old = grouped.SOURCE.read_text("ascii")
        self.assertEqual(hashlib.sha256(old.encode("ascii")).hexdigest(),
                         "49b0c63840fc5acec31b08b92aeac99ff4ae14d49ac35be09e8667e1c5b66afe")
        new = SOURCE.read_text("ascii")
        for suffix in ("experts","scatter"):
            self.assertIn(shim(old,suffix),new)
        dim=ordinary.DIM
        model=[((i*13+i//dim*11)%29)-14 for i in range(ordinary.PARAMS)]
        model[3*dim:6*dim]=[0]*(3*dim)
        for i in range(3):
            model[(3+i)*dim+i]=19
        choose=lambda e,i:ordinary.features((e,8),(3+i%251,i%17-8),(255,(3*i)%17-8))
        a,b,c=(choose(e,e) for e in range(3))
        same=[choose(2,i) for i in range(64)]
        varied=[choose((i*i+2*i+i//4)%3,i) for i in range(64)]
        z=[8]*dim
        bad=ordinary.features((255,-9))
        bias=ordinary.features(bias=7)
        fits=[varied[:32],varied[32:]]
        panel=[
            (model,[[a]],0),(model,[[b],[c]],0),(model,[[a,c],[c,b,a],[b]],0),
            (model,[same],0),(model,fits,0),
            (model,[varied[:16],varied[16:32],varied[32:48],varied[48:]],0),
            (model,[varied[:1],varied[1:8],varied[8:25],varied[25:]],0),
            (model,[same[:61],[b],[c],[a]],0),
            ([32767]*ordinary.PARAMS,[[z],[z,z]],0),
            ([-32767]*ordinary.PARAMS,[[z],[z]],0),
            ([0]*ordinary.PARAMS,[[a,c],[z,b]],0),
            (model,[[a],[b,c],[],[a]],4),
            (model,[[a],[b],[c],[]],4),
            (model,[[a],[b],[],[bad]],4),
            (model,[[a],[b],[c],[a,bias]],5),
            (model,[[bad],[],[a]],5),
            (model,[varied[:1],varied[1:8],varied[8:25],varied[25:-1]+[bad]],5),
            (ordinary.change(model,ordinary.PARAMS-1,32768),[[a],[]],3),
        ]
        frames=[frame(m,children) for m,children,_ in panel]
        raw=b"".join(struct.pack("<I",len(f))+f for f in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-int257-grouped-multi-original-") as tmp:
            with patch.object(ordinary,"CALLER",CALLER):
                captured=ordinary.locked_ordinary(Path(tmp),raw)
        exact=list(ordinary.records(captured,len(panel)))
        self.assertEqual([v[0] for v in exact],[v[2] for v in panel])
        probes=[]
        for f,(_,children,s),(code,data) in zip(frames,panel,exact,strict=True):
            n=sum(map(len,children))
            minimum=32+48*len(children)+51*n
            if not s:
                self.assertEqual(len(data),minimum)
                for p,rows in zip(segments(data,children),children,strict=True):
                    useful,padded,live,values,groups=direct.parse(p,len(rows))
                    self.assertEqual((useful,padded,live),(1542*len(rows),0,sum(map(bool,groups))))
                    self.assertEqual(groups,[tuple(i for i,v in enumerate(values) if v[3]==j) for j in range(3)])
            probes.append((f,children,code,data,minimum+3,STAGE+50*n+7))
        f,children,s,data,o,w=probes[5]
        self.assertEqual((len(f),len(data),w-7),(81236,3488,70736))
        # Preserve both no-partial output/scratch and exact result at finite boundaries.
        probes.extend([
            (f,children,s,data,o-3,w-7),(f,children,102,b"",o-4,w-7),(f,children,102,b"",o-3,w-8),
            (f[:-1],[],100,b"",0,0),(f+b"\0",[],100,b"",0,0),
            (b"",[],100,b"",0,0),(b"\xff"*4+f[4:],[],100,b"",0,0),
            (f[:-20]+struct.pack("<5I",5,16,16,16,16),[],100,b"",0,0),
            (frames[0][:-20]+struct.pack("<5I",1,1,1,0,0),[],100,b"",0,0),
            (frames[0][:-20]+struct.pack("<5I",1,2,0,0,0),[],100,b"",0,0),
            (frame(model,[same,[a]]),[],4,b"",0,0),
            (frames[16],[],5,b"",0,0),
        ])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as kernel:
                for i in range(0,len(probes),4):
                    block=probes[i:i+4]
                    results=kernel.call_many([("f0",[f,b"\xA5"*o,b"\x57"*w])
                                              for f,_,_,_,o,w in block],timeout=60)
                    for j,((f,children,s,data,o,w),result) in enumerate(zip(block,results,strict=True),i):
                        self.assertEqual(result.require_returned().value,s,(backend,j))
                        self.assertEqual(result.arguments[:2],[f,data+b"\xA5"*(o-len(data))],j)
                        scratch=result.arguments[2]
                        if s:
                            self.assertEqual(scratch,b"\x57"*w,j)
                            continue
                        p=segments(data,children)
                        rows=[r for child in children for r in child]
                        shared=grouped.scratch_after(b"\x57"*STAGE,global_product(children,p),rows)
                        self.assertEqual(scratch[195:STAGE],shared[195:],j)
                        staging=b"".join(d[48:48+50*len(x)] for d,x in zip(p,children,strict=True))
                        self.assertEqual(scratch[STAGE:STAGE+len(staging)],staging,j)
                        self.assertEqual(scratch[STAGE+len(staging):],b"\x57"*(w-STAGE-len(staging)),j)

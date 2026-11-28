"""One immutable model/factor frame reused across bounded genuine original batches."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_factored as factored
from hia.tests import test_routed_int257_factor_preparation as factors
from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests.native_support import NativeModule

SOURCE = ordinary.SOURCE.with_name("routed_int257_factored_multibatch.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_factored_multibatch_reference.rs")


def encode(model, batches):
    counts = [len(b) for b in batches]
    return model + struct.pack("<5I",len(batches),*counts,*([0]*(4-len(counts)))) + b"".join(
        struct.pack("<257i",*r) for b in batches for r in b)


def split(raw, batches):
    sizes = struct.unpack_from("<4Q",raw)
    if sizes != tuple([88+51*len(b) for b in batches]+[0]*(4-len(batches))):
        raise ValueError("bad segment lengths")
    at = 32
    results=[]
    for n in sizes[:len(batches)]:
        results.append(raw[at:at+n])
        at += n
    if at != len(raw):
        raise ValueError("unconsumed segment bytes")
    return results


class RoutedInt257FactoredMultibatch(unittest.TestCase):
    def test_locked_original_once_prepared_across_all_batches_with_atomic_late_rejections(self):
        model = factored.routed((1,3,8))
        a = ordinary.features((0,8),(1,8),(2,8))
        b = ordinary.features((1,7),(255,8))
        c = ordinary.features((2,8),(255,-8))
        rows = [a,b,c,b] * 16
        bad = ordinary.features((255,9))
        bias = ordinary.features(bias=7)
        delta = factors.delta(2,2,256)
        value = struct.unpack_from("<i",model,delta)[0]
        inconsistent = factors.modify(model,(delta,value+1))
        rank_error = factors.modify(model,(factors.BASE+2*factors.SLOT,9))
        panel = [
            (model,[[a]],0), (model,[[a],[c]],0),
            (model,[[a,b,c],[c,b],[b]],0),
            (model,[rows[:1],rows[1:8],rows[8:32],rows[32:]],0),
            (model,[rows],0),
            (model,[[a]*61,[b],[c],[a]],0),
            (factored.extreme(1),[[[8]*257],[[8]*257]],0),
            (factored.extreme(-1),[[[8]*257]],0),
            (model,[[a],[],[c]],4), (model,[[a],[b],[c],[]],4),
            (model,[[a],[b],[c],[a,bad]],7),
            (model,[[a],[b],[c],rows[:-4]+[bias]],7),
            (model,[[bad],[]],7), (model,[[],[bad]],4),
            (inconsistent,[[a],[b],[c]],11),
            (inconsistent,[[a],[bad]],11),
            (rank_error,[[a],[]],9),
            (factors.modify(rank_error,(32,32768)),[[a],[bad]],3),
        ]
        frames = [encode(m,batches) for m,batches,_ in panel]
        original = b"".join(struct.pack("<I",len(x))+x for x in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-int257-multi-original-") as tmp:
            with patch.object(ordinary,"CALLER",CALLER):
                exact = ordinary.locked_ordinary(Path(tmp),original)
        pos=0
        probes=[]
        for i,(raw,(_,batches,s)) in enumerate(zip(frames,panel,strict=True)):
            status,size=struct.unpack_from("<BI",exact,pos)
            pos += 5
            data=exact[pos:pos+size]
            pos += size
            self.assertEqual(status,s,i)
            total = sum(map(len,batches))
            o = 32+88*len(batches)+51*total
            w = 264+50*total
            if s:
                self.assertEqual(data,b"",i)
            else:
                self.assertEqual(len(data),o,i)
                parts = split(data,batches)
                for j,(p,batch) in enumerate(zip(parts,batches,strict=True)):
                    g = struct.unpack_from("<3Q",p,24)
                    self.assertEqual(sum(g),len(batch),(i,j))
                    self.assertEqual(sorted(p[48+50*len(batch):48+51*len(batch)]),
                                     list(range(len(batch))),(i,j))
            probes.append((raw,s,data,o+5,w+13,batches))
        self.assertEqual(pos,len(exact))
        raw,s,data,o,w,bs = probes[3]
        self.assertEqual((len(raw),len(data),w-13),(106272,3648,3464))
        unchanged_limit = (probes[10][0],7,b"",0,0,probes[10][-1])
        extra = encode(model,[rows,[a]])
        probes.extend([
            (raw,s,data,o-5,w-13,bs),
            (raw,102,b"",o-6,w-13,bs),
            (raw,102,b"",o-5,w-14,bs),
            (raw[:-1],100,b"",o,w,bs),
            (raw+b"\0",100,b"",o,w,bs),
            (b"",100,b"",0,0,[]),
            (raw[:40460]+b"\x05\0\0\0"+raw[40464:],100,b"",o,w,bs),
            (frames[0][:40468]+b"\x01\0\0\0"+frames[0][40472:],100,b"",0,0,[]),
            (extra,4,b"",0,0,[]),
            unchanged_limit,
        ])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as native:
                for start in range(0,len(probes),4):
                    group=probes[start:start+4]
                    replies=native.call_many([("f0",[f,b"\xa2"*o,b"\xb8"*w])
                                              for f,_,_,o,w,_ in group],timeout=60)
                    for i,((f,s,data,o,w,bs),reply) in enumerate(zip(group,replies,strict=True),start):
                        self.assertEqual(reply.require_returned().value,s,(backend,i))
                        self.assertEqual(reply.arguments[:2],[f,data+b"\xa2"*(o-len(data))],i)
                        work=reply.arguments[2]
                        if s:
                            self.assertEqual(work,b"\xb8"*w,i)
                        else:
                            parts=split(data,bs)
                            staged=b"".join(p[48:48+50*len(b)] for p,b in zip(parts,bs,strict=True))
                            extent=264+len(staged)
                            self.assertEqual(work[264:extent],staged,i)
                            self.assertEqual(work[extent:],b"\xb8"*(w-extent),i)

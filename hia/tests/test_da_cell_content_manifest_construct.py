"""Original in-memory TCM2 construction of deterministic inert supplied bytes."""
from collections import Counter
from hashlib import sha512
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_cell_content_closure_observe import (
    DOMAIN, PINNED, ROOT, WORK, alter, original, pins, put, tcm2,
)

SOURCE = ROOT / "hia/src/data_availability/cell_content_manifest_construct.hepta"
WITNESS = Path(__file__).with_name("rust_da_cell_content_manifest_construct_reference.rs")
CAP = 1 << 20
OUT = b"\x93" * 457
ALIASES = bytes(range(160))
NORMAL = tcm2()[-213:-72]


def frame(family, inert, *, context=NORMAL, reads=1, size=None, aliases=ALIASES):
    if size is None:
        size=len(inert)+1
    assert len(context)==141 and len(aliases)==160
    return context+struct.pack(">QQB",reads,size,len(family))+family+aliases+inert


def matrix():
    x=b"inert example"
    base=frame(b"safe",x)
    yield base,0
    yield frame(b"safe",x,reads=(1<<64)-1,size=(1<<64)-1),0
    yield frame(b"x",b""),10
    yield frame(b"x",b"",size=0),30
    yield frame(b"x",x,reads=0),30
    yield frame(b"x",x,size=1),35
    yield frame(b"x",x,size=len(x)),35
    yield frame(b"x",x,context=put(NORMAL,0,b"FAKE")),31
    yield frame(b"x",x,context=alter(NORMAL,68,255)),31
    yield frame(b"x",x,context=put(NORMAL,4,bytes(64))),32
    yield frame(b"x",x,context=put(NORMAL,69,bytes(64))),32
    yield frame(b"a/b",x,size=1),35
    yield frame(b"a/b",b"",context=alter(NORMAL,68,3)),8
    yield frame(b"safe",b"",context=alter(NORMAL,68,3)),9
    for typ in (1,2,3,5):
        yield frame(b"x",x,context=alter(NORMAL,68,typ)),9
    for bad in (b"\xc3",b"\xed\xa0\x80",b"\xf4\x90\x80\x80"):
        yield frame(bad,x),5
        yield frame(bad,x,size=1),35
    for bad in (b"",b"a"*65,b"a"*255,b" ",b"a/b","é".encode(),b"\0"):
        yield frame(bad,x),8
    for n in (0,1,141,317):
        yield bytes(n),100
    yield alter(base,157,255),100
    # Both SHA-512 padding boundaries, different bytes and synthetic metadata.
    for n in (1,2,15,16,31,32,63,64,65,111,112,127,128,129,248,249,
              250,251,255,256,257,511,512,513,1023,1024,4095,4096):
        fam=b"K"*max(1,n%65)
        context=tcm2(size=1,generation=n<<48,instance=bytes([n%255+1])*64,
                     profile=bytes([n%253+1])*64)[-213:-72]
        inert=bytes([n%256])*n
        yield frame(fam,inert,context=context,aliases=bytes([n%255])*160),0
    maximum=CAP-318-64
    yield frame(b"z"*64,bytes(range(256))*(maximum//256)+bytes(maximum%256)),0


class DaCellContentManifestConstruct(unittest.TestCase):
    def test_exact_original_held_inert_bytes_construct_tcm2_both_stock(self):
        cases=list(matrix())
        stream=b"".join(struct.pack("<I",len(raw))+raw for raw,_ in cases)
        self.assertEqual(pins(),PINNED)
        with tempfile.TemporaryDirectory(prefix="trnm-tcm2-inert-constructor-") as t:
            captured, proof=original(Path(t),stream,WITNESS)
        self.assertEqual(pins(),PINNED)
        parsed=[]
        offset=0
        for j,(raw,status) in enumerate(cases):
            actual,length=struct.unpack_from("<BH",captured,offset)
            offset+=3
            wire=captured[offset:offset+length]
            offset+=length
            self.assertEqual(actual,status,j)
            if status:
                self.assertEqual(length,0)
            else:
                f=raw[157]
                end=318+f
                b=raw[end:]
                h=raw[:141]+struct.pack(">Q",len(b))
                self.assertEqual(wire,b"TCM2"+raw[157:end]+h+sha512(DOMAIN+h+b).digest())
                self.assertEqual(len(wire),378+f)
            parsed.append((raw,OUT,WORK,status,wire))
        self.assertEqual(offset,len(captured))
        self.assertEqual(len(cases[-1][0]),CAP)
        print(json.dumps(dict(proof,original_matches=len(cases),statuses=Counter(s for _,s in cases),
                              original_pins=PINNED),sort_keys=True),flush=True)
        normal,_,_,_,wanted=parsed[0]
        controls=[(normal,OUT[:len(wanted)-1],WORK,102,b""),
                  (normal,OUT,WORK[:131231],102,b""),
                  (normal,b"",b"",102,b""),
                  (normal,OUT[:len(wanted)],WORK[:131232],0,wanted),
                  (cases[6][0],b"",b"",35,b"")]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend,max_input_extent=CAP+(backend=="selfhost")) as n:
                group=parsed+controls
                if backend=="selfhost":
                    group+=[(cases[-1][0]+b"z",OUT,WORK,100,b"")]
                small=[x for x in group if len(x[0])<40000]
                large=[x for x in group if len(x[0])>=40000]
                batches=[small[i:i+7] for i in range(0,len(small),7)]+[[x] for x in large]
                for batch in batches:
                    result=n.call_many([("f0",list(x[:3])) for x in batch],timeout=60)
                    for (raw,out,w,code,wire),got in zip(batch,result,strict=True):
                        self.assertEqual(got.require_returned().value,code,(backend,len(raw)))
                        self.assertEqual(got.arguments[0],raw)
                        self.assertEqual(got.arguments[1],wire+out[len(wire):])
                        if code:
                            self.assertEqual(got.arguments[2],w)
                        else:
                            self.assertEqual(got.arguments[2][1544:131168],w[1544:131168])
                            self.assertEqual(got.arguments[2][131232:],w[131232:])
                print(json.dumps(dict(backend=backend,native_elf=n.artifact_sha256,
                                      original_matches=len(cases),abi_controls=len(group)-len(cases)),
                                 sort_keys=True),flush=True)

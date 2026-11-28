"""Independent expected CCH1 matched to actual declared TCM2/TCC2 observations."""
from collections import Counter
from hashlib import sha512
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_cell_content_closure_observe import (
    DOMAIN, OUT, PINNED, ROOT, WORK, alter, close, context_from_manifest, original, pins, put, tcm2,
)
from hia.tests.test_da_cell_content_closure_value import matrix as closure_matrix

SOURCE = ROOT / "hia/src/data_availability/cell_content_claim_verify.hepta"
WITNESS = Path(__file__).with_name("rust_da_cell_content_claim_verify_reference.rs")


def claim(context,declaration):
    header = context + struct.pack(">Q",len(declaration))
    return header + sha512(DOMAIN+header+declaration).digest()


def frame(context, reads, size, expected, mode, declaration):
    assert len(context)==141 and len(expected)==213
    return context+struct.pack(">QQ",reads,size)+expected+bytes([mode])+declaration


def matrix():
    m=tcm2()
    c=context_from_manifest(m)
    zero=bytes(64)
    max_u64=(1<<64)-1
    for mode in (0,1):
        fixture=close(m) if mode else m
        p=claim(c,fixture)
        n=len(fixture)
        for limits in ((1,n+1),(17,n+2),(max_u64,max_u64)):
            yield frame(c,*limits,p,mode,fixture),0
        for location in (4,67,69,132,133,140,141,148,149,160,191,212):
            changed=alter(p,location,p[location]^1)
            yield frame(c,1,n+1,changed,mode,fixture),38
        for k in (1,2,4,5):
            yield frame(c,1,n+1,alter(p,68,k),mode,fixture),38
        other=close(tcm2(digest=bytes(64))) if mode else tcm2(digest=bytes(64))
        yield frame(c,1,n+1,p,mode,other),38
        yield frame(c,1,n+1,claim(c,other),mode,other),0
        yield frame(c,1,n+1,claim(c,close(m) if not mode else m),mode,fixture),38
        yield frame(c,1,n+1,put(p,0,b"XXXX"),mode,fixture),36
        yield frame(c,1,n+1,alter(p,68,255),mode,fixture),36
        yield frame(c,1,n+1,put(p,4,zero),mode,fixture),37
        yield frame(c,1,n+1,put(p,69,zero),mode,fixture),37
        yield frame(put(c,0,b"XXXX"),1,n+1,p,mode,fixture),31
        yield frame(put(c,69,zero),1,n+1,p,mode,fixture),32
        yield frame(alter(c,68,4),1,1,p,mode,fixture),33
        yield frame(alter(c,140,1),1,1,p,mode,fixture),34
        yield frame(c,0,n+1,p,mode,fixture),30
        yield frame(c,1,0,p,mode,fixture),30
        yield frame(c,1,n,p,mode,fixture),35
        yield frame(c,1,n,alter(p,212,0),mode,fixture),35
        yield frame(put(c,69,zero),0,0,put(p,4,zero),mode,fixture),37
        yield frame(c,1,n+1,p,mode,fixture+b"x"),22 if mode else 4
        changed=alter(fixture,0,0)
        yield frame(put(c,69,zero),0,0,put(p,4,zero),mode,changed),21 if mode else 2
        for size in range(1,65,3):
            mf=tcm2(b"b"*size,generation=size<<55,instance=bytes([size])*64)
            ctx=context_from_manifest(mf)
            body=close(mf) if mode else mf
            exact=claim(ctx,body)
            yield frame(ctx,1,len(body)+1,exact,mode,body),0
            yield frame(ctx,1,len(body)+1,alter(exact,212,exact[-1]^255),mode,body),38
    exemplar=claim(c,close(m))
    for bad,s in closure_matrix():
        if s:
            yield frame(c,0,0,put(exemplar,4,zero),1,bad),s
    for z in (0,1,156,370):
        yield bytes(z),100
    yield frame(c,1,1,exemplar,2,m),100


class DaCellContentClaimVerify(unittest.TestCase):
    def test_actual_original_claim_verify_over_declared_tcm2_and_tcc2_both_stock(self):
        cases=list(matrix())
        data=b"".join(struct.pack("<I",len(raw))+raw for raw,_ in cases)
        self.assertEqual(pins(),PINNED)
        with tempfile.TemporaryDirectory(prefix="trnm-declared-claim-verify-") as t:
            observed, proof=original(Path(t),data,WITNESS)
        self.assertEqual(pins(),PINNED)
        self.assertEqual(len(observed),len(cases))
        for j,((_,want),have) in enumerate(zip(cases,observed,strict=True)):
            self.assertEqual(want,have,j)
        print(json.dumps(dict(proof,original_matches=len(cases),
                              statuses=Counter(observed),original_pins=PINNED),
                         sort_keys=True),flush=True)
        admitted=cases[0][0]
        probes=[(raw,OUT,WORK,s) for raw,s in cases]
        probes.extend([(admitted,b"",WORK[:131232],0),
                       (admitted,OUT,WORK[:131231],102),
                       (admitted,OUT,b"",102),
                       # A mismatch must be computed; short scratch wins.
                       (cases[3][0],OUT,b"",102)])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as n:
                for start in range(0,len(probes),7):
                    batch=probes[start:start+7]
                    got=n.call_many([("f0",list(r[:3])) for r in batch],timeout=60)
                    for j,((raw,out,w,status),v) in enumerate(zip(batch,got,strict=True),start):
                        self.assertEqual(v.require_returned().value,status,(backend,j))
                        self.assertEqual(v.arguments[0],raw)
                        self.assertEqual(v.arguments[1],out)
                        if status in (0,38):
                            independently=claim(raw[:141],raw[371:])
                            self.assertEqual(v.arguments[2][131168:131232],independently[-64:])
                            self.assertEqual(v.arguments[2][1544:131168],w[1544:131168])
                            self.assertEqual(v.arguments[2][131232:],w[131232:])
                        else:
                            self.assertEqual(v.arguments[2],w)
                print(json.dumps(dict(backend=backend,original_matches=len(cases),
                                      abi_controls=len(probes)-len(cases),native_elf=n.artifact_sha256),
                                 sort_keys=True),flush=True)

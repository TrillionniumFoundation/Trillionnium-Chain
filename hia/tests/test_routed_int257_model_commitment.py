"""Actual original PreparedModel commitment on typed owned synthetic models."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests.native_support import NativeModule

SOURCE = ordinary.SOURCE.with_name("routed_int257_model_commitment.hepta")
CALLER = Path(__file__).with_name("rust_routed_int257_model_commitment_reference.rs")
WORK = 32272
PREIMAGE = 1208
SCRATCH = b"\x57" * (WORK + 7)
DOMAIN = b"pon-routed-int257-grouped-model-v0"
PROFILE = b"pon-routed-int257-grouped-research-v0"
NUMERIC = b"signed-i32-coeff-i64-accum-bias8-lowest-argmax"
GOLDEN = bytes.fromhex("b5d026559147238e4ea30289a88e15f20ab05880d613989705008b28b7829352")


def frame(version, matrices):
    return version + struct.pack(f"<{ordinary.PARAMS}i",*matrices)


def reference_preimage(version, matrices):
    body = version + struct.pack(">QQQ",257,3,3) + struct.pack(f">{len(matrices)}q",*matrices)
    assert len(body) == 30896
    parts = [DOMAIN,PROFILE,NUMERIC,body]
    return b"trnm.domain.hash.v1" + b"".join(struct.pack(">Q",len(x))+x for x in parts)


class RoutedInt257ModelCommitment(unittest.TestCase):
    def test_locked_public_model_commitment_and_both_stock_exact_transcripts(self):
        dim,count = ordinary.DIM,ordinary.PARAMS
        version = b"\x04"*32
        golden = [0]*count
        # Model setup from the original committed public research fixture.
        for r in range(3):
            for k in range(dim):
                golden[r*dim+k] = (r*17+k*7)%19-9
                for e in range(3):
                    golden[(6+e*3+r)*dim+k] = (e*11+r*5+k*13)%17-8
        for r in range(3):
            golden[(3+r)*dim+r] = 1
        zero = [0]*count
        alternating = [32767 if k%2 else -32767 for k in range(count)]
        panel = [(version,golden,0),(b"\0"*32,zero,0),(b"\xff"*32,zero,0),
                 (bytes(range(32)),alternating,0),
                 (version,[32767]*count,0),(version,[-32767]*count,0)]
        for matrix in range(5):
            begin = matrix*3*dim
            end = begin+3*dim-1
            panel.extend([
                (version,ordinary.change(zero,begin,1),0),
                (version,ordinary.change(zero,end,-1),0),
                (version,ordinary.change(zero,begin,-32768),3),
                (version,ordinary.change(zero,end,32768),3),
            ])
        panel += [(version,ordinary.change(golden,count-1,-(1<<31)),3),
                  (version,ordinary.change(golden,count-1,(1<<31)-1),3)]
        frames = [frame(version,m) for version,m,_ in panel]
        wire = b"".join(struct.pack("<I",len(raw))+raw for raw in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-model-commitment-original-") as tmp:
            with patch.object(ordinary,"CALLER",CALLER):
                exact = list(ordinary.records(ordinary.locked_ordinary(Path(tmp),wire),len(panel)))
        self.assertEqual([s for s,_ in exact],[s for _,_,s in panel])
        self.assertEqual(exact[0],(0,GOLDEN))
        self.assertEqual(len({v for s,v in exact if not s}),16)
        probes = []
        for raw,(s,digest),(v,coeffs,_) in zip(frames,exact,panel,strict=True):
            transcript = reference_preimage(v,coeffs) if not s else b""
            if not s:
                self.assertEqual(len(transcript),31064)
                self.assertEqual(digest,hashlib.sha256(transcript).digest())
            probes.append((raw,s,digest,39,len(SCRATCH),transcript))
        preimage = reference_preimage(version,golden)
        first = frames[0]
        probes += [
            (b"",100,b"",0,0,b""),
            (first[:-1],100,b"",39,WORK,b""),
            (first+b"\0",100,b"",39,WORK,b""),
            (first,102,b"",31,WORK,b""),
            (first,102,b"",39,WORK-1,b""),
            (frames[-1],3,b"",0,0,b""),
            (first,0,GOLDEN,32,WORK,preimage),
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as kernel:
                for start in range(0,len(probes),5):
                    rows = probes[start:start+5]
                    observed = kernel.call_many(
                        [("f0",[raw,b"\xa5"*out,SCRATCH[:w]]) for raw,_,_,out,w,_ in rows],
                        timeout=60)
                    for i, ((raw,s,digest,out,w,transcript),ret) in enumerate(zip(rows,observed,strict=True),start):
                        self.assertEqual(ret.require_returned().value,s,i)
                        self.assertEqual(ret.arguments[:2],[raw,digest+b"\xa5"*(out-len(digest))],i)
                        if s:
                            self.assertEqual(ret.arguments[2],SCRATCH[:w],i)
                        else:
                            self.assertEqual(ret.arguments[2][PREIMAGE:WORK],transcript,i)
                            self.assertEqual(ret.arguments[2][WORK:],SCRATCH[WORK:w],i)

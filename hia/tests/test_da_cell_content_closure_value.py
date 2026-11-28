"""Exact frozen TCC2 canonical value, without observing any declared contents."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_cell_content_manifest_value import CAP, PINS, alter, tcm2
from hia.tests.test_da_protocol_context import ROOT, locked_reference

SOURCE = ROOT / "hia/src/data_availability/cell_content_closure_value.hepta"
CALLER = Path(__file__).with_name("rust_da_cell_content_closure_value_reference.rs")
CLAIM = 213
PROFILE = bytes(range(64))
PINNED = {**PINS, "trnm-data-availability/src/cell/content_v2/closure.rs":
          "1c0382b63872465491a52bc40fa475d22e77e9ab44de16df4c2f5fd5f4bd8f1b"}
OUT_MARK = b"\xa5"
WORK = b"\x72" * 11


def sha(x):
    return hashlib.sha256(x).hexdigest()


def pins():
    base = ROOT / "trillionnium/crates"
    return {p: sha((base / p).read_bytes()) for p in PINNED}


def put(raw, at, data):
    return raw[:at] + data + raw[at + len(data):]


def claim(**kwargs):
    return tcm2(**kwargs)[-CLAIM:]


def close(manifest, deps=None):
    dep = [claim()] * 5 if deps is None else deps
    assert len(dep) == 5 and all(len(x) == CLAIM for x in dep)
    return (b"TCC2" + struct.pack(">I", len(manifest)) + manifest
            + b"".join(bytes([i]) + x for i, x in enumerate(dep, 1)))


def matrix():
    manifest = tcm2()
    small = close(manifest)
    large_manifest = tcm2(b"n"*64, size=CAP, generation=(1<<64)-1)
    large = close(large_manifest, [claim(size=CAP, generation=(1<<64)-1)]*5)
    assert len(small) == 1457 and len(large) == 1520
    yield small, 0
    yield large, 0
    for i in range(1,65):
        profile = bytes([i]) * 64
        m = tcm2(b"m"*(i-1) + b"7", profile=profile, size=(CAP if i%2 else i),
                 generation=i << 56, aliases=bytes([i])*160, digest=bytes([64-i])*64)
        d = [claim(profile=profile, size=(CAP if role%2 else role),
                   generation=role+i, instance=bytes([i+role])*64,
                   digest=bytes([i-role if i>role else 88])*64) for role in range(1,6)]
        yield close(m,d), 0
    for x in (b"",small[:-1],large+b"z",large+bytes(100)):
        yield x,20
    for x in (alter(small,0,0),alter(large,3,51),b"TCD1"+large[4:]):
        yield x,21
    for m in (0,378,380,442,443,(1<<32)-1):
        yield put(small,4,struct.pack(">I",m)),22
    yield small+b"z",22
    yield large[:-1],22
    for m,status in [
        (alter(manifest,0,0),2),(alter(manifest,4,0),3),
        (alter(manifest,4,2),4),(tcm2(b"\xc3"),5),(tcm2(kind=6),6),
        (tcm2(profile=bytes(64)),7),(tcm2(b"/"),8),(tcm2(kind=3),9),(tcm2(size=0),10),
    ]:
        yield close(m),status
    start = 8 + len(manifest)
    for idx in range(5):
        offset = start+idx*(CLAIM+1)
        for role in (0, (idx+1)%5+1, 255):
            yield alter(small,offset,role),23
        at = offset+1
        for dep,status in [
            (claim(claim_magic=b"CTH1"),6), (claim(kind=255),6),
            (claim(instance=bytes(64)),7), (claim(profile=bytes(64)),7),
            *((claim(kind=k),26) for k in (1,2,3,5)),
            (claim(profile=b"\x01"+PROFILE[1:]),27),
            (claim(profile=PROFILE[:-1]+b"\xaa"),27),
            (claim(size=0),28), (claim(size=CAP+1),28), (claim(size=(1<<64)-1),28),
        ]:
            yield put(small,at,dep),status
        # Correct purpose and profile; different instance/generation/digest
        # are independent declarations, not trusted proof claims.
        yield put(small,at,claim(instance=bytes([idx+2])*64,
                                  generation=(1<<64)-1,digest=bytes(64),size=1)),0
    last = start+4*(CLAIM+1)
    early_policy = put(small,start+1,claim(kind=3,size=CAP+1))
    yield alter(early_policy,last,0),23
    yield put(early_policy,last+1,claim(claim_magic=b"ZZZZ")),6
    yield put(early_policy,last+1,claim(instance=bytes(64))),7
    yield put(early_policy,last+1,claim(profile=PROFILE[:-1]+b"\x01")),26
    early_size = put(small,start+1,claim(size=0))
    yield put(early_size,last+1,claim(kind=3)),28
    early_profile = put(small,start+1,claim(profile=b"\x01"+PROFILE[1:],size=0))
    yield put(early_profile,last+1,claim(kind=3)),27
    yield alter(close(tcm2(kind=3)),last,0),9
    yield alter(put(small,start+1,claim(claim_magic=b"ZZZZ")),last,0),6


class DaCellContentClosureValue(unittest.TestCase):
    def test_public_original_tcc2_canonical_declarations_direct_and_selfhost(self):
        cases = list(matrix())
        self.assertEqual(pins(),PINNED)
        stream = b"".join(struct.pack("<I",len(f))+f for f,_ in cases)
        with tempfile.TemporaryDirectory(prefix="trnm-tcc2-original-") as tmp:
            observed = locked_reference(Path(tmp),stream,CALLER)
        self.assertEqual(pins(),PINNED)
        offset = 0
        proof = []
        for raw,predicted in cases:
            status,n = struct.unpack_from("<BI",observed,offset)
            offset += 5
            data = observed[offset:offset+n]
            offset += n
            self.assertEqual(status,predicted)
            self.assertEqual(data,b"" if status else raw)
            proof.append((raw,status,data,len(raw)+6))
        self.assertEqual(offset,len(observed))
        self.assertEqual({s for _,s in cases},{0,*range(2,11),*range(20,24),26,27,28})
        print(json.dumps(dict(original_rows=len(cases),status_counts=Counter(s for _,s in cases),
                              input_sha256=sha(stream),original_stdout_sha256=sha(observed),
                              oracle_source_sha256=sha(CALLER.read_bytes()),source_pins=PINNED),
                         sort_keys=True),flush=True)
        min_wire,max_wire = cases[0][0],cases[1][0]
        controls = [(min_wire,102,b"",len(min_wire)-1),
                    (max_wire,102,b"",len(max_wire)-1),
                    (max_wire,0,max_wire,len(max_wire)),
                    (min_wire,102,b"",0),
                    (alter(min_wire,0,0),21,b"",0),
                    (close(tcm2(size=0)),10,b"",0)]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as n:
                group=proof+controls
                for start in range(0,len(group),12):
                    batch=group[start:start+12]
                    got=n.call_many([("f0",[raw,OUT_MARK*out_len,WORK])
                                     for raw,_,_,out_len in batch],timeout=60)
                    for i,((raw,status,data,out_len),res) in enumerate(zip(batch,got,strict=True),start):
                        self.assertEqual(res.require_returned().value,status,(backend,i))
                        self.assertEqual(res.arguments,[raw,data+OUT_MARK*(out_len-len(data)),WORK],i)
                print(json.dumps(dict(backend=backend,original_matches=len(cases),
                                      abi_controls=len(controls),native_elf=n.artifact_sha256),
                                 sort_keys=True),flush=True)

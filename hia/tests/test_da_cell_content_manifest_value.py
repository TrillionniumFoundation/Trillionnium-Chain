"""Exact original TCM2 declaration decode/encode, with no payload or ownership."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_protocol_context import ROOT, locked_reference

SOURCE = ROOT / "hia/src/data_availability/cell_content_manifest_value.hepta"
CALLER = Path(__file__).with_name("rust_da_cell_content_manifest_value_reference.rs")
CAP = 64 * 1024**3
PINS = {
    "trnm-data-availability/src/cell/content_v2.rs":
        "e3cfc3e57583f0fe016879c5c1d8b5123200883c870bb212ed5195df04983a06",
    "trnm-data-availability/src/cell/manifest.rs":
        "cf945af731b8172d6b093bded63d546ac3f3a15756524e739a50187dcdaebdc5",
    "trnm-protocol/src/content_commitment.rs":
        "1e85bb848addea4287ae4f8d5f26dcc1aece9919106dfd73c531ba0b96eeb5e1",
    "trnm-protocol/src/crypto_profile.rs":
        "1913065a325e540797df6bf1b7319b331d76ac1c7c2ea1920d19a822e702654a",
}


def pinned():
    root = ROOT / "trillionnium/crates"
    return {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in PINS}


def tcm2(family=b"x", *, kind=4, size=9, generation=2, profile=bytes(range(64)),
         instance=b"\0"*63+b"\x08", digest=bytes(range(64))[::-1], aliases=bytes(range(160)),
         claim_magic=b"CCH1"):
    return (b"TCM2" + bytes([len(family)]) + family + aliases +
            claim_magic + profile + bytes([kind]) + instance +
            struct.pack(">QQ",generation,size) + digest)


def alter(src, at, value):
    return src[:at]+bytes([value])+src[at+1:]


class DaCellContentManifestValue(unittest.TestCase):
    def test_original_cch1_shape_and_tcm2_roundtrip_dual(self):
        first = tcm2()
        largest = tcm2(b"A_.-0123456789abcdefGHIJKLMNOPQRSTUVWXYZ"+b"z"*24, size=CAP,
                       generation=(1<<64)-1,profile=b"\x01"+bytes(63),
                       instance=b"\x08"+bytes(63))
        self.assertEqual((len(first),len(largest)),(379,442))
        panel = [(first,0),(largest,0),(tcm2(b"abcdefgh",size=1,generation=0),0),
                 (tcm2(b"m.0_2-z",aliases=bytes(160),digest=bytes(64)),0),
                 (b"",1),(first[:-1],1),(largest+b"\0",1),
                 (alter(first,0,0),2),(alter(first,3,49),2),
                 (alter(first,4,0),3),(alter(largest,4,65),3),
                 (alter(first,4,2),4),(largest[:-1],4),
                 (tcm2(b"\xc0\xaf"),5),(tcm2(b"\xed\xa0\x80"),5),
                 (tcm2(b"\xf4\x90\x80\x80"),5),(tcm2(b"\xc3"),5),
                 (tcm2(b"\x00"),8),(tcm2("é".encode()),8),
                 (tcm2("模型".encode()),8),(tcm2("🔬".encode()),8),
                 (tcm2(b"a/b"),8),(tcm2(b"bad family"),8),
                 (tcm2(b"bad family",kind=0),6),
                 (tcm2(b"\xc3",claim_magic=b"NOPE",kind=0),5),
                 (tcm2(claim_magic=b"ZZZZ",profile=bytes(64)),6),
                 (tcm2(kind=6,profile=bytes(64)),6),
                 (tcm2(profile=bytes(64)),7),(tcm2(instance=bytes(64)),7),
                 (tcm2(b"/",profile=bytes(64),size=0),7),
                 (tcm2(b"/",kind=3,size=0),8),
                 *((tcm2(kind=k,size=0),9) for k in (1,2,3,5)),
                 (tcm2(size=0),10),(tcm2(size=CAP+1),10),
                 (tcm2(size=(1<<64)-1),10)]
        self.assertEqual(pinned(),PINS)
        with tempfile.TemporaryDirectory(prefix="trnm-tcm2-original-") as tmp:
            observed=locked_reference(Path(tmp),b"".join(struct.pack("<I",len(f))+f for f,_ in panel),CALLER)
        self.assertEqual(pinned(),PINS)
        pos=0
        probes=[]
        for i,(raw,expected) in enumerate(panel):
            s,n=struct.unpack_from("<BI",observed,pos)
            pos+=5
            data=observed[pos:pos+n]
            pos+=n
            self.assertEqual(s,expected,i)
            self.assertEqual(data,raw if not s else b"",i)
            probes.append((raw,s,data, max(5,len(raw)+5)))
        self.assertEqual(pos,len(observed))
        probes.extend([
            (first,102,b"",len(first)-1),(largest,102,b"",len(largest)-1),
            (first,0,first,len(first)),(largest,0,largest,len(largest)),
            (tcm2(size=0),10,b"",0),(b"",1,b"",0),
        ])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as native:
                for start in range(0,len(probes),9):
                    group=probes[start:start+9]
                    results=native.call_many([("f0",[f,b"\xaa"*out,b"\x77"*8])
                                              for f,_,_,out in group],timeout=60)
                    for i,((f,s,data,out),result) in enumerate(zip(group,results,strict=True),start):
                        self.assertEqual(result.require_returned().value,s,(backend,i))
                        self.assertEqual(result.arguments,[f,data+b"\xaa"*(out-len(data)),b"\x77"*8],i)

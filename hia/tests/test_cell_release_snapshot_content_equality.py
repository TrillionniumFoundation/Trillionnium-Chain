"""Offline supplied digest equality and actual original CTS1 rejection order."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_cell_release_snapshot_metadata as cts
from hia.tests.cell_manifest_original import ENV
from hia.tests.cts_content_equality_derivation import BEGIN, SOURCE, derive
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks

SRC = ROOT/"hia/src/data_availability/cell_release_snapshot_content_equality.hepta"
OBSERVER = Path(__file__).with_name("rust_cell_release_snapshot_content_equality_reference.rs")
CAP = 1 << 20
PIN = 64
WORK = cts.WORK


def digest(data):
    return hashlib.sha512(cts.DOMAIN+data).digest()


def changed(data,index):
    return data[:index]+bytes([data[index]^1])+data[index+1:]


def corpus():
    stock=cts.corpus()
    good=stock[0][0]
    a=[(digest(w)+w,k,reason,out) for w,k,reason,out in stock if len(w)+PIN<=CAP]
    boundary=cts.bounded(CAP-PIN)
    bd=digest(boundary)
    a.append((bd+boundary,0,None,boundary[-34:]+bd))
    missing=bytes(PIN)
    wrong=digest(b"other ordinary metadata")
    bads=[(reason,n,w) for w,n,reason,_ in stock if reason is not None]
    by_reason={reason:w for reason,_,w in bads}
    # Incorrect equality must win over all parse/semantic conditions except length.
    for msg in ("snapshot wire version","snapshot frame bound","version magic",
                "tensor model manifest version","snapshot trailing bytes",
                "snapshot exact tensor/version model","snapshot composition profile",
                "snapshot composition rules file"):
        for supplied in (missing,wrong):
            a.append((supplied+by_reason[msg],208,"snapshot wire pin",b""))
    a.extend([
        (missing+good[:45],200,"snapshot wire length",b""),
        (wrong+good[:45],200,"snapshot wire length",b""),
        (missing+good,208,"snapshot wire pin",b""),
        (wrong+good,208,"snapshot wire pin",b""),
        (changed(digest(good),0)+good,208,"snapshot wire pin",b""),
        (changed(digest(good),63)+good,208,"snapshot wire pin",b""),
        (digest(good)+changed(good,len(good)-1),208,"snapshot wire pin",b""),
        (digest(good)+changed(good,0),208,"snapshot wire pin",b""),
    ])
    return a


def build_original(work):
    # Only the observation shell differs. The actual old Rust builder verifies
    # all source and dependency bytes and runs the same unchanged decode_pinned.
    with patch.object(cts,"ORACLE",OBSERVER):
        return cts.genuine_original(work)


class SnapshotContentDerivation(unittest.TestCase):
    def test_readback_of_exact_relocated_post_pin_source(self):
        current=SOURCE.read_bytes()
        new=SRC.read_text()
        self.assertEqual(new.split("\n"+BEGIN,1)[1],
                         derive(current).split(BEGIN,1)[1])
        with self.assertRaisesRegex(ValueError,"published CTS1 post-pin source changed"):
            derive(current+b"\n")


class CellReleaseSnapshotContentEquality(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def panel(self,cases):
        for backend,mod in self.modules.items():
            for i,(data,code,want,out_n,work_n) in enumerate(cases):
                with self.subTest(backend=backend,row=i,extent=len(data)):
                    out,scratch=MARK*out_n,SCRATCH*work_n
                    got=mod.call("f0",[data,out,scratch],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertTrue(got.arguments[0]==data,"changed immutable envelope")
                    self.assertEqual(got.arguments[1],want+out[len(want):])
                    if code==200 or (code==208 and not any(data[:PIN])):
                        self.assertTrue(got.arguments[2]==scratch,"length/zero digest hashed or parsed")
                    if code==208:
                        self.assertTrue(got.arguments[2][1512:16032]==scratch[1512:16032],
                                        "mismatching digest entered child layout")
                    self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])

    def test_native_length_then_pin_then_layout_and_atomic_output(self):
        rows=corpus()
        good=rows[0][0]
        zero=bytes(PIN)+good[PIN:]
        self.panel([(w,c,o,105,WORK+7) for w,c,_,o in rows]
                   +[(good,102,b"",97,WORK),(good,102,b"",98,WORK-1),
                     (zero,208,b"",0,0),(b"",200,b"",0,0),
                     (b"A"*63,200,b"",0,0),(b"A"*64,200,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV),"requires genuine locked Rust SHA-2 graph")
    def test_stock_matches_original_with_explicit_synthetic_digest(self):
        rows=corpus()
        wire=cts.bounded(CAP-PIN+1)
        expected=digest(wire)
        over=(expected+wire,0,None,wire[-34:]+expected)
        with tempfile.TemporaryDirectory(prefix="trnm-cts-content-") as work:
            binary,proof=build_original(Path(work))
            data=b"".join(struct.pack("<I",len(w))+w for w,_,_,_ in rows+[over])
            orig=subprocess.run([binary],input=data,capture_output=True,check=True,timeout=45)
        self.assertEqual(orig.stderr,b"")
        self.assertEqual(proof["original_snapshot_sha256"],cts.ORIGINAL_PIN)
        at=0
        stock=[]
        for w,code,error,want in rows+[over]:
            flag=orig.stdout[at]; at+=1
            if error is None:
                self.assertEqual(flag,0)
                actual=orig.stdout[at:at+98]; at+=98
                self.assertEqual(actual,want)
            elif error=="unexpected eof":
                self.assertEqual(flag,255)
                actual=b""
            else:
                self.assertNotIn(flag,(0,255))
                self.assertEqual(orig.stdout[at:at+flag].decode(),error); at+=flag
                actual=b""
            if len(w)<=CAP:
                stock.append((w,code,actual,98,WORK))
        self.assertEqual(at,len(orig.stdout))
        self.assertEqual(len(over[0]),CAP+1)
        self.panel(stock)

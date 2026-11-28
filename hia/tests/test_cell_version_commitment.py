"""Same-call canonical TCV1 validation and its original commitment."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import ENV
from hia.tests.test_cell_complete_version import (
    OBSERVER, bound_packet, corpus as version_cases, generated, packet,
)
from hia.tests.test_cell_manifest import CHUNK, MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_cell_release_manifest import CAP
from hia.tests.test_cell_version_environment import env_id, genuine_original
from hia.tests.tcv_commitment_guard import PRIMARY, IDENTITY, derive

SRC = ROOT/"hia/src/data_availability/cell_version_commitment.hepta"
DOMAIN = b"TRNM/Cell/CompleteVersion/v1\0"
WORK = 131232
TCV_WORK = 16032


def corpus():
    base,vector = version_cases()
    rows = []
    for wire, code, reason, meta in base:
        out=meta+hashlib.sha512(DOMAIN+wire).digest() if code==0 else b""
        rows.append((wire,code,reason,out))
    dims = ((CHUNK,), (CHUNK+1,))
    start = len(packet(*generated(dims))) + len(DOMAIN)
    for residue in (0,1,110,111,112,113,127):
        # A canonical chunk record adds 36 bytes. Use that geometry instead
        # of extending a lexical path component beyond its original bound.
        pad,added=min(((residue-start-36*k) % 128,k) for k in range(32))
        assert 0<=pad<=3
        a,b,cells = generated(((CHUNK*(1+added),),dims[1]),extra_path=pad)
        data=packet(a,b,cells)
        assert (len(DOMAIN)+len(data)) % 128 == residue
        meta=env_id(b)+struct.pack("<I",len(cells))
        rows.append((data,0,None,meta+hashlib.sha512(DOMAIN+data).digest()))
    return rows,vector


class DerivedCommitmentGuard(unittest.TestCase):
    def test_exact_old_cfg_except_nonpublishing_boundary(self):
        old=PRIMARY.read_bytes()
        checked=derive(old)
        self.assertEqual(SRC.read_text().split(f"\nfn {IDENTITY}(",1)[1],
                         checked.split(f"fn {IDENTITY}(",1)[1])
        with self.assertRaisesRegex(ValueError,"published canonical TCV1 validator changed"):
            derive(old.replace(b"branch",b"Branch",1))


class CellVersionCommitment(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def panel(self, cases):
        for backend,mod in self.modules.items():
            for i,(data,code,expected,out_n,work_n) in enumerate(cases):
                with self.subTest(backend=backend,row=i,extent=len(data)):
                    output,scratch=MARK*out_n,SCRATCH*work_n
                    got=mod.call("f0",[data,output,scratch],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertTrue(got.arguments[0]==data,"immutable input changed")
                    self.assertEqual(got.arguments[1],expected+output[len(expected):])
                    if code:
                        self.assertTrue(got.arguments[2][TCV_WORK:]==scratch[TCV_WORK:],
                                        "SHA-512 ran on a refused TCV1 or short output")
                    self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])

    def test_native_domain_padding_complete_count_and_atomic_refusals(self):
        rows,vector=corpus()
        wire,_,_,first=rows[0]
        self.assertEqual(first[36:].hex(),vector["commitment_sha512"])
        self.panel([(w,c,out,107,WORK+9) for w,c,_,out in rows]
                   +[(wire,102,b"",99,WORK),(wire,102,b"",100,WORK-1),
                     (b"TCV",106,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV),"requires genuine locked Rust TCV1 SHA-2 graph")
    def test_native_commitment_same_complete_bytes_as_original(self):
        rows,_=corpus()
        a,b,cells=bound_packet(CAP+1)
        over=packet(a,b,cells)
        extra=(over,0,None,env_id(b)+struct.pack("<I",len(cells))+hashlib.sha512(DOMAIN+over).digest())
        with tempfile.TemporaryDirectory(prefix="trnm-tcv-commitment-") as work:
            binary,proof=genuine_original(Path(work),observer=OBSERVER)
            req=b"".join(struct.pack("<I",len(w))+w for w,_,_,_ in rows+[extra])
            result=subprocess.run([binary],input=req,capture_output=True,check=True,timeout=45)
        self.assertFalse(result.stderr)
        self.assertIn("original_version_source_sha256",proof)
        cursor=0
        real=[]
        for w,code,reason,expected in rows+[extra]:
            flag=result.stdout[cursor]
            cursor+=1
            if reason is None:
                self.assertEqual(flag,0)
                output=result.stdout[cursor:cursor+100]
                self.assertEqual(output,expected)
                cursor+=100
            elif reason=="unexpected eof":
                self.assertEqual(flag,255)
                output=b""
            else:
                self.assertNotIn(flag,(0,255))
                self.assertEqual(result.stdout[cursor:cursor+flag].decode(),reason)
                cursor+=flag
                output=b""
            if len(w)<=CAP:
                real.append((w,code,output,100,WORK))
        self.assertEqual(cursor,len(result.stdout))
        self.assertEqual(len(over),CAP+1)
        self.panel(real)

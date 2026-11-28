"""TCR1 canonical declared metadata only: no payload, cached data or release."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import ENV, build
from hia.tests.test_cell_manifest import MARK, SCRATCH, ROOT, NativeManifestChecks, change

SRC = ROOT / "hia/src/data_availability/cell_release_manifest.hepta"
DOMAIN = b"trnm.cell-release-manifest.v1\0"
CAP = 1 << 20
MAX_CELLS = (CAP-256)//32
MAX_CANONICAL = 169+64+32*MAX_CELLS
WORK_SIZE = 1240
OPAQUE = b"".join(bytes((i,))*32 for i in range(1,6))


def ident(i):
    return i.to_bytes(32,"big")


def release(family=b"Cell.Integration_v1", context=OPAQUE, cells=None):
    if cells is None:
        cells = [ident(1),ident(1024),ident(65535)]
    return b"TCR1"+bytes([len(family)])+family+context+struct.pack(">I",len(cells))+b"".join(cells)


def result(data):
    count = struct.unpack_from(">I",data,165+data[4])[0]
    return hashlib.sha256(DOMAIN+data).digest()+struct.pack("<I",count)


def cases():
    ordinary = release()
    h = 169+ordinary[4]
    highest = release(family=b"Z"*64,cells=[ident(i) for i in range(1,MAX_CELLS+1)])
    assert len(highest)==MAX_CANONICAL
    rows = [(ordinary,0),(highest,0),(release(family=b"0",cells=[ident(1)]),0),
            (release(family=b"Aa9.-_",cells=[ident(0x7f),ident(0x80),ident(0xff),ident(0x100)]),0)]
    rows.extend((ordinary[:n],2 if n<4 else 3 if n<h else 9)
                for n in (0,1,3,4,5,9,24,25,52,88,111,140,h-5,h-4,h-1,h,h+1,len(ordinary)-1))
    rows += [(b"TCM1",2),(b"TCR1\0",4),(b"TCR1\x41",4),
             (b"TCR1\x01\xff",5),(b"TCR1\x02\xf0\x90",5),
             (release("é".encode()),6),(release("🐦".encode()),6),
             (release(b"\x00"),6),(release(b"abc/def"),6),
             (release(context=bytes(160)),7),(ordinary+b"!",9),
             (change(ordinary,h-4,struct.pack(">I",MAX_CELLS+1)),8),
             (change(ordinary,h-4,bytes(4)),8),(change(ordinary,h-4,struct.pack(">I",2)),9),
             (release(cells=[ident(2),ident(1)]),10),
             (release(cells=[ident(1),ident(1)]),10),
             (release(cells=[bytes(32),ident(1)]),11),
             (release(cells=[ident(1),bytes(32)]),10),
             (release(cells=[bytes(32)]),11)]
    for i in range(5):
        context = change(OPAQUE,i*32,bytes(32))
        bad = release(context=context)
        # Fully decoded faulty context wins even when the count is absent.
        rows += [(bad,7),(bad[:h-4],7)]
    rows += [(release(family=b"!",context=bytes(160)),6),
             (release(cells=[bytes(32),ident(2),ident(1)]),10),
             (change(highest,len(highest)-32,ident(MAX_CELLS-1)),10)]
    return rows


class CellReleaseManifest(NativeManifestChecks, unittest.TestCase):
    source = SRC

    def emitted_release(self, panel):
        for emitter,module in self.modules.items():
            for i,(data,code,payload,out_n,scratch_n) in enumerate(panel):
                with self.subTest(emitter=emitter,index=i):
                    output,scratch = MARK*out_n,SCRATCH*scratch_n
                    got = module.call("f0",[data,output,scratch],timeout=40).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],payload+output[len(payload):])
                    self.assertEqual(got.arguments[2][WORK_SIZE:],scratch[WORK_SIZE:])
                    if code:
                        self.assertEqual(got.arguments[2],scratch)

    def test_metadata_identity_and_complete_original_row_extent(self):
        self.emitted_release([(data,code,result(data) if not code else b"",47,WORK_SIZE+11)
                              for data,code in cases()])

    def test_private_extent_and_no_write_on_refusal(self):
        good = release()
        self.emitted_release([(good,0,result(good),36,WORK_SIZE),
            (good,102,b"",35,WORK_SIZE),(good,102,b"",36,WORK_SIZE-1),
            (b"",2,b"",0,0),(good+bytes(CAP-len(good)),9,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV),"requires genuine locked Rust+SHA-256")
    def test_original_release_codec_complete_order_and_id(self):
        rows = cases()
        over = (bytes(CAP+1),1)
        expected = [(data,code,result(data) if not code else b"") for data,code in rows]
        command = b"".join(struct.pack("<I",len(data))+data for data,_ in rows+[over])
        with tempfile.TemporaryDirectory(prefix="trnm-tcr1-") as d:
            binary,proof = build(Path(d))
            observed = subprocess.run([binary,"--release"],input=command,check=True,
                                      capture_output=True,timeout=50)
        self.assertEqual(proof["mode"],"verified-prebuilt-original-sha2")
        self.assertEqual(observed.stderr,b"")
        self.assertEqual(observed.stdout,b"".join(bytes([code])+value for _,code,value in expected)+b"\x01")
        # The existing generic ABI harness cannot hold CAP+1; the over-limit
        # assertion was Rust-only, never represented as a native call.
        at = 0
        measured = []
        for data,code,_ in expected:
            stop = at+1 if code else at+37
            measured.append((data,observed.stdout[at],observed.stdout[at+1:stop],47,WORK_SIZE+11))
            at = stop
        self.emitted_release(measured)

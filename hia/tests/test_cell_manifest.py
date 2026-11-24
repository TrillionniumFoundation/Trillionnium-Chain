"""Original TCM1 manifest readback without obtaining any referenced payload."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import ENV, build
from hia.tests.native_support import NativeModule
from hia.tests.test_verification_profile_registry import ROOT

SRC = ROOT / "hia/src/data_availability/cell_manifest.hepta"
DOMAIN = b"trnm.cell-manifest.v1\0"
CHUNK = 16_384
MAX_CHUNK = 4_194_304
MAX_CELL = 64 * 1024**3
MAX_MANIFEST = 1024**2
MAX_ROWS = 16_384
WORK = 1232
MARK, SCRATCH = b"\xa5", b"\x49"


def wire(family=b"Cell.example_1-v2", size=CHUNK+13, chunk_bytes=CHUNK, n=None, opaque=False):
    count = (size+chunk_bytes-1)//chunk_bytes if n is None else n
    digest = bytes(range(32)) if opaque else bytes(32)
    row = struct.pack(">I", chunk_bytes)+digest
    tail = struct.pack(">I", size-(count-1)*chunk_bytes)+digest if count else b""
    return (b"TCM1"+bytes([len(family)])+family+digest*5+struct.pack(">Q", size)+digest+
            struct.pack(">II", chunk_bytes,count)+row*(count-1)+tail)


def change(data, offset, content):
    if len(data) < offset+len(content):
        raise ValueError("fixture slice outside manifest")
    return data[:offset]+content+data[offset+len(content):]


def result(data):
    return hashlib.sha256(DOMAIN+data).digest()+data


def cases():
    family = b"Aa9.-_"
    good = wire(family, opaque=True)
    start = 213+len(family)
    out = [(good, 0), (wire(b"0",1), 0), (wire(b"A"*64,MAX_CELL, MAX_CHUNK), 0),
           (wire(b"a",CHUNK), 0), (wire(b"A-B_9",MAX_CHUNK+256,MAX_CHUNK), 0)]
    # Full original length below every fixed field and one byte inside each
    # semantic field. One full extra byte is a separate coverage diagnostic.
    out += [(good[:n], 2 if n < start else 7)
            for n in (0,1,3,4,5,7,10,11,42,75,105,171,178,201,210,start-1,start,start+1,len(good)-1)]
    out += [(b"HAVE",3), (b"TCM1\x00",4), (b"TCM1\x41",4),
            (b"TCM1\x01\xff",5), (b"TCM1\x02\xf3\x80",5),
            (wire("ë".encode()),8), (wire(b"\x00"),8), (wire(b"family/name"),8),
            (wire("𐀀".encode()),8), (b"TCM1\x02" + "ë".encode(),2),
            (good+b"x",7), (change(good,start-4,struct.pack(">I",0)),6),
            (change(good,start-4,struct.pack(">I",MAX_ROWS+1)),6),
            (change(good,start-4,struct.pack(">I",1)),7),
            (change(good,start-8,struct.pack(">I",CHUNK-1)),9),
            (change(good,start-8,struct.pack(">I",CHUNK+1)),9),
            (change(good,start-8,struct.pack(">I",MAX_CHUNK*2)),9),
            (change(good,start-48,struct.pack(">Q",0)),10),
            (change(good,start-48,struct.pack(">Q",MAX_CELL+1)),10),
            (change(good,start-48,struct.pack(">Q",CHUNK)),11),
            (change(good,start,struct.pack(">I",CHUNK-1)),12),
            (change(good,start+36,struct.pack(">I",12)),12)]
    invalid_family = change(good,5,b"/")
    invalid_geometry = change(good,start-8,struct.pack(">I",0))
    invalid_count = change(invalid_family,start-4,struct.pack(">I",0))
    out += [(invalid_count,6),(invalid_family+b"x",7),
            (change(invalid_geometry,5,b"/"),8),
            (change(invalid_geometry,start-48,bytes(8)),9),
            (change(change(good,start-48,struct.pack(">Q",CHUNK)),start,bytes(4)),11)]
    # Each 32-bit declared chunk size is in network order and validation
    # covers even the last row at the exact original 16,384-row limit.
    last = wire(b"A"*64,MAX_CELL-1,MAX_CHUNK)
    out += [(last,0),(change(last,len(last)-36,struct.pack(">I",MAX_CHUNK)),12)]
    return out


class NativeManifestChecks:
    source = SRC

    @classmethod
    def setUpClass(cls):
        cls.modules = {backend: cls.enterClassContext(NativeModule(cls.source,backend=backend,byte_exports=("f0",)))
                       for backend in ("direct","selfhost")}
        if len({x.artifact_sha256 for x in cls.modules.values()}) != 2:
            raise ValueError("both distinct pinned artifacts required")

    def emitted(self, panel):
        for backend, module in self.modules.items():
            for idx, (data, code, payload, output, scratch) in enumerate(panel):
                with self.subTest(backend=backend,index=idx):
                    got = module.call("f0",[data,MARK*output,SCRATCH*scratch],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],payload+MARK*(output-len(payload)))
                    self.assertEqual(got.arguments[2][WORK:],SCRATCH*max(0,scratch-WORK))
                    if code != 0:
                        self.assertEqual(got.arguments[2],SCRATCH*scratch)

class CellManifest(NativeManifestChecks, unittest.TestCase):
    def test_original_domain_and_geometry_with_full_size_and_last_row(self):
        rows = [(data, code, result(data) if code == 0 else b"") for data, code in cases()]
        self.emitted([(data,code,payload,len(payload)+11,WORK+9) for data,code,payload in rows])

    def test_capacity_and_full_declared_input_limit(self):
        good = wire()
        value = result(good)
        self.emitted([(good,0,value,len(value),WORK),(good,102,b"",len(value)-1,WORK),
                      (good,102,b"",len(value),WORK-1),
                      (good+bytes(MAX_MANIFEST-len(good)),7,b"",0,0),
                      (b"NOPE",3,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV), "requires verified locked real Rust SHA-256 oracle")
    def test_genuine_original_manifest_codec_and_id(self):
        rows = cases()
        beyond = bytes(MAX_MANIFEST+1)
        with tempfile.TemporaryDirectory(prefix="trnm-tcm1-") as d:
            binary, proof = build(Path(d))
            command = b"".join(struct.pack("<I",len(data))+data for data,_ in rows+[(beyond,1)])
            run = subprocess.run([binary],input=command,check=True,capture_output=True,timeout=40)
            self.assertEqual(run.stderr,b"")
        self.assertEqual(proof["mode"],"verified-prebuilt-original-sha2")
        actual = run.stdout
        at = 0
        panel = []
        for data, code in rows:
            self.assertLess(at,len(actual))
            self.assertEqual(actual[at],code)
            stop = at+1 if code else at+1+32+len(data)
            value = actual[at+1:stop]
            self.assertEqual(value,b"" if code else result(data))
            panel.append((data,code,value,len(value)+11,WORK+9))
            at = stop
        # The generic borrowed test harness itself permits at most 1 MiB.
        # An over-limit Rust sample is observed, not claimed as a native call.
        self.assertEqual(actual[at:],b"\x01")
        self.emitted(panel)


def chunk_cases():
    panel = []
    plain = wire(b"Cell-1", size=2*CHUNK+9, opaque=True)
    maximum = wire(b"A"*64, MAX_CELL-1, MAX_CHUNK)
    for data, index, code in [(plain,0,0),(plain,1,0),(plain,2,0),(plain,3,13),
                              (plain,2**32-1,13),(maximum,MAX_ROWS-1,0),
                              (maximum,MAX_ROWS,13),
                              (change(plain,len(plain)-36,bytes(4)),0,12),
                              (change(plain,len(plain)-36,bytes(4)),300,12),
                              (plain[:-1],0,7),(b"TCM1\x01\xff",0,5)]:
        data = bytes(data)
        payload = b""
        if code == 0:
            row = 213+data[4]+36*index
            size = struct.unpack_from(">I",data,row)[0]
            payload = result(data)[:32]+struct.pack("<II",index,size)+data[row+4:row+36]
        panel.append((struct.pack("<I",index)+data, code, payload))
    return panel


class CellManifestChunk(NativeManifestChecks, unittest.TestCase):
    source = SRC.with_name("cell_manifest_chunk.hepta")

    def test_native_read_only_row_projection_checks_the_complete_manifest(self):
        self.emitted([(data,code,payload,81,WORK+9) for data,code,payload in chunk_cases()])

    def test_projection_frame_and_output_workspace_extent(self):
        data, _, payload = chunk_cases()[0]
        self.emitted([(data,0,payload,72,WORK),(data,102,b"",71,WORK),
                      (data,102,b"",72,WORK-1),(b"",100,b"",0,0),(b"x"*3,100,b"",0,0),
                      (b"\0"*4,2,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV), "requires verified locked real Rust SHA-256 oracle")
    def test_genuine_original_decoded_get_index_and_id(self):
        rows = chunk_cases()
        with tempfile.TemporaryDirectory(prefix="trnm-tcm1-select-") as d:
            binary, proof = build(Path(d))
            command = b"".join(struct.pack("<I",len(data))+data for data,_,_ in rows)
            run = subprocess.run([binary,"--chunk"],input=command,check=True,capture_output=True,timeout=40)
            self.assertEqual(run.stderr,b"")
        self.assertEqual(proof["mode"],"verified-prebuilt-original-sha2")
        actual = run.stdout
        self.assertEqual(actual,b"".join(bytes([code])+value for _,code,value in rows))
        at = 0
        observed = []
        for data, code, _ in rows:
            u = at+1
            stop = u if code else u+72
            observed.append((data,actual[at],actual[u:stop],81,WORK+9))
            at = stop
        self.emitted(observed)

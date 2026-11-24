"""Standalone TMT1 declares shape metadata only; no tensor payload or I/O."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import TENSOR_CONTRACT, ENV, build, sha, tensor_contract_source
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks, change
from hia.tests.test_cell_release_manifest import CAP, ident

SRC = ROOT / "hia/src/data_availability/cell_tensor_contract.hepta"
DOMAIN = b"trnm.cell-tensor-contract.v1\0"
WORK = 1240
ROOT_ID = ident(17)


def row(name, shape=(), dtype=1, rank=None):
    return (struct.pack(">H",len(name))+name+bytes([dtype,len(shape) if rank is None else rank])
            + b"".join(struct.pack(">Q",v) for v in shape))


def file(index, *rows, count=None):
    return struct.pack(">HH",index,len(rows) if count is None else count)+b"".join(rows)


def wire(*files, root=ROOT_ID, profile=1, codec=1, count=None):
    return (b"TMT1"+bytes([profile,codec])+root+
            struct.pack(">H",len(files) if count is None else count)+b"".join(files))


def value(data, files, tensors):
    return hashlib.sha256(DOMAIN+data).digest()+struct.pack("<II",files,tensors)


def cases():
    base = wire(file(0,row(b"weight")))
    at_max_names = [row(f"t{i:05d}".encode()+b"x"*(54 if i<16383 else 10)) for i in range(16384)]
    maximum = wire(file(0,*at_max_names))
    assert len(maximum)==CAP
    full_files = wire(*(file(i,row(b"bias",shape=(1,)*8,dtype=3)) for i in range(256)))
    meta_shape = (65536,262144) # 64GiB for the original u64 byte calculation
    opt = wire(file(1,row(b"Z"),row(b"a"),row("é".encode()),row("𐀀".encode())),
               file(255,row("alpha\u200b".encode(),dtype=3),row("beta".encode(),dtype=2)))
    accepted = [(base,1,1),(maximum,1,16384),(full_files,256,256),(opt,2,6),
                (wire(file(7,row(b"a"*255,meta_shape))),1,1),
                (wire(file(255,row("A\u00a0".encode(),dtype=2))),1,1)]
    late_name_start = len(maximum)-20+2
    bad_rows = [
        (b"",1),(base[:39],1),(change(base,0,b"NONE"),2),
        (wire(file(0,row(b"bias")),profile=2,codec=3,root=bytes(32)),3),
        (wire(file(0,row(b"bias")),codec=2,root=bytes(32)),4),
        (wire(),5),(wire(file(0,row(b"bias")),count=257),5),
        (base[:40],6),(base[:41],6),(base[:42],6),(base[:43],6),
        (wire(file(0,count=0)),7),(wire(file(0,count=16385)),7),
        (wire(file(0,count=1)),8),(wire(file(0,b"abc",count=1)),8),
        (wire(file(0,row(b"abc"),count=2)),8),
        (wire(file(0,row(b"",rank=1)+bytes(8))),9),
        (wire(file(0,row(b"a"*256))),9),
        (wire(file(0,struct.pack(">H",8)+b"abc")),6),
        (wire(file(0,row(b"\xff",dtype=0))),10),
        (wire(file(0,row(b"\xc2",dtype=0))),10),
        (wire(file(0,struct.pack(">H",3)+b"abc")),6),
        (wire(file(0,row(b"abc",dtype=0,rank=9))),11),
        (wire(file(0,row(b"abc",dtype=4,rank=9))),11),
        (wire(file(0,row(b"abc")[:-1])),6),
        (wire(file(0,row(b"a",rank=9))),12),
        (wire(file(0,row(b"a",rank=1))),6),
        (base+b".",13),
        # Complete syntax and suffix precede any semantically invalid model.
        (wire(file(0,row(b"__metadata__")),root=bytes(32))+b".",13),
        (wire(file(0,row(b"__metadata__")),root=bytes(32)),15),
        (wire(file(0,row(b"__metadata__")),file(2,row(b"x",dtype=7))),11),
        (wire(file(2,row(b"__metadata__")),file(0,row(b"bias"))),16),
        (wire(file(0,row(b"x")),file(0,row(b"z"))),16),
        (wire(file(256,row(b"__metadata__"),row(b"Z"))),17),
        (wire(file(0,row(b"__metadata__"),row(b"A"))),18),
        (wire(file(0,row(b"t"),row(b"t"))),18),
        (wire(file(0,row("é".encode()),row(b"z"))),18),
        (wire(file(0,row(b"__metadata__",(0,)))),19),
        (wire(file(0,row(b"ascii\0"))),19),(wire(file(0,row(b"ascii\x7f"))),19),
        (wire(file(0,row("name\u0085".encode()))),19),
        (wire(file(0,row("name\u009f".encode()))),19),
        (wire(file(0,row(b"shape",(0,)),row(b"z"))),20),
        (wire(file(0,row(b"shape",(1<<32,)))),20),
        (wire(file(0,row(b"shape",(65536,262145,0)))),20),
        (wire(file(0,row(b"shape",(0xffffffff,0xffffffff,0)))),21),
        (wire(file(0,row(b"shape",(65536,262145)))),22),
        (wire(file(0,row(b"shape",(0xffffffff,0xffffffff),dtype=2))),21),
        (wire(file(0,row(b"a",meta_shape),row(b"b"))),23),
        (change(maximum,late_name_start,b"a"+maximum[late_name_start+1:late_name_start+16]),18),
    ]
    return [(d,0,value(d,f,n)) for d,f,n in accepted]+[(d,c,b"") for d,c in bad_rows]


class CellTensorContract(NativeManifestChecks, unittest.TestCase):
    source = SRC

    def panel(self, rows):
        for emitter,module in self.modules.items():
            for j,(data,code,payload,out_n,work_n) in enumerate(rows):
                with self.subTest(emitter=emitter,row=j):
                    output,scratch = MARK*out_n,SCRATCH*work_n
                    got = module.call("f0",[data,output,scratch],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],payload+output[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])
                    if code:
                        self.assertEqual(got.arguments[2],scratch)

    def test_native_atomic_and_actual_complete_declared_limits(self):
        self.panel([(data,code,payload,49,WORK+5) for data,code,payload in cases()])
        good,_,data = cases()[0]
        self.panel([(good,0,data,40,WORK),(good,102,b"",39,WORK),
                    (good,102,b"",40,WORK-1),(good+b".",13,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV), "requires genuine locked Rust+SHA-256")
    def test_original_pure_tensor_contract_and_exact_failure_order(self):
        rows = cases()
        over = (bytes(CAP+1),1,b"")
        command = b"".join(struct.pack("<I",len(d))+d for d,_,_ in rows+[over])
        with tempfile.TemporaryDirectory(prefix="trnm-tmt1-original-") as d:
            binary,proof=build(Path(d),with_tensor_contract=True)
            observed=subprocess.run([binary],input=command,check=True,capture_output=True,timeout=55)
        self.assertEqual(proof["original_tensor_contract_source_sha256"],sha(TENSOR_CONTRACT.read_bytes()))
        self.assertEqual(proof["original_tensor_contract_pure_extract_sha256"],sha(tensor_contract_source()))
        self.assertEqual(observed.stderr,b"")
        self.assertEqual(observed.stdout,b"".join(bytes([code])+payload for _,code,payload in rows+[over]))
        measured=[]
        pos=0
        for data,code,_ in rows:
            stop=pos+(1 if code else 41)
            measured.append((data,observed.stdout[pos],observed.stdout[pos+1:stop],49,WORK+5))
            pos=stop
        self.panel(measured)

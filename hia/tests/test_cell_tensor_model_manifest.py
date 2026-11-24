"""Scoped TMA1 composition of canonical declarations; no model or file is opened."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import (
    TENSOR_CONTRACT, ENV, build, sha, tensor_contract_source,
)
from hia.tests.test_cell_dependency_closure import WORK, closure, row as cell_row
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks, change
from hia.tests.test_cell_model_release_root import (
    ROOT_DOMAIN as TMR_DOMAIN, cases as tmr_cases, roster, wire as tmr,
)
from hia.tests.test_cell_release_manifest import CAP, ident
from hia.tests.test_cell_tensor_contract import (
    DOMAIN as TMT_DOMAIN, cases as tmt_cases, file, row, wire as tmt,
)

SRC = ROOT / "hia/src/data_availability/cell_tensor_model_manifest.hepta"
DOMAIN = b"trnm.cell-tensor-model-manifest.v1\0"
MAX_ROOT = CAP+553
MAX_WIRE = 12+MAX_ROOT+CAP


def root(files, *, parents=()):
    rows = [cell_row(f"Cell/File{i:03}.dat".encode(),i+1,role=role,size=size)
            for i,(role,size) in enumerate(files)]
    td = closure(*rows,roots=range(len(rows)),cells=range(1,len(rows)+1))
    return tmr(td,roster(rows),parents)


def root_id(rd):
    return hashlib.sha256(TMR_DOMAIN+rd).digest()


def contract(rd, *files):
    return tmt(*files,root=root_id(rd))


def wire(rd, td):
    return b"TMA1"+struct.pack(">I",len(rd))+rd+struct.pack(">I",len(td))+td


def value(rd, td, data):
    return hashlib.sha256(DOMAIN+data).digest()+root_id(rd)+hashlib.sha256(TMT_DOMAIN+td).digest()


def at_extent(rd, extent):
    # 16,384 scalars in one required Base cell. Shorten only names, retaining
    # the exact sorted unique prefix in each row, until the requested TMT size.
    count = 16384
    decrease = 44 + count*64 - extent
    rs = []
    for i in range(count):
        shrink = min(54,decrease)
        rs.append(row(f"t{i:05d}".encode()+b"x"*(54-shrink)))
        decrease -= shrink
    assert decrease == 0
    content = contract(rd,file(0,*rs))
    assert len(content) == extent
    return content


def cases():
    rd = root([(1,14)])
    tc = contract(rd,file(0,row(b"weight")))
    ordinary = wire(rd,tc)
    cap_root = root([(1,16384*4+10)])
    cap_tc = at_extent(cap_root,CAP-len(cap_root)-12)
    saturated = wire(cap_root,cap_tc)
    assert len(saturated) == CAP
    many = root([(5,14)]*255+[(4,14)],parents=(ident(1),ident(2)))
    many_tc = contract(many,file(255,row(b"vector",dtype=1)))
    rows = [(ordinary,0,value(rd,tc,ordinary)),
            (saturated,0,value(cap_root,cap_tc,saturated)),
            (wire(many,many_tc),0,value(many,many_tc,wire(many,many_tc)))]
    for fixture, specs in [
        (root([(1,14),(5,14),(4,18),(2,1)]), (file(0,row(b"z")),file(2,row(b"b",(2,))))),
        (root([(5,14),(2,12)]), (file(1,row(b"z",dtype=3)),)),
        (root([(1,14),(4,14)]), (file(0,row(b"x")),file(1,row(b"x")))),
    ]:
        tf = contract(fixture,*specs)
        data = wire(fixture,tf)
        rows.append((data,0,value(fixture,tf,data)))
    tiny_rd = root([(1,13)])
    few = root([(1,14),(4,14),(5,14)])
    with_no_base = root([(5,14),(4,14)])
    mismatched = change(tc,6,ident(900))
    cases = [
        (b"",90),(ordinary[:11],90),(change(ordinary,0,b"NONE"),91),
        (change(ordinary,4,struct.pack(">I",MAX_ROOT+1)),92),
        (change(ordinary,4,struct.pack(">I",len(ordinary))),92),
        (wire(b"",tc),2),(wire(b"NONE",tc),52),
        (ordinary[:8+len(rd)]+bytes(2),2),
        (change(ordinary,8+len(rd),struct.pack(">I",CAP+1)),92),
        (change(ordinary,8+len(rd),struct.pack(">I",len(ordinary))),92),
        (wire(rd,b""),65),
        (wire(rd,mismatched)+b".",93),
        (wire(rd,mismatched),79),
        (wire(rd,change(contract(rd,file(1,row(b"x"))),6,ident(981))),79),
        (wire(rd,contract(rd,file(1,row(b"x")))),94),
        (wire(tiny_rd,contract(tiny_rd,file(0,row(b"x")),file(1,row(b"y")))),95),
        (wire(tiny_rd,contract(tiny_rd,file(0,row(b"x")))),95),
        (wire(few,contract(few,file(0,row(b"x")))),96),
        (wire(few,contract(few,file(1,row(b"x")))),96),
        (wire(few,contract(few,file(2,row(b"x")))),96),
        (wire(with_no_base,contract(with_no_base,file(0,row(b"x")))),96),
        (wire(few,contract(few,file(0,row(b"x")),file(2,row(b"z",(2,))))),95),
        (wire(rd,change(tc,6,bytes(32)))+b".",79),
        (bytes(CAP),91),
    ]
    # Nested failures must remain their original conditions at nonzero offsets.
    cases.extend((wire(invalid,tc),code) for invalid,code,_ in tmr_cases()
                 if code and len(invalid)+len(tc)+12<=CAP)
    cases.extend((wire(rd,invalid),2 if code==6 else 64+code)
                 for invalid,code,_ in tmt_cases() if code and len(rd)+len(invalid)+12<=CAP)
    return rows+[(d,c,b"") for d,c in cases]


def above_loan():
    rd = root([(1,16384*4+10)])
    tc = at_extent(rd,CAP)
    d = wire(rd,tc)
    assert CAP < len(d) < MAX_WIRE
    return [(d,0,value(rd,tc,d)), (d+b".",93,b""), (bytes(MAX_WIRE+1),90,b"")]


class CellTensorModelManifest(NativeManifestChecks, unittest.TestCase):
    source = SRC

    def panel(self, rows):
        for emitter,module in self.modules.items():
            for i,(data,code,payload,out_n,work_n) in enumerate(rows):
                with self.subTest(emitter=emitter,row=i):
                    out,scratch = MARK*out_n,SCRATCH*work_n
                    got = module.call("f0",[data,out,scratch],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],payload+out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])

    def test_native_binding_saturation_and_atomic_output(self):
        rows = cases()
        self.panel([(d,c,p,107,WORK+11) for d,c,p in rows])
        good,_,payload = rows[0]
        self.panel([(good,0,payload,96,WORK),(good,102,b"",95,WORK),
                    (good,102,b"",96,WORK-1),(b"",90,b"",0,0),(good+b".",93,b"",0,WORK)])

    @unittest.skipUnless(os.environ.get(ENV), "requires genuine locked Rust+SHA-256")
    def test_unchanged_original_full_binding_and_over_loan_independent(self):
        rows = cases()
        over = above_loan()
        frame = b"".join(struct.pack("<I",len(data))+data for data,_,_ in rows+over)
        with tempfile.TemporaryDirectory(prefix="trnm-tma1-original-") as d:
            binary,proof = build(Path(d),with_tensor_model_manifest=True)
            original = subprocess.run([binary],input=frame,check=True,capture_output=True,timeout=55)
        self.assertEqual(proof["original_tensor_model_source_sha256"],sha(TENSOR_CONTRACT.read_bytes()))
        self.assertEqual(proof["original_tensor_model_pure_extract_sha256"],
                         sha(tensor_contract_source(with_model_manifest=True)))
        self.assertEqual(original.stderr,b"")
        self.assertEqual(original.stdout,b"".join(bytes([code])+data for _,code,data in rows+over))
        pos=0
        measured=[]
        for data,code,_ in rows:
            stop=pos+(1 if code else 97)
            measured.append((data,original.stdout[pos],original.stdout[pos+1:stop],107,WORK+11))
            pos=stop
        self.panel(measured)

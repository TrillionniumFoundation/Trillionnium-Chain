"""Original public verify_reader through immutable synthetic Cursor; only pre-JSON parity."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.test_cell_dependency_closure import WORK, closure, row
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH
from hia.tests.test_cell_model_release_root import roster, wire as root_wire
from hia.tests.test_cell_tensor_model_manifest import root_id
from hia.tests.test_cell_tensor_contract import DOMAIN, file, row as tensor, wire as contract_wire
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests.native_support import NativeModule

SRC = ROOT / "hia/src/data_availability/cell_tensor_reader_framing.hepta"
ORACLE = Path(__file__).with_name("rust_cell_tensor_reader_framing_reference.rs")
TENSOR = ROOT / "trillionnium/crates/trnm-data-availability/src/cell/tensor.rs"
TENSOR_SHA = "73499faf43769355947c598040ddedf9139341bb1a1745924425cd5f11f6c5e8"
CAP = 1 << 20
GOOD = b'{"a":{"dtype":"F32","shape":[],"data_offsets":[0,4]}}'
LATER = {
    "ok", "tensor header JSON", "tensor roster coverage", "tensor roster metadata",
    "tensor data range", "tensor overlap or hole", "tensor trailing data", "tensor payload digest",
}
EARLY = {
    "tensor contract version": 2,
    "model root version": 52,
    "tensor contract pin": 211,
    "tensor model root": 79,
    "tensor closure file index": 94,
    "tensor closure payload size": 95,
    "tensor missing required file": 96,
    "tensor undeclared file": 212,
    "tensor actual file length": 213,
    "tensor header length": 214,
    "tensor header prefix": 215,
    "tensor header padding": 216,
}


def container(header=GOOD, data=b"\x00\x00\x00\x80", *, count=None):
    return struct.pack("<Q", len(header) if count is None else count) + header + data


def declare(contents, *, roles=None, claims=None):
    if roles is None:
        roles = [1] + [2]*(len(contents)-1)
    if claims is None:
        claims = contents
    ids = range(1, len(contents)+1)
    rows = [row(f"File{i:03}.synthetic".encode(), i, role=role, size=len(data),
                payload=hashlib.sha256(data).digest())
            for i, role, data in zip(ids, roles, claims, strict=True)]
    return root_wire(closure(*rows, roots=range(len(rows)), cells=ids), roster(rows))


def loan(contents, *, r=None, ct=None, scope=None, index=0, pin=None, actual=None):
    if r is None:
        r = declare(contents)
    if ct is None:
        if scope is None:
            scope = [file(0, tensor(b"a"))]
        ct = contract_wire(*scope,root=root_id(r))
    if pin is None:
        pin = hashlib.sha256(DOMAIN+ct).digest()
    if actual is None:
        actual = contents[index]
    return pin+struct.pack(">HI",index,len(ct))+ct+struct.pack(">I",len(r))+r+actual


def saturated(total):
    fixed = len(loan([container()]))
    payload = container(GOOD + b" "*(total-fixed))
    result = loan([payload])
    assert len(result)==total
    return result


def cases():
    good = container()
    different = container(data=bytes(4))
    long_header = container(GOOD+b" "*65533)
    big_payload = container(b'{"a":{"shape":[16385],"data_offsets":[0,65540],"dtype":"F32"}}',
                            bytes(65540))
    multi_roster = container(
        '{"𝄞":{"shape":[],"data_offsets":[0,2],"dtype":"BF16"},'
        '"__metadata__":{"fixture":"only"},"\u00e9":{"data_offsets":[2,4],"dtype":"F16","shape":[]}}'
        .encode(),bytes(4))
    r = declare([good])
    ordinary = contract_wire(file(0,tensor(b"a")),root=root_id(r))
    c_bad = b"VOID"+ordinary[4:]
    r_bad = b"VOID"+r[4:]
    wrong_model = contract_wire(file(0,tensor(b"a")),root=bytes([1])*32)
    changed = declare([good,good],roles=(1,4))
    malformed = [
        (container(GOOD,count=0),"tensor header length"),
        (container(GOOD,count=1),"tensor header length"),
        (container(GOOD,count=len(GOOD)+5),"tensor header length"),
        (container(GOOD,count=2**64-1),"tensor header length"),
        (container(GOOD,count=CAP+1),"tensor header length"),
        (container(b" "+GOOD),"tensor header prefix"),
        (container(GOOD[:-1]+b"]"),"tensor header padding"),
        (container(GOOD+b" \t"),"tensor header padding"),
        (container(b"{"+b" "*500),"tensor header padding"),
        (container(b"{broken}"),"tensor header JSON"),
        (container(b"{}"),"tensor roster coverage"),
        (container(GOOD.replace(b'"F32"',b'"F16"')),"tensor roster metadata"),
        (container(GOOD.replace(b'[0,4]',b'[1,4]')),"tensor data range"),
        (container(GOOD.replace(b'[0,4]',b'[1,5]'),bytes(5)),"tensor overlap or hole"),
        (container(GOOD,bytes(5)),"tensor trailing data"),
    ]
    return [
        (loan([good]),"ok"),
        (loan([long_header]),"ok"),
        (loan([big_payload],scope=[file(0,tensor(b"a",(16385,)))]),"ok"),
        (loan([multi_roster],scope=[file(0,tensor("é".encode(),dtype=2),
                                             tensor("𝄞".encode(),dtype=3))]),"ok"),
        (loan([good,good],index=1,scope=[file(0,tensor(b"a")),file(1,tensor(b"a"))]),"ok"),
        (loan([good],r=r_bad,ct=c_bad,pin=bytes(32)),"tensor contract version"),
        (loan([good],r=r_bad,ct=ordinary,pin=bytes(32)),"model root version"),
        (loan([good],ct=wrong_model,pin=bytes(32),actual=b""),"tensor contract pin"),
        (loan([good],ct=wrong_model,actual=b""),"tensor model root"),
        (loan([good],scope=[file(1,tensor(b"a"))]),"tensor closure file index"),
        (loan([good],scope=[file(0,tensor(b"a",(40,))),file(1,tensor(b"a"))]),"tensor closure payload size"),
        (loan([good,good],r=changed,index=1),"tensor missing required file"),
        (loan([good,good],index=1),"tensor undeclared file"),
        (loan([good],index=256,actual=b""),"tensor undeclared file"),
        (loan([good],index=65535,actual=b""),"tensor undeclared file"),
        (loan([good],actual=good[:-1]),"tensor actual file length"),
        (loan([good],actual=b""),"tensor actual file length"),
        (loan([good],actual=good+b"x"),"tensor actual file length"),
        (loan([good],actual=different),"tensor payload digest"),
        (loan([container(b"{broken}")],r=declare([container(b"{broken}")],
                                               claims=[bytes(len(container(b"{broken}")))])),"tensor header JSON"),
        *[(loan([data]),why) for data,why in malformed],
        (saturated(CAP),"ok"),
        (saturated(CAP+1),"ok"),
    ]


class CellTensorReaderFraming(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules={backend:cls.enterClassContext(NativeModule(SRC,backend=backend,byte_exports=("f0",)))
                     for backend in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.modules.values()})!=2:
            raise ValueError("both distinct pinned backends required")

    def panel(self, rows):
        for backend,m in self.modules.items():
            for i,(data,code,want,output,scratch) in enumerate(rows):
                with self.subTest(backend=backend,case=i):
                    out,w=MARK*output,SCRATCH*scratch
                    r=m.call("f0",[data,out,w],timeout=35).require_returned()
                    self.assertEqual(r.value,code)
                    self.assertEqual(r.arguments[0],data)
                    self.assertEqual(r.arguments[1],want+out[len(want):])
                    self.assertEqual(r.arguments[2][WORK:],w[WORK:])

    def test_locked_public_cursor_and_over_bound(self):
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        selected=cases()
        raw=b"".join(struct.pack("<I",len(v))+v for v,_ in selected)
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-reader-framing-") as d:
            measured=locked_reference(Path(d),raw,caller=ORACLE,extra_externs=("sha2",))
        self.assertEqual(hashlib.sha256(TENSOR.read_bytes()).hexdigest(),TENSOR_SHA)
        at=0
        qualified=[]
        for data,expected in selected:
            n,=struct.unpack_from("<H",measured,at)
            reason=measured[at+2:at+2+n].decode()
            at+=2+n
            self.assertEqual(reason,expected)
            seeks,count=struct.unpack_from("<QQ",measured,at)
            at+=16
            reads=[struct.unpack_from("<QQ",measured,at+16*i) for i in range(count)]
            at+=16*count
            if reason in LATER:
                head,body=struct.unpack_from("<QQ",measured,at)
                observed=measured[at:at+48]; at+=48
                self.assertEqual(reads[:2],[(0,8),(8,head)])
                if reason in ("ok","tensor payload digest"):
                    self.assertEqual(seeks,3)
                    self.assertEqual(sum(n for _,n in reads[2:]),body)
                else:
                    self.assertEqual((seeks,count),(2,2))
                code=0
            else:
                observed=b""
                code=EARLY[reason]
                if code<213:
                    self.assertEqual((seeks,count),(0,0))
                elif code==213:
                    self.assertEqual((seeks,count),(1,0))
                elif code==214:
                    self.assertEqual((seeks,reads),(2,[(0,8)]))
                else:
                    self.assertEqual((seeks,count),(2,2))
            if len(data)>CAP:
                self.assertEqual((len(data),reason),(CAP+1,"ok"))
            else:
                qualified.append((data,code,observed,53,WORK+13))
        self.assertEqual(at,len(measured))
        self.panel(qualified)

    def test_private_envelope_and_atomic_output(self):
        good=loan([container()])
        self.panel([
            (b"",210,b"",0,0),(good[:37],210,b"",53,WORK),
            (good[:34]+bytes([255])*4+good[38:],210,b"",53,WORK),
            (good,102,b"",53,WORK-1),(good,102,b"",47,WORK),
            (loan([container(b" "+GOOD)]),215,b"",0,WORK),
            (loan([container(b" "+GOOD)],pin=bytes(32)),211,b"",0,WORK),
            (good,0,struct.pack("<QQ",len(GOOD),4)+hashlib.sha256(container()).digest(),48,WORK),
        ])

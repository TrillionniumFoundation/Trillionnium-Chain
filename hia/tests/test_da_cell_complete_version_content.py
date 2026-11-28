"""TCV2 public original versus two stock HIA emitters; no payload reads."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.test_cell_complete_version import generated, packet
from hia.tests.test_cell_manifest import CHUNK, MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_cell_closure_manifest_relation import id_of
from hia.tests.test_da_protocol_context import locked_reference

SRC = ROOT / "hia/src/data_availability/cell_complete_version_content.hepta"
ORACLE = Path(__file__).with_name("rust_cell_complete_version_content_reference.rs")
DOMAIN = b"TRNM/Cell/CompleteVersionContent/v2\0"
WORK = 131232
CAP = 1 << 20
OLD = ROOT/"trillionnium/crates/trnm-data-availability/src/cell"
PINS = {
    "version_content.rs": "4b1df7fd0500303667873e560c66f90a86ed7cae0ae7784cc46bcc49e69ef57c",
    "version.rs": "e0d11e7cddbb670af8411bed97612e738edf9a7c89b161e1ee4cdd9178cda832",
    "manifest.rs": "cf945af731b8172d6b093bded63d546ac3f3a15756524e739a50187dcdaebdc5",
}
NAMESPACE = "content wire namespace"
TRUNC = "content truncated field"
BIND = "content manifest binding"
TRUNC_CHUNKS = "content truncated chunks"
TRAIL = "content trailing bytes"
COVERAGE = "content manifest coverage"


def digest64(index):
    return int(index).to_bytes(64,"little")


def declarations(cells):
    return [id_of(m)+digest64(i+1)+m[209+m[4]:213+m[4]]
            +digest64(2000+i)*int.from_bytes(m[209+m[4]:213+m[4]],"big")
            for i,m in enumerate(cells)]


def wire(cv, records, count=None):
    n=len(records) if count is None else count
    return b"TCV2"+struct.pack(">I",len(cv))+cv+struct.pack(">H",n)+b"".join(records)


def result(raw, count):
    return struct.pack("<I",count)+hashlib.sha512(DOMAIN+raw).digest()


def at_bound(extent):
    base=((CHUNK*5000,),(CHUNK*5000,))
    def used(args):
        return len(wire(packet(*args),declarations(args[-1])))
    delta=extent-used(generated(base))
    chunks,path=divmod(delta,100)
    args=generated(((CHUNK*(5000+chunks),),base[1]),extra_path=path)
    raw=wire(packet(*args),declarations(args[-1]))
    assert len(raw)==extent
    return raw


def corpus():
    args=generated(((CHUNK,CHUNK*3+7),(CHUNK+1,)))
    cv,rows=packet(*args),declarations(args[-1])
    good=wire(cv,rows)
    out=[(good,0,None,result(good,len(rows)))]
    def add(raw,code,why):
        out.append((raw,code,why,b""))
    def accept(args):
        rs=declarations(args[-1])
        raw=wire(packet(*args),rs)
        out.append((raw,0,None,result(raw,len(rs))))
    accept(generated(((CHUNK,)*256,(CHUNK+1,)*256)))
    maximum=at_bound(CAP)
    out.append((maximum,0,None,result(maximum,2)))
    high=[r[:32]+b"\0"*63+b"\1"+r[96:100]+
          (b"\0"*63+b"\1")*((len(r)-100)//64) for r in rows]
    high_raw=wire(cv,high)
    out.append((high_raw,0,None,result(high_raw,len(rows))))
    out.append((wire(cv,[r[:32]+r[32:96][::-1]+r[96:] for r in rows]),0,None,
                result(wire(cv,[r[:32]+r[32:96][::-1]+r[96:] for r in rows]),len(rows))))
    add(good[:3],211,TRUNC)
    add(b"TCV1"+good[4:],212,NAMESPACE)
    add(good[:7],211,TRUNC)
    add(good[:8]+cv[:-1],211,TRUNC)
    add(good[:8+len(cv)+1],211,TRUNC)
    add(wire(b"",[]),106,"version truncated field")
    add(wire(b"FAKE"+cv[4:],rows,count=0),104,"version magic")
    add(wire(cv+b"x",rows,count=0),88,"version trailing bytes")
    add(wire(packet(*args[:-1],args[-1][::-1]),rows,count=0),89,"version canonical manifests")
    for n in (0,len(rows)-1,len(rows)+1,513):
        add(wire(cv,rows,n),213,COVERAGE)
    add(wire(cv,[*rows[:-1],rows[-1][:31]]),211,TRUNC)
    add(wire(cv,[*rows[:-1],rows[-1][:95]]),211,TRUNC)
    add(wire(cv,[*rows[:-1],rows[-1][:99]]),211,TRUNC)
    add(wire(cv,[*rows[:-1],rows[-1][:-1]]),215,TRUNC_CHUNKS)
    add(wire(cv,[*rows[:-1],rows[-1][:96]+struct.pack(">I",0xffffffff)]),214,BIND)
    add(wire(cv,[*rows[:-1],b"\0"*32+rows[-1][32:100]]),214,BIND)
    add(wire(cv,rows[::-1]),214,BIND)
    add(wire(cv,[rows[0],rows[0],*rows[2:]]),214,BIND)
    add(good+b"x",216,TRAIL)
    zeros=[rows[0][:32]+bytes(64)+rows[0][96:],*rows[1:]]
    add(wire(cv,zeros)+b"x",216,TRAIL)
    add(wire(cv,zeros),214,BIND)
    add(wire(cv,[*zeros[:-1],zeros[-1][:-1]]),215,TRUNC_CHUNKS)
    add(wire(cv,[*zeros[:-1],b"\0"*32+zeros[-1][32:100]]),214,BIND)
    missing_chunk=[*rows[:-1],rows[-1][:-64]+bytes(64)]
    add(wire(cv,missing_chunk),214,BIND)
    add(wire(cv,missing_chunk)+b"x",216,TRAIL)
    return out


class CellCompleteVersionContent(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def validate(self,cases):
        for backend,mod in self.modules.items():
            for idx,(wire,code,expected,output,space) in enumerate(cases):
                with self.subTest(backend=backend,index=idx,extent=len(wire)):
                    before,work=MARK*output,SCRATCH*space
                    got=mod.call("f0",[wire,before,work],timeout=40).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],wire)
                    self.assertEqual(got.arguments[1],expected+before[len(expected):])
                    self.assertEqual(got.arguments[2][WORK:],work[WORK:])

    def test_original_canonical_content_and_rejection_order(self):
        at_bound_plus_one=at_bound(CAP+1)
        cases=corpus()+[(at_bound_plus_one,0,None,result(at_bound_plus_one,2))]
        before={s:hashlib.sha256((OLD/s).read_bytes()).hexdigest() for s in PINS}
        self.assertEqual(before,PINS)
        with tempfile.TemporaryDirectory(prefix="trnm-tcv2-locked-") as private:
            data=b"".join(struct.pack("<I",len(w))+w for w,_,_,_ in cases)
            original=locked_reference(Path(private),data,caller=ORACLE)
        self.assertEqual({s:hashlib.sha256((OLD/s).read_bytes()).hexdigest() for s in PINS},PINS)
        pos=0
        native=[]
        for item,code,error,want in cases:
            size=original[pos]
            pos+=1
            if error is None:
                self.assertEqual(size,0)
                outcome=original[pos:pos+68]
                pos+=68
                self.assertEqual(want,outcome)
            else:
                self.assertGreater(size,0)
                self.assertEqual(original[pos:pos+size].decode(),error)
                pos+=size
                outcome=b""
            if len(item)<=CAP:
                native.append((item,code,outcome,75,WORK+9))
        self.assertEqual(pos,len(original))
        self.assertEqual(len(at_bound_plus_one),CAP+1)
        self.validate(native)

    def test_atomic_output_capacity_and_child_scratch_minimum(self):
        args=generated(((CHUNK,),(CHUNK+1,)))
        rows=declarations(args[-1])
        good=wire(packet(*args),rows)
        self.validate([(good,0,result(good,len(rows)),68,WORK),
                       (good,102,b"",67,WORK),(good,102,b"",68,WORK-1),
                       (good,102,b"",68,16031),(b"TCV1",212,b"",0,0),
                       (b"",211,b"",0,0)])

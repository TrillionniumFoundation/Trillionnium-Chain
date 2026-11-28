"""Original public TMT1 declarations and genuine resident typed get/byte witnesses."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.native_support import NativeModule
from hia.tests.test_da_protocol_context import locked_reference
from hia.tests import test_cell_tensor_contract as tmt
from hia.tests import test_da_cell_tensor_view_bytes as tvb

SRC=ROOT/"hia/src/data_availability/cell_tensor_declared_spec_lookup.hepta"
ORACLE=Path(__file__).with_name("rust_cell_tensor_declared_spec_lookup_reference.rs")
FIXTURE=tvb.ORACLE
FIXTURE_PIN="a1116927a3be100cca2a61b34f0300e6e4c26d498e197680c60b611377c657d2"
CAP=1<<20
MISSING=249


def query(file,name,contract):
    return struct.pack(">HH",file,len(name))+name+contract


def truth(n,item):
    return struct.pack("<Q",n)+item


def saturated(total):
    names=[f"t{i:05d}".encode()+b"x"*54 for i in range(16383)]
    name=b"t16383"+b"x"*10
    rows=[tmt.row(n) for n in names]+[tmt.row(name)]
    current=query(0,name,tmt.wire(tmt.file(0,*rows)))
    shorten=len(current)-total
    assert 0<=shorten<=54
    if shorten:
        rows[0]=tmt.row(names[0][:-shorten])
    both=query(0,name,tmt.wire(tmt.file(0,*rows)))
    assert len(both)==total
    return both,rows[-1]


def declared_cases():
    a=tmt.row(b"Z",(17,),1)
    b=tmt.row(b"a",(),3)
    f=tmt.row("é".encode(),(5,7),2)
    g=tmt.row("𐀀".encode(),(1,2,3,1,1,1,1,1),1)
    c=tmt.wire(tmt.file(1,a,b,f,g),tmt.file(255,tmt.row(b"a")))
    k=tmt.wire(*(tmt.file(i,tmt.row(b"same",(i+1,),3)) for i in range(256)))
    huge=tmt.row(b"x"*255,(65536,262144))
    big=tmt.wire(tmt.file(255,huge))
    r=[(query(1,b"Z",c),0,None,68,a),(query(1,b"a",c),0,None,2,b),
       (query(1,"é".encode(),c),0,None,70,f),(query(1,"𐀀".encode(),c),0,None,24,g),
       (query(255,b"a",c),0,None,4,tmt.row(b"a")),
       (query(255,b"same",k),0,None,512,tmt.row(b"same",(256,),3)),
       (query(0,b"same",k),0,None,2,tmt.row(b"same",(1,),3)),
       (query(255,b"x"*255,big),0,None,1<<36,huge)]
    for f_,n in ((0,b"a"),(2,b"a"),(256,b"a"),(65535,b"a"),(1,b""),(1,b"z"),
                 (1,b"__metadata__"),(1,"e\u0301".encode()),(1,"😀".encode()),
                 (1,b"x"*256),(1,b"x"*65535)):
        r.append((query(f_,n,c),MISSING,None,0,b""))
    for t in (CAP,CAP+1):
        v,row=saturated(t);r.append((v,0,None,4,row))
    bad=[
        (b"",1,"tensor contract length"),
        (c[:39],1,"tensor contract length"),
        (b"NONE"+c[4:],2,"tensor contract version"),
        (c[:4]+b"\0"+c[5:],3,"tensor hash profile"),
        (c[:5]+b"\0"+c[6:],4,"tensor codec"),
        (tmt.wire(),5,"tensor file count"),
        (c[:41],6,"unexpected eof"),
        (tmt.wire(tmt.file(0,count=0)),7,"tensor count"),
        (c+b".",13,"tensor contract suffix"),
        (tmt.wire(tmt.file(1,a),tmt.file(255,b),root=bytes(32)),15,"tensor model root"),
        (tmt.wire(tmt.file(1,a),tmt.file(0,b)),16,"tensor canonical files"),
        (tmt.wire(tmt.file(1,a),tmt.file(256,b)),17,"tensor file roster"),
        (tmt.wire(tmt.file(1,a),tmt.file(2,g,a)),18,"tensor canonical names"),
        (tmt.wire(tmt.file(1,a),tmt.file(2,tmt.row(b"a\x7f"))),19,"tensor name"),
        (tmt.wire(tmt.file(1,a),tmt.file(2,tmt.row(b"x",(0,)))),20,"tensor dimension"),
        (tmt.wire(tmt.file(1,a),tmt.file(2,tmt.row(b"x",(0xffffffff,0xffffffff)))),21,"tensor shape overflow"),
        (tmt.wire(tmt.file(1,a),tmt.file(2,tmt.row(b"x",(65536,262145)))),22,"tensor byte bound"),
        (tmt.wire(tmt.file(1,a),tmt.file(2,huge,tmt.row(b"z"))),23,"tensor file bytes"),
    ]
    r.extend((query(1,b"Z",d),code,why,0,b"") for d,code,why in bad)
    return r


def model_observation(where,queries):
    raw=FIXTURE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=FIXTURE_PIN:
        raise ValueError("Published synthetic resident fixture changed")
    cut=raw.index(b"fn send(")
    setup=raw[:cut]
    assert setup.count(b"const N: usize = 4097;")==1
    setup=setup.replace(b"const N: usize = 4097;",b"const N: usize = 12291;")
    adapter=where/"genuine_public_tensor_spec.rs"
    adapter.write_bytes(setup+ORACLE.read_bytes())
    return locked_reference(where,queries,caller=adapter,extra_externs=("sha2",))


class CellTensorDeclaredSpecLookup(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def panel(self,cases):
        for backend,mod in self.modules.items():
            for k,(data,code,want,nout) in enumerate(cases):
                with self.subTest(backend=backend,case=k,length=len(data)):
                    o,w=MARK*nout,SCRATCH*5
                    got=mod.call("f0",[data,o,w],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],want+o[len(want):])
                    self.assertEqual(got.arguments[2],w)

    def test_original_declared_and_resident_selection_and_wide_old_view(self):
        source=tvb.OLD/"tensor.rs"
        pin=tvb.PINS["tensor.rs"]
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),pin)
        rows=declared_cases()
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-spec-original-") as d:
            req=b"".join(struct.pack("<I",len(f))+f for f,*_ in rows)
            observed=model_observation(Path(d),req)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),pin)
        pos=0
        def frame():
            nonlocal pos
            tag,n=struct.unpack_from("<BI",observed,pos);pos+=5
            p=observed[pos:pos+n];pos+=n
            self.assertEqual(len(p),n)
            return tag,p
        tag,contract=frame()
        self.assertEqual(tag,0)
        actual=[]
        for file,name in ((0,b"a"),(0,b"b"),(0,b"c"),(0,b"z"),(0,b"A"),(1,b"a")):
            tag,raw=frame()
            self.assertIn(tag,(0,2))
            actual.append((query(file,name,contract),0 if tag==0 else MISSING,raw,len(raw)+4))
        tag,payload=frame();self.assertEqual(tag,0)
        tag,parts=frame();self.assertEqual(tag,0)
        tag,copy=frame();self.assertEqual(tag,0)
        reads=[frame() for _ in range(3)]
        self.assertTrue(all(t==0 and len(b)==4 for t,b in reads))
        start=8+struct.unpack_from("<Q",payload)[0]
        count=struct.unpack_from("<I",parts)[0]
        self.assertEqual(count,4)
        spans=struct.unpack_from("<IIII",parts,4)
        self.assertEqual(spans,(tvb.WIDTH-start,tvb.WIDTH,tvb.WIDTH,12291*4-3*tvb.WIDTH+start))
        self.assertEqual(len(copy),12291*4-2)
        for backend in self.modules:
            with NativeModule(tvb.SRC,backend=backend,byte_exports=("f0",)) as stock:
                gathered=[(0,0,0,parts),(1,1,len(copy),copy)]
                left=0
                for span,(_,bits) in zip(spans[:3],reads,strict=True):
                    left+=span
                    gathered.append((2,left//4,0,bits))
                for op,arg,n,want in gathered:
                    d=tvb.envelope(payload,op,1,tvb.WIDTH,start,12291*4,arg,n)
                    got=stock.call("f0",[d,b"\xa5"*(len(want)+1),b""],timeout=35).require_returned()
                    self.assertEqual(got.value,0)
                    self.assertEqual(got.arguments,[d,want+b"\xa5",b""])
        for d,code,error,n,decl in rows:
            tag,out=frame()
            if error is not None:
                self.assertEqual((tag,out),(1,error.encode()))
                want=b""
            elif code==MISSING:
                self.assertEqual((tag,out),(2,b""))
                want=b""
            else:
                self.assertEqual((tag,out),(0,decl))
                # The Rust declaration getter supplies the raw typed row. The
                # u64 bytes are an independent fixture expectation on these
                # inputs; actual public byte_length is compared above.
                want=truth(n,out)
            if len(d)<=CAP:
                actual.append((d,code,want,len(want)+9))
        self.assertEqual(pos,len(observed))
        self.assertEqual(sum(len(d)==CAP+1 for d,*_ in rows),1)
        self.panel(actual)

    def test_private_query_envelope_capacity_and_late_refusal(self):
        item=tmt.row(b"x"*255,(1,)*8)
        body=tmt.wire(tmt.file(255,item))
        q=query(255,b"x"*255,body)
        wanted=truth(4,item)
        self.panel([(q,0,wanted,len(wanted)),(q,102,b"",len(wanted)-1),
                    (q+b".",13,b"",0),(query(255,b"",body),MISSING,b"",0),
                    (query(255,b"\xff",body),248,b"",0),
                    (q[:3],247,b"",0),(q[:7],247,b"",0)])

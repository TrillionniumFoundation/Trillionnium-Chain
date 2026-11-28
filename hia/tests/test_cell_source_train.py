"""Immutable hex to original Cell training through one stock HIA call."""
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import cell_held_rows_original as oracle
from hia.tests.test_cell_held_rows import fields
from hia.tests.test_cell_held_train import HARNESS, frame, E, UMAX
from hia.tests.native_support import NativeModule

HERE=Path(__file__).parent
HIA=HERE.parent
MODULE=HIA/"src/state/cell_source_train.hepta"
ADAPTER=HERE/"rust_cell_source_train_reference.rs"
CELL=oracle.NODE/"cell_native_v1"
MAX_INPUT=606384
ARENA=933376
MAX_OUTPUT=160936
ROWS=396288
TRACE=930304
UNMASKED=798720
NORMAL=536576
OUT=b"\xa9"
WORK=b"\x51"


def sha(data):
    return sha256(data).hexdigest()


def packet(remaining,texts,*,before=None,memory=(0,-1,1),rows=None,
           weights=(),moments=(),update=(),router=None,disabled=(),
           policy=(1,2,1,2,1),already_hex=False):
    count=len(texts)
    if rows is None:
        rows=[(7,j%3) for j in range(count)]
    old=frame(remaining,memory,tuple(fields(mask=m,label=label) for m,label in rows),
              step=before,weights=weights,moments=moments,masks=update,settings=policy)
    if router is None:
        router=(0,)*771
    assert len(router)==771
    mask=bytes(int(k not in disabled) for k in range(257))
    parts=[b"CCT00001",old[8:74128],struct.pack("<771q",*router),mask,bytes(7)]
    for (m,label),text in zip(rows,texts,strict=True):
        hexed=text if already_hex else text.hex().encode()
        parts.extend((struct.pack("<3Q",len(hexed),m,label),hexed))
    return b"".join(parts)


@lru_cache(maxsize=1)
def fixtures():
    text=("  Oak9 TRNMdrop CEDAR\r\n élan  a!".encode(),b" B_c m10 a9 __  9z\t")
    rows=[(5,1),(6,2)]
    weights=tuple((k,((k*5+(k//257)*3)%39)-19) for k in range(E))
    router=tuple(((k*7+(k//257)*3)%33)-16 for k in range(771))
    args=dict(rows=rows,weights=weights,router=router,
              update=tuple((k,1) for k in range(E) if k%3!=0),
              disabled=tuple(k for k in range(256) if k%3==0),policy=(1,1,0,1,3))
    full_texts=tuple((b"a!" if j%2==0 else b"z!")*1024+b"?"*2048 for j in range(64))
    worst=dict(weights=((0,-32767),(256,32767),(E-1,-32767)),
               router=(32767,)*257+(-32767,)*257+(32767,)*257,
               disabled=(62,),moments=((0,-((1<<63)-1)),(1,(1<<63)-1)),
               update=((0,1),(1,1)),policy=(0,1<<32,65535,65536,1<<40))
    late=dict(weights=((E-1,32767),),moments=((0,4),(E-1,-4)),update=((0,1),(E-1,1)))
    return [
        ("two-active",packet(2,text,**args)),
        ("inactive-tail",packet(1,text,**args)),
        ("dry",packet(0,text,before=UMAX,**args)),
        ("carry",packet(2,text,before=(1<<63)-1,**args)),
        ("step-before-update",packet(1,(b"a",),before=UMAX,**late)),
        ("late-weight",packet(1,(b"a",),before=8,**late)),
        ("late-invalid-utf8",packet(1,(b"a",b"good\xff"))),
        ("late-invalid-hex",packet(0,(b"61",b"ffg0"),already_hex=True)),
        ("full-physical-and-token-cap",packet(UMAX,full_texts,before=UMAX-1,**worst)),
    ]


def locked_driver():
    driver=HARNESS.read_bytes()
    source=(CELL/"source.rs").read_bytes()
    work=(CELL/"work.rs").read_bytes()
    assert sha(driver)=="3e44133e38f27cc3b64881f54a9f8585fdcd317eb3dcdfeda573d1593c530805"
    assert sha(source)=="8c27cdadece9f1f9c26bd20869a74318bb7490aea436e6dc0140684c20cf6c3e"
    assert sha(work)=="deb160835dda7a0efacef8975ed55a2a31fd6e4372a635a601cbac9e0c8b672c"
    weights=oracle.exactly(rb"^fn weights\(.*?^\}\n",work)
    scalar,=re.findall(rb"let scalar: i64 = weight\.iter\(\)\.zip\(row\).*?\.sum\(\);",work)
    adapter=ADAPTER.read_bytes()
    adapter=adapter.replace(b"// @FROZEN_WEIGHTS@",weights).replace(b"// @FROZEN_CELL_SCALAR@",scalar)
    selectors=[
        (b'b"CTRX0001"',b'b"CCT00001"'),
        (b'f.len()==74128+2192*n',b'f.len()>=80560'),
        (b"    let mut router=vec![vec![0;DIM];3];\n    router[0][0]=33;",
         b"    let router=matrix(74128,0);"),
        (oracle.exactly(rb"    let mut inputs=Vec::new\(\);.*?(?=    let policy=)",driver),
          b"""    let mut inputs=Vec::new();
    let mut expert_mask=Vec::new();
    let feature_mask=f[80296..80553].iter().map(|&x|match x{0=>false,1=>true,_=>panic!("mask")}).collect();
    assert_eq!(&f[80553..80560],&[0;7]);
    let mut tail=&f[80560..];
    for index in 0..n {
        let width=word(tail,0) as usize;
        let mask=word(tail,8);
        let label=word(tail,16);
        assert!((1..=7).contains(&mask) && label<=2);
        expert_mask.push((0..3).map(|k|mask&(1<<k)!=0).collect::<Vec<_>>());
        let (raw,next)=tail[24..].split_at(width);
        inputs.push(SourceSnippet{id:format!("{:064x}",index+1),origin:"inert".into(),
            content_hex:std::str::from_utf8(raw).unwrap().into(),label:label as u8});
        tail=next;
    }
    assert!(tail.is_empty());
"""),
        (b"feature_mask:vec![true;DIM],expert_mask",b"feature_mask,expert_mask"),
        (b"    let result=match execution::execute(&admission,source::PreparedInputs{features,stages:vec![]},products) {",
         b"""    let prepared=match source::prepare(&admission) {
        Ok(x)=>x,
        Err(e)=>return out.write_all(&[match e.to_string().as_str() {
            "CELL_SOURCE_HEX"=>10,"CELL_SOURCE_UTF8"=>11,
            other=>panic!("Unexpected frozen source refusal: {other}"),
        }]),
    };
    let products=numeric_products(&admission.model,&prepared.features);
    write_source_trace(&prepared,&products,&admission.policy,&admission.inputs,out)?;
    let result=match execution::execute(&admission,prepared,products) {"""),
        (b'let feat=&result.stages[0].inputs["features"];',b'let feat=&result.stages[2].inputs["features"];'),
        (b"let row=&result.stages[1+i];",b"let row=&result.stages[3+i];"),
    ]
    for left,right in selectors:
        assert driver.count(left)==1,(left[:100],left[-100:])
        driver=driver.replace(left,right)
    return driver+b"\n"+adapter,source,dict(weights=sha(weights),scalar=sha(scalar),work=sha(work))


@lru_cache(maxsize=1)
def original():
    driver,source,exact=locked_driver()
    base=oracle.execute_source
    def full(harness=None):
        d=base(harness)
        d["source.rs"]=source
        return d
    cases=fixtures()
    raw=b"".join(struct.pack("<I",len(f))+f for _,f in cases)
    with tempfile.TemporaryDirectory(prefix="trnm-exact-source-train-") as d, patch.object(oracle,"execute_source",full):
        out,pins=oracle.locked_original(Path(d),raw,harness=driver)
    answer=[]
    index=0
    for name,f in cases:
        status=out[index]
        index+=1
        rows=[]
        report=active=b""
        if status==0:
            count,=struct.unpack_from("<I",out,index)
            index+=4
            for _ in range(count):
                size,used=struct.unpack_from("<2Q",out,index)
                assert size<=4096 and used<=1024
                end=index+4160+size
                rows.append((out[index:end],out[end:end+136]))
                index=end+136
            status=out[index]
            index+=1
            if status==0:
                r,a=struct.unpack_from("<2I",out,index)
                index+=8
                report=out[index:index+r]
                active=out[index+r:index+r+a]
                index+=r+a
        answer.append((name,f,status,rows,report,active))
    assert index==len(out)
    p=os.environ.get("HIA_CELL_SOURCE_TRAIN_ORIGINAL_PROOF")
    if p:
        Path(p).write_text(json.dumps(dict(pins=pins,exact=exact,observation_bytes=len(out),observation_sha=sha(out),
           rows=[[tag,len(f),sha(f),status,len(rows),sha(b"".join(x+y for x,y in rows)),len(report),sha(report),
                  len(active),sha(active)] for tag,f,status,rows,report,active in answer]),indent=2,sort_keys=True)+"\n")
    return answer


class CellSourceTrain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock={role:cls.enterClassContext(NativeModule(MODULE,backend=role,byte_exports=("f0",)))
                   for role in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.stock.values()})!=2:
            raise ValueError("Both exact native stocks must emit real separate images")

    def invoke(self,m,frame,code,report=b"",*,out=MAX_OUTPUT+13,arena=ARENA+11):
        obs=m.call("f0",[frame,OUT*out,WORK*arena],timeout=30).require_returned()
        self.assertEqual((obs.abi_status,obs.value),(0,code))
        self.assertEqual(obs.arguments[:2],[frame,report+OUT*(out-len(report))])
        self.assertEqual(obs.arguments[2][ARENA:],WORK*max(0,arena-ARENA))
        return obs.arguments[2]

    def observations(self,arena,rows):
        for j,(prep,num) in enumerate(rows):
            size,=struct.unpack_from("<Q",prep)
            self.assertEqual(len(prep),4160+size)
            row=ROWS+2192*j
            header=TRACE+48*j
            masked=row+136
            unk=UNMASKED+2056*j
            norm=NORMAL+4096*j
            self.assertEqual(arena[header:header+48],prep[:48])
            self.assertEqual(arena[unk:unk+2056],prep[48:2104])
            self.assertEqual(arena[masked:masked+2056],prep[2104:4160])
            self.assertEqual(arena[norm:norm+size],prep[4160:])
            self.assertEqual(arena[norm+size:norm+4096],WORK*(4096-size))
            self.assertEqual(arena[row:row+136],num)

    def test_pure_frozen_full_prepare_products_execute_matches_every_phase(self):
        cases=original()
        by={tag:(f,code,rows,report,active) for tag,f,code,rows,report,active in cases}
        self.assertEqual([c[2] for c in cases],[0,0,0,0,201,203,11,10,0])
        full,code,rows,report,active=by["full-physical-and-token-cap"]
        self.assertEqual((len(full),code,len(rows),len(report),len(active)),(MAX_INPUT,0,64,MAX_OUTPUT,134144))
        self.assertTrue(all(struct.unpack_from("<2Q",x)==(4096,1024) for x,_ in rows))
        self.assertGreater(len(set(struct.iter_unpack("<q",b"".join(num[16:] for _,num in by["two-active"][2])))),10)
        self.assertNotEqual(by["two-active"][3],by["inactive-tail"][3])
        first_bound=30848+80*2
        self.assertEqual(struct.unpack_from("<Q",by["carry"][3],first_bound+8),(1<<63,))
        for role,m in self.stock.items():
            for tag,f,code,rows,report,active in cases:
                with self.subTest(backend=role,case=tag):
                    if tag=="full-physical-and-token-cap":
                        w=self.invoke(m,f,code,report,out=MAX_OUTPUT,arena=ARENA)
                    else:
                        w=self.invoke(m,f,code,report)
                    self.observations(w,rows)
                    if code==0:
                        self.assertEqual(w[:len(report)],report)
                        self.assertEqual(w[262144:262144+len(active)],active)
                        self.assertEqual(w[262144+len(active):ROWS],WORK*(ROWS-262144-len(active)))
                    elif code==203:
                        at=30848+80+32
                        self.assertTrue(any(c!=WORK[0] for c in w[at:at+40]))
                        final=30848+80+123392-40
                        self.assertEqual(w[final:final+40],WORK*40)
                    else:
                        self.assertEqual(w[262144:ROWS],WORK*(ROWS-262144))

    def test_malformed_and_loan_refusals_never_publish(self):
        seen={tag:(f,code,rows,report,active) for tag,f,code,rows,report,active in original()}
        f,_,_,out,_=seen["two-active"]
        last=seen["late-weight"][0]
        step=seen["step-before-update"][0]
        bad_source=seen["late-invalid-utf8"][0]
        change=lambda pos,data:f[:pos]+data+f[pos+len(data):]
        guards=[
            (f[:80559],100), (b"BadMagic"+f[8:],100),
            (change(8,struct.pack("<Q",65)),100), (f+b"\0",100), (f[:-1],100),
            (change(80560,struct.pack("<Q",8193)),10),
            (change(80296,b"\x02"),101), (change(80552,b"\x00"),101),
            (change(80559,b"\x01"),101), (change(74128,struct.pack("<q",32768)),100),
        ]
        for role,m in self.stock.items():
            for f0,code in guards:
                with self.subTest(backend=role,code=code):
                    self.invoke(m,f0,code,out=0)
            self.assertEqual(self.invoke(m,f,102,out=len(out),arena=ARENA-1),WORK*(ARENA-1))
            self.invoke(m,f,102,out=len(out)-1,arena=ARENA)
            self.invoke(m,last,203,out=0,arena=ARENA)
            self.invoke(m,step,201,out=0,arena=ARENA)
            self.invoke(m,bad_source,11,out=0,arena=ARENA)
            self.invoke(m,f,0,out,out=len(out),arena=ARENA)

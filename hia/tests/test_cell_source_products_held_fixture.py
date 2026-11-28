"""One synthetic text/masked-input -> all actual signed lanes -> real CTRX."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import cell_held_rows_original as old
from hia.tests.native_support import NativeModule
from hia.tests.test_cell_held_train import HARNESS, SOURCE as CTRX, arena_size, frame
from hia.tests.test_cell_held_rows import fields

ROOT = Path(__file__).resolve().parents[2]
CSP = ROOT/"hia/src/model/cell_source_prepare.hepta"
DOT = ROOT/"hia/src/state/cell_scalar_products.hepta"
FRAGMENT = Path(__file__).with_name("rust_cell_source_products_held_fixture.rs")
OWNER = ROOT/"trillionnium/crates/trnm-pon-node/src/cell_native_v1"
WORK = OWNER/"work.rs"
ROUTED = ROOT/"trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs"
D, R, E = 257, 3*257, 4*3*257
START, WIDTH = 74128, 2192
TEXT = ("  Gamma\tALpha\n_gamma M00 m04 TRNMSkip café Brass beta ".encode(),
        "\u2003beta\r\nDELTA9 _k9 delta9 m10 \tGamma alpha\r".encode())
PREFIXES = (2,1,0)


def digest(src):
    return sha256(src).hexdigest()


def locked_reference(skeletons, mask, router):
    draft=HARNESS.read_bytes()
    assert digest(draft)=="3e44133e38f27cc3b64881f54a9f8585fdcd317eb3dcdfeda573d1593c530805"
    full_source=(OWNER/"source.rs").read_bytes()
    work,routed=WORK.read_bytes(),ROUTED.read_bytes()
    pins=dict(source=digest(full_source),work=digest(work),routed=digest(routed))
    assert pins==dict(source="8c27cdadece9f1f9c26bd20869a74318bb7490aea436e6dc0140684c20cf6c3e",
                      work="deb160835dda7a0efacef8975ed55a2a31fd6e4372a635a601cbac9e0c8b672c",
                      routed="e9416457ee3df24cf5446ebffde6d7748a8eeff8f0f46e77b6ad9555e0ef6b0a")
    weight=old.exactly(rb"^fn weights\(.*?^\}\n",work)
    dot=old.exactly(rb"^fn dot\(.*?^\}\n",routed)
    [scalar]=re.findall(rb"let scalar: i64 = weight\.iter\(\)\.zip\(row\).*?\.sum\(\);",work)
    saved_fragment=FRAGMENT.read_bytes()
    helpers=saved_fragment.replace(b"// @FROZEN_DOT_AND_WEIGHT_ORDER@",weight+dot)
    helpers=helpers.replace(b"// @FROZEN_CELL_SCALAR_EXPRESSION@",scalar)
    changes=[
        (b"fn observe(f:&[u8],out:&mut impl Write)->io::Result<()> {",
         b"fn observe(f:&[u8],texts:&[&[u8]],feature_mask:Vec<bool>,router_raw:&[u8],out:&mut impl Write)->io::Result<()> {"),
        (b"    let mut router=vec![vec![0;DIM];3];\n    router[0][0]=33;",
         b"    let router:Matrix=(0..3).map(|j|(0..DIM).map(|k|word(router_raw,8*(j*DIM+k)) as i64).collect()).collect();"),
        (b'content_hex:"61".into(),label:label as u8',
         b'content_hex:hex::encode(texts[index]),label:label as u8'),
        (b"feature_mask:vec![true;DIM],expert_mask",b"feature_mask,expert_mask"),
        (b"    let result=match execution::execute(&admission,source::PreparedInputs{features,stages:vec![]},products) {",
         b"    let prepared=source::prepare(&admission).unwrap();\n"
         b"    let inputs=frozen_numeric_products(&admission.model,&prepared.features);\n"
         b"    stage_trace(&prepared,&inputs,out)?;\n"
         b"    let result=match execution::execute(&admission,prepared,inputs) {"),
        (b'let feat=&result.stages[0].inputs["features"];',b'let feat=&result.stages[2].inputs["features"];'),
        (b"let row=&result.stages[1+i];",b"let row=&result.stages[3+i];"),
        (b"        observe(frame,&mut out)?;\n        f=rest;",
         b"        let (mask,payload)=rest.split_at(DIM);\n"
         b"        let feature_mask=mask.iter().map(|v| match v {0=>false,1=>true,_=>unreachable!()}).collect();\n"
         b"        let (router,mut payload)=payload.split_at(3*DIM*8);\n"
         b"        let mut texts=Vec::new();\n"
         b"        for _ in 0..word(frame,8) {\n"
         b"            let count=u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;\n"
         b"            let (text,rest)=payload[4..].split_at(count);\n"
         b"            texts.push(text); payload=rest;\n"
         b"        }\n"
         b"        observe(frame,&texts,feature_mask,router,&mut out)?;\n"
         b"        f=payload;"),
    ]
    for before,after in changes:
        assert draft.count(before)==1
        draft=draft.replace(before,after)
    # No changes to the pinned original execution body, full preparation
    # body, or settled existing fixtures. Thin original witness declares
    # only the previously compiled owner types and selected exact functions.
    dispatch=old.execute_source
    def original_modules(harness=None):
        result=dispatch(harness)
        result["source.rs"]=full_source
        return result
    suffix=bytes(mask)+router+b"".join(struct.pack("<I",len(s))+s for s in TEXT)
    wire=b"".join(struct.pack("<I",len(s))+s+suffix for s in skeletons)
    with tempfile.TemporaryDirectory(prefix="trnm-source-products-ctrx-") as td, patch.object(old,"execute_source",original_modules):
        answer,receipt=old.locked_original(Path(td),wire,harness=draft+b"\n"+helpers)
    assert FRAGMENT.read_bytes()==saved_fragment and (OWNER/"source.rs").read_bytes()==full_source
    assert WORK.read_bytes()==work and ROUTED.read_bytes()==routed
    found=[]; offset=0
    for _ in skeletons:
        count,=struct.unpack_from("<I",answer,offset); offset+=4
        assert count==len(TEXT)
        preps=[]; lanes=[]
        for _ in range(count):
            length,=struct.unpack_from("<I",answer,offset); offset+=4
            preps.append(answer[offset:offset+length]); offset+=length
            lanes.append(answer[offset:offset+120]); offset+=120
        code,n,prepared=struct.unpack_from("<BII",answer,offset); offset+=9
        assert code==0
        report=answer[offset:offset+n]; offset+=n
        rows=answer[offset:offset+prepared]; offset+=prepared
        found.append((preps,lanes,report,rows))
    assert offset==len(answer)
    receipt.update(full_sources=pins,exact_weights_body_sha256=digest(weight),exact_dot_sha256=digest(dot),
                   exact_scalar_sha256=digest(scalar),bridge_sha256=digest(draft+b"\n"+helpers),
                   original_stdout_sha256=digest(answer),original_input_sha256=digest(wire))
    return found,receipt


def original_fixture():
    # Distinct bounded signed domains for every element/lane, not precomputed dots.
    model=tuple(((k*5+(k//D)*3)%39)-19 for k in range(5*R))
    weights=model[:R]+model[2*R:]
    router=struct.pack(f"<{R}q",*model[R:2*R])
    feature_mask=bytes(int(k%3!=0 or k==D-1) for k in range(D))
    # These are placeholder *transport* rows for the original witness parser.
    # Native CTRX gets the actual feature/product bytes, never these placeholders.
    headers=((5,1),(6,2))
    no_product=tuple(fields(mask=mask,label=label) for mask,label in headers)
    skeletons=[frame(n,(0,-1,1),no_product,
                    weights=tuple(enumerate(weights)),masks=tuple((j,1) for j in range(E) if j%3!=0),
                    settings=(1,1,0,1,3)) for n in PREFIXES]
    return model,router,feature_mask,skeletons,headers


def i32_exact(words):
    assert len(words)%8==0
    count=len(words)//8
    values=struct.unpack(f"<{count}q",words)
    result=struct.pack(f"<{count}i",*values)
    assert struct.pack(f"<{count}q",*struct.unpack(f"<{count}i",result))==words
    return result


class CellSourceProductsHeldFixture(unittest.TestCase):
    def test_actual_stock_bytes_consume_real_source_and_all_products(self):
        model,router,mask,skeletons,headers=original_fixture()
        expected,source_proof=locked_reference(skeletons,mask,router)
        preps,lanes=expected[0][:2]
        self.assertTrue(all(x[:2]==expected[0][:2] for x in expected))
        self.assertNotEqual(preps[0][2104:4160],preps[1][2104:4160])
        self.assertTrue(any(p[48:2104]!=p[2104:4160] for p in preps))
        numeric=tuple(v for row in lanes for (v,) in struct.iter_unpack("<q",row))
        self.assertGreater(len(set(numeric)),10)
        self.assertLess(min(numeric),0)
        self.assertGreater(max(numeric),0)
        self.assertEqual({len(p) for p in lanes},{120})
        observed={}
        for backend in ("direct","selfhost"):
            with (NativeModule(CSP,byte_exports=("f0",),backend=backend) as prep,
                  NativeModule(DOT,byte_exports=("f0",),backend=backend) as product,
                  NativeModule(CTRX,byte_exports=("f0",),backend=backend) as train):
                outputs=[]
                for raw,want in zip(TEXT,preps,strict=True):
                    req=b"CSP00001"+mask+raw.hex().encode()
                    dst=b"\xa5"*(len(want)+13)
                    work=b"\x37"*(19712+11)
                    ret=prep.call("f0",[req,dst,work]).require_returned()
                    self.assertEqual((ret.value,ret.arguments[:2],ret.arguments[2][19712:]),
                                     (0,[req,want+dst[len(want):]],work[19712:]))
                    outputs.append(ret.arguments[1][:len(want)])
                masked=[o[2104:4160] for o in outputs]
                prod_frame=(struct.pack("<I",len(masked))+i32_exact(struct.pack(f"<{len(model)}q",*model))
                            +b"".join(i32_exact(r) for r in masked))
                prod_dst=b"\xc7"*(120*len(masked)+5)
                got=product.call("f0",[prod_frame,prod_dst,b"\x89"]).require_returned()
                want=b"".join(lanes)
                self.assertEqual((got.value,got.arguments),(0,[prod_frame,want+prod_dst[len(want):],b"\x89"]))
                actual_products=got.arguments[1][:len(want)]
                requests=[]
                reports=[]
                for i,(n,seed,ref) in enumerate(zip(PREFIXES,skeletons,expected,strict=True)):
                    rows=b"".join(struct.pack("<2Q",*header)+actual_products[k*120:k*120+120]+masked[k]
                                  for k,header in enumerate(headers))
                    self.assertEqual(len(rows),WIDTH*len(headers))
                    request=seed[:START]+rows
                    report,training_rows=ref[2:]
                    self.assertEqual(len(training_rows),2096*n)
                    self.assertEqual(len(report),154280+104*n)
                    self.assertEqual(struct.unpack_from("<Q",report,len(report)-40-24*n),(n,))
                    typed_stage=struct.unpack_from("<4Q",report,30848+80*n)
                    self.assertEqual(typed_stage,(1,1,1,1) if n else (0,0,0,0))
                    update_start=30848+80*n+32
                    consumed_weights=b"".join(report[update_start+40*j:update_start+40*j+8] for j in range(E))
                    old_weights=seed[80:80+8*E]
                    if n:
                        self.assertNotEqual(consumed_weights,old_weights)
                    else:
                        self.assertEqual(consumed_weights,old_weights)
                    self.assertEqual(struct.unpack_from("<Q",report,len(report)-32-24*n),(0,))
                    output=b"\xd4"*(len(report)+19)
                    bound=arena_size(n)
                    work=b"\x8e"*(bound+17)
                    got=train.call("f0",[request,output,work]).require_returned()
                    self.assertEqual((got.value,got.arguments[:2],got.arguments[2][bound:]),
                                     (0,[request,report+output[len(report):]],work[bound:]))
                    if n:
                        self.assertEqual(got.arguments[2][262144:bound],training_rows)
                    requests.append(digest(request))
                    reports.append(digest(got.arguments[1][:len(report)]))
                observed[backend]=dict(csp_inputs_sha256=[digest(b"CSP00001"+mask+x.hex().encode()) for x in TEXT],
                    csp_masked_sha256=[digest(x) for x in masked],csp_outputs_sha256=[digest(x) for x in outputs],
                    product_input_sha256=digest(prod_frame),product_output_sha256=digest(actual_products),
                    ctrx_input_sha256=requests,ctrx_output_sha256=reports,
                    modules={label:dict(artifact_sha256=m.artifact_sha256,closure=m.receipt["chain_migration"])
                             for label,m in (("source",prep),("fifteen",product),("ctrx",train))})
        for key in observed["direct"].keys()-{"modules"}:
            self.assertEqual(observed["direct"][key],observed["selfhost"][key])
        output=os.environ.get("HIA_CELL_SOURCE_PRODUCTS_HELD_PROOF")
        if output:
            Path(output).write_text(json.dumps(dict(original=source_proof,native=observed,
                    rows=len(TEXT),active_counts=PREFIXES,exact_products=numeric,
                    owner_execution_used_only_as_original_numeric_oracle=True,
                    real_data_actions_proofs_authority=False),indent=2,sort_keys=True)+"\n")

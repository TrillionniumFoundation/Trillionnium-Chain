"""True one-loan CCT updated bytes into a later synthetic ordinary forward."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_cell_source_train as published
from hia.tests.native_support import NativeModule
from hia.tests.test_cell_trained_ctrx_model_held_forward import (
    ROOT, E, MATRIX, SERIALIZER, packed_i64, ordinary_packet, exact_decode, candidate_words,
)
from hia.tests.test_routed_int257_ordinary import (
    CALLER, DIM, ORIGINAL, PIN, SOURCE as ORDINARY, locked_ordinary, records,
)


def sha(data):
    return sha256(data).hexdigest()


def reference(named):
    driver,source,spans=published.locked_driver()
    # Add two observations of the actual original typed Model values
    # already held by the driver. Original source and execute are untouched.
    anchor=b"    out.write_all(&active_records)"
    assert driver.count(anchor)==1
    changed=driver.replace(anchor,b"""    out.write_all(&active_records)?;
    for model in [&admission.model,&result.after_model] {
        let bytes=canonical(model).unwrap();
        out.write_all(&(bytes.len() as u32).to_le_bytes())?;
        out.write_all(&bytes)?;
    }
    Ok(())""")
    old=published.oracle.execute_source
    def exact(harness=None):
        extracted=old(harness)
        extracted["source.rs"]=source
        return extracted
    request=b"".join(struct.pack("<I",len(f))+f for _,f in named)
    with tempfile.TemporaryDirectory(prefix="trnm-cct-held-model-") as d, patch.object(published.oracle,"execute_source",exact):
        raw,pins=published.oracle.locked_original(Path(d),request,harness=changed)
    offset=0
    traced=[]
    for _,frame in named:
        status,count=struct.unpack_from("<BI",raw,offset)
        offset+=5
        assert status==0 and count==2
        rows=[]
        for _ in range(count):
            n,=struct.unpack_from("<Q",raw,offset)
            end=offset+4160+n
            rows.append((raw[offset:end],raw[end:end+136]))
            offset=end+136
        status,p,a=struct.unpack_from("<BII",raw,offset)
        offset+=9
        assert status==0
        report=raw[offset:offset+p]; offset+=p
        active=raw[offset:offset+a]; offset+=a
        views=[]
        for _ in range(2):
            n,=struct.unpack_from("<I",raw,offset)
            offset+=4
            views.append(raw[offset:offset+n]); offset+=n
        traced.append((rows,report,active,*views))
    assert offset==len(raw)
    return traced,dict(pins=pins,spans=spans,base_harness_sha256=sha(driver),
                       harness_sha256=sha(changed),source_sha256=sha(source),
                       input_sha256=sha(request),stdout_sha256=sha(raw))


def held():
    # These fixed non-text feature probes are separate from the trained text
    # rows. They are not samples of a later real or independent population.
    rows=[]
    for j in (3,7,11,41,102,201):
        x=[0]*DIM
        x[j]=1 if j%2 else -2
        x[-1]=8
        rows.append(tuple(x))
    return rows


def original_planes(request):
    return request[80:80+8*E]+request[74128:74128+8*MATRIX]


def source_bytes(arena,j,length):
    row=published.ROWS+2192*j
    h=published.TRACE+48*j
    u=published.UNMASKED+2056*j
    no=published.NORMAL+4096*j
    feature=(arena[h:h+48]+arena[u:u+2056]+arena[row+136:row+2192]+arena[no:no+length])
    return feature,arena[row:row+136]


class CellCctTrainedModelHeldForward(unittest.TestCase):
    def test_nonzero_text_training_emitted_weights_reach_exact_held_ordinary(self):
        published_fixtures=dict(published.fixtures())
        named=[(k,published_fixtures[k]) for k in ("two-active","inactive-tail","dry")]
        original,train_pins=reference(named)
        before=original[0][3]
        views=[before,*(o[4] for o in original)]
        self.assertEqual(original[1][3],before)
        self.assertEqual(original[2][3],before)
        self.assertEqual(views[3],before)
        self.assertNotEqual(views[1],before)
        self.assertNotEqual(views[2],before)
        self.assertNotEqual(views[1],views[2])
        held_rows=held()
        model_weights=[packed_i64(exact_decode(b)) for b in views]
        original_wire=[ordinary_packet(raw,weights,held_rows) for raw,weights in zip(views,model_weights,strict=True)]
        native={}
        output_by_mode={}
        for mode in ("direct","selfhost"):
            with (NativeModule(published.MODULE,backend=mode,byte_exports=("f0",)) as cct,
                  NativeModule(SERIALIZER,backend=mode,byte_exports=("f0",)) as canon,
                  NativeModule(ORDINARY,backend=mode,byte_exports=("f0",)) as forward):
                candidate_words_used=[original_planes(named[0][1])]
                inputs=[];traces=[]
                for count,(k,request),(rows,report,active,old_json,updated_json) in zip((2,1,0),named,original,strict=True):
                    out=b"\xa3"*(len(report)+9)
                    arena=b"\xd9"*(published.ARENA+11)
                    ret=cct.call("f0",[request,out,arena]).require_returned()
                    source,out_result,work=ret.arguments
                    self.assertEqual((ret.value,source,out_result,work[published.ARENA:]),
                                     (0,request,report+out[len(report):],arena[published.ARENA:]))
                    self.assertEqual(work[262144:262144+len(active)],active)
                    self.assertEqual(len(active),2096*count)
                    self.assertEqual(len(report),154280+104*count)
                    inputs.append(sha(request)); products=[]
                    for j,(feature,numeric) in enumerate(rows):
                        got=source_bytes(work,j,len(feature)-4160)
                        self.assertEqual(got,(feature,numeric))
                        products.append(got[1][16:])
                    signed=[x for row in products for (x,) in struct.iter_unpack("<q",row)]
                    self.assertEqual(len(signed),30)
                    self.assertLess(min(signed),0)
                    self.assertGreater(max(signed),0)
                    self.assertGreater(len(set(signed)),10)
                    changed=candidate_words(out_result,count)
                    router=request[74128:80296]
                    self.assertEqual(len(router),8*MATRIX)
                    self.assertEqual(packed_i64(exact_decode(old_json)),original_planes(request))
                    self.assertEqual(changed+router,packed_i64(exact_decode(updated_json)))
                    candidate_words_used.append(changed+router)
                    traces.append(dict(case=k,report_sha256=sha(out_result[:len(report)]),
                                       product_sha256=sha(b"".join(products)),router_sha256=sha(router)))
                self.assertEqual(candidate_words_used,model_weights)
                native_wire=[];payloads=[]; digests=[]
                for words,want in zip(candidate_words_used,views,strict=True):
                    raw=b"CMCV0001"+words
                    out=b"\xa5"*(len(want)+11)
                    ret=canon.call("f0",[raw,out,b""]).require_returned()
                    self.assertEqual((ret.value,ret.arguments),(len(want),[raw,want+out[len(want):],b""]))
                    # Decode the actual candidate output once; no oracle bytes
                    # are substituted for model words in the inference call.
                    emitted=ret.arguments[1][:ret.value]
                    packet=ordinary_packet(emitted,words,held_rows)
                    native_wire.append(packet)
                    digests.append(dict(typed_model_sha256=sha(words),actual_canonical_sha256=sha(emitted),
                                        actual_consumed_packet_sha256=sha(packet)))
                    expected_size=len(held_rows)*26
                    o=b"\xc5"*(expected_size+13)
                    ret=forward.call("f0",[packet,o,b"\x23"]).require_returned()
                    self.assertEqual((ret.value,ret.arguments[0],ret.arguments[1][expected_size:],ret.arguments[2]),
                                     (0,packet,o[expected_size:],b"\x23"))
                    payloads.append(ret.arguments[1][:expected_size])
                self.assertEqual(native_wire,original_wire)
                output_by_mode[mode]=(native_wire,payloads)
                native[mode]=dict(input_hashes=inputs,observed=traces,forward_inputs=digests,
                                  modules={n:dict(artifact_sha256=m.artifact_sha256,closure=m.receipt["chain_migration"])
                                           for n,m in (("cct",cct),("model",canon),("ordinary",forward))})
        self.assertEqual(output_by_mode["direct"],output_by_mode["selfhost"])
        exact_requests,exact_outputs=output_by_mode["direct"]
        wire=b"".join(struct.pack("<I",len(packet))+packet for packet in exact_requests)
        self.assertEqual(sha(ORIGINAL.read_bytes()),PIN)
        with tempfile.TemporaryDirectory(prefix="trnm-cct-held-ordinary-") as d:
            out=locked_ordinary(Path(d),wire)
        traced=list(records(out,len(exact_requests)))
        self.assertEqual(traced,[(0,v) for v in exact_outputs])
        self.assertEqual(exact_outputs[0],exact_outputs[3])
        self.assertNotEqual(exact_outputs[0],exact_outputs[1])
        self.assertNotEqual(exact_outputs[0],exact_outputs[2])
        if saved:=os.environ.get("HIA_CELL_CCT_HELD_FORWARD_PROOF"):
            Path(saved).write_text(json.dumps(dict(original_cct=train_pins,stock=native,
                old_ordinary_source_sha256=PIN,ordinary_reference_sha256=sha(CALLER.read_bytes()),
                ordinary_same_request_sha256=sha(wire),old_ordinary_stdout_sha256=sha(out),
                forward_results=[list(struct.iter_unpack("<qqqBB",r)) for r in exact_outputs],
                original_canonical_from_true_held_models=True,synthetic_only=True),indent=2,sort_keys=True)+"\n")

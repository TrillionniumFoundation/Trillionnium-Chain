"""Synthetic train -> same model bytes -> original/stock held routed arithmetic."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_model_artifact import ORIGINAL, PINS, ROOT, RUST_ROOT
from hia.tests import cell_held_rows_original as EXECUTE_SOURCE
from hia.tests.test_cell_held_rows import fields
from hia.tests.test_cell_held_train import HARNESS as HELD_REFERENCE, SOURCE as TRAIN, arena_size, frame as held_train_frame
from hia.tests.test_routed_int257_ordinary import (
    CALLER as ORDINARY_REF, DIM, MANIFEST, ORIGINAL as ORDINARY_RUST, SOURCE as ORDINARY,
    locked_ordinary, records,
)

SERIALIZER = ROOT/"hia/src/model/cell_model_canonical.hepta"
CANON_REF = Path(__file__).with_name("rust_cell_model_forward_canonical_reference.rs")
TUPLE = struct.Struct("<qqqBB")
MATRIX = 3*DIM
E = 4*MATRIX
SCHEMA = "pon-cell-stateful-native-int257-v1/model"


def digest(raw):
    return sha256(raw).hexdigest()


def checked(command, *, cwd, env=None, data=None, timeout=60):
    result = subprocess.run(command,cwd=cwd,env=env,input=data,capture_output=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result


def exact_canonical(directory, raw):
    """Link the unchanged original Rust Node under its actual manifest/lockfile."""
    def source_ids():
        return {p:digest((RUST_ROOT/p).read_bytes()) for p in PINS}
    git = ["git","--no-replace-objects"]
    assert checked([*git,"rev-parse","HEAD:trillionnium"],cwd=ROOT).stdout.strip().decode()==ORIGINAL
    checked([*git,"diff","--quiet","HEAD","--","trillionnium"],cwd=ROOT)
    assert source_ids()==PINS
    reference=CANON_REF.read_bytes()
    rustc=os.environ.get("TRNM_HIA_RUSTC","rustc")
    version=checked([rustc,"--version"],cwd=directory).stdout
    assert version.startswith(b"rustc 1.95.0 (59807616e ")
    sr=Path(checked([rustc,"--print","sysroot"],cwd=directory).stdout.decode().strip())
    rustc,cargo=sr/"bin/rustc",sr/"bin/cargo"
    assert checked([rustc,"--version"],cwd=directory).stdout==version
    target=directory/"target"
    env={**os.environ,"RUSTC":str(rustc),"CARGO_BUILD_JOBS":"1",
         "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    build=checked([cargo,"build","--locked","--offline","--no-default-features","--lib",
                   "-p","trnm-pon-node","--manifest-path",MANIFEST,"--target-dir",target,
                   "--message-format=json"],cwd=directory,env=env,timeout=360)
    events=[json.loads(line) for line in build.stdout.splitlines()]
    assert events[-1]=={"reason":"build-finished","success":True}
    [artifact]=[e for e in events if e.get("reason")=="compiler-artifact"
                and e["target"]["name"]=="trnm_pon_node" and e["target"]["kind"]==["lib"]]
    crate=RUST_ROOT/"crates/trnm-pon-node"
    assert not artifact["features"] and not artifact["fresh"]
    assert Path(artifact["manifest_path"])==crate/"Cargo.toml"
    assert Path(artifact["target"]["src_path"])==crate/"src/lib.rs"
    [rlib]=[str(p) for p in artifact["filenames"] if p.endswith(".rlib")]
    assert Path(rlib).is_relative_to(target)
    exe=directory/"original-model-canonical"
    checked([rustc,"--edition=2021",CANON_REF,"--extern",f"trnm_pon_node={rlib}",
             "-L",f"dependency={target/'debug/deps'}","-o",exe],cwd=directory,env=env)
    inert=directory/"inert"
    inert.mkdir()
    run=checked([exe],cwd=inert,env={},data=raw)
    assert not run.stderr and not list(inert.iterdir())
    assert source_ids()==PINS and CANON_REF.read_bytes()==reference
    views=[];at=0
    while at<len(run.stdout):
        size,=struct.unpack_from("<I",run.stdout,at)
        assert at+4+size<=len(run.stdout)
        views.append(run.stdout[at+4:at+4+size])
        at+=4+size
    return views,dict(workspace_tree=ORIGINAL,binary_sha256=digest(exe.read_bytes()),
                      reference_sha256=digest(reference),stdout_sha256=digest(run.stdout))


def flat(model):
    return tuple(v for matrix in (model["base"],*model["deltas"],model["router"])
                 for row in matrix for v in row)


def exact_decode(raw):
    def ordered(values):
        assert len(values)==len({k for k,_ in values})
        return dict(values)
    model=json.loads(raw.decode("ascii"),object_pairs_hook=ordered)
    assert list(model)==["base","deltas","router","schema"] and model["schema"]==SCHEMA
    assert len(model["deltas"])==3
    matrices=(model["base"],*model["deltas"],model["router"])
    assert all(len(m)==3 and all(len(row)==DIM for row in m) for m in matrices)
    values=flat(model)
    assert len(values)==E+MATRIX
    assert all(type(v) is int and -32767<=v<=32767 for v in values)
    assert json.dumps(model,ensure_ascii=True,separators=(",",":")).encode()==raw
    return values


def packed_i64(values):
    return struct.pack(f"<{len(values)}q",*values)


def frozen_execute(fixture_dir, frames):
    """Change only the inert driver router and add original before/after byte observations."""
    harness=HELD_REFERENCE.read_bytes()
    expected="3e44133e38f27cc3b64881f54a9f8585fdcd317eb3dcdfeda573d1593c530805"
    assert digest(harness)==expected
    fixture_router=b"    router[0][0]=33;"
    distinct_routes=b"    router[1][7]=2; router[2][11]=3;"
    emit=b"    out.write_all(&active_records)"
    trace=(b"    out.write_all(&active_records)?;\n"
           b"    for matrix in [&admission.model.router,&result.after_model.router] {\n"
           b"        for row in matrix { for value in row { out.write_all(&value.to_le_bytes())?; } }\n"
           b"    }\n"
           b"    Ok(())")
    assert harness.count(fixture_router)==harness.count(emit)==1
    bridge=harness.replace(fixture_router,distinct_routes).replace(emit,trace)
    request=b"".join(struct.pack("<I",len(w))+w for w in frames)
    raw,pins=EXECUTE_SOURCE.locked_original(fixture_dir,request,harness=bridge)
    records=[]; pos=0
    for _ in frames:
        status,length,rows=struct.unpack_from("<BII",raw,pos)
        pos+=9
        assert status==0
        report=raw[pos:pos+length]; pos+=length
        prepared=raw[pos:pos+rows]; pos+=rows
        before=raw[pos:pos+MATRIX*8]; pos+=MATRIX*8
        after=raw[pos:pos+MATRIX*8]; pos+=MATRIX*8
        assert before==after and len(after)==MATRIX*8
        records.append((report,prepared,before,after))
    assert pos==len(raw)
    return records,dict(**pins,harness_sha256=expected,bridge_sha256=digest(bridge),
                        request_sha256=digest(request),stdout_sha256=digest(raw))


def candidate_words(report, count):
    begin=30848+80*count
    return b"".join(report[begin+32+40*j:begin+40+40*j] for j in range(E))


def training_frames():
    # Simple old synthetic algebra: bias-only feature row, and every
    # corresponding coefficient of each old matrix is zero. The 15 held
    # product lanes are explicitly the inert zero fixture, not a result
    # purported to come from a host or a native product execution.
    held=fields(mask=7,label=1,features=(0,)*256+(8,))
    # Only class 1 bias in base and delta0 trains.
    mask=((2*DIM-1,1),(MATRIX+2*DIM-1,1))
    return [held_train_frame(n,(0,0,0),(held,),masks=mask,settings=(1,1,0,1,3)) for n in (1,0)]


def held_features():
    # Train is bias-only; each held row contributes at a different non-bias position.
    rows=[]
    for coordinate in (3,7,11):
        r=[0]*DIM
        r[coordinate]=1
        r[-1]=8
        rows.append(tuple(r))
    return rows


def ordinary_packet(canonical, exact_weights, held):
    # Numeric values on this boundary come from decoding the bytes actually
    # emitted by HIA, not the original oracle or an independently built model.
    weights=exact_decode(canonical)
    assert packed_i64(weights)==exact_weights
    model=weights[:MATRIX]+weights[E:]+weights[MATRIX:E]
    packed=struct.pack(f"<{len(model)}i",*model)
    # Roundtrip every narrowing and the reversed model signature, no dot product.
    i32=struct.unpack(f"<{len(model)}i",packed)
    assert i32[:MATRIX]+i32[2*MATRIX:]+i32[MATRIX:2*MATRIX]==weights
    return struct.pack("<I",len(held))+packed+b"".join(struct.pack(f"<{DIM}i",*r) for r in held)


class CellTrainedModelHeldForward(unittest.TestCase):
    def test_exact_fused_candidate_serialized_and_used_by_original_and_stocks(self):
        fixtures=training_frames()
        self.assertTrue(all(frame[:8]==b"CTRX0001" for frame in fixtures))
        with tempfile.TemporaryDirectory(prefix="trnm-train-held-execute-") as tmp:
            actual_train,train_receipt=frozen_execute(Path(tmp),fixtures)
        router=actual_train[0][2]
        self.assertEqual(actual_train[1][2],router)
        plain=fixtures[0][80:80+8*E]+router
        original_candidates=[]
        for count,(report,prepared,old_router,new_router) in zip((1,0),actual_train,strict=True):
            self.assertEqual((old_router,new_router),(router,router))
            self.assertEqual(len(prepared),2096*count)
            self.assertEqual(len(report),154280+104*count)
            self.assertEqual(struct.unpack_from("<Q",report,len(report)-40-24*count)[0],count)
            original_candidates.append(candidate_words(report,count)+new_router)
        self.assertNotEqual(original_candidates[0],plain)
        self.assertEqual(original_candidates[1],plain)
        native_builds={}
        native_semantics={}
        with tempfile.TemporaryDirectory(prefix="trnm-train-held-canon-") as tmp:
            original_json,canon_receipt=exact_canonical(Path(tmp),plain+b"".join(original_candidates))
        self.assertEqual(len(original_json),3)
        self.assertNotEqual(original_json[0],original_json[1])
        self.assertEqual(original_json[0],original_json[2])
        held=held_features()
        originals=[ordinary_packet(canon,coeff,held)
                   for canon,coeff in zip(original_json,[plain,*original_candidates],strict=True)]
        ordinary_pin=digest(ORDINARY_RUST.read_bytes())
        ordinary_ref_pin=digest(ORDINARY_REF.read_bytes())
        # Every native candidate packet must equal these full expected bytes.
        # The original ordinary process is invoked on the actual native trace's
        # candidate packets below, not on a separately reconstructed model.
        packets_by_kind={}
        for mode in ("direct","selfhost"):
            with (NativeModule(TRAIN,backend=mode,byte_exports=("f0",)) as train,
                  NativeModule(SERIALIZER,backend=mode,byte_exports=("f0",)) as canon,
                  NativeModule(ORDINARY,backend=mode,byte_exports=("f0",)) as forward):
                native_builds[mode]={n:{"artifact_sha256":m.artifact_sha256,
                                       "closure":m.receipt["chain_migration"]}
                                     for n,m in (("train",train),("canonical",canon),("ordinary",forward))}
                typed=[plain]
                for count,frame,(want,prepared,old_router,new_router) in zip((1,0),fixtures,actual_train,strict=True):
                    out=b"\xa5"*(len(want)+15)
                    used=arena_size(count)
                    scratch=b"\xd3"*(used+13)
                    result=train.call("f0",[frame,out,scratch]).require_returned()
                    self.assertEqual((result.value,result.arguments[:2],result.arguments[2][used:]),
                                     (0,[frame,want+out[len(want):]],scratch[used:]))
                    if count:
                        self.assertEqual(result.arguments[2][262144:used],prepared)
                    observed=result.arguments[1][:len(want)]
                    candidate=candidate_words(observed,count)
                    # CTRX does not consume/edit router; carry the exact
                    # before/after-matched bytes observed from original execute.
                    self.assertEqual(old_router,new_router)
                    typed.append(candidate+old_router)
                self.assertEqual(typed,[plain,*original_candidates])
                packets=[];counts=[]
                for words,ref in zip(typed,original_json,strict=True):
                    req=b"CMCV0001"+words
                    out=b"\xbc"*(len(ref)+7)
                    ret=canon.call("f0",[req,out,b""]).require_returned()
                    self.assertEqual((ret.value,ret.arguments),(len(ref),[req,ref+out[len(ref):],b""]))
                    computed=ret.arguments[1][:ret.value]
                    packets.append(ordinary_packet(computed,words,held))
                    counts.append(dict(weights_sha256=digest(words[:E*8]),router_sha256=digest(words[E*8:]),
                                       model_canonical_sha256=digest(computed),consumed_packet_sha256=digest(packets[-1])))
                self.assertEqual(packets,originals)
                packets_by_kind[mode]=packets
                payloads=[]
                for req in packets:
                    out=b"\xff"*(len(held)*26+13)
                    ret=forward.call("f0",[req,out,b"\x74"*17]).require_returned()
                    self.assertEqual(ret.value,0)
                    self.assertEqual((ret.arguments[0],ret.arguments[1][len(held)*26:],ret.arguments[2]),
                                     (req,out[len(held)*26:],b"\x74"*17))
                    payloads.append(ret.arguments[1][:len(held)*26])
                native_semantics[mode]=dict(views=counts,payloads=payloads)
        self.assertEqual(packets_by_kind["direct"],packets_by_kind["selfhost"])
        physical=packets_by_kind["direct"]
        ordinary_wire=b"".join(struct.pack("<I",len(req))+req for req in physical)
        with tempfile.TemporaryDirectory(prefix="trnm-train-held-ordinary-") as tmp:
            raw=locked_ordinary(Path(tmp),ordinary_wire)
        actual=records(raw,len(physical))
        payloads=[]
        for status,data in actual:
            self.assertEqual((status,len(data)),(0,3*26))
            payloads.append(data)
        for mode in ("direct","selfhost"):
            self.assertEqual(native_semantics[mode]["payloads"],payloads)
        held_rows=[list(TUPLE.iter_unpack(p)) for p in payloads]
        self.assertEqual([row[3] for row in held_rows[0]],[0,1,2])
        self.assertEqual([row[3] for row in held_rows[1]],[0,1,2])
        self.assertEqual([row[4] for row in held_rows[0]],[0,0,0])
        self.assertEqual([row[4] for row in held_rows[1]],[1,1,1])
        self.assertEqual([row[1] for row in held_rows[1]],[48,24,24])
        self.assertEqual(held_rows[0],held_rows[2])
        proof=os.environ.get("HIA_CELL_TRAIN_HELD_PROOF")
        if proof:
            Path(proof).write_text(json.dumps(dict(rust_execute_some=train_receipt,rust_canonical=canon_receipt,
                original_ordinary_body_sha256=ordinary_pin,ordinary_reference_sha256=ordinary_ref_pin,
                original_ordinary_input_sha256=digest(ordinary_wire),original_ordinary_stdout_sha256=digest(raw),
                held_rows=held_rows,native_physical=native_builds,
                native_forward_models={k:v["views"] for k,v in native_semantics.items()},
                actual_owner_invoked=False),sort_keys=True,indent=2)+"\n")

"""Differential against the unchanged complete integer cell train function."""
import hashlib
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/"hia/src/state/integer_training_backward.hepta"
NODE = ROOT/"trillionnium/crates/trnm-pon-node/src"
PINS = {
    "cell_native_v1.rs": "d807c924d7e9657d4126d9092d32585427fccba8144133066deb3ea7db54fe26",
    "cell_native_v1/execution.rs": "cbe589c07dfe2fef0c900676e74300946ae00e424359d43f11002989db5eb20d",
    "cell_native_v1/source.rs": "8c27cdadece9f1f9c26bd20869a74318bb7490aea436e6dc0140684c20cf6c3e",
    "lib.rs": "baafb16f125fda88b09d2342a0b6badb253497742c9a106921e8416e930f108d",
    "error.rs": "0f7952a02aca0dfc9d6da3f38e6a1883b7943ad5b9ab94cfef9b4036dd1395fc",
}
LOCK_SHA = "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e"
DIM, MAX_BATCH, LOGIT = 257, 64, 134746096
ROW, BASE, ROW_OUT = 2096, 30848, 80


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original():
    files={n:(NODE/n).read_bytes() for n in PINS}
    assert {n:sha(d) for n,d in files.items()}==PINS
    cell, exe, lib, err=(files[n] for n in ("cell_native_v1.rs","cell_native_v1/execution.rs","lib.rs","error.rs"))

    def extract(raw,start,end):
        return raw[raw.index(start):raw.index(end)]

    def decls(start,end):
        return cell[cell.rindex(b"#[derive",0,cell.index(start)):cell.rindex(b"#[derive",0,cell.index(end))]
    declarations = decls(b"pub struct Model",b"pub struct CellState") + decls(b"pub struct TrainableMask",b"pub struct Policy")
    stages = decls(b"struct Stage",b"struct Execution")
    constants=b"\n".join(re.search(rb"(?m)^pub const "+n+rb":[^\n]+",cell).group(0)
                         for n in (b"MODEL_SCHEMA",b"OPTIMIZER_SCHEMA",b"DIM",b"MAX_BATCH",b"PRODUCT_BOUND",b"LOGIT_BOUND"))
    alias=extract(cell,b"type Matrix",b"#[derive")
    result=re.search(rb"(?m)^pub type Result<T> = [^\n]+",lib).group(0)
    ensure=extract(lib,b"pub(crate) fn ensure(",b"pub fn digest(")
    err=err[err.index(b"use std::"):err.index(b"impl Error {")]+extract(err,b"impl fmt::Display for Error",b"impl From<std::io::Error>")
    numeric=extract(exe,b"#[derive(Clone, Debug, Serialize)]",b"fn sample(")
    train=extract(exe,b"fn train(",b"pub(super) fn execute(")
    return (b"\n".join((b"#![allow(dead_code)]",b"use serde::{Deserialize, Serialize};",
                        b"use serde_json::{json, Value};",err,result,ensure,constants,alias,
                        declarations,stages,numeric,train))+br"""
fn main() {
    use std::io::{BufRead, Write};
    let mut values=zero_parameters();
    values.base[0][0]=2;
    values.deltas[1][1][4]=-11;
    let model=Model {schema:MODEL_SCHEMA.into(),base:values.base,router:zero_matrix(),deltas:values.deltas};
    let optimizer=Some(Optimizer {schema:OPTIMIZER_SCHEMA.into(),step:7,base:model.base.clone(),deltas:model.deltas.clone()});
    let mask=vec![vec![false;DIM];3];
    let spec=Training {learning_rate_num:1,learning_rate_den:1,momentum_num:0,momentum_den:1,
                       clip_abs:1,trainable_mask:TrainableMask {base:mask.clone(),deltas:vec![mask;3]}};
    let mut out=std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line=line.unwrap();
        let nums: Vec<i64>=line.split_whitespace().map(|s|s.parse().unwrap()).collect();
        let mut active=Vec::new();
        assert!(nums.len()%(DIM+5)==0 && nums.len()/(DIM+5)<=MAX_BATCH);
        for (i,r) in nums.chunks_exact(DIM+5).enumerate() {
            active.push(ActiveRow {row:i,route:r[0] as usize,label:r[1] as u8,
                logits:r[2..5].to_vec(),features:r[5..].to_vec()});
        }
        let (next,moment,_,stages)=train(&model,&active,&optimizer,&spec).unwrap();
        assert_eq!(next,model);
        let mut preserved=optimizer.clone();
        if !active.is_empty() { preserved.as_mut().unwrap().step+=1; }
        assert_eq!(moment,preserved);
        assert_eq!(stages[0].stage,"training-loss");
        assert_eq!(stages[1].stage,"training-backward");
        writeln!(out,"{}",json!([stages[0].outputs,stages[1].outputs])).unwrap();
    }
}
""", sha(train))


def frame(rows):
    return b"CTRN0001"+struct.pack("<Q",len(rows))+b"".join(struct.pack("<262q",*row) for row in rows)


def corpus():
    # Boundary values for every route/label, isolated single-feature cases,
    # maximal signed loss and gradient, every coordinate and mixed batches.
    z=(0,)*256+(8,)
    dense=(8,)*128+(0,)*128+(8,)
    dense_negative=(-8,)*128+(0,)*128+(8,)
    def row(route,label,logs,vec=z):
        return (route,label,*logs,*vec)
    cases=[(),*(tuple([row(route,label,((-LOGIT,8192,LOGIT)[label],0,-8192))])
                 for route in range(3) for label in range(3))]
    cases.extend([
        (row(2,1,(0,8192,0)),),
        (row(0,0,(LOGIT,LOGIT,LOGIT),dense),row(0,0,(-LOGIT,-LOGIT,-LOGIT),dense_negative)),
        tuple(row(i%3,i%3,(-LOGIT,-LOGIT,-LOGIT),dense) for i in range(64)),
        tuple(row(2,0,(-LOGIT,LOGIT,LOGIT),dense_negative) for i in range(64)),
        tuple(row(i%3,i%3,(-LOGIT,LOGIT,(-1)**i*8192),(0,)*(i*4)+(8,-8,1,-1)+(0,)*(252-i*4)+(8,))
              for i in range(64)),
    ])
    rng=random.Random(334563)
    for n in range(1,30):
        rows=[]
        for _ in range(1+n%12):
            v=[0]*256
            for i in rng.sample(range(256),1+(n*9)%100):
                v[i]=rng.randint(-8,8)
            rows.append(row(rng.randrange(3),rng.randrange(3),
                            tuple(rng.randint(-LOGIT,LOGIT) for _ in range(3)),(*v,8)))
        cases.append(tuple(rows))
    return cases


def old_rows(cases):
    raw, train_body=original()
    lock=(ROOT/"trillionnium/Cargo.lock").read_bytes()
    assert sha(lock)==LOCK_SHA
    allowed={(r["name"],r["version"],r.get("checksum")) for r in tomllib.loads(lock.decode())["package"]}
    assert subprocess.check_output(["rustc","--version"]).startswith(b"rustc 1.95.0 (59807616e ")
    with tempfile.TemporaryDirectory(prefix="trnm-training-original-") as d:
        root=Path(d)
        (root/"src").mkdir()
        (root/"src/main.rs").write_bytes(raw)
        (root/"Cargo.toml").write_text("""[package]
name = "trnm-hia-training-original"
version = "0.0.0"
edition = "2021"
[dependencies]
serde = {version = "=1.0.229", features = ["derive"]}
serde_json = "=1.0.149"
""")
        env={**os.environ,"CARGO_PROFILE_DEV_DEBUG":"0","CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"2","RUSTFLAGS":"-Dwarnings"}
        run=subprocess.run(["cargo","generate-lockfile","--offline"],cwd=d,env=env,capture_output=True,timeout=15)
        assert run.returncode==0,run.stderr
        closure=tomllib.loads((root/"Cargo.lock").read_text())["package"]
        assert all((r["name"],r["version"],r.get("checksum")) in allowed for r in closure if r["name"]!="trnm-hia-training-original")
        build=subprocess.run(["cargo","build","--locked","--offline"],cwd=d,env=env,capture_output=True,timeout=150)
        assert build.returncode==0,build.stderr
        exe=root/"target/debug/trnm-hia-training-original"
        wire="".join(" ".join(str(value) for row in rows for value in row)+"\n" for rows in cases).encode()
        sandbox=root/"inert"
        sandbox.mkdir()
        run=subprocess.run([str(exe)],cwd=sandbox,env={},input=wire,capture_output=True,timeout=30)
        assert (run.returncode,run.stderr)==(0,b""),run.stderr
        assert not list(sandbox.iterdir())
        out=[json.loads(line) for line in run.stdout.splitlines()]
        return out,dict(original_artifact_sha256=sha(exe.read_bytes()), original_source_sha256=sha(raw),
                        original_train_body_sha256=train_body,original_stdout_sha256=sha(run.stdout),
                        original_registered_source_pins=PINS,original_cargo_lock_sha256=LOCK_SHA)


def projection(stages, count):
    loss, backward=stages
    gradients=backward["gradients"]
    matrices=[gradients["base"],*gradients["deltas"],backward["router_gradients"]]
    assert len(matrices)==5 and all(len(m)==3 and all(len(row)==DIM for row in m) for m in matrices)
    assert matrices[-1]==[[0]*DIM for _ in range(3)]
    fields=[loss["loss"]]+[v for m in matrices for row in m for v in row]
    assert len(loss["rows"])==count
    for i,row in enumerate(loss["rows"]):
        assert row["row"]==i
        fields.extend([*row["target"],*row["errors"],*row["d_logits"],row["loss"]])
    return struct.pack(f"<{len(fields)}q",*fields)


class IntegerTrainingBackward(unittest.TestCase):
    def test_frozen_original_complete_train_projection_and_atomic_outputs(self):
        cases=corpus()
        rust,pins=old_rows(cases)
        self.assertEqual(len(rust),len(cases))
        expected=[projection(result,len(rows)) for result,rows in zip(rust,cases,strict=True)]
        self.assertEqual(max(map(len,expected)),BASE+MAX_BATCH*ROW_OUT)
        self.assertEqual(expected[0],bytes(BASE))
        self.assertGreater(max(struct.unpack_from("<q",r)[0] for r in expected),3*10**18)
        calls=[("f0",[frame(rows),b"\xa5"*(len(data)+i%2*11),b"\xd3"*17]) for i,(rows,data) in enumerate(zip(cases,expected,strict=True))]
        seed=frame(cases[1])
        def overwrite(at,value):
            return seed[:at]+struct.pack("<q",value)+seed[at+8:]
        malformed=[
            seed[:15],seed[:-1],seed+b"\0",b"x"+seed[1:],
            frame((cases[1][0],)*65),
            overwrite(16,3),overwrite(24,3),overwrite(32,LOGIT+1),overwrite(48,-LOGIT-1),
            overwrite(56,9),overwrite(56,-9),overwrite(56,-(1<<63)),overwrite(len(seed)-8,7),
            frame(((0,0,0,0,0,*((8,)*128+(1,)+(0,)*127+(8,))),)),
        ]
        control=[("f0",[x,b"\xa5",b""]) for x in malformed]
        control += [("f0",[seed,b"\xa5"*(BASE+ROW_OUT-1),b"\xd3"*11]),
                    ("f0",[frame(()),b"\xa5"*(BASE-1),b""])]
        answers=[(0,x) for x in expected]+[(1,b"")]*len(malformed)+[(2,b""),(2,b"")]
        calls+=control
        artifacts={}
        for backend in ("direct","selfhost"):
            module=NativeModule(SOURCE,byte_exports=("f0",),backend=backend)
            self.addCleanup(module.close)
            artifacts[backend]=module.artifact_sha256
            for i in range(0,len(calls),5):
                batch=calls[i:i+5]
                for call,ret,(code,data) in zip(batch,module.call_many(batch,timeout=30),answers[i:i+5],strict=True):
                    ret.require_returned()
                    src,dst,scratch=call[1]
                    self.assertEqual((ret.value,ret.arguments),(code,[src,data+dst[len(data):],scratch]))
        proof=os.environ.get("HIA_INTEGER_TRAINING_PROOF")
        if proof:
            Path(proof).write_text(json.dumps(dict(**pins,original_batches=len(cases),
                original_active_rows=sum(map(len,cases)),native_cases_each=len(answers),
                max_active_rows=max(map(len,cases)),maximum_output_bytes=max(map(len,expected)),
                native_artifacts=artifacts,owner_invoked=False),sort_keys=True,indent=2)+"\n")

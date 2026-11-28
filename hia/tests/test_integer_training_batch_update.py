"""Differential of staged Cell batch updates against unchanged Rust train."""
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import unittest
import subprocess
import tempfile
import tomllib
from hia.tests.test_integer_training_backward import (original,ROOT,LOCK_SHA,LOGIT,DIM,
    PINS,frame,projection)
from hia.tests.native_support import NativeModule

ORACLE_MAIN = br"""
fn main() {
    use std::io::{BufRead,Write};
    fn matrices(v: &[i64]) -> Vec<Matrix> {
        assert_eq!(v.len(),4*3*DIM);
        v.chunks_exact(3*DIM).map(|a|a.chunks_exact(DIM).map(|x|x.to_vec()).collect()).collect()
    }
    fn plain(num:&[u64]) -> Training {
        let flags=vec![vec![false;DIM];3];
        Training { learning_rate_num:num[0], learning_rate_den:num[1], momentum_num:num[2],
            momentum_den:num[3], clip_abs:num[4], trainable_mask:TrainableMask {
                base:flags.clone(), deltas:vec![flags;3] } }
    }
    fn from_rows(buf:&[i64]) -> Vec<ActiveRow> {
        assert_eq!(buf.len()%(DIM+5),0);
        buf.chunks_exact(DIM+5).enumerate().map(|(i,r)|ActiveRow {
            row:i,route:r[0] as usize,label:r[1] as u8,logits:r[2..5].to_vec(),features:r[5..].to_vec(),
        }).collect()
    }
    let mut out=std::io::stdout().lock();
    const E:usize=4*3*DIM;
    const R:usize=3*DIM;
    for line in std::io::stdin().lock().lines() {
        let v:Vec<&str>;
        let line=line.unwrap();
        v=line.split_whitespace().collect();
        let settings:Vec<u64>=v[..8].iter().map(|x|x.parse().unwrap()).collect();
        let opts:Vec<i64>=v[8..].iter().map(|x|x.parse().unwrap()).collect();
        let active=from_rows(&opts[3*E+R..]);
        assert_eq!(active.len() as u64,settings[7]);
        let model_groups=matrices(&opts[..E]);
        let router=opts[3*E..3*E+R].chunks_exact(DIM).map(|x|x.to_vec()).collect();
        let model=Model {schema:MODEL_SCHEMA.into(),base:model_groups[0].clone(),router,
                         deltas:model_groups[1..].to_vec()};
        let mut spec=plain(&settings[..5]);
        let m=matrices(&opts[2*E..3*E]);
        let masks:Vec<BoolMatrix>=m.iter().map(|a|a.iter().map(|r|r.iter().map(|&v|{
            assert!(v==0 || v==1);
            v==1
        }).collect()).collect()).collect();
        spec.trainable_mask=TrainableMask{base:masks[0].clone(),deltas:masks[1..].to_vec()};
        let moment=matrices(&opts[E..2*E]);
        let maybe=match settings[5] {
            0=>{assert_eq!(settings[6],0);assert_eq!(moment,vec![zero_matrix();4]);None},
            1=>Some(Optimizer{schema:OPTIMIZER_SCHEMA.into(),step:settings[6],base:moment[0].clone(),deltas:moment[1..].to_vec()}),
            _=>unreachable!(),
        };
        // Obtain original preceding gradients even when an optimizer refusal
        // later discards all partial work. A separately frozen call has identical
        // original stages 0/1 for the same immutable typed ActiveRows.
        let (_,_,_,before)=train(&model,&active,&None,&plain(&settings[..5])).unwrap();
        assert_eq!(before[0].stage,"training-loss");
        assert_eq!(before[1].stage,"training-backward");
        let snapshot=serde_json::to_vec(&(&model,&maybe,&spec,&active)).unwrap();
        let update=match train(&model,&active,&maybe,&spec) {
            Err(e)=>json!({"error":e.to_string()}),
            Ok((trained,moment,summary,stages))=>{
                assert_eq!(stages[0].outputs,before[0].outputs);
                assert_eq!(stages[1].outputs,before[1].outputs);
                assert_eq!(stages[2].stage,"training-update");
                assert_eq!(trained.schema,model.schema);
                assert_eq!(trained.router,model.router);
                assert_eq!(trained.deltas.len(),3);
                if active.is_empty() {
                    assert_eq!(trained,model); assert_eq!(moment,maybe);
                }
                json!({"model":trained,"optimizer":moment,"summary":summary,"stage2":stages[2].outputs})
            },
        };
        assert_eq!(serde_json::to_vec(&(&model,&maybe,&spec,&active)).unwrap(),snapshot);
        writeln!(out,"{}",json!([before[0].outputs,before[1].outputs,update])).unwrap();
    }
}
"""

E=4*3*DIM
R=3*DIM
IMAX=(1<<63)-1
UMAX=(1<<64)-1
LEFT=(0,)*256+(8,)
RIGHT=(8,)*128+(0,)*128+(8,)
MID=(1,)*11+(0,)*245+(8,)
POLICY=(1,19,1,3,8192)

def active(route=0,label=0,logits=(8193,0,0),features=LEFT): return (route,label,*logits,*features)

def cases():
    def datum(tag,rows=(),policy=POLICY,step=None,weight=(),moment=(),mask=(),all_mask=False):
        weights=[0]*E; moments=[0]*E; masks=[int(all_mask)]*E
        for i,v in weight:weights[i]=v
        for i,v in moment:moments[i]=v
        for i,v in mask:masks[i]=v
        router=[(i%23)-11 for i in range(R)]
        return dict(tag=tag,settings=(*policy,int(step is not None),0 if step is None else step,len(rows)),
                    weights=weights,moments=moments,mask=masks,router=router,rows=rows)
    carry_rows=(active(0,0,(8193,0,0),(1,)+(0,)*255+(8,)),
                active(2,2,(0,0,8191)))
    carry_policy=(1,2,1,2,1)
    carry_moments=((0,5),(E-1,-5))
    carry_mask=((0,1),(E-1,1))
    result = [
      datum("empty-none"),
      datum("empty-some-max",step=UMAX,weight=((1,123),(E-1,-23)), moment=((0,IMAX),(1,-IMAX))),
      datum("first-active-none-unmasked",rows=(active(),),all_mask=True),
      datum("active-all-frozen",rows=(active(),),step=8,moment=((DIM-1,-77),(E-1,IMAX))),
      datum("step-overflow-before-coordinate",rows=(active(logits=(LOGIT,0,0)),),
            step=UMAX,weight=((DIM-1,-32767),),mask=((DIM-1,1),),policy=(1,1,0,1,1<<40)),
      datum("weight-first-group",rows=(active(logits=(LOGIT,0,0)),),
            weight=((DIM-1,-32767),),mask=((DIM-1,1),),policy=(1,1,0,1,1<<40)),
      datum("weight-last-group-after-prefix",rows=carry_rows,
            step=20,weight=((0,-32766),(E-1,32767)),moment=carry_moments,mask=carry_mask,policy=carry_policy),
      datum("signed-fraction-changes",rows=(active(1,0,(8195,-2,7),MID),active(2,2,(-17,33,8187),MID)),
            step=3,moment=((0,-7),(DIM,-11),(2*DIM+1,9),(E-1,-11)),all_mask=True,policy=(1,13,2,5,21)),
      datum("maximum-old-moment-with-lr-zero",rows=(active(2,0,(-LOGIT,LOGIT,0),RIGHT),),
            step=UMAX-1,moment=((0,IMAX),(DIM-1,-IMAX),(E-1,IMAX)),all_mask=True,policy=(0,1<<32,65535,65536,1<<40)),
      datum("clipped-full-64",rows=tuple(active(i%3,i%3,([-LOGIT,LOGIT,-LOGIT] if i%2 else [LOGIT,-LOGIT,LOGIT]),RIGHT) for i in range(64)),
            step=0,all_mask=True,policy=(1,1<<20,1,65536,1073741824)),
      datum("freeze-mixed-and-no-parameter-change",rows=(active(1,1,(0,8192,0)),),step=0,
            weight=((32,92),),moment=((32,-120),(E-1,IMAX)),mask=((E-1,1),),policy=(0,19,1,2,7)),
      datum("successful-mirrored-bound-and-step-carry",rows=carry_rows,
            step=(1<<63)-1,weight=((0,-32766),(E-1,32766)),moment=carry_moments,mask=carry_mask,policy=carry_policy),
    ]
    generator=random.Random(722431)
    for n in range(25):
        rows=[]
        for k in range(1+n%13):
            v=[0]*256
            for i in generator.sample(range(256),17):
                v[i]=generator.randrange(-8,9)
            rows.append(active(generator.randrange(3),generator.randrange(3),
                               tuple(generator.randint(-999,999)+8192 for _ in range(3)), (*v,8)))
        indices=generator.sample(range(E),12)
        weights=tuple((i,generator.randrange(-200,201)) for i in indices)
        moments=tuple((i,generator.randrange(-1000,1001)) for i in indices)
        masks=tuple((i,0) for i in indices[:6])
        result.append(datum(f"mixed-signed-{n:02d}",rows=tuple(rows),
                            policy=(n%3,33+n,1,2,97+n),step=None if n%7==0 else n,
                            weight=weights,moment=() if n%7==0 else moments,
                            mask=masks,all_mask=True))
    return result

def run(cases):
    existing,body_sha=original()
    src=existing[:existing.rindex(b"fn main()")]+ORACLE_MAIN
    lock=(ROOT/"trillionnium/Cargo.lock").read_bytes()
    assert sha256(lock).hexdigest()==LOCK_SHA
    allowed={(r["name"],r["version"],r.get("checksum")) for r in tomllib.loads(lock.decode())["package"]}
    assert subprocess.check_output(["rustc","--version"]).startswith(b"rustc 1.95.0 (59807616e ")
    with tempfile.TemporaryDirectory(prefix="trnm-cell-batch-oracle-") as d:
        root=Path(d);(root/"src").mkdir()
        (root/"src/main.rs").write_bytes(src)
        (root/"Cargo.toml").write_text('''[package]
name = "trnm-hia-cell-batch-oracle"
version = "0.0.0"
edition = "2021"
[dependencies]
serde = {version = "=1.0.229", features = ["derive"]}
serde_json = "=1.0.149"
''')
        env={**os.environ,"CARGO_PROFILE_DEV_DEBUG":"0","CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"2","RUSTFLAGS":"-Dwarnings"}
        generate=subprocess.run(["cargo","generate-lockfile","--offline"],cwd=d,env=env,capture_output=True,timeout=15)
        assert generate.returncode==0,generate.stderr
        closure=tomllib.loads((root/"Cargo.lock").read_text())["package"]
        assert all((r["name"],r["version"],r.get("checksum")) in allowed for r in closure if r["name"]!="trnm-hia-cell-batch-oracle")
        build=subprocess.run(["cargo","build","--locked","--offline"],cwd=d,env=env,capture_output=True,timeout=150)
        assert build.returncode==0,build.stderr
        exe=root/"target/debug/trnm-hia-cell-batch-oracle"
        encoded_lists=[]
        for x in cases:
            data=(*x["settings"],*x["weights"],*x["moments"],*x["mask"],*x["router"],*(v for row in x["rows"] for v in row))
            encoded_lists.append(" ".join(map(str,data)))
        wire=("\n".join(encoded_lists)+"\n").encode()
        sandbox=root/"inert";sandbox.mkdir()
        test=subprocess.run([str(exe)],cwd=sandbox,env={},input=wire,capture_output=True,timeout=30)
        assert (test.returncode,test.stderr)==(0,b""),test.stderr
        assert not list(sandbox.iterdir())
        proof=dict(body_sha256=body_sha,oracle_src_sha256=sha256(src).hexdigest(),stdout_sha256=sha256(test.stdout).hexdigest(),
                   input_sha256=sha256(wire).hexdigest(),raw_pins=PINS,original_lock_sha256=LOCK_SHA,dep_closure=closure)
        return [json.loads(line) for line in test.stdout.splitlines()],proof


ROOT_HIA=ROOT/"hia/src/state"
BATCH=ROOT_HIA/"integer_training_batch_update.hepta"
BACKWARD=ROOT_HIA/"integer_training_backward.hepta"
RESULT=123392
FAILS={"CELL_OPTIMIZER_STEP_OVERFLOW":201,"CELL_MOMENT_OVERFLOW":202,"CELL_TRAINED_WEIGHT_RANGE":203}


def flatten(parameters):
    return [x for group in (parameters["base"],*parameters["deltas"]) for row in group for x in row]


def raw_frame(record,stages):
    settings=record["settings"]
    loss,backward,_=stages
    return (b"CTUP0001"+struct.pack("<9Q", settings[7],loss["loss"],settings[5],settings[6],*settings[:5])
            +struct.pack(f"<{4*E}q",*record["weights"],*record["moments"],*record["mask"],*flatten(backward["gradients"])))


def result_bytes(stages):
    update=stages[2]
    if "error" in update:
        return FAILS[update["error"]],b""
    stage=update["stage2"]
    optimizer=update["optimizer"]
    presence=int(optimizer is not None)
    step=optimizer["step"] if presence else 0
    applied=int(stage["applied"])
    changed=int(update["summary"]["parameters_changed"])
    weights=flatten(update["model"])
    moments=flatten(optimizer) if presence else [0]*E
    if applied:
        traces=[flatten(stage[key]) for key in ("masked_gradients","clipped_gradients","updates")]
    else:
        assert stage["reason"]=="no-active-rows"
        traces=[[0]*E]*3
    values=[x for row in zip(weights,moments,*traces,strict=True) for x in row]
    return 0, struct.pack("<4Q",presence,step,applied,changed)+struct.pack(f"<{5*E}q",*values)


class IntegerTrainingBatchUpdate(unittest.TestCase):
    def test_frozen_original_full_batch_outputs_and_shared_helper(self):
        fixtures=cases()
        original_stages,proof=run(fixtures)
        self.assertEqual(len(fixtures),len(original_stages))
        wire=[raw_frame(case,stage) for case,stage in zip(fixtures,original_stages,strict=True)]
        expected=[result_bytes(stage) for stage in original_stages]
        self.assertEqual({status for status,_ in expected},{0,201,203})
        self.assertEqual(struct.unpack_from("<4Q",expected[0][1]),(0,0,0,0))
        self.assertEqual(struct.unpack_from("<4Q",expected[1][1]),(1,UMAX,0,0))
        self.assertEqual(struct.unpack_from("<4Q",expected[2][1])[:3],(1,1,1))
        self.assertTrue(any(struct.unpack_from("<4Q",b)[3] for status,b in expected if status==0))
        self.assertEqual(sum(len(w) for w in wire),len(wire)*98768)
        carry=expected[11][1]
        self.assertEqual(struct.unpack_from("<4Q",carry),(1,1<<63,1,1))
        first=(-32767,3,2,1,1)
        last=(32767,-3,-16,-1,-1)
        self.assertEqual(struct.unpack_from("<5q",carry,32),first)
        self.assertEqual(struct.unpack_from("<5q",carry,RESULT-40),last)
        seed=wire[2]
        def patch(src,at,value):
            return src[:at]+struct.pack("<Q",value & UMAX)+src[at+8:]
        malformed = [seed[:-1],seed+b"X",b"?"+seed[1:],patch(seed,8,65),patch(seed,16,UMAX),
                     patch(seed,24,2),patch(seed,32,1),patch(seed,40,1+(1<<20)),
                     patch(seed,48,0),patch(seed,56,3),patch(seed,64,0),
                     patch(seed,72,0),patch(seed,80,32768),patch(seed,80+8*E,1),
                     patch(seed,80+2*8*E,2),patch(seed,80+3*8*E,3),
                     patch(seed,80+3*8*E,1<<40),patch(wire[1],80+3*8*E,2),
                     patch(wire[8],80+8*E,1<<63)]
        sent=[("f0",[raw,b"\xa5"*(RESULT+i%2*11),b"\xd3"*(RESULT+i%2*13)]) for i,raw in enumerate(wire)]
        sent.extend(("f0",[bad,b"\xa5"*17,b"\xd3"*23]) for bad in malformed)
        answers=expected+[(100,b"")]*len(malformed)
        sent.extend([("f0",[seed,b"\xa5"*(RESULT-1),b"\xd3"*RESULT]),
                     ("f0",[seed,b"\xa5"*RESULT,b"\xd3"*(RESULT-1)]),
                     ("f0",[wire[4],b"",b""]),
                     ("f0",[wire[6],b"\xa5",b"\xd3"*RESULT])])
        answers.extend([(102,b""),(102,b""),(201,b""),(203,b"")])
        back_cases=[("f0",[frame(case["rows"]),b"\xa5"*len(answer),b""]) for case,answer in
                    zip(fixtures,(projection(stage[:2],len(case["rows"])) for case,stage in zip(fixtures,original_stages,strict=True)),strict=True)]
        hashes={}
        for backend in ("direct","selfhost"):
            batch=NativeModule(BATCH,backend=backend,byte_exports=("f0",))
            self.addCleanup(batch.close)
            before=NativeModule(BACKWARD,backend=backend,byte_exports=("f0",))
            self.addCleanup(before.close)
            hashes[backend]={"batch":batch.artifact_sha256,"backward":before.artifact_sha256}
            native_wires=[]
            for i in range(0,len(back_cases),4):
                subset=back_cases[i:i+4]
                result=before.call_many(subset,timeout=30)
                for case,ret,frozen,stage,expected_wire in zip(subset,result,fixtures[i:i+4],original_stages[i:i+4],wire[i:i+4],strict=True):
                    ret.require_returned()
                    self.assertEqual((ret.value,ret.arguments),
                                     (0,[case[1][0],projection(stage[:2],len(frozen["rows"])),b""]))
                    # Forward the native loss word and exact four gradient
                    # matrices into the update frame, with no host arithmetic.
                    backward=ret.arguments[1]
                    native=(expected_wire[:16]+backward[:8]+expected_wire[24:80+24*E]+backward[8:8+8*E])
                    self.assertEqual(native,expected_wire)
                    native_wires.append(native)
            native_inputs=[(name,[raw,*args[1:]]) for (name,args),raw in zip(sent[:len(wire)],native_wires,strict=True)]
            native_inputs.extend(sent[len(wire):])
            for i in range(0,len(native_inputs),2):
                subset=native_inputs[i:i+2]
                for ask,ret,(status,payload) in zip(subset,batch.call_many(subset,timeout=30),answers[i:i+2],strict=True):
                    ret.require_returned()
                    src,dst,scratch=ask[1]
                    self.assertEqual((ret.value,ret.arguments[:2],ret.arguments[2][RESULT:]),
                                     (status,[src,payload+dst[len(payload):]],scratch[RESULT:]))
                    if src==wire[6]:
                        self.assertEqual(status,203)
                        self.assertEqual(struct.unpack_from("<5q",ret.arguments[2],32),first)
                        self.assertEqual(ret.arguments[2][RESULT-40:RESULT],scratch[RESULT-40:RESULT])
                    if status in (100,201) or len(scratch)<RESULT:
                        self.assertEqual(ret.arguments[2],scratch)
        seal=os.environ.get("HIA_INTEGER_TRAINING_BATCH_PROOF")
        if seal:
            Path(seal).write_text(json.dumps(dict(**proof,actual_original_batches=len(fixtures),
                real_active_rows=sum(len(a["rows"]) for a in fixtures),native_cases_each=len(answers),
                statuses={str(code):sum(code==v for v,_ in expected) for code in (0,201,203)},
                native_artifacts=hashes,owner_invoked=False),sort_keys=True,indent=2)+"\n")

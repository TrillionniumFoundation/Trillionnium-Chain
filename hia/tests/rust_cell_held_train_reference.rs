#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::io::{self,Read,Write};
type Error=Box<dyn std::error::Error>;
type Result<T>=std::result::Result<T,Error>;
// EXACT_OWNER_DECLARATIONS
mod execution;
mod source;

fn word(raw:&[u8],at:usize)->u64 {
    u64::from_le_bytes(raw[at..at+8].try_into().unwrap())
}

fn signed(v:&Value)->i64 { v.as_i64().unwrap() }
fn matrix_out(dst:&mut Vec<u8>,m:&Value) {
    for row in m.as_array().unwrap() {
        for cell in row.as_array().unwrap() {
            dst.extend_from_slice(&signed(cell).to_le_bytes());
        }
    }
}

fn parameters(v:&Value)->Vec<i64> {
    let mut cells=Vec::new();
    for matrix in std::iter::once(&v["base"]).chain(v["deltas"].as_array().unwrap()) {
        for row in matrix.as_array().unwrap() {
            cells.extend(row.as_array().unwrap().iter().map(signed));
        }
    }
    cells
}

fn observe(f:&[u8],out:&mut impl Write)->io::Result<()> {
    const E:usize=4*3*DIM;
    assert_eq!(&f[..8],b"CTRX0001");
    let n=word(f,8) as usize;
    let remaining=word(f,74096);
    assert!((1..=MAX_BATCH).contains(&n) && f.len()==74128+2192*n);
    assert_eq!(word(f,16),0);
    let oldmem=(0..3).map(|k|word(f,74104+k*8) as i64).collect::<Vec<_>>();
    assert!(oldmem.iter().all(|x|(-8192..=8192).contains(x)));
    let matrix=|off:usize,group:usize| -> Matrix {
        (0..3).map(|row|(0..DIM).map(|c|word(f,off+8*(group*3*DIM+row*DIM+c)) as i64).collect()).collect()
    };
    let mut router=vec![vec![0;DIM];3];
    router[0][0]=33;
    let model=Model {schema:MODEL_SCHEMA.into(),base:matrix(80,0),router,
        deltas:(1..4).map(|g|matrix(80,g)).collect()};
    let old_at=80+8*E;
    let mask_at=80+16*E;
    let masks=(0..4).map(|g|matrix(mask_at,g).into_iter().map(|r|r.into_iter().map(|v| {
        assert!((0..=1).contains(&v)); v!=0
    }).collect::<Vec<_>>()).collect::<BoolMatrix>()).collect::<Vec<_>>();
    let opt=match word(f,24) {
        0=>{assert_eq!(word(f,32),0); assert!((old_at..mask_at).step_by(8).all(|i|word(f,i)==0));None},
        1=>Some(Optimizer {schema:OPTIMIZER_SCHEMA.into(),step:word(f,32),base:matrix(old_at,0),
            deltas:(1..4).map(|g|matrix(old_at,g)).collect()}),
        _=>panic!("Private presence")
    };
    let training=Training {learning_rate_num:word(f,40),learning_rate_den:word(f,48),
        momentum_num:word(f,56),momentum_den:word(f,64),clip_abs:word(f,72),
        trainable_mask:TrainableMask{base:masks[0].clone(),deltas:masks[1..].to_vec()}};
    assert!(training.learning_rate_num<=1<<20 && (1..=1<<32).contains(&training.learning_rate_den)
             && training.momentum_num<training.momentum_den && training.momentum_den<=1<<16
             && (1..=1<<40).contains(&training.clip_abs));
    let before=CellState {schema:STATE_SCHEMA.into(),cell_id:"10".repeat(32),generation:0,
        scope:"inert-held-train".into(),model_artifact:model_artifact(&model).unwrap(),
        memory:oldmem,rng_seed:"21".repeat(32),rng_counter:41,remaining_steps:remaining,
        sequence:3,optimizer:opt};
    validate_state(&before,&model).unwrap();
    let mut inputs=Vec::new();
    let mut expert_mask=Vec::new();
    let mut features=Vec::new();
    let mut products=vec![Vec::new();15];
    for (index,r) in f[74128..].chunks_exact(2192).enumerate() {
        let mask=word(r,0);
        let label=word(r,8);
        assert!((1..=7).contains(&mask) && label<=2);
        expert_mask.push((0..3).map(|k|mask&(1<<k)!=0).collect::<Vec<_>>());
        let feat=(0..DIM).map(|k|word(r,136+k*8) as i64).collect::<Vec<_>>();
        assert!(feat[..DIM-1].iter().all(|x|(-8..=8).contains(x)));
        assert!(feat[..DIM-1].iter().map(|x|x.abs()).sum::<i64>()<=1024);
        assert_eq!(feat[DIM-1],8);
        features.push(feat);
        for k in 0..15 {
            let v=word(r,16+k*8) as i64;
            assert!((-PRODUCT_BOUND..=PRODUCT_BOUND).contains(&v));
            products[k].push(v);
        }
        inputs.push(SourceSnippet {id:format!("{:064x}",index+1),origin:"inert".into(),
            content_hex:"61".into(),label:label as u8});
    }
    let policy=Policy {feature_mask:vec![true;DIM],expert_mask,allowed_actions:vec![Action::Stop,Action::Emit],
        sampler:Sampler::ArgmaxLowest,abstain_margin:0,tool_names:vec![None;3],training:Some(training)};
    let admission=OwnerAdmission {schema:ADMISSION_SCHEMA.into(),input_profile:INPUT_PROFILE.into(),
        consumer:"inert".into(),allowed_use:"observation".into(),request_id:"ab".repeat(32),
        issued_at_unix_seconds:0,deadline_unix_seconds:0,work_target:"01".repeat(32),model,inputs,before,policy};
    let result=match execution::execute(&admission,source::PreparedInputs{features,stages:vec![]},products) {
        Ok(x)=>x,
        Err(e)=>{
            return out.write_all(&[match e.to_string().as_str() {
                "CELL_OPTIMIZER_STEP_OVERFLOW"=>201,"CELL_MOMENT_OVERFLOW"=>202,"CELL_TRAINED_WEIGHT_RANGE"=>203,
                t=>panic!("Unexpected frozen prefix status: {t}"),
            }]);
        }
    };
    assert_eq!(result.after_model.router,admission.model.router);
    assert_eq!(result.after_state.rng_counter,admission.before.rng_counter);
    let stage=|name:&str|&result.stages.iter().find(|s|s.stage==name).unwrap().outputs;
    let loss=stage("training-loss");
    let gradients=stage("training-backward");
    let update=stage("training-update");
    let mut report=Vec::new();
    report.extend_from_slice(&signed(&loss["loss"]).to_le_bytes());
    matrix_out(&mut report,&gradients["gradients"]["base"]);
    for d in gradients["gradients"]["deltas"].as_array().unwrap() {
        matrix_out(&mut report,d);
    }
    matrix_out(&mut report,&gradients["router_gradients"]);
    let trace_rows=loss["rows"].as_array().unwrap();
    let active=trace_rows.len();
    for row in trace_rows {
        for key in ["target","errors","d_logits"] {
            for v in row[key].as_array().unwrap() { report.extend_from_slice(&signed(v).to_le_bytes()); }
        }
        report.extend_from_slice(&signed(&row["loss"]).to_le_bytes());
    }
    assert_eq!(report.len(),30848+80*active);
    let model=serde_json::to_value(&result.after_model).unwrap();
    let some=u64::from(result.after_state.optimizer.is_some());
    let step=result.after_state.optimizer.as_ref().map_or(0,|o|o.step);
    let moments=result.after_state.optimizer.as_ref().map_or_else(||vec![0;E],|o|
        parameters(&serde_json::to_value(o).unwrap()));
    let applied=update["applied"].as_bool().unwrap();
    let changed=result.after_model!=admission.model;
    for v in [some,step,u64::from(applied),u64::from(changed)] {
        report.extend_from_slice(&v.to_le_bytes());
    }
    let read_trace=|key:&str| if applied {parameters(&update[key])} else {vec![0;E]};
    let weights=parameters(&model);
    let masked=read_trace("masked_gradients");
    let clipped=read_trace("clipped_gradients");
    let delta=read_trace("updates");
    for i in 0..E {
        for v in [weights[i],moments[i],masked[i],clipped[i],delta[i]] {
            report.extend_from_slice(&v.to_le_bytes());
        }
    }
    assert_eq!(report.len(),30848+80*active+123392);
    report.extend_from_slice(&(active as u64).to_le_bytes());
    report.extend_from_slice(&result.after_state.remaining_steps.to_le_bytes());
    for v in result.after_state.memory { report.extend_from_slice(&v.to_le_bytes()); }
    let feat=&result.stages[0].inputs["features"];
    let mut active_records=Vec::new();
    for i in 0..n {
        let row=&result.stages[1+i];
        assert_eq!(row.stage,format!("decision/{i}"));
        if i<active {
            let route=row.outputs["route"].as_u64().unwrap();
            active_records.extend_from_slice(&route.to_le_bytes());
            active_records.extend_from_slice(&u64::from(admission.inputs[i].label).to_le_bytes());
            for v in row.outputs["logits"].as_array().unwrap().iter().chain(feat[i].as_array().unwrap()) {
                active_records.extend_from_slice(&signed(v).to_le_bytes());
            }
            for v in row.outputs["memory"].as_array().unwrap() {
                report.extend_from_slice(&signed(v).to_le_bytes());
            }
        } else {
            assert!(row.outputs["route"].is_null());
            assert!(row.outputs["logits"].is_null());
        }
    }
    assert_eq!(active_records.len(),2096*active);
    assert_eq!(report.len(),30848+80*active+123392+40+24*active);
    out.write_all(&[0])?;
    out.write_all(&(report.len() as u32).to_le_bytes())?;
    out.write_all(&(active_records.len() as u32).to_le_bytes())?;
    out.write_all(&report)?;
    out.write_all(&active_records)
}

fn main()->io::Result<()> {
    let mut raw=Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut f=raw.as_slice();
    let mut out=io::BufWriter::new(io::stdout().lock());
    while !f.is_empty() {
        let n=u32::from_le_bytes(f[..4].try_into().unwrap()) as usize;
        let (frame,rest)=f[4..].split_at(n);
        observe(frame,&mut out)?;
        f=rest;
    }
    out.flush()
}

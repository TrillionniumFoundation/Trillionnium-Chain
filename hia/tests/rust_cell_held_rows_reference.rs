#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::io::{self,Read,Write};

// Private display carrier only; the fixture does not compile any Node owner.
type Error=Box<dyn std::error::Error>;
type Result<T>=std::result::Result<T,Error>;
// EXACT_OWNER_DECLARATIONS
mod execution;
mod source;

fn word(raw:&[u8],n:usize)->u64 {
    u64::from_le_bytes(raw[n*8..n*8+8].try_into().unwrap())
}

fn zipped(out:&mut impl Write, numbers:impl IntoIterator<Item=i64>)->io::Result<()> {
    for n in numbers { out.write_all(&n.to_le_bytes())?; }
    Ok(())
}

fn observe(f:&[u8],out:&mut impl Write)->io::Result<()> {
    assert_eq!(&f[..8],b"CTRW0001");
    let n=word(f,1) as usize;
    let remaining=word(f,2);
    assert!((1..=MAX_BATCH).contains(&n) && f.len()==48+n*2192);
    let before_mem=(3..6).map(|i|word(f,i) as i64).collect::<Vec<_>>();
    assert!(before_mem.iter().all(|x|(-8192..=8192).contains(x)));
    let zero=||vec![vec![0;DIM];3];
    let model=Model {schema:MODEL_SCHEMA.into(),base:zero(),router:zero(),deltas:vec![zero();3]};
    let before=CellState {schema:STATE_SCHEMA.into(),cell_id:"10".repeat(32),generation:0,
        scope:"inert-held-rows".into(),model_artifact:model_artifact(&model).unwrap(),
        memory:before_mem.clone(),rng_seed:"21".repeat(32),rng_counter:41,remaining_steps:remaining,
        sequence:3,optimizer:None};
    let mut inputs=Vec::new();
    let mut masks=Vec::new();
    let mut features=Vec::new();
    let mut products=vec![Vec::new();15];
    for (index,r) in f[48..].chunks_exact(2192).enumerate() {
        let mask=word(r,0);
        let label=word(r,1);
        assert!((1..=7).contains(&mask) && label<=2);
        masks.push((0..3).map(|j|mask&(1<<j)!=0).collect::<Vec<_>>());
        for k in 0..15 {
            let x=word(r,k+2) as i64;
            assert!((-PRODUCT_BOUND..=PRODUCT_BOUND).contains(&x));
            products[k].push(x);
        }
        let ft=(17..17+DIM).map(|k|word(r,k) as i64).collect::<Vec<_>>();
        assert!(ft[..DIM-1].iter().all(|x|(-8..=8).contains(x)));
        assert!(ft[..DIM-1].iter().map(|x|x.abs()).sum::<i64>()<=1024);
        assert_eq!(ft[DIM-1],8);
        features.push(ft);
        inputs.push(SourceSnippet {id:format!("{:064x}",index+1),origin:"inert".into(),
                                   content_hex:"61".into(),label:label as u8});
    }
    let policy=Policy {feature_mask:vec![true;DIM],expert_mask:masks,
        allowed_actions:vec![Action::Stop,Action::Emit], sampler:Sampler::ArgmaxLowest,
        abstain_margin:0,tool_names:vec![None;3],training:None};
    let admission=OwnerAdmission {schema:ADMISSION_SCHEMA.into(),input_profile:INPUT_PROFILE.into(),
        consumer:"inert".into(),allowed_use:"observation".into(),request_id:"ab".repeat(32),
        issued_at_unix_seconds:0,deadline_unix_seconds:0,work_target:"01".repeat(32),
        model,inputs,before,policy};
    let result=execution::execute(&admission,source::PreparedInputs{features,stages:vec![]},products).unwrap();
    assert_eq!(result.after_model,admission.model);
    assert_eq!(result.after_state.rng_counter,admission.before.rng_counter);
    assert!(result.after_state.optimizer.is_none());
    assert_eq!(result.stages[0].stage,"five-w1-products");
    let source_ft=&result.stages[0].inputs["features"];
    let mut records=Vec::new();
    let mut traces=Vec::new();
    let mut stopped=false;
    for i in 0..n {
        let t=&result.stages[1+i];
        assert_eq!(t.stage,format!("decision/{i}"));
        let route=&t.outputs["route"];
        let logits=&t.outputs["logits"];
        let memory=t.outputs["memory"].as_array().unwrap();
        if let Some(route)=route.as_u64() {
            let logits=logits.as_array().unwrap();
            assert!(!stopped);
            let label=admission.inputs[i].label;
            zipped(&mut records,[route as i64,label as i64])?;
            zipped(&mut records,logits.iter().map(|x|x.as_i64().unwrap()))?;
            let ft=source_ft[i].as_array().unwrap();
            zipped(&mut records,ft.iter().map(|x|x.as_i64().unwrap()))?;
            zipped(&mut traces,memory.iter().map(|x|x.as_i64().unwrap()))?;
        } else {
            stopped=true;
            assert!(logits.is_null());
            assert_eq!(t.outputs["remaining_steps"].as_u64(),Some(0));
        }
    }
    let active=records.len()/2096;
    assert_eq!(records.len(),active*2096);
    assert_eq!(traces.len(),active*24);
    let length=40+records.len()+traces.len();
    out.write_all(&(length as u32).to_le_bytes())?;
    out.write_all(&(active as u64).to_le_bytes())?;
    out.write_all(&result.after_state.remaining_steps.to_le_bytes())?;
    zipped(out,result.after_state.memory)?;
    out.write_all(&records)?;
    out.write_all(&traces)
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

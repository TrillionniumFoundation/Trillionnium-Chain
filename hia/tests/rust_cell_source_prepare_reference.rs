#![allow(dead_code)]
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::io::{self,Read,Write};
type Error=Box<dyn std::error::Error>;
type Result<T>=std::result::Result<T,Error>;
// EXACT_OWNER_DECLARATIONS
mod execution;
mod source;

fn projected(frame:&[u8])->Result<Vec<u8>> {
    assert_eq!(&frame[..8],b"CSP00001");
    assert!(frame.len()>=265);
    let feature_mask=frame[8..265].iter().map(|&flag|match flag {
        0=>false,1=>true,_=>panic!("not a typed boolean fixture")
    }).collect::<Vec<_>>();
    assert!(feature_mask[DIM-1]);
    // Only source::prepare is invoked. It consults the original input and
    // feature-mask fields; all other original struct fields are inert.
    let request=OwnerAdmission {
        schema:String::new(), input_profile:String::new(),consumer:String::new(),
        allowed_use:String::new(),request_id:String::new(),
        issued_at_unix_seconds:0,deadline_unix_seconds:0,work_target:String::new(),
        model:Model{schema:String::new(),base:vec![],router:vec![],deltas:vec![]},
        inputs:vec![SourceSnippet{id:"bounded-inert-fixture".into(),origin:String::new(),
            content_hex:std::str::from_utf8(&frame[265..]).unwrap().into(),label:0}],
        before:CellState{schema:String::new(),cell_id:String::new(),generation:0,scope:String::new(),
            model_artifact:String::new(),memory:vec![],rng_seed:String::new(),rng_counter:0,
            remaining_steps:0,sequence:0,optimizer:None},
        policy:Policy{feature_mask,expert_mask:vec![],allowed_actions:vec![],
            sampler:Sampler::ArgmaxLowest,abstain_margin:0,tool_names:vec![],training:None},
    };
    let prepared=source::prepare(&request)?;
    assert_eq!(prepared.stages.len(),2);
    let first=&prepared.stages[0];
    let second=&prepared.stages[1];
    assert_eq!((&*first.stage,&*second.stage),("source-preprocessing","feature-mask"));
    assert_eq!(first.outputs["shape"],json!([1,DIM]));
    assert_eq!(second.outputs["shape"],json!([1,DIM]));
    let trace=&first.outputs["rows"][0];
    let normalized=hex::decode(trace["normalized_hex"].as_str().unwrap())?;
    let digest=hex::decode(trace["raw_sha256"].as_str().unwrap())?;
    let original=trace["features"].as_array().unwrap();
    let masked=second.outputs["values"][0].as_array().unwrap();
    assert_eq!(original.len(),DIM);
    assert_eq!(masked.len(),DIM);
    assert_eq!([1,DIM],[prepared.features.len(),prepared.features[0].len()]);
    assert_eq!(trace["id"],request.inputs[0].id);
    let mut out=Vec::new();
    out.extend_from_slice(&(normalized.len() as u64).to_le_bytes());
    out.extend_from_slice(&trace["used_tokens"].as_u64().unwrap().to_le_bytes());
    assert_eq!(digest.len(),32);
    out.extend_from_slice(&digest);
    for x in original { out.extend_from_slice(&x.as_i64().unwrap().to_le_bytes()); }
    for (x,actual) in masked.iter().zip(&prepared.features[0]) {
        assert_eq!(&x.as_i64().unwrap(),actual);
        out.extend_from_slice(&actual.to_le_bytes());
    }
    out.extend_from_slice(&normalized);
    Ok(out)
}

fn main()->io::Result<()> {
    let mut raw=Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut f=raw.as_slice();
    let mut out=io::BufWriter::new(io::stdout().lock());
    while !f.is_empty() {
        let n=u32::from_le_bytes(f[..4].try_into().unwrap()) as usize;
        let (frame,rest)=f[4..].split_at(n);
        match projected(frame) {
            Ok(bytes)=> {
                out.write_all(&[0])?;
                out.write_all(&(bytes.len() as u32).to_le_bytes())?;
                out.write_all(&bytes)?;
            }
            Err(e)=>out.write_all(&[match e.to_string().as_str() {
                "CELL_SOURCE_HEX"=>10,"CELL_SOURCE_UTF8"=>11,
                other=>panic!("Unexpected frozen source status: {other}"),
            }])?,
        }
        f=rest;
    }
    out.flush()
}

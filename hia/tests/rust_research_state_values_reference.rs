//! Marshal typed state values and observe original canonical encoders.
#[allow(dead_code)]
#[path = "rust_research_payload_reference.rs"]
mod payload;
use payload::hex;
use serde_json::{json,Value};
use std::io::{self,BufRead};
use trnm_research_protocol::*;
fn uint(o:&mut Vec<u8>,v:u64){o.extend_from_slice(&v.to_le_bytes())}
fn key(o:&mut Vec<u8>,v:ExternalKey){o.extend_from_slice(v.as_bytes())}
fn text(o:&mut Vec<u8>,v:&str){uint(o,v.len() as u64);o.extend_from_slice(v.as_bytes())}
fn reference(o:&mut Vec<u8>,v:ObjectRefV1){uint(o,v.kind as u64);key(o,v.key);uint(o,v.object_version)}
fn shares(o:&mut Vec<u8>,v:&[ClaimShareV1]){uint(o,v.len() as u64);for s in v {key(o,s.contributor);uint(o,u64::from(s.share_bps));}}
fn flat_identity(o:&mut Vec<u8>,v:&AuthorityIdentityV1){text(o,&v.signer_did);o.extend_from_slice(&v.public_key)}
fn identity(v:&Value)->AuthorityIdentityV1{AuthorityIdentityV1{signer_did:v["signer_did"].as_str().unwrap().into(),public_key:serde_json::from_value(v["public_key"].clone()).unwrap()}}
fn authorities(v:&Value)->AuthoritySetV1 {AuthoritySetV1{nakama_authorities:v["nakama_authorities"].as_array().unwrap().iter().map(identity).collect(),hepta_authorities:v["hepta_authorities"].as_array().unwrap().iter().map(identity).collect()}}
fn flat_authorities(o:&mut Vec<u8>,v:&AuthoritySetV1){for a in [&v.nakama_authorities,&v.hepta_authorities]{uint(o,a.len() as u64);for i in a {flat_identity(o,i)}}}
fn flat_record(o:&mut Vec<u8>,v:&AppliedCommandRecordV1){key(o,v.command_id);o.extend_from_slice(&v.fingerprint);reference(o,v.primary_object_ref);text(o,&v.chain_id);text(o,&v.signer_did);uint(o,v.signer_role as u64);uint(o,v.nonce);o.extend_from_slice(&v.public_key)}
fn object(kind:u64,v:&Value)->(Vec<u8>,Vec<u8>){
 let mut o=Vec::new();let cb=match kind {
  1=>{let x:MatchEvidenceObjectV1=serde_json::from_value(v.clone()).unwrap();reference(&mut o,x.object_ref);o.extend(payload::flat(&ResearchCommandV1::MatchEvidenceCommitment(x.commitment.clone())));x.canonical_bytes()},
  2=>{let x:EvaluationCommitmentObjectV1=serde_json::from_value(v.clone()).unwrap();reference(&mut o,x.object_ref);o.extend(payload::flat(&ResearchCommandV1::EvaluationCommitment(x.commitment.clone())));x.canonical_bytes()},
  3=>{let x:WorkloadReceiptObjectV1=serde_json::from_value(v.clone()).unwrap();reference(&mut o,x.object_ref);o.extend(payload::flat(&ResearchCommandV1::IssueWorkloadReceipt(x.receipt.clone())));x.canonical_bytes()},
  4=>{let x:ResearchClaimObjectV1=serde_json::from_value(v.clone()).unwrap();reference(&mut o,x.object_ref);o.extend(payload::flat(&ResearchCommandV1::CreateResearchClaim(x.claim.clone())));shares(&mut o,&x.current_claimants);uint(&mut o,x.status as u64);uint(&mut o,u64::from(x.active_challenge.is_some()));if let Some(k)=x.active_challenge{key(&mut o,k)};x.canonical_bytes()},
  5=>{let x:LicenseDeclarationObjectV1=serde_json::from_value(v.clone()).unwrap();reference(&mut o,x.object_ref);o.extend(payload::flat(&ResearchCommandV1::DeclareLicense(x.declaration.clone())));x.canonical_bytes()},
  6=>{let x:ClaimChallengeObjectV1=serde_json::from_value(v.clone()).unwrap();reference(&mut o,x.object_ref);o.extend(payload::flat(&ResearchCommandV1::ChallengeResearchClaim(x.challenge.clone())));uint(&mut o,x.status as u64);uint(&mut o,u64::from(x.resolution_ref.is_some()));if let Some(r)=x.resolution_ref{reference(&mut o,r)};x.canonical_bytes()},
  7=>{let x:ClaimResolutionObjectV1=serde_json::from_value(v.clone()).unwrap();reference(&mut o,x.object_ref);o.extend(payload::flat(&ResearchCommandV1::ResolveResearchClaim(x.resolution.clone())));x.canonical_bytes()},
  _=>panic!("unknown typed object")
 };(o,cb)
}
fn snapshot(v:&Value)->ResearchProtocolSnapshotV1 {ResearchProtocolSnapshotV1{
 protocol_version:serde_json::from_value(v["protocol_version"].clone()).unwrap(),authorities:authorities(&v["authorities"]),
 matches:serde_json::from_value(v["matches"].clone()).unwrap(),evaluations:serde_json::from_value(v["evaluations"].clone()).unwrap(),
 workload_receipts:serde_json::from_value(v["workload_receipts"].clone()).unwrap(),claims:serde_json::from_value(v["claims"].clone()).unwrap(),
 licenses:serde_json::from_value(v["licenses"].clone()).unwrap(),challenges:serde_json::from_value(v["challenges"].clone()).unwrap(),
 resolutions:serde_json::from_value(v["resolutions"].clone()).unwrap(),applied_commands:serde_json::from_value(v["applied_commands"].clone()).unwrap()}}
fn observe(v:Value)->Value {
 let op=v["op"].as_u64().unwrap();let mut out=Vec::new();let mut kind=0;let mut hash=[0;32];
 let cb=match op {
  1=>{kind=v["kind"].as_u64().unwrap();uint(&mut out,kind);let(flat,cb)=object(kind,&v["object"]);out.extend(flat);hash=canonical_hash("trnm-research-protocol-object-leaf-v1",&cb);cb},
  2=>{let x=snapshot(&v["snapshot"]);uint(&mut out,u64::from(x.protocol_version));flat_authorities(&mut out,&x.authorities);let j=serde_json::to_value(&x).unwrap();for(k,name)in ["matches","evaluations","workload_receipts","claims","licenses","challenges","resolutions"].iter().enumerate(){let a=j[name].as_array().unwrap();uint(&mut out,a.len() as u64);for x in a{out.extend(object(k as u64+1,x).0)}}uint(&mut out,x.applied_commands.len() as u64);for r in &x.applied_commands{flat_record(&mut out,r)}let cb=x.canonical_bytes();hash=canonical_hash("trnm-research-protocol-snapshot-v2",&cb);cb},
  3=>{let r:AppliedCommandRecordV1=serde_json::from_value(v["record"].clone()).unwrap();flat_record(&mut out,&r);r.canonical_bytes()},
  _=>panic!("unknown operation")
 };json!({"flat":hex(&out),"canonical":hex(&cb),"hash":hex(&hash),"kind":kind,"hash_present":op!=3})
}
fn main(){for line in io::stdin().lock().lines(){let v:Value=serde_json::from_str(&line.unwrap()).unwrap();println!("{}",observe(v));}}

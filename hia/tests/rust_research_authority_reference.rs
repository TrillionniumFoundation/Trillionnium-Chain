//! Public authority constructors, validation, authorization and canonical bytes.
#[allow(dead_code)]
#[path = "rust_research_payload_reference.rs"]
mod payload;
use ed25519_dalek::SigningKey;
use payload::hex;
use serde_json::{json,Value};
use std::io::{self,BufRead};
use trnm_research_protocol::*;
fn identity(v:&Value)->AuthorityIdentityV1 {
    let public_key=if let Some(seed)=v.get("seed") {
        let b:[u8;32]=payload::unhex(seed.as_str().unwrap()).try_into().unwrap();SigningKey::from_bytes(&b).verifying_key().to_bytes()
    } else {serde_json::from_value(v["public_key"].clone()).unwrap()};
    AuthorityIdentityV1{signer_did:v["signer_did"].as_str().unwrap().into(),public_key}
}
fn flat_identity(out:&mut Vec<u8>,v:&AuthorityIdentityV1) {
    out.extend_from_slice(&(v.signer_did.len() as u64).to_le_bytes());out.extend_from_slice(v.signer_did.as_bytes());out.extend_from_slice(&v.public_key);
}
fn flat_set(v:&AuthoritySetV1)->Vec<u8> {
    let mut out=Vec::new();
    for bucket in [&v.nakama_authorities,&v.hepta_authorities] {
        out.extend_from_slice(&(bucket.len() as u64).to_le_bytes());for i in bucket {flat_identity(&mut out,i)}
    }out
}
fn error(input:&[u8],e:ProtocolStateError)->Value {assert_eq!(e,ProtocolStateError::InvalidAuthoritySet);json!({"code":301,"flat_input":hex(input),"error":e.to_string()})}
fn observe(v:Value)->Value {
    let op=v["op"].as_u64().unwrap();
    if op==1 {
        let i=identity(&v["identity"]);let mut input=Vec::new();flat_identity(&mut input,&i);
        return match AuthorityIdentityV1::new(i.signer_did,i.public_key) {
            Ok(i)=>json!({"code":0,"flat_input":hex(&input),"flat":hex(&input),"canonical":hex(&i.canonical_bytes()),"authorized":false}),Err(e)=>error(&input,e)
        }
    }
    let mut set=AuthoritySetV1{nakama_authorities:v["nakama"].as_array().unwrap().iter().map(identity).collect(),hepta_authorities:v["hepta"].as_array().unwrap().iter().map(identity).collect()};
    let mut input=flat_set(&set);let mut authorized=false;
    if op==2 {set=match AuthoritySetV1::new(set.nakama_authorities,set.hepta_authorities) {Ok(s)=>s,Err(e)=>return error(&input,e)}}
    if op==3 {if let Err(e)=set.validate(){return error(&input,e)}}
    if op==4 {
        let query=identity(&v["query"]);let role:AuthorityRole=serde_json::from_value(v["role"].clone()).unwrap();
        input.extend_from_slice(&(role as u64).to_le_bytes());flat_identity(&mut input,&query);
        authorized=set.authorizes_identity(role,&query.signer_did,query.public_key);
        let signed=SignedResearchCommandV1{chain_id:String::new(),command_id:ExternalKey::from_bytes([0;32]),signer_did:query.signer_did,signer_role:role,nonce:0,public_key:query.public_key,command:serde_json::from_value(v["command"].clone()).unwrap(),signature:Vec::new()};
        assert_eq!(authorized,set.authorizes(&signed));
    }
    json!({"code":0,"flat_input":hex(&input),"flat":hex(&flat_set(&set)),"canonical":hex(&set.canonical_bytes()),"authorized":authorized,"set":set})
}
fn main(){for line in io::stdin().lock().lines(){let v:Value=serde_json::from_str(&line.unwrap()).unwrap();println!("{}",observe(v));}}

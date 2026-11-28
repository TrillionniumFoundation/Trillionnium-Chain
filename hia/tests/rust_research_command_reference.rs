//! Actual public signed-command methods, with flat bytes only for borrowed ABI.
#[allow(dead_code)]
#[path = "rust_research_payload_reference.rs"]
mod payload;
use ed25519_dalek::SigningKey;
use payload::{canonical, flat, hex, unhex, validation};
use serde_json::{json, Value};
use std::io::{self, BufRead};
use trnm_research_protocol::*;

fn number(out: &mut Vec<u8>, n: u64) { out.extend_from_slice(&n.to_le_bytes()); }
fn text(out: &mut Vec<u8>, s: &str) { number(out, s.len() as u64); out.extend_from_slice(s.as_bytes()); }
fn flattened(v: &SignedResearchCommandV1) -> Vec<u8> {
    let mut out=Vec::new();
    text(&mut out,&v.chain_id);
    out.extend_from_slice(v.command_id.as_bytes());
    text(&mut out,&v.signer_did);
    number(&mut out,v.signer_role as u64);
    number(&mut out,v.nonce);
    out.extend_from_slice(&v.public_key);
    number(&mut out,v.command.primary_object_ref().kind as u64);
    out.extend_from_slice(&flat(&v.command));
    number(&mut out,v.signature.len() as u64);
    out.extend_from_slice(&v.signature);
    out
}
fn failure(e: SignedResearchCommandValidationError) -> Value {
    use SignedResearchCommandValidationError::*;
    let (code,name,a,b,encoding) = match &e {
        CanonicalDecode(v) => { let(c,n,a,b)=canonical(v);(c,n,a,b,String::new()) },
        Payload(v) => { let(c,n,a,b)=validation(v);(c,n,a,b,String::new()) },
        EncodingMismatch(v) => (201,"",0,0,v.clone()),
        InvalidChainId => (202,"",0,0,String::new()),
        InvalidSignerDid => (203,"",0,0,String::new()),
        ZeroNonce => (204,"",0,0,String::new()),
        InvalidPublicKey => (205,"",0,0,String::new()),
        InvalidSignature => (206,"",0,0,String::new()),
        UnauthorizedCommand{role,command_type} => {
            let names=["match_evidence_commitment_v1","evaluation_commitment_v1","issue_workload_receipt_v1","create_research_claim_v1","declare_license_v1","challenge_research_claim_v1","resolve_research_claim_v1"];
            (207,"",*role as u64,names.iter().position(|x|x==command_type).unwrap() as u64+1,String::new())
        }
    };
    json!({"code":code,"name":name,"detail1":a,"detail2":b,"encoding":encoding,"error":e.to_string()})
}
fn observe(input: Value) -> Value {
    let op=input["op"].as_u64().unwrap();
    let mut flat_input=String::new();
    let signed: Result<SignedResearchCommandV1,SignedResearchCommandValidationError>=if op==3 {
        SignedResearchCommandV1::from_canonical_bytes(&unhex(input["cbor"].as_str().unwrap()))
    } else {
        let v=&input["signed"];
        let role: AuthorityRole=serde_json::from_value(v["signer_role"].clone()).unwrap();
        let command: ResearchCommandV1=serde_json::from_value(v["command"].clone()).unwrap();
        let mut signed=SignedResearchCommandV1 {
            chain_id:v["chain_id"].as_str().unwrap().into(),
            command_id:serde_json::from_value(v["command_id"].clone()).unwrap(),
            signer_did:v["signer_did"].as_str().unwrap().into(),
            signer_role:role,
            nonce:v["nonce"].as_u64().unwrap(),
            public_key:serde_json::from_value(v["public_key"].clone()).unwrap(),
            command,
            signature:serde_json::from_value(v["signature"].clone()).unwrap()
        };
        if op==4 {
            let seed:[u8;32]=unhex(input["seed"].as_str().unwrap()).try_into().unwrap();
            signed.public_key=seed;
            signed.signature.clear();
            flat_input=hex(&flattened(&signed));
            SignedResearchCommandV1::sign(signed.chain_id,signed.command_id,signed.signer_did,role,signed.nonce,signed.command,&SigningKey::from_bytes(&seed))
        } else {
            flat_input=hex(&flattened(&signed));
            if op==1 { Ok(signed) } else { signed.validate().map(|()|signed) }
        }
    };
    match signed {
        Err(e) => {let mut out=failure(e);out["flat_input"]=json!(flat_input);out},
        Ok(v) => json!({"code":0,"flat_input":flat_input,"flat":hex(&flattened(&v)),"canonical":hex(&v.canonical_bytes()),"unsigned":hex(&v.signing_bytes()),"fingerprint":hex(&v.command_fingerprint()),"payload_hash":hex(&v.payload_hash()),"payload":hex(&v.command.canonical_bytes()),"public_key":hex(&v.public_key),"signature":hex(&v.signature),"kind":v.command.primary_object_ref().kind as u64,"signed":v})
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let input:Value=serde_json::from_str(&line.unwrap()).unwrap();
        println!("{}",observe(input));
    }
}

// Every semantic result calls original TaskKernel private methods or Dalek.
use std::io::{self,BufRead};
use ed25519_dalek::{Signer,SigningKey,VerifyingKey};
#[path = "ORIGINAL_ERROR_PATH"] mod error;
pub use error::{AgentMarketErrorCodeV1,AgentMarketErrorV1,AgentMarketResultV1};
#[path = "ORIGINAL_CODEC_PATH"] mod codec;
#[path = "ORIGINAL_TYPES_PATH"] mod types;
pub use types::*;
#[path = "ORIGINAL_STORE_PATH"] mod store;

fn put(v:&mut Vec<u8>,n:u64){v.extend_from_slice(&n.to_le_bytes());}
fn reply(code:u64,message:&str,display:&str,payload:&[u8])->Vec<u8>{let mut out=Vec::new();for n in [code,message.len() as u64,display.len() as u64,payload.len() as u64]{put(&mut out,n);}out.extend_from_slice(message.as_bytes());out.extend_from_slice(display.as_bytes());out.extend_from_slice(payload);out}
fn failure(e:AgentMarketErrorV1)->Vec<u8>{reply(e.code() as u64+1,e.message(),&e.to_string(),&[])}
fn number(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn run(s:&[u8])->(u32,Vec<u8>){
 if s.len()<40||&s[..8]!=b"TKPL0001"{return (100,vec![])}
 let op=number(s,8);let n=number(s,24) as usize;
 if op>5||n>s.len()-40||number(s,32)!=((s.len()-40-n) as u64){return (100,vec![])}
 let extra=&s[40+n..];
 if (op==0&&!extra.is_empty())||(op==4&&extra.len()!=32)||(op==5&&(n!=0||extra.len()!=32)){return (100,vec![])}
 if op==5 {let key:&[u8;32]=extra.try_into().unwrap();let result=match VerifyingKey::from_bytes(key){Ok(k)=>vec![1,u8::from(k.is_weak())],Err(_)=>vec![0,0]};return (0,reply(0,"","",&result))}
 let bundle=match codec::strict_decode(&s[40..40+n]){Ok(b)=>b,Err(e)=>return (0,failure(e))};
 (0,match store::qualification_policy(op,number(s,16),bundle,extra){Ok(v)=>reply(0,"","",&v),Err(e)=>failure(e)})
}

// Fixture-only preparation invokes original IDs and genuine signing keys.
fn prepare_trust(data:&[u8])->Vec<u8>{
 let mut bundle:AgentMarketFreshGenesisTrustBundleV1=borsh::from_slice(data).expect("fixture trust");
 bundle.schema_version=1;bundle.context.protocol_version=1;if bundle.context.chain_id.is_empty(){bundle.context.chain_id="kernel-policy-fixture".to_owned();}
 bundle.initial_order_block_id=Hash32V1([3;32]);
 bundle.requester=BootstrapAgentV1{agent_id:AgentIdV1([1;32]),controller_key_id:AgentKeyIdV1([11;32]),controller_public_key:SigningKey::from_bytes(&[11;32]).verifying_key().to_bytes(),session_key_id:AgentKeyIdV1([12;32]),session_public_key:SigningKey::from_bytes(&[12;32]).verifying_key().to_bytes()};
 bundle.provider=BootstrapAgentV1{agent_id:AgentIdV1([2;32]),controller_key_id:AgentKeyIdV1([21;32]),controller_public_key:SigningKey::from_bytes(&[21;32]).verifying_key().to_bytes(),session_key_id:AgentKeyIdV1([22;32]),session_public_key:SigningKey::from_bytes(&[22;32]).verifying_key().to_bytes()};
 bundle.requester_account_body.context=bundle.context.clone();bundle.requester_account_body.owner_agent_id=bundle.requester.agent_id;
 bundle.requester_account_id=bundle.requester_account_body.account_id().expect("fixture account");bundle.requester_account_funding=1000;
 bundle.provider_bond_body.context=bundle.context.clone();bundle.provider_bond_body.owner_agent_id=bundle.provider.agent_id;
 bundle.provider_bond_id=bundle.provider_bond_body.bond_id().expect("fixture bond");bundle.provider_bond_funding=500;bundle.provider_bond_hold=100;
 borsh::to_vec(&bundle).expect("fixture serialize")
}
fn prepare_ids(data:&[u8])->Vec<u8>{
 let mut bundle:AgentMarketFreshGenesisTrustBundleV1=borsh::from_slice(data).expect("fixture trust");
 bundle.requester_account_id=bundle.requester_account_body.account_id().expect("fixture account");
 bundle.provider_bond_id=bundle.provider_bond_body.bond_id().expect("fixture bond");
 borsh::to_vec(&bundle).expect("fixture serialize")
}
fn prepare_command(bundle:&[u8],command:&[u8],provider:bool,normalize:bool)->Vec<u8>{
 let bundle:AgentMarketFreshGenesisTrustBundleV1=borsh::from_slice(bundle).expect("fixture trust");
 let mut command:KernelCommandV1=borsh::from_slice(command).expect("fixture command");
 let kind=command.operation_kind();let digest=command.operation_digest().expect("fixture digest");
 let auth=match &mut command {KernelCommandV1::CapabilityGrant{authorization,..}|KernelCommandV1::SessionGrant{authorization,..}|KernelCommandV1::TaskCreate{authorization,..}|KernelCommandV1::Bid{authorization,..}|KernelCommandV1::LeaseAccept{authorization,..}|KernelCommandV1::ProviderAccept{authorization,..}=>authorization};
 let actor=if provider{&bundle.provider}else{&bundle.requester};
 if normalize {auth.statement.schema_version=1;auth.statement.context=bundle.context.clone();auth.statement.operation_kind=kind;auth.statement.operation_digest=digest;
 auth.statement.sender_agent_id=actor.agent_id;auth.signer_key_id=if kind<=3{actor.controller_key_id}else{actor.session_key_id};auth.statement.valid_after_height=0;auth.statement.expires_after_height=u64::MAX;}
 let domain=match kind{2=>"trnm.portable.v2.capability-grant-kernel-signature.candidate.v1",3=>"trnm.portable.v2.session-grant-kernel-signature.candidate.v1",4=>"trnm.portable.v2.task-offer-kernel-signature.candidate.v1",5=>"trnm.portable.v2.bid-kernel-signature.candidate.v1",6=>"trnm.portable.v2.lease-requester-kernel-signature.candidate.v1",7=>"trnm.portable.v2.lease-provider-kernel-signature.candidate.v1",_=>unreachable!()};
 let message=codec::digest_value(domain,&auth.statement).expect("fixture signature digest");
 let seed=if provider{if kind<=3{21}else{22}}else if kind<=3{11}else{12};
 auth.signature=SigningKey::from_bytes(&[seed;32]).sign(&message.0).to_bytes().to_vec();
 borsh::to_vec(&command).expect("fixture serialize")
}
fn unhex(s:&str)->Vec<u8>{assert!(s.len()%2==0);s.as_bytes().chunks_exact(2).map(|v|(v[0] as char).to_digit(16).expect("hex") as u8*16+(v[1] as char).to_digit(16).expect("hex") as u8).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn main(){for line in io::stdin().lock().lines(){let line=line.expect("input");if let Some(data)=line.strip_prefix("trust:"){println!("{}",hex(&prepare_trust(&unhex(data))));}else if let Some(data)=line.strip_prefix("ids:"){println!("{}",hex(&prepare_ids(&unhex(data))));}else if line.starts_with("command:")||line.starts_with("sign:"){let parts:Vec<_>=line.split(':').collect();assert_eq!(parts.len(),4);println!("{}",hex(&prepare_command(&unhex(parts[1]),&unhex(parts[2]),parts[3]=="1",parts[0]=="command")));}else{let (code,out)=run(&unhex(&line));println!("{code}|{}",hex(&out));}}}

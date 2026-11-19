// Qualification adapter. All semantic results call the actual unchanged crate.
use std::io::{self, BufRead};
pub use trnm_task_kernel::*;
#[path = "ORIGINAL_ERROR_PATH"] mod error;
#[path = "ORIGINAL_CODEC_PATH"] mod codec;

fn put(v:&mut Vec<u8>,n:u64){v.extend_from_slice(&n.to_le_bytes());}
fn reply(code:u64,message:&str,display:&str,payload:&[u8])->Vec<u8>{let mut out=Vec::new();for n in [code,message.len() as u64,display.len() as u64,payload.len() as u64]{put(&mut out,n);}out.extend_from_slice(message.as_bytes());out.extend_from_slice(display.as_bytes());out.extend_from_slice(payload);out}
fn original_error(e:error::AgentMarketErrorV1)->Vec<u8>{reply(e.code() as u64+1,e.message(),&e.to_string(),&[])}
fn public_error(e:AgentMarketErrorV1)->Vec<u8>{reply(e.code() as u64+1,e.message(),&e.to_string(),&[])}
fn number(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn packed(value:AgentTransactionV1)->Vec<u8>{
 let command=borsh::to_vec(value.command()).expect("actual command Borsh");
 let wire=value.encoded();let id=value.transaction_id();let mut out=Vec::new();
 put(&mut out,command.len() as u64);put(&mut out,wire.len() as u64);
 out.extend_from_slice(&id.0);out.extend_from_slice(&command);out.extend_from_slice(wire);
 reply(0,"","",&out)
}
fn run(s:&[u8])->(u32,Vec<u8>){
 if s.len()<24||&s[..8]!=b"TKAW0001" {return (100,vec![])}
 let op=number(s,8);if op>1||number(s,16)!=s.len() as u64-24{return (100,vec![])}
 let data=&s[24..];
 let result=if op==0 {match codec::strict_decode::<KernelCommandV1>(data){Ok(command)=>AgentTransactionV1::from_kernel_command(command),Err(e)=>return (0,original_error(e))}}
 else {AgentTransactionV1::decode(data)};
 (0,match result {Ok(value)=>packed(value),Err(e)=>public_error(e)})
}

// Fixture preparation changes public fields, then calls the original operation
// digest. It is not a tested runtime method and is counted separately.
fn prepare(data:&[u8])->Vec<u8>{
 let mut command=borsh::from_slice::<KernelCommandV1>(data).expect("fixture command");
 let kind=command.operation_kind();let digest=command.operation_digest().expect("fixture operation digest");
 let auth=match &mut command {
  KernelCommandV1::CapabilityGrant{authorization,..}|KernelCommandV1::SessionGrant{authorization,..}|
  KernelCommandV1::TaskCreate{authorization,..}|KernelCommandV1::Bid{authorization,..}|
  KernelCommandV1::LeaseAccept{authorization,..}|KernelCommandV1::ProviderAccept{authorization,..}=>authorization,
 };
 auth.statement.schema_version=1;auth.statement.context.protocol_version=1;
 auth.statement.context.chain_id="typed-wire-fixture".to_owned();
 auth.statement.operation_kind=kind;auth.statement.operation_digest=digest;
 auth.statement.valid_after_height=0;auth.statement.expires_after_height=u64::MAX;
 auth.signature=vec![0x41;64];
 borsh::to_vec(&command).expect("fixture serialize")
}

// Qualification-only malformed-wire fixture builder. The original digest
// implementation creates both commitments; actual decode still decides errors.
fn repair(data:&[u8])->Vec<u8>{
 assert!(data.len()>=326);let mut wire=data.to_vec();let size=wire.len()-326;
 wire[258..262].copy_from_slice(&u32::try_from(size).expect("fixture length").to_le_bytes());
 let payload=codec::digest_encoded("trnm.portable.v2.agent-transaction-payload.v1",&wire[294..294+size]).expect("fixture payload");
 wire[262..294].copy_from_slice(&payload.0);
 let end=wire.len()-32;let digest=codec::digest_encoded("trnm.portable.v2.agent-transaction-wire.v1",&wire[..end]).expect("fixture wire");
 wire[end..].copy_from_slice(&digest.0);wire
}
fn unhex(s:&str)->Vec<u8>{assert!(s.len()%2==0);s.as_bytes().chunks_exact(2).map(|v|(v[0] as char).to_digit(16).expect("hex") as u8*16+(v[1] as char).to_digit(16).expect("hex") as u8).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn main(){for line in io::stdin().lock().lines(){let line=line.expect("input");if let Some(s)=line.strip_prefix("prepare:"){println!("{}",hex(&prepare(&unhex(s))));}else if let Some(s)=line.strip_prefix("repair:"){println!("{}",hex(&repair(&unhex(s))));}else{let (code,out)=run(&unhex(&line));println!("{code}|{}",hex(&out));}}}

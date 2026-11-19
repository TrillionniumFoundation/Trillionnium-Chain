use std::{io::{self,BufRead},os::unix::ffi::OsStringExt,path::PathBuf,ffi::OsString};
#[path="ORIGINAL_ERROR_PATH"] mod error;
pub use error::{AgentMarketErrorCodeV1,AgentMarketErrorV1,AgentMarketResultV1};
#[path="ORIGINAL_CODEC_PATH"] mod codec;
#[path="ORIGINAL_TYPES_PATH"] mod types;
pub use types::*;
#[path="ORIGINAL_STORE_PATH"] mod store;
fn number(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn reply(code:u64,message:&str,display:&str,payload:&[u8])->Vec<u8>{let mut out=Vec::new();for n in [code,message.len() as u64,display.len() as u64,payload.len() as u64]{out.extend_from_slice(&n.to_le_bytes());}out.extend_from_slice(message.as_bytes());out.extend_from_slice(display.as_bytes());out.extend_from_slice(payload);out}
fn run(raw:&[u8],prepare:u8)->(u64,Vec<u8>){
 if raw.len()<72||&raw[..8]!=b"TKSA0001"||number(raw,8)>14||number(raw,24)>raw.len() as u64-72{return(100,vec![])}
 let n=number(raw,24) as usize;if number(raw,32)!=(raw.len()-72-n) as u64{return(100,vec![])}
 let bundle=match codec::strict_decode(&raw[72+n..]){Ok(b)=>b,Err(e)=>return(0,reply(e.code() as u64+1,e.message(),&e.to_string(),&[]))};
 let config=store::AgentMarketStoreConfigV1{path:PathBuf::from(OsString::from_vec(raw[72..72+n].to_vec())),store_id:Hash32V1(raw[40..72].try_into().unwrap()),trust_bundle:bundle};
 let result=match prepare{1=>store::qualification_create(config).map(|_|Vec::new()),2=>store::qualification_reseal_metadata(config).map(|_|Vec::new()),3=>store::qualification_reseal_objects(config).map(|_|Vec::new()),4=>store::qualification_reseal_operations(config).map(|_|Vec::new()),5=>store::qualification_reseal_markers(config).map(|_|Vec::new()),6=>store::qualification_empty_blocks(config,number(raw,16)).map(|_|Vec::new()),_=>store::qualification_store_audit(number(raw,8),number(raw,16),config)};
 (0,match result{Ok(out)=>reply(0,"","",&out),Err(e)=>reply(e.code() as u64+1,e.message(),&e.to_string(),&[])})
}
fn unhex(s:&str)->Vec<u8>{assert!(s.len()%2==0);s.as_bytes().chunks_exact(2).map(|v|(v[0] as char).to_digit(16).expect("hex") as u8*16+(v[1] as char).to_digit(16).expect("hex") as u8).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn main(){for line in io::stdin().lock().lines(){
 let line=line.expect("input");
 if line.starts_with("object:"){let p:Vec<_>=line.split(':').collect();assert_eq!(p.len(),6);let out=store::qualification_object_fixture(p[1].parse().unwrap(),&unhex(p[2]),&unhex(p[3]),p[4].parse().unwrap(),p[5].parse().unwrap()).expect("fixture object");println!("{}",hex(&out));continue;}
 if line.starts_with("operation:"){let p:Vec<_>=line.split(':').collect();assert_eq!(p.len(),6);let out=store::qualification_operation_fixture(&unhex(p[1]),p[2].parse().unwrap(),p[3].parse().unwrap(),unhex(p[4]).try_into().unwrap(),unhex(p[5]).try_into().unwrap()).expect("fixture operation");println!("{}",hex(&out));continue;}
 let (kind,line)=if let Some(s)=line.strip_prefix("create:"){(1,s)}else if let Some(s)=line.strip_prefix("reseal:"){(2,s)}else if let Some(s)=line.strip_prefix("reseal-objects:"){(3,s)}else if let Some(s)=line.strip_prefix("reseal-operations:"){(4,s)}else if let Some(s)=line.strip_prefix("reseal-markers:"){(5,s)}else if let Some(s)=line.strip_prefix("empty-blocks:"){(6,s)}else{(0,line.as_str())};
 let(code,out)=run(&unhex(line),kind);println!("{code}|{}",hex(&out));
}}

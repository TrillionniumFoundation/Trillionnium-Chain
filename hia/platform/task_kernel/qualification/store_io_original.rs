use std::{io::{self,BufRead},os::unix::ffi::OsStringExt,path::PathBuf,ffi::OsString};
#[path="ORIGINAL_ERROR_PATH"] mod error;
pub use error::{AgentMarketErrorCodeV1,AgentMarketErrorV1,AgentMarketResultV1};
#[path="ORIGINAL_CODEC_PATH"] mod codec;
#[path="ORIGINAL_TYPES_PATH"] mod types;
pub use types::*;
#[path="ORIGINAL_STORE_PATH"] mod store;
fn number(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn reply(code:u64,message:&str,display:&str,payload:&[u8])->Vec<u8>{let mut out=Vec::new();for n in [code,message.len() as u64,display.len() as u64,payload.len() as u64]{out.extend_from_slice(&n.to_le_bytes());}out.extend_from_slice(message.as_bytes());out.extend_from_slice(display.as_bytes());out.extend_from_slice(payload);out}
fn run(raw:&[u8])->(u64,Vec<u8>){
 if raw.len()<24||&raw[..8]!=b"TKIO0001"||number(raw,8)>4||number(raw,16)!=raw.len() as u64-24{return(100,vec![])}
 let path=PathBuf::from(OsString::from_vec(raw[24..].to_vec()));
 (0,match store::qualification_store_io(number(raw,8),path){Ok(out)=>reply(0,"","",&out),Err(e)=>reply(e.code() as u64+1,e.message(),&e.to_string(),&[])})
}
fn unhex(s:&str)->Vec<u8>{assert!(s.len()%2==0);s.as_bytes().chunks_exact(2).map(|v|(v[0] as char).to_digit(16).expect("hex") as u8*16+(v[1] as char).to_digit(16).expect("hex") as u8).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn main(){for line in io::stdin().lock().lines(){let(code,out)=run(&unhex(&line.expect("input")));println!("{code}|{}",hex(&out));}}

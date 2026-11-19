use std::{collections::BTreeMap, ffi::OsString, io::{self, BufRead, Write}, os::unix::ffi::OsStringExt, path::PathBuf};
use borsh::BorshDeserialize;
#[path="ORIGINAL_ERROR_PATH"] mod error;
pub use error::{AgentMarketErrorCodeV1,AgentMarketErrorV1,AgentMarketResultV1};
#[path="ORIGINAL_CODEC_PATH"] mod codec;
#[path="ORIGINAL_TYPES_PATH"] mod types;
pub use types::*;
#[path="ORIGINAL_STORE_PATH"] mod store;
#[path="PUBLIC_OBSERVATION_PATH"] mod observation;
use observation::Owned;

fn unhex(s:&str)->Vec<u8>{assert!(s.len()%2==0);s.as_bytes().chunks_exact(2).map(|v|(v[0] as char).to_digit(16).expect("hex") as u8*16+(v[1] as char).to_digit(16).expect("hex") as u8).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn number(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn config(raw:&[u8])->AgentMarketResultV1<store::AgentMarketStoreConfigV1>{
    assert!(raw.len()>=48);let path=number(raw,0) as usize;let bundle=number(raw,8) as usize;assert_eq!(path+bundle,raw.len()-48);
    let trust_bundle=codec::strict_decode(&raw[48+path..])?;
    Ok(store::AgentMarketStoreConfigV1{path:PathBuf::from(OsString::from_vec(raw[48..48+path].to_vec())),store_id:Hash32V1(raw[16..48].try_into().unwrap()),trust_bundle})
}
fn commands(raw:&[u8])->AgentMarketResultV1<Vec<KernelCommandV1>>{
    assert!(raw.len()>=8);let count=number(raw,0);let mut source=&raw[8..];let mut out=Vec::new();
    for _ in 0..count{out.push(KernelCommandV1::deserialize(&mut source).map_err(|e|error::error(AgentMarketErrorCodeV1::NonCanonical,e.to_string()))?);}
    if !source.is_empty(){return Err(error::error(AgentMarketErrorCodeV1::NonCanonical,"Not all bytes read"))}Ok(out)
}
fn store<'a>(objects:&'a BTreeMap<String,Owned>,id:&str)->&'a store::TaskKernelStoreV1{match objects.get(id).expect("live store"){Owned::Store(v)=>v,_=>panic!("store type")}}
fn readback<'a>(objects:&'a BTreeMap<String,Owned>,id:&str)->&'a store::AgentMarketFreshReadbackV1{match objects.get(id).expect("live readback"){Owned::Readback(v)=>v,_=>panic!("readback type")}}
fn run(parts:&[&str],objects:&BTreeMap<String,Owned>)->AgentMarketResultV1<Owned>{
    let action=parts[0];
    if action=="open"||action=="existing"{let cfg=config(&unhex(parts[2]))?;return if action=="open"{store::TaskKernelStoreV1::open(cfg)}else{store::TaskKernelStoreV1::open_existing(cfg)}.map(Owned::Store)}
    if action=="error_clone"{return match objects.get(parts[2]).expect("error owner"){Owned::Error(v)=>Ok(Owned::Error(v.clone())),_=>panic!("error type")}}
    let s=store(objects,parts[2]);
    match action{
        "clone"=>Ok(Owned::Store(s.clone())),
        "fresh"=>s.fresh_readback().map(Owned::Readback),
        "execute"=>{let execution=codec::strict_decode(&unhex(parts[3]))?;let command=codec::strict_decode(&unhex(parts[4]))?;s.execute_committed_execution(&execution,&command).map(Owned::Outcome)},
        "empty"=>{let execution=codec::strict_decode(&unhex(parts[3]))?;s.advance_empty_committed_execution_v1(&execution).map(Owned::Readback)},
        "confirm"=>{let receipt=codec::strict_decode(&unhex(parts[3]))?;s.confirm_receipt(&receipt).map(Owned::Confirmed)},
        "preview"=>{let parent=readback(objects,parts[3]);let height=parts[4].parse().unwrap();let block=Hash32V1(unhex(parts[5]).try_into().unwrap());let values=commands(&unhex(parts[6]))?;s.preview_before_vote_v1(parent,height,block,&values).map(Owned::Preview)},
        "state"=>{let kind:u64=parts[3].parse().unwrap();let id:[u8;32]=unhex(parts[4]).try_into().unwrap();let bytes=match kind{
            2=>codec::canonical_bytes(&s.capability_state(CapabilityIdV1(id))?)?,
            3=>codec::canonical_bytes(&s.session_state(SessionKeyGrantIdV1(id))?)?,
            4=>codec::canonical_bytes(&s.task_state(TaskIdV1(id))?)?,
            5=>codec::canonical_bytes(&s.bid_state(BidIdV1(id))?)?,
            6=>codec::canonical_bytes(&s.lease_state(LeaseIdV1(id))?)?,
            7=>codec::canonical_bytes(&s.escrow_state(EscrowIdV1(id))?)?,
            44=>codec::canonical_bytes(&s.nonce_lane_state(NonceLaneIdV1(id))?)?,
            45=>codec::canonical_bytes(&s.account_state(AccountIdV1(id))?)?,
            47=>codec::canonical_bytes(&s.bond_state(BondIdV1(id))?)?,
            _=>panic!("object kind")};Ok(Owned::State(kind,bytes))},
        _=>panic!("action")
    }
}
fn main(){let mut objects=BTreeMap::<String,Owned>::new();for line in io::stdin().lock().lines(){let line=line.expect("input");let parts:Vec<_>=line.split('|').collect();
    if parts[0]=="drop"{assert!(objects.remove(parts[1]).is_some());println!("D");}
    else if parts[0]=="parallel"{let s=store(&objects,parts[1]);let threads:usize=parts[2].parse().unwrap();let repeats:usize=parts[3].parse().unwrap();let rows=std::thread::scope(|scope|{let jobs:Vec<_>=(0..threads).map(|_|scope.spawn(move||{let mut rows=Vec::new();for _ in 0..repeats{let value=s.fresh_readback().map(Owned::Readback).unwrap_or_else(Owned::Error);let (kind,bytes)=observation::pack(&value);rows.push(format!("V|{kind}|{}",hex(&bytes)));}rows})).collect();jobs.into_iter().flat_map(|job|job.join().expect("reader thread")).collect::<Vec<_>>()});println!("P|{}",rows.join(";"));}
    else if parts[0]=="equal"{println!("S|{}",u8::from(readback(&objects,parts[1])==readback(&objects,parts[2])));}
    else if parts[0]=="observe"{let (kind,bytes)=observation::pack(objects.get(parts[1]).expect("live value"));println!("V|{kind}|{}",hex(&bytes));}
    else{assert!(!objects.contains_key(parts[1]),"unique result slot");let value=run(&parts,&objects).unwrap_or_else(Owned::Error);let (kind,bytes)=observation::pack(&value);objects.insert(parts[1].to_owned(),value);println!("V|{kind}|{}",hex(&bytes));}
    io::stdout().flush().expect("flush");
}}

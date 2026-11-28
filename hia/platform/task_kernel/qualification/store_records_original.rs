use std::{io::{self,BufRead},os::unix::ffi::OsStringExt,path::PathBuf,ffi::OsString};
#[path="ORIGINAL_ERROR_PATH"] mod error;
pub use error::{AgentMarketErrorCodeV1,AgentMarketErrorV1,AgentMarketResultV1};
#[path="ORIGINAL_CODEC_PATH"] mod codec;
#[path="ORIGINAL_TYPES_PATH"] mod types;
pub use types::*;
#[path="ORIGINAL_STORE_PATH"] mod store;
fn number(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn reply(code:u64,message:&str,display:&str,payload:&[u8])->Vec<u8>{let mut out=Vec::new();for n in [code,message.len() as u64,display.len() as u64,payload.len() as u64]{out.extend_from_slice(&n.to_le_bytes());}out.extend_from_slice(message.as_bytes());out.extend_from_slice(display.as_bytes());out.extend_from_slice(payload);out}
fn error_reply(e:AgentMarketErrorV1)->(u64,Vec<u8>){(0,reply(e.code() as u64+1,e.message(),&e.to_string(),&[]))}
fn run(raw:&[u8])->(u64,Vec<u8>){
    if raw.len()<160||&raw[..8]!=b"TKSR0001"||number(raw,8)>26||number(raw,144)!=0||number(raw,152)!=0{return(100,vec![])}
    let method=number(raw,8);let kind=number(raw,16);
    if method==24&&kind>3{return(100,vec![])}
    if method==26&&(number(raw,56)<178||number(raw,64)<4||number(raw,72)!=32){return(100,vec![])}
    if (method<=2||method==15)&&!matches!(kind,2|3|4|5|6|7|44|45|47){return(100,vec![])}
    let mut offsets=vec![160usize];let mut left=raw.len()-160;
    for i in 0..5{let n=number(raw,40+i*8);if n>left as u64{return(100,vec![])}left-=n as usize;offsets.push(offsets.last().unwrap()+n as usize);}
    if left!=0{return(100,vec![])}
    if method==5&&(number(raw,56)!=64||number(raw,64)!=1){return(100,vec![])}
    if method==5&&raw[offsets[3]]>1{return(100,vec![])}
    if method==6&&number(raw,56)!=296{return(100,vec![])}
    if method==7&&number(raw,64)!=128{return(100,vec![])}
    if method==8&&number(raw,56)!=64{return(100,vec![])}
    let bundle=match codec::strict_decode(&raw[offsets[1]..offsets[2]]){Ok(v)=>v,Err(e)=>return error_reply(e)};
    let config=store::AgentMarketStoreConfigV1{path:PathBuf::from(OsString::from_vec(raw[offsets[0]..offsets[1]].to_vec())),store_id:Hash32V1(raw[80..112].try_into().unwrap()),trust_bundle:bundle};
    let id=raw[112..144].try_into().unwrap();let body=&raw[offsets[2]..offsets[3]];let state=&raw[offsets[3]..offsets[4]];let command=&raw[offsets[4]..offsets[5]];
    macro_rules! object{($body:ty,$state:ty,$kind:ident)=>{store::qualification_records_object::<$body,$state>(method,config,ObjectKindV1::$kind,id,number(raw,24),number(raw,32),body,state)}};
    let result=if method==26{store::qualification_records_preview(config,number(raw,24),body,state,command)}else if method>=24{store::qualification_records_execution(method,config,kind,body,state)}else if method>=21{store::qualification_records_authorize(method,config,number(raw,24),body,command)}else if method==20{store::qualification_records_budget(number(raw,24),body,state,command)}else if method==19{store::qualification_records_grant(config,number(raw,24),body)}else if method>=11{store::qualification_records_verified(method,config,kind,id,body)}else if method>=9{store::qualification_records_bootstrap(method,config,body)}else if method>=5{store::qualification_records_progress(method,config,id,number(raw,24),number(raw,32),body,state)}else if method>=3{store::qualification_records_operation(method,config,id,body,state,command)}else{match kind{
        2=>object!(CapabilityGrantBodyV1,CapabilityStateV1,Capability),
        3=>object!(SessionKeyGrantBodyV1,SessionKeyGrantStateV1,SessionGrant),
        4=>object!(TaskOfferBodyV1,TaskStateV1,Task),
        5=>object!(BidBodyV1,BidStateV1,Bid),
        6=>object!(TaskLeaseBodyV1,TaskLeaseStateV1,Lease),
        7=>object!(EscrowBodyV1,EscrowStateV1,Escrow),
        44=>object!(NonceLaneKeyBodyV1,NonceLaneStateV1,NonceLane),
        45=>object!(AccountBodyV1,AccountStateV1,Account),
        47=>object!(BondBodyV1,BondStateV1,Bond),
        _=>unreachable!(),
    }};
    match result{Ok(payload)=>(0,reply(0,"","",&payload)),Err(e)=>error_reply(e)}
}
fn unhex(s:&str)->Vec<u8>{assert!(s.len()%2==0);s.as_bytes().chunks_exact(2).map(|v|(v[0] as char).to_digit(16).expect("hex") as u8*16+(v[1] as char).to_digit(16).expect("hex") as u8).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn main(){for line in io::stdin().lock().lines(){
    let line=line.expect("input");
    if let Some(value)=line.strip_prefix("value-id:"){
        let (kind,raw)=value.split_once(':').expect("fixture ID fields");let raw=unhex(raw);
        let id=match kind{
            "33"=>codec::strict_decode::<CapabilityGrantBodyV1>(&raw).expect("fixture capability").capability_id().expect("fixture capability ID").0,
            "37"=>codec::strict_decode::<SessionKeyGrantBodyV1>(&raw).expect("fixture session").session_key_grant_id().expect("fixture session ID").0,
            "39"=>codec::strict_decode::<NonceLaneKeyBodyV1>(&raw).expect("fixture lane").nonce_lane_id().expect("fixture lane ID").0,
            "48"=>codec::strict_decode::<TaskOfferBodyV1>(&raw).expect("fixture task").task_id().expect("fixture task ID").0,
            "54"=>codec::strict_decode::<BidBodyV1>(&raw).expect("fixture bid").bid_id().expect("fixture bid ID").0,
            "56"=>codec::strict_decode::<TaskLeaseBodyV1>(&raw).expect("fixture lease").lease_id().expect("fixture lease ID").0,
            _=>panic!("fixture ID kind"),
        };println!("{}",hex(&id));continue;
    }
    if let Some(value)=line.strip_prefix("terms:"){
        let terms:EscrowTermsV1=codec::strict_decode(&unhex(value)).expect("fixture terms");
        println!("{}",hex(&codec::digest_value("trnm.portable.v2.escrow-terms.v1",&terms).expect("fixture terms digest").0));
        continue;
    }
    let (code,out)=run(&unhex(&line));println!("{code}|{}",hex(&out));
}}

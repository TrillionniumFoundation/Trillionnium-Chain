// Qualification adapter: calls the actual crate and includes its private codec unchanged.
use std::io::{self, BufRead};
use borsh::{BorshSerialize, BorshDeserialize};
pub use trnm_task_kernel::*;
#[path = "ORIGINAL_ERROR_PATH"] mod error;
#[path = "ORIGINAL_CODEC_PATH"] mod codec;
fn put(v:&mut Vec<u8>,n:u64){v.extend_from_slice(&n.to_le_bytes());}
fn reply(code:u64,message:&str,display:&str,payload:&[u8])->Vec<u8>{let mut out=Vec::new();for n in [code,message.len() as u64,display.len() as u64,payload.len() as u64]{put(&mut out,n);}out.extend_from_slice(message.as_bytes());out.extend_from_slice(display.as_bytes());out.extend_from_slice(payload);out}
fn ok(v:Vec<u8>)->Vec<u8>{reply(0,"","",&v)}
fn original_error(e:error::AgentMarketErrorV1)->Vec<u8>{reply(e.code() as u64+1,e.message(),&e.to_string(),&[])}
fn public_error(e:AgentMarketErrorV1)->Vec<u8>{reply(e.code() as u64+1,e.message(),&e.to_string(),&[])}
fn strict<T:BorshDeserialize+BorshSerialize>(s:&[u8])->Result<T,Vec<u8>>{codec::strict_decode(s).map_err(original_error)}
fn canonical<T:BorshDeserialize+BorshSerialize>(s:&[u8])->Vec<u8>{match strict::<T>(s){Ok(v)=>match codec::canonical_bytes(&v){Ok(b)=>ok(b),Err(e)=>original_error(e)},Err(e)=>e}}
fn method<T:BorshDeserialize+BorshSerialize>(s:&[u8],f:impl FnOnce(T)->AgentMarketResultV1<Vec<u8>>)->Vec<u8>{match strict::<T>(s){Ok(v)=>match f(v){Ok(b)=>ok(b),Err(e)=>public_error(e)},Err(e)=>e}}
fn number(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn run(s:&[u8])->(u32,Vec<u8>){
 if s.len()<32 || &s[..8]!=b"TKTV0001" {return (100,vec![])}
 let op=number(s,8);let kind=number(s,16);if op>5||kind>96||number(s,24)!=s.len() as u64-32 {return (100,vec![])}
 let data=&s[32..];
 if op==0 {return (0,match kind {
  0 => canonical::<()>(data),
  1 => canonical::<u8>(data),
  2 => canonical::<u16>(data),
  3 => canonical::<u32>(data),
  4 => canonical::<u64>(data),
  5 => canonical::<u128>(data),
  6 => canonical::<bool>(data),
  7 => canonical::<[u8; 32]>(data),
  8 => canonical::<String>(data),
  9 => canonical::<Hash32V1>(data),
  10 => canonical::<AgentIdV1>(data),
  11 => canonical::<AgentKeyIdV1>(data),
  12 => canonical::<CapabilityIdV1>(data),
  13 => canonical::<SessionKeyGrantIdV1>(data),
  14 => canonical::<NonceLaneIdV1>(data),
  15 => canonical::<TaskIdV1>(data),
  16 => canonical::<BidIdV1>(data),
  17 => canonical::<LeaseIdV1>(data),
  18 => canonical::<EscrowIdV1>(data),
  19 => canonical::<AccountIdV1>(data),
  20 => canonical::<BondIdV1>(data),
  21 => canonical::<ArtifactIdV1>(data),
  22 => canonical::<SettlementIdV1>(data),
  23 => canonical::<CheckpointIdV1>(data),
  24 => canonical::<KernelOperationIdV1>(data),
  25 => canonical::<ProtocolContextV1>(data),
  26 => canonical::<BootstrapAgentV1>(data),
  27 => canonical::<AgentMarketFreshGenesisTrustBundleV1>(data),
  28 => canonical::<CommittedExecutionContextV1>(data),
  29 => canonical::<VerificationProfileRefV1>(data),
  30 => canonical::<OperationScopeV1>(data),
  31 => canonical::<ResourceScopeV1>(data),
  32 => canonical::<AssetLimitV1>(data),
  33 => canonical::<CapabilityGrantBodyV1>(data),
  34 => canonical::<AssetBudgetCounterV1>(data),
  35 => canonical::<CapabilityBudgetStateV1>(data),
  36 => canonical::<CapabilityStateV1>(data),
  37 => canonical::<SessionKeyGrantBodyV1>(data),
  38 => canonical::<SessionKeyGrantStateV1>(data),
  39 => canonical::<NonceLaneKeyBodyV1>(data),
  40 => canonical::<NonceLaneStateV1>(data),
  41 => canonical::<AssetChargeV1>(data),
  42 => canonical::<KernelResourceChargeV1>(data),
  43 => canonical::<AccountBodyV1>(data),
  44 => canonical::<AccountStateV1>(data),
  45 => canonical::<BondBodyV1>(data),
  46 => canonical::<BondStateV1>(data),
  47 => canonical::<EscrowTermsV1>(data),
  48 => canonical::<TaskOfferBodyV1>(data),
  49 => canonical::<TaskCreationOperationBodyV1>(data),
  50 => canonical::<TaskStateV1>(data),
  51 => canonical::<EscrowBodyV1>(data),
  52 => canonical::<EscrowReservationEntryV1>(data),
  53 => canonical::<EscrowStateV1>(data),
  54 => canonical::<BidBodyV1>(data),
  55 => canonical::<BidStateV1>(data),
  56 => canonical::<TaskLeaseBodyV1>(data),
  57 => canonical::<TaskLeaseStateV1>(data),
  58 => canonical::<LeaseProviderAcceptanceBodyV1>(data),
  59 => canonical::<KernelAuthorizationStatementV1>(data),
  60 => canonical::<KernelAuthorizationV1>(data),
  61 => canonical::<KernelTransitionReceiptV1>(data),
  62 => canonical::<TaskArchivePolicyV1>(data),
  63 => canonical::<TerminalTaskArchiveRecordV1>(data),
  64 => canonical::<TaskArchiveSealV1>(data),
  65 => canonical::<TaskArchiveBatchV1>(data),
  66 => canonical::<TaskArchiveInclusionProofV1>(data),
  67 => canonical::<KernelCommandV1>(data),
  68 => canonical::<(CapabilityGrantBodyV1,KernelAuthorizationV1,)>(data),
  69 => canonical::<(SessionKeyGrantBodyV1,KernelAuthorizationV1,)>(data),
  70 => canonical::<(TaskCreationOperationBodyV1,KernelResourceChargeV1,KernelAuthorizationV1,)>(data),
  71 => canonical::<(BidBodyV1,KernelResourceChargeV1,KernelAuthorizationV1,)>(data),
  72 => canonical::<(TaskLeaseBodyV1,u64,u64,u64,KernelResourceChargeV1,KernelAuthorizationV1,)>(data),
  73 => canonical::<(LeaseProviderAcceptanceBodyV1,u64,KernelResourceChargeV1,KernelAuthorizationV1,)>(data),
  74 => canonical::<Vec<u8>>(data),
  75 => canonical::<Option<TaskIdV1>>(data),
  76 => canonical::<Option<Hash32V1>>(data),
  77 => canonical::<Option<VerificationProfileRefV1>>(data),
  78 => canonical::<Option<u8>>(data),
  79 => canonical::<Option<u128>>(data),
  80 => canonical::<Vec<Hash32V1>>(data),
  81 => canonical::<Option<AgentKeyIdV1>>(data),
  82 => canonical::<Option<CapabilityIdV1>>(data),
  83 => canonical::<Vec<OperationScopeV1>>(data),
  84 => canonical::<Vec<ResourceScopeV1>>(data),
  85 => canonical::<Vec<AssetLimitV1>>(data),
  86 => canonical::<Vec<u16>>(data),
  87 => canonical::<Vec<AssetBudgetCounterV1>>(data),
  88 => canonical::<Option<u64>>(data),
  89 => canonical::<Vec<AssetChargeV1>>(data),
  90 => canonical::<Vec<ArtifactIdV1>>(data),
  91 => canonical::<Option<LeaseIdV1>>(data),
  92 => canonical::<Option<CheckpointIdV1>>(data),
  93 => canonical::<Vec<EscrowReservationEntryV1>>(data),
  94 => canonical::<Option<SettlementIdV1>>(data),
  95 => canonical::<Option<SessionKeyGrantIdV1>>(data),
  96 => canonical::<Vec<TerminalTaskArchiveRecordV1>>(data),
  _=>return (100,vec![]),
 })}
 if op==1{return (0,match kind {
  33 => method::<CapabilityGrantBodyV1>(data,|v| v.capability_id().map(|id|id.0.to_vec())),
  37 => method::<SessionKeyGrantBodyV1>(data,|v| v.session_key_grant_id().map(|id|id.0.to_vec())),
  39 => method::<NonceLaneKeyBodyV1>(data,|v| v.nonce_lane_id().map(|id|id.0.to_vec())),
  43 => method::<AccountBodyV1>(data,|v| v.account_id().map(|id|id.0.to_vec())),
  45 => method::<BondBodyV1>(data,|v| v.bond_id().map(|id|id.0.to_vec())),
  48 => method::<TaskOfferBodyV1>(data,|v| v.task_id().map(|id|id.0.to_vec())),
  51 => method::<EscrowBodyV1>(data,|v| v.escrow_id().map(|id|id.0.to_vec())),
  54 => method::<BidBodyV1>(data,|v| v.bid_id().map(|id|id.0.to_vec())),
  56 => method::<TaskLeaseBodyV1>(data,|v| v.lease_id().map(|id|id.0.to_vec())),
  _=>return (100,vec![]),
 })}
 if kind!=67{return (100,vec![])}
 (0,method::<KernelCommandV1>(data,|v|match op {
  2=>Ok(v.operation_kind().to_le_bytes().to_vec()),
  3=>v.operation_digest().map(|x|x.0.to_vec()),
  4=>Ok(borsh::to_vec(v.authorization()).expect("original Borsh serializer")),
  5=>v.operation_id().map(|x|x.0.to_vec()),
  _=>unreachable!(),
 }))
}
fn unhex(s:&str)->Option<Vec<u8>>{if s.len()%2!=0{return None} s.as_bytes().chunks_exact(2).map(|v|Some((v[0] as char).to_digit(16)? as u8*16+(v[1] as char).to_digit(16)? as u8)).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn main(){for line in io::stdin().lock().lines(){let s=unhex(&line.expect("input")).expect("hex fixture");let (code,out)=run(&s);println!("{}|{}",code,hex(&out));}}

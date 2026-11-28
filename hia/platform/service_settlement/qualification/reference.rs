//! Test-only adapter. Every transition, digest, fee and signature decision calls
//! the unchanged original modules. It is never linked into the HIA runtime.
#![forbid(unsafe_code)]
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::io::{Read, Write};

mod types { include!(concat!(env!("TRNM_SETTLEMENT_ORIGINAL"), "/types.rs")); }
mod error { include!(concat!(env!("TRNM_SETTLEMENT_ORIGINAL"), "/error.rs")); }
mod codec { include!(concat!(env!("TRNM_SETTLEMENT_ORIGINAL"), "/codec.rs")); }
mod engine {
    include!(concat!(env!("TRNM_SETTLEMENT_ORIGINAL"), "/engine.rs"));
    pub fn qualification_cumulative(prior: Option<&crate::ConsumptionReceiptStateV1>, usage: &[crate::ResourceUsageV1]) -> crate::ConsumptionSettlementResultV1<Vec<crate::CumulativeResourceUsageV1>> {
        derive_cumulative_usage(prior, usage)
    }
    pub fn qualification_price(trust: &crate::ConsumptionSettlementFreshGenesisTrustBundleV1, usage: &[crate::ResourceUsageV1]) -> crate::ConsumptionSettlementResultV1<u128> {
        price_usage(trust, usage)
    }
}
pub use types::*;
pub use error::{ConsumptionSettlementErrorCodeV1, ConsumptionSettlementErrorV1, ConsumptionSettlementResultV1};
pub use engine::{consumption_receipt_id_v1, consumption_rollup_id_v1, settlement_policy_hash_v1};

fn h(v: u64) -> Hash32V1 { let mut b=[0;32];b[..8].copy_from_slice(&v.to_le_bytes());Hash32V1(b) }
fn bytes<T:BorshSerialize>(v:&T)->Vec<u8>{codec::canonical_bytes(v).unwrap()}
fn hex(raw:&[u8])->String{raw.iter().map(|b|format!("{b:02x}")).collect()}
fn decode<T:BorshDeserialize+BorshSerialize>(raw:&[u8])->Option<T>{codec::strict_decode(raw).ok()}
fn code(error:&ConsumptionSettlementErrorV1)->u64{
    let rows:Vec<Vec<String>>=serde_json::from_str(include_str!(env!("TRNM_SETTLEMENT_ERROR_TABLE"))).unwrap();
    rows.iter().position(|r|r[1]==format!("{:?}",error.code()) && r[2]==error.message()).map(|i|i as u64+1).unwrap_or_else(||panic!("unmapped original error: {error}"))
}
fn u64_at(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
fn word(o:&mut Vec<u8>,v:u64){o.extend(v.to_le_bytes());}
#[derive(Clone)]
struct Owner {trust:ConsumptionSettlementFreshGenesisTrustBundleV1,state:ConsumptionSettlementKernelStateV1,history:Vec<(u64,Vec<u8>,ConsumptionOperationIdV1)>}
#[derive(Clone)]
struct Action{op:u64,slot:u64,height:u64,data:Vec<u8>}
impl Action{
    fn new(trust:&ConsumptionSettlementFreshGenesisTrustBundleV1)->Self{Self{op:0,slot:0,height:0,data:bytes(trust)}}
    fn apply(height:u64,command:&ConsumptionSettlementCommandV1)->Self{Self{op:1,slot:0,height,data:bytes(command)}}
    fn empty(op:u64,slot:u64)->Self{Self{op,slot,height:0,data:vec![]}}
}
fn frame(actions:&[Action])->Vec<u8>{let mut out=b"SSO10001".to_vec();word(&mut out,actions.len() as u64);for a in actions{for v in [a.op,a.slot,a.height,a.data.len() as u64]{word(&mut out,v)}out.extend(&a.data)}out}
fn original(frame:&[u8])->Vec<u8>{
    assert_eq!(&frame[..8],b"SSO10001");let count=u64_at(frame,8);let mut owners:[Option<Owner>;2]=[None,None];let mut out=b"SSR10001".to_vec();word(&mut out,count);word(&mut out,0);word(&mut out,0);let mut p=16;
    for _ in 0..count{
        let op=u64_at(frame,p);let slot=u64_at(frame,p+8) as usize;let height=u64_at(frame,p+16);let n=u64_at(frame,p+24) as usize;let data=&frame[p+32..p+32+n];p+=32+n;
        let mut status=0;let mut body=Vec::new();
        match op{
            0=>{if owners[slot].is_some(){status=104}else if let Some(trust)=decode::<ConsumptionSettlementFreshGenesisTrustBundleV1>(data){match engine::validate_trust_bundle(&trust){Err(e)=>status=code(&e),Ok(())=>{let state=engine::initial_state(&trust);owners[slot]=Some(Owner{trust,state,history:vec![]});}}}else{status=101}},
            1|5=>{if let Some(owner)=owners[slot].as_mut(){if let Some(command)=decode::<ConsumptionSettlementCommandV1>(data){let id=engine::operation_id(&command).unwrap();let replay=if op==5{owner.history.iter().find(|(_,_,old)|*old==id)}else{None};if let Some((oldheight,olddata,_))=replay{if *oldheight!=height || olddata!=data{status=62;}}else{match engine::apply_transition(&owner.trust,&owner.state,height,&command){Err(e)=>status=code(&e),Ok((next,_))=>{owner.state=next;owner.history.push((height,data.to_vec(),id));}}}}else{status=101}}else{status=103}},
            2=>{if owners[slot].is_none(){status=103}},
            3=>{if owners[slot].is_none(){status=103}else if owners[1-slot].is_some(){status=104}else{owners[1-slot]=owners[slot].clone()}},
            4=>{if owners[slot].take().is_none(){status=103}},
            6=>{if let Some(v)=decode::<ConsumptionReceiptBodyV1>(data){body.extend(consumption_receipt_id_v1(&v).unwrap().0)}else{status=101}},
            7=>{if let Some(v)=decode::<ConsumptionRollupBodyV1>(data){body.extend(consumption_rollup_id_v1(&v).unwrap().0)}else{status=101}},
            8=>{if let Some(v)=decode::<SettlementPolicyV1>(data){body.extend(settlement_policy_hash_v1(&v).unwrap().0)}else{status=101}},
            9=>{let v:Vec<u128>=data.chunks_exact(16).map(|x|u128::from_le_bytes(x.try_into().unwrap())).collect();body=bytes(&engine::proportional_fee(v[0],v[1],v[2]));},
            10=>{if let Some(owner)=owners[slot].as_ref(){if let Some(execution)=decode::<ConsumptionCommittedExecutionContextV1>(data){if let Err(e)=engine::validate_execution_static(&owner.trust,&execution){status=code(&e)}}else{status=101}}else{status=103}},
            11=>{if let Some(command)=decode::<ConsumptionSettlementCommandV1>(data){body.extend(engine::operation_id(&command).unwrap().0)}else{status=101}},
            _=>panic!("invalid adapter opcode"),
        }
        if op<6 || op==10{if let Some(owner)=&owners[slot]{body.extend(engine::state_root(&owner.state).unwrap().0);word(&mut body,owner.history.len() as u64);if op==2{body.extend(bytes(&owner.state));}}}
        for v in [op,slot as u64,status,body.len() as u64]{word(&mut out,v)}out.extend(body);
    }
    assert_eq!(p,frame.len());let n=out.len() as u64;out[16..24].copy_from_slice(&n.to_le_bytes());out
}

struct Harness{trust:ConsumptionSettlementFreshGenesisTrustBundleV1,provider:SigningKey,consumer:SigningKey}
impl Harness{
    fn new()->Self{
        let provider=SigningKey::from_bytes(&[7;32]);let consumer=SigningKey::from_bytes(&[9;32]);
        let trust=ConsumptionSettlementFreshGenesisTrustBundleV1{
            schema_version:1,context:ProtocolContextV1{genesis_hash:h(1),chain_id:"trnm-test".into(),protocol_version:1,stack_profile_hash:h(2)},initial_order_height:9,initial_order_block_id:h(900),
            provider:RegisteredBilateralKeyV1{agent_id:AgentIdV1(h(10).0),key_id:AgentKeyIdV1(h(11).0),public_key:provider.verifying_key().to_bytes(),policy_revision:4,key_generation:5},
            consumer:RegisteredBilateralKeyV1{agent_id:AgentIdV1(h(20).0),key_id:AgentKeyIdV1(h(21).0),public_key:consumer.verifying_key().to_bytes(),policy_revision:6,key_generation:7},
            task_id:TaskIdV1(h(30).0),lease_id:LeaseIdV1(h(31).0),attempt:1,result_id:ResultIdV1(h(32).0),result_revision:8,result_status:3,escrow_id:EscrowIdV1(h(33).0),escrow_version:2,asset_id:h(34),escrow_funding:1000,
            provider_account_id:AccountIdV1(h(40).0),consumer_account_id:AccountIdV1(h(41).0),protocol_account_id:AccountIdV1(h(42).0),provider_opening_balance:100,consumer_opening_balance:200,protocol_opening_balance:300,
            prices:vec![ConsumptionPriceV1{resource_class:7,resource_id:b"gpu".to_vec(),meter_id:b"meter".to_vec(),meter_version:1,unit:3,unit_price:3}],accepted_evidence_certificates:vec![AvailabilityCertificateIdV1(h(50).0)],related_party_policy_hash:h(51),
            settlement_policy:SettlementPolicyV1{schema_version:1,policy_revision:3,minimum_rollup_challenge_blocks:2,maximum_rollups:1,protocol_fee_numerator:1,protocol_fee_denominator:10,fee_schedule_hash:h(91)}};
        Self{trust,provider,consumer}
    }
    fn entry(&self,registered:&RegisteredBilateralKeyV1,key:&SigningKey,body_id:Hash32V1,height:u64,domain:&str)->BilateralSignatureEntryV1{
        let statement=BilateralSignatureStatementV1{schema_version:1,body_id,agent_id:registered.agent_id,key_id:registered.key_id,key_role:4,policy_revision:registered.policy_revision,key_generation:registered.key_generation,authority_height:height};
        let digest=codec::digest_value(domain,&statement).unwrap();BilateralSignatureEntryV1{agent_id:registered.agent_id,key_id:registered.key_id,key_role:4,policy_revision:registered.policy_revision,key_generation:registered.key_generation,authority_height:height,signature_scheme:0,signature:key.sign(&digest.0).to_bytes().to_vec()}
    }
    fn sign_receipt(&self,body:ConsumptionReceiptBodyV1)->ConsumptionReceiptV1{let id=Hash32V1::from(consumption_receipt_id_v1(&body).unwrap());let height=body.period_end_height;ConsumptionReceiptV1{provider_signature:self.entry(&self.trust.provider,&self.provider,id,height,"trnm.portable.v2.consumption-receipt-provider-signature.v1"),consumer_signature:self.entry(&self.trust.consumer,&self.consumer,id,height,"trnm.portable.v2.consumption-receipt-consumer-signature.v1"),body}}
    fn receipt(&self,prior:Option<&ConsumptionReceiptStateV1>,height:u64,amount:u128)->ConsumptionReceiptV1{
        let sequence=prior.map_or(1,|p|p.receipt.body.sequence+1);let usage=vec![ResourceUsageV1{resource_class:7,resource_id:b"gpu".to_vec(),meter_id:b"meter".to_vec(),meter_version:1,amount,unit:3,measurement_commitment:h(2000+sequence)}];self.receipt_usage(prior,height,usage)
    }
    fn receipt_usage(&self,prior:Option<&ConsumptionReceiptStateV1>,height:u64,usage:Vec<ResourceUsageV1>)->ConsumptionReceiptV1{
        let cumulative=engine::qualification_cumulative(prior,&usage).expect("fixture cumulative");let charge=engine::qualification_price(&self.trust,&usage).expect("fixture charge");
        let body=ConsumptionReceiptBodyV1{schema_version:1,context:self.trust.context.clone(),provider_id:self.trust.provider.agent_id,consumer_id:self.trust.consumer.agent_id,task_id:self.trust.task_id,lease_id:self.trust.lease_id,attempt:self.trust.attempt,result_id:self.trust.result_id,meter_id:b"meter".to_vec(),meter_version:1,sequence:prior.map_or(1,|p|p.receipt.body.sequence+1),period_start_height:prior.map_or(height,|p|p.receipt.body.period_end_height+1),period_end_height:height,usage,prior_receipt_id:prior.map(|p|p.receipt_id),cumulative_usage_root:codec::digest_value("trnm.portable.v2.consumption-cumulative-usage-root.v1",&cumulative).unwrap(),cumulative_usage:cumulative,cumulative_charge:prior.map_or(0,|p|p.receipt.body.cumulative_charge)+charge,evidence_certificate_id:self.trust.accepted_evidence_certificates[0],related_party_policy_hash:self.trust.related_party_policy_hash};self.sign_receipt(body)
    }
    fn sign_rollup(&self,body:ConsumptionRollupBodyV1,height:u64)->ConsumptionRollupV1{let id=Hash32V1::from(consumption_rollup_id_v1(&body).unwrap());ConsumptionRollupV1{provider_signature:self.entry(&self.trust.provider,&self.provider,id,height,"trnm.portable.v2.consumption-rollup-provider-signature.v1"),consumer_signature:self.entry(&self.trust.consumer,&self.consumer,id,height,"trnm.portable.v2.consumption-rollup-consumer-signature.v1"),body}}
    fn rollup(&self,state:&ConsumptionSettlementKernelStateV1,height:u64)->ConsumptionRollupV1{
        let ids:Vec<_>=state.receipts.iter().map(|r|r.receipt_id).collect();let pairs:Vec<_>=ids.iter().enumerate().map(|(i,id)|(i as u64+1,*id)).collect();let last=&state.receipts.last().unwrap().receipt.body;
        self.sign_rollup(ConsumptionRollupBodyV1{schema_version:1,context:self.trust.context.clone(),provider_id:self.trust.provider.agent_id,consumer_id:self.trust.consumer.agent_id,task_id:self.trust.task_id,lease_id:self.trust.lease_id,attempt:self.trust.attempt,result_id:self.trust.result_id,meter_id:b"meter".to_vec(),meter_version:1,first_sequence:1,last_sequence:ids.len() as u64,receipt_count:ids.len() as u32,receipts_root:codec::digest_value("trnm.portable.v2.rollup-receipts-root.candidate.v1",&pairs).unwrap(),receipt_ids:ids,usage_totals:last.cumulative_usage.iter().map(|r|ResourceUsageV1{resource_class:r.resource_class,resource_id:r.resource_id.clone(),meter_id:r.meter_id.clone(),meter_version:r.meter_version,amount:r.total_amount,unit:r.unit,measurement_commitment:r.accumulator_commitment}).collect(),total_charge:last.cumulative_charge,evidence_certificate_id:last.evidence_certificate_id,escrow_id:self.trust.escrow_id,settlement_policy_hash:settlement_policy_hash_v1(&self.trust.settlement_policy).unwrap(),related_party_policy_hash:self.trust.related_party_policy_hash},height)
    }
    fn settle(&self,state:&ConsumptionSettlementKernelStateV1)->ConsumptionSettlementCommandV1{ConsumptionSettlementCommandV1::Settle{operation:SettlementOperationBodyV1{schema_version:1,context:self.trust.context.clone(),task_id:self.trust.task_id,lease_id:self.trust.lease_id,attempt:self.trust.attempt,result_id:self.trust.result_id,expected_result_revision:state.result.revision,expected_escrow_version:state.escrow.version,expected_rollup_version:state.rollup.as_ref().map_or(0,|r|r.version),settlement_policy_hash:settlement_policy_hash_v1(&self.trust.settlement_policy).unwrap()}}}
}
fn append_state(h:&Harness,state:&mut ConsumptionSettlementKernelStateV1,actions:&mut Vec<Action>,height:u64,command:ConsumptionSettlementCommandV1){*state=engine::apply_transition(&h.trust,state,height,&command).expect("valid fixture prefix").0;actions.push(Action::apply(height,&command));}
fn prefix(h:&Harness)->(Vec<Action>,ConsumptionSettlementKernelStateV1){let mut a=vec![Action::new(&h.trust)];let mut state=engine::initial_state(&h.trust);let r=h.receipt(None,10,100);append_state(h,&mut state,&mut a,10,ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r});let r=h.receipt(state.receipts.last(),11,50);append_state(h,&mut state,&mut a,11,ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r});(a,state)}
fn add(cases:&mut Vec<Value>,name:&str,actions:Vec<Action>){let input=frame(&actions);let output=original(&input);cases.push(json!({"name":name,"input":hex(&input),"expected":hex(&output),"operation_count":actions.len()}));}
fn extended(cases:&mut Vec<Value>){
    let harness=Harness::new();let good=harness.receipt(None,10,100);
    let mutations:Vec<(&str,fn(&mut ConsumptionReceiptBodyV1))>=vec![
        ("schema",|b|b.schema_version=2),("genesis",|b|b.context.genesis_hash.0[0]^=1),("chain",|b|b.context.chain_id.push(' ')),("protocol",|b|b.context.protocol_version+=1),("profile",|b|b.context.stack_profile_hash.0[0]^=1),
        ("provider",|b|b.provider_id.0[0]^=1),("consumer",|b|b.consumer_id.0[0]^=1),("task",|b|b.task_id.0[0]^=1),("lease",|b|b.lease_id.0[0]^=1),("attempt",|b|b.attempt+=1),("result",|b|b.result_id.0[0]^=1),
        ("meter-empty",|b|b.meter_id.clear()),("meter-129",|b|b.meter_id=vec![1;129]),("related",|b|b.related_party_policy_hash.0[0]^=1),("period-end",|b|b.period_end_height+=1),("period-zero",|b|b.period_start_height=0),("period-reversed",|b|b.period_start_height=11),("certificate",|b|b.evidence_certificate_id.0[0]^=1),
        ("usage-empty",|b|b.usage.clear()),("usage-33",|b|b.usage=vec![b.usage[0].clone();33]),("usage-duplicate",|b|b.usage.push(b.usage[0].clone())),("usage-key-duplicate",|b|{let mut v=b.usage[0].clone();v.amount+=1;b.usage.push(v);}),
        ("resource-empty",|b|b.usage[0].resource_id.clear()),("resource-129",|b|b.usage[0].resource_id=vec![1;129]),("usage-meter-empty",|b|b.usage[0].meter_id.clear()),("usage-meter-129",|b|b.usage[0].meter_id=vec![1;129]),("usage-zero",|b|b.usage[0].amount=0),
        ("sequence-zero",|b|b.sequence=0),("sequence-gap",|b|b.sequence=2),("sequence-max",|b|b.sequence=u64::MAX),("first-prior",|b|b.prior_receipt_id=Some(ConsumptionReceiptIdV1(h(55).0))),
        ("cumulative-empty",|b|b.cumulative_usage.clear()),("cumulative-amount",|b|b.cumulative_usage[0].total_amount+=1),("cumulative-key",|b|b.cumulative_usage[0].unit+=1),("cumulative-accumulator",|b|b.cumulative_usage[0].accumulator_commitment.0[0]^=1),("cumulative-root",|b|b.cumulative_usage_root.0[0]^=1),
        ("charge",|b|b.cumulative_charge+=1),("charge-max",|b|b.cumulative_charge=u128::MAX),
        ("context-before-all",|b|{b.schema_version=2;b.period_start_height=0;b.usage.clear();b.sequence=99;}),
        ("period-before-certificate",|b|{b.period_start_height=0;b.evidence_certificate_id.0[0]^=1;b.usage.clear();}),
        ("certificate-before-usage",|b|{b.evidence_certificate_id.0[0]^=1;b.usage.clear();}),
    ];
    for (name,change) in mutations{let mut body=good.body.clone();change(&mut body);let receipt=harness.sign_receipt(body);add(cases,&format!("receipt-{name}"),vec![Action::new(&harness.trust),Action::apply(10,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt}),Action::empty(2,0)]);}
    for which in 0..30{let mut receipt=good.clone();let entry=if which>=15{&mut receipt.consumer_signature}else{&mut receipt.provider_signature};match which%15{0=>entry.agent_id.0[0]^=1,1=>entry.key_id.0[0]^=1,2=>entry.key_role=0,3=>entry.policy_revision+=1,4=>entry.key_generation+=1,5=>entry.authority_height+=1,6=>entry.signature_scheme=1,7=>entry.signature.clear(),8=>{entry.signature.pop();},9=>entry.signature.push(0),10=>entry.signature[0]^=1,11=>entry.signature[..32].fill(0),12=>entry.signature[32..].fill(0),13=>entry.signature[..32].fill(255),_=>entry.signature[32..].fill(255)};add(cases,&format!("signature-entry-{which}"),vec![Action::new(&harness.trust),Action::apply(10,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt}),Action::empty(2,0)]);}
    for which in 0..12{let mut receipt=good.clone();let r=&mut receipt.provider_signature.signature[..32];match which{0=>{r.fill(0);r[0]=1},1=>{r.fill(0);r[0]=1;r[31]=128},2=>r.fill(0),3=>{r.fill(0);r[31]=128},4=>{r.fill(255);r[0]=236;r[31]=127},5=>{r.fill(255);r[0]=236},6=>{r.fill(255);r[0]=237;r[31]=127},7=>{r.fill(255);r[0]=238;r[31]=127},8=>{r.fill(255);r[0]=237},9=>{r.fill(255);r[0]=238},10=>{r.fill(255);r[0]=239;r[31]=127},_=>r.fill(255)};add(cases,&format!("strict-signature-R-{which}"),vec![Action::new(&harness.trust),Action::apply(10,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt})]);}
    for delta in [-1i8,0,1]{let mut receipt=good.clone();let mut l=[0u8;32];l[..16].copy_from_slice(&27742317777372353535851937790883648493u128.to_le_bytes());l[31]=16;l[0]=(l[0] as i16+delta as i16) as u8;receipt.provider_signature.signature[32..].copy_from_slice(&l);add(cases,&format!("strict-signature-S-order-{delta}"),vec![Action::new(&harness.trust),Action::apply(10,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt})]);}
    let mut receipt=good.clone();receipt.provider_signature.signature.clear();receipt.consumer_signature.key_role=0;add(cases,"provider-before-consumer",vec![Action::new(&harness.trust),Action::apply(10,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt})]);
    let (base_actions,state)=prefix(&harness);let second=harness.receipt(state.receipts.last(),12,1);
    for which in 0..4{let mut body=second.body.clone();match which{0=>body.prior_receipt_id=None,1=>body.prior_receipt_id=Some(ConsumptionReceiptIdV1(h(999).0)),2=>body.period_start_height=11,_=>body.sequence=2};let mut a=base_actions.clone();a.push(Action::apply(12,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:harness.sign_receipt(body)}));a.push(Action::empty(2,0));add(cases,&format!("receipt-prior-{which}"),a);}
    let base_rollup=harness.rollup(&state,12);
    for which in 0..31{let mut body=base_rollup.body.clone();match which{0=>body.schema_version=2,1=>body.context.chain_id.push('x'),2=>body.provider_id.0[0]^=1,3=>body.consumer_id.0[0]^=1,4=>body.task_id.0[0]^=1,5=>body.lease_id.0[0]^=1,6=>body.attempt+=1,7=>body.result_id.0[0]^=1,8=>body.escrow_id.0[0]^=1,9=>body.settlement_policy_hash.0[0]^=1,10=>body.evidence_certificate_id.0[0]^=1,11=>body.related_party_policy_hash.0[0]^=1,12=>body.first_sequence=0,13=>body.last_sequence+=1,14=>body.receipt_count+=1,15=>body.receipt_ids.clear(),16=>body.receipt_ids.swap(0,1),17=>body.receipt_ids[0].0[0]^=1,18=>body.receipts_root.0[0]^=1,19=>body.usage_totals.clear(),20=>body.usage_totals[0].amount+=1,21=>body.usage_totals[0].unit+=1,22=>body.usage_totals[0].measurement_commitment.0[0]^=1,23=>body.total_charge+=1,24=>body.meter_id.clear(),25=>body.meter_id=vec![0;129],26=>body.meter_version=u32::MAX,27=>{body.schema_version=2;body.receipt_ids.clear()},28=>{body.receipt_count=0;body.receipts_root.0[0]^=1},29=>{body.receipts_root.0[0]^=1;body.total_charge+=1},_=>{body.total_charge+=1;}};let mut rollup=harness.sign_rollup(body,12);if which==30{rollup.provider_signature.signature.clear();}let mut a=base_actions.clone();a.push(Action::apply(12,&ConsumptionSettlementCommandV1::AdmitRollup{rollup,receipts:state.receipts.iter().map(|r|r.receipt.clone()).collect()}));a.push(Action::empty(2,0));add(cases,&format!("rollup-{which}"),a);}
    for which in 0..5{let mut receipts:Vec<_>=state.receipts.iter().map(|r|r.receipt.clone()).collect();match which{0=>{receipts.pop();},1=>receipts.push(receipts[0].clone()),2=>receipts.swap(0,1),3=>receipts[0].provider_signature.signature[0]^=1,_=>receipts[0].body.usage[0].amount+=1};let mut a=base_actions.clone();a.push(Action::apply(12,&ConsumptionSettlementCommandV1::AdmitRollup{rollup:base_rollup.clone(),receipts}));a.push(Action::empty(2,0));add(cases,&format!("rollup-supplied-{which}"),a);}
    let mut pre=base_actions.clone();let mut rolled=state.clone();append_state(&harness,&mut rolled,&mut pre,12,ConsumptionSettlementCommandV1::AdmitRollup{rollup:base_rollup,receipts:state.receipts.iter().map(|r|r.receipt.clone()).collect()});
    for which in 0..15{let ConsumptionSettlementCommandV1::Settle{mut operation}=harness.settle(&rolled) else{unreachable!()};let mut height=15;match which{0=>operation.schema_version=2,1=>operation.context.chain_id.push('x'),2=>operation.task_id.0[0]^=1,3=>operation.lease_id.0[0]^=1,4=>operation.attempt+=1,5=>operation.result_id.0[0]^=1,6=>operation.expected_result_revision+=1,7=>operation.expected_escrow_version+=1,8=>operation.expected_rollup_version+=1,9=>operation.settlement_policy_hash.0[0]^=1,10=>height=14,11=>height=0,12=>height=u64::MAX,13=>{operation.schema_version=2;height=0},_=>{operation.expected_escrow_version=99;operation.expected_rollup_version=99;height=0}};let mut a=pre.clone();a.push(Action::apply(height,&ConsumptionSettlementCommandV1::Settle{operation}));a.push(Action::empty(2,0));add(cases,&format!("settlement-{which}"),a);}
    let mut a=pre.clone();a.push(Action::apply(20,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:good.clone()}));a.push(Action::apply(20,&ConsumptionSettlementCommandV1::AdmitRollup{rollup:harness.rollup(&state,20),receipts:vec![]}));a.push(Action::empty(2,0));add(cases,"closed-admissions",a);
    add(cases,"settle-without-rollup",vec![Action::new(&harness.trust),Action::apply(0,&harness.settle(&engine::initial_state(&harness.trust))),Action::empty(2,0)]);
    for which in 0..12{let mut custom=Harness::new();match which{0=>custom.trust.escrow_version=u64::MAX,1=>custom.trust.result_revision=u64::MAX,2=>custom.trust.provider_opening_balance=u128::MAX,3=>custom.trust.consumer_opening_balance=u128::MAX,4=>custom.trust.protocol_opening_balance=u128::MAX,5=>{custom.trust.settlement_policy.protocol_fee_numerator=0;custom.trust.protocol_opening_balance=u128::MAX},6=>{custom.trust.settlement_policy.protocol_fee_numerator=10;custom.trust.provider_opening_balance=u128::MAX},7=>{custom.trust.context.chain_id=" \0\u{0085}\u{2028}\u{1f680} ".into();},8=>{custom.trust.provider_account_id=AccountIdV1(h(255).0);custom.trust.consumer_account_id=AccountIdV1(h(256).0);custom.trust.protocol_account_id=AccountIdV1(h(0).0)},9=>{custom.trust.settlement_policy.protocol_fee_numerator=u128::MAX-1;custom.trust.settlement_policy.protocol_fee_denominator=u128::MAX},10=>{custom.trust.settlement_policy.protocol_fee_numerator=u128::MAX;custom.trust.settlement_policy.protocol_fee_denominator=u128::MAX},_=>{custom.trust.provider.policy_revision=u64::MAX;custom.trust.consumer.key_generation=u64::MAX;custom.trust.attempt=u32::MAX;custom.trust.settlement_policy.policy_revision=u32::MAX}};let(mut a,mut s)=prefix(&custom);let rollup=custom.rollup(&s,12);let receipts=s.receipts.iter().map(|r|r.receipt.clone()).collect();append_state(&custom,&mut s,&mut a,12,ConsumptionSettlementCommandV1::AdmitRollup{rollup,receipts});a.push(Action::empty(3,0));a.push(Action::apply(15,&custom.settle(&s)));a.push(Action::empty(2,0));a.push(Action::empty(2,1));add(cases,&format!("economic-lifecycle-{which}"),a);}
    for which in 0..7{let mut custom=Harness::new();custom.trust.escrow_funding=u128::MAX;custom.trust.provider_opening_balance=0;custom.trust.consumer_opening_balance=0;custom.trust.protocol_opening_balance=0;custom.trust.prices[0].unit_price=1;let amount=match which{0=>u128::MAX,1=>1<<127,2=>(1<<64)+1,3=>1,_=>u128::MAX-1};if which==4{custom.trust.settlement_policy.protocol_fee_numerator=0;}if which==5{custom.trust.settlement_policy.protocol_fee_numerator=u128::MAX;custom.trust.settlement_policy.protocol_fee_denominator=u128::MAX;}if which==6{custom.trust.settlement_policy.protocol_fee_numerator=1<<127;custom.trust.settlement_policy.protocol_fee_denominator=u128::MAX;}let mut a=vec![Action::new(&custom.trust)];let mut s=engine::initial_state(&custom.trust);let receipt=custom.receipt(None,10,amount);append_state(&custom,&mut s,&mut a,10,ConsumptionSettlementCommandV1::AdmitReceipt{receipt});let rollup=custom.rollup(&s,11);let receipts=s.receipts.iter().map(|r|r.receipt.clone()).collect();append_state(&custom,&mut s,&mut a,11,ConsumptionSettlementCommandV1::AdmitRollup{rollup,receipts});a.push(Action::apply(14,&custom.settle(&s)));a.push(Action::empty(2,0));add(cases,&format!("u128-full-settlement-{which}"),a);}
    let mut random=vec![];let mut x=0x123456789abcdef00123456789abcdefu128;for i in 0..160{x=x.wrapping_mul(0xda942042e4dd58b5da942042e4dd58b5).wrapping_add(1);let amount=x;x=x.rotate_left(33).wrapping_add(0x9e3779b97f4a7c15);let den=x|1;let num=if i%13==0{den}else{x.rotate_left(71)%den};let mut data=vec![];for v in [amount,num,den]{data.extend(v.to_le_bytes())}random.push(Action{op:9,slot:0,height:0,data});}add(cases,"u128-fee-random-160",random);
    for count in [32usize,128,1024]{let mut custom=Harness::new();custom.trust.escrow_funding=10000;let mut a=vec![Action::new(&custom.trust)];let mut state=engine::initial_state(&custom.trust);for i in 0..count{let receipt=custom.receipt(state.receipts.last(),10+i as u64,1);append_state(&custom,&mut state,&mut a,10+i as u64,ConsumptionSettlementCommandV1::AdmitReceipt{receipt});}if count==1024{let receipt=custom.receipt(state.receipts.last(),10+count as u64,1);a.push(Action::apply(10+count as u64,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt}));}let height=10+count as u64;let rollup=custom.rollup(&state,height);let receipts=state.receipts.iter().map(|r|r.receipt.clone()).collect();append_state(&custom,&mut state,&mut a,height,ConsumptionSettlementCommandV1::AdmitRollup{rollup,receipts});a.push(Action::apply(height+3,&custom.settle(&state)));a.push(Action::empty(2,0));add(cases,&format!("receipt-chain-{count}"),a);}
}
fn final_cases(cases: &mut Vec<Value>) {
    let mut harness = Harness::new();
    let good = harness.receipt(None, 10, 1);
    let (_, state) = prefix(&harness);
    let rollup = harness.rollup(&state, 12);
    let raw_commands = vec![
        ConsumptionSettlementCommandV1::AdmitReceipt { receipt: good.clone() },
        ConsumptionSettlementCommandV1::AdmitRollup { rollup: rollup.clone(), receipts: state.receipts.iter().map(|v|v.receipt.clone()).collect() },
        harness.settle(&state),
    ];
    let mut hashes = vec![];
    let mut receipt_body = good.body.clone(); receipt_body.schema_version = 0; receipt_body.usage.clear();
    hashes.push(Action { op:6, slot:0, height:0, data:bytes(&receipt_body) });
    let mut rollup_body = rollup.body.clone(); rollup_body.meter_id.clear(); rollup_body.total_charge = u128::MAX;
    hashes.push(Action { op:7, slot:0, height:0, data:bytes(&rollup_body) });
    let mut policy = harness.trust.settlement_policy.clone(); policy.protocol_fee_denominator=0; policy.schema_version=0;
    hashes.push(Action { op:8, slot:0, height:0, data:bytes(&policy) });
    for command in &raw_commands { hashes.push(Action {op:11,slot:0,height:0,data:bytes(command)}); }
    add(cases, "value-ids-preserve-invalid-semantic-bytes", hashes);
    for which in 0..11 {
        let mut e=ConsumptionCommittedExecutionContextV1{schema_version:1,context:harness.trust.context.clone(),expected_order_height:9,expected_order_block_id:h(900),order_height:10,order_block_id:h(901)};
        match which { 0=>e.schema_version=2, 1=>e.context.genesis_hash.0[0]^=1, 2=>e.context.chain_id.clear(), 3=>e.context.protocol_version=2,4=>e.context.stack_profile_hash.0[0]^=1,5=>e.order_height=8,6=>e.order_height=9,7=>{e.order_height=9;e.order_block_id=e.expected_order_block_id;},8=>{e.order_height=u64::MAX;e.expected_order_height=u64::MAX;e.order_block_id=e.expected_order_block_id;},9=>{e.expected_order_height=u64::MAX;e.order_height=0;},_=>{e.schema_version=2;e.order_height=0;}}
        add(cases,&format!("execution-static-{which}"),vec![Action::new(&harness.trust),Action{op:10,slot:0,height:0,data:bytes(&e)},Action::empty(2,0)]);
    }
    let execute=ConsumptionCommittedExecutionContextV1{schema_version:1,context:harness.trust.context.clone(),expected_order_height:0,expected_order_block_id:h(0),order_height:u64::MAX,order_block_id:h(1)};
    for (op, original) in [(0,bytes(&harness.trust)),(1,bytes(&raw_commands[0])),(6,bytes(&good.body)),(7,bytes(&rollup.body)),(8,bytes(&harness.trust.settlement_policy)),(10,bytes(&execute)),(11,bytes(&raw_commands[2]))] {
        for which in 0..3 {
            let mut data=original.clone(); match which {0=>data.push(0),1=>{data.pop();},_=>data.clear()}
            let mut actions=if op==0{vec![]}else{vec![Action::new(&harness.trust)]};
            actions.push(Action{op,slot:0,height:if op==1{10}else{0},data});actions.push(Action::empty(2,0));
            add(cases,&format!("borsh-strict-{op}-{which}"),actions);
        }
    }
    for bad in [3u8, 255] { add(cases,&format!("borsh-command-tag-{bad}"),vec![Action::new(&harness.trust),Action{op:1,slot:0,height:10,data:vec![bad]},Action::empty(2,0)]); }
    let mut invalid_utf8=bytes(&harness.trust); invalid_utf8[38]=255;
    add(cases,"borsh-trust-invalid-utf8",vec![Action{op:0,slot:0,height:0,data:invalid_utf8},Action::empty(2,0)]);
    // The table switch is an implementation detail. Every prefix, rejection,
    // clone and retry below is observed through unchanged original operations.
    for cut in [6usize,7,8,9] {
        let mut custom=Harness::new();custom.trust.escrow_funding=10000;
        let mut actions=vec![Action::new(&custom.trust)];let mut state=engine::initial_state(&custom.trust);
        for i in 0..cut { let r=custom.receipt(state.receipts.last(),10+i as u64,1);append_state(&custom,&mut state,&mut actions,10+i as u64,ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r}); }
        actions.push(Action::empty(3,0));
        let r=custom.receipt(state.receipts.last(),10+cut as u64,1);let mut invalid=r.clone();invalid.provider_signature.signature[0]^=1;
        actions.push(Action::apply(10+cut as u64,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:invalid}));actions.push(Action::empty(2,0));actions.push(Action::empty(2,1));
        let mut wrong_charge=r.body.clone();wrong_charge.cumulative_charge+=1;
        actions.push(Action::apply(10+cut as u64,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:custom.sign_receipt(wrong_charge)}));
        actions.push(Action::apply(10+cut as u64,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r.clone()}));
        let mut alternate=Action::apply(10+cut as u64,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r});alternate.slot=1;actions.push(alternate);
        actions.push(Action::empty(2,0));actions.push(Action::empty(2,1));add(cases,&format!("table-boundary-clone-retry-{cut}"),actions);
    }
    for sign in 0..2 { for low in 0..19 {
        let mut custom=Harness::new();let mut key=[255;32];key[0]=237+low;key[31]=127|(sign<<7);custom.trust.provider.public_key=key;
        let r=custom.receipt(None,10,1);
        add(cases,&format!("noncanonical-key-call-{sign}-{low}"),vec![Action::new(&custom.trust),Action::apply(10,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r}),Action::empty(2,0)]);
    }}
    // Original wide arithmetic and error precedence, with no fixture arithmetic
    // silently replacing a failing original helper.
    for which in 0..4 {
        let mut custom=Harness::new();custom.trust.escrow_funding=u128::MAX;
        if which==0 {custom.trust.prices[0].unit_price=u128::MAX;}
        if which==1 {let mut second=custom.trust.prices[0].clone();second.resource_id=b"gpu2".to_vec();custom.trust.prices[0].unit_price=u128::MAX;second.unit_price=u128::MAX;custom.trust.prices.push(second);}
        let mut body=good.body.clone();body.usage[0].amount=if which==0{2}else{1};
        if which==1 {let mut second=body.usage[0].clone();second.resource_id=b"gpu2".to_vec();body.usage.push(second);}
        if which==2 {body.usage[0].resource_id=b"unpriced".to_vec();}
        body.cumulative_usage=engine::qualification_cumulative(None,&body.usage).unwrap();body.cumulative_usage_root=codec::digest_value("trnm.portable.v2.consumption-cumulative-usage-root.v1",&body.cumulative_usage).unwrap();body.cumulative_charge=0;
        let r=custom.sign_receipt(body);add(cases,&format!("price-overflow-or-missing-{which}"),vec![Action::new(&custom.trust),Action::apply(10,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r}),Action::empty(2,0)]);
    }
    for which in 0..2 {
        let mut custom=Harness::new();custom.trust.escrow_funding=u128::MAX;custom.trust.prices[0].unit_price=if which==0{1}else{2};
        let amount=if which==0{u128::MAX}else{u128::MAX/2};let r=custom.receipt(None,10,amount);
        let mut state=engine::initial_state(&custom.trust);let mut actions=vec![Action::new(&custom.trust)];append_state(&custom,&mut state,&mut actions,10,ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r});
        let prior=state.receipts.last().unwrap();let mut body=prior.receipt.body.clone();body.sequence=2;body.prior_receipt_id=Some(prior.receipt_id);body.period_start_height=11;body.period_end_height=11;body.usage[0].amount=1;
        if which==1 {body.cumulative_usage=engine::qualification_cumulative(Some(prior),&body.usage).unwrap();body.cumulative_usage_root=codec::digest_value("trnm.portable.v2.consumption-cumulative-usage-root.v1",&body.cumulative_usage).unwrap();}
        actions.push(Action::apply(11,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:custom.sign_receipt(body)}));actions.push(Action::empty(2,0));add(cases,&format!("cumulative-overflow-{which}"),actions);
    }
    {
        let custom=Harness::new();let mut actions=vec![Action::new(&custom.trust)];let mut state=engine::initial_state(&custom.trust);let r=custom.receipt(None,u64::MAX,1);append_state(&custom,&mut state,&mut actions,u64::MAX,ConsumptionSettlementCommandV1::AdmitReceipt{receipt:r});
        for mismatch in [false,true] {let prior=state.receipts.last().unwrap();let mut body=prior.receipt.body.clone();body.sequence=2;body.period_start_height=1;body.prior_receipt_id=Some(if mismatch{ConsumptionReceiptIdV1(h(999).0)}else{prior.receipt_id});actions.push(Action::apply(u64::MAX,&ConsumptionSettlementCommandV1::AdmitReceipt{receipt:custom.sign_receipt(body)}));}
        let rollup=custom.rollup(&state,u64::MAX);actions.push(Action::apply(u64::MAX,&ConsumptionSettlementCommandV1::AdmitRollup{rollup,receipts:state.receipts.iter().map(|r|r.receipt.clone()).collect()}));actions.push(Action::empty(2,0));add(cases,"height-max-overflow-precedence",actions);
    }
    {
        let mut custom=Harness::new();custom.trust.escrow_funding=100000;
        custom.trust.prices=(0..32u8).map(|i|ConsumptionPriceV1{resource_class:u16::MAX,resource_id:vec![i;128],meter_id:vec![255;128],meter_version:u32::MAX,unit:u16::MAX,unit_price:1}).collect();
        let mut state=engine::initial_state(&custom.trust);let mut actions=vec![Action::new(&custom.trust)];
        for i in 0..128 {
            let usage=custom.trust.prices.iter().map(|p|ResourceUsageV1{resource_class:p.resource_class,resource_id:p.resource_id.clone(),meter_id:p.meter_id.clone(),meter_version:p.meter_version,amount:1,unit:p.unit,measurement_commitment:h(3000+i)}).collect();
            let mut body=custom.receipt_usage(state.receipts.last(),10+i,usage).body;body.meter_id=vec![0;128];body.meter_version=u32::MAX;
            append_state(&custom,&mut state,&mut actions,10+i,ConsumptionSettlementCommandV1::AdmitReceipt{receipt:custom.sign_receipt(body)});
        }
        assert!(bytes(&state).len()>2_098_176,"actual original state must exceed the old helper bound");
        actions.push(Action::empty(2,0));actions.push(Action::empty(3,0));
        let rollup=custom.rollup(&state,138);let command=ConsumptionSettlementCommandV1::AdmitRollup{rollup,receipts:state.receipts.iter().map(|r|r.receipt.clone()).collect()};
        assert!(bytes(&command).len()>2_098_176,"actual original command must exceed the old helper bound");
        append_state(&custom,&mut state,&mut actions,138,command);actions.push(Action::apply(141,&custom.settle(&state)));actions.push(Action::empty(2,0));actions.push(Action::empty(2,1));
        add(cases,"wide-128-receipts-32-usage-state-over-2mib",actions);
    }
    // Keep a raw method body that can be reused for allocator-failure retries.
    harness.trust.escrow_funding=10000;
}

fn fixtures()->Value{
    let mut cases=vec![];let h=Harness::new();
    add(&mut cases,"empty-lifecycle",vec![Action::empty(2,0),Action::empty(3,0),Action::empty(4,0)]);
    let(mut a,mut state)=prefix(&h);a.push(Action::empty(2,0));a.push(Action::empty(3,0));let rollup=h.rollup(&state,12);let cmd=ConsumptionSettlementCommandV1::AdmitRollup{rollup,receipts:state.receipts.iter().map(|r|r.receipt.clone()).collect()};append_state(&h,&mut state,&mut a,12,cmd);a.push(Action::apply(14,&h.settle(&state)));a.push(Action::empty(2,1));let settle=h.settle(&state);a.push(Action::apply(15,&settle));a.push(Action::apply(15,&settle));a.push(Action{op:5,slot:0,height:15,data:bytes(&settle)});a.push(Action{op:5,slot:0,height:16,data:bytes(&settle)});a.push(Action::empty(2,0));a.push(Action::empty(4,0));a.push(Action::empty(2,1));add(&mut cases,"complete-clone-replay-lifecycle",a);
    for which in 0..22{let mut trust=h.trust.clone();match which{0=>trust.schema_version=2,1=>trust.context.protocol_version=2,2=>trust.context.chain_id.clear(),3=>trust.provider.agent_id=trust.consumer.agent_id,4=>trust.provider.key_id=trust.consumer.key_id,5=>trust.provider.public_key=trust.consumer.public_key,6=>trust.provider.public_key=[0;32],7=>trust.consumer.public_key=[0;32],8=>trust.consumer_account_id=trust.provider_account_id,9=>trust.escrow_funding=0,10=>trust.result_status=2,11=>trust.settlement_policy.schema_version=2,12=>trust.settlement_policy.maximum_rollups=2,13=>trust.settlement_policy.minimum_rollup_challenge_blocks=0,14=>trust.settlement_policy.protocol_fee_denominator=0,15=>trust.settlement_policy.protocol_fee_numerator=11,16=>trust.prices.clear(),17=>trust.prices.push(trust.prices[0].clone()),18=>trust.prices[0].resource_id.clear(),19=>trust.prices[0].unit_price=0,20=>trust.accepted_evidence_certificates.clear(),_=>trust.accepted_evidence_certificates.push(trust.accepted_evidence_certificates[0])};add(&mut cases,&format!("trust-error-{which}"),vec![Action::new(&trust),Action::empty(2,0)]);}
    for sign in 0..2{for low in 0..19{let mut trust=h.trust.clone();let mut key=[255;32];key[0]=237+low;key[31]=127|(sign<<7);trust.provider.public_key=key;add(&mut cases,&format!("noncanonical-key-{sign}-{low}"),vec![Action::new(&trust),Action::empty(2,0)]);}}
    for sign in 0..2{for low in [1,236]{let mut trust=h.trust.clone();let mut key=if low==1{[0;32]}else{[255;32]};key[0]=low;key[31]=(if low==1{0}else{127})|(sign<<7);trust.provider.public_key=key;add(&mut cases,&format!("zero-x-key-{sign}-{low}"),vec![Action::new(&trust)]);}}
    let mut fee=vec![];for (amount,num,den) in [(0,0,1),(1,1,1),(10,1,3),(u128::MAX,u128::MAX,u128::MAX),(u128::MAX,1<<127,u128::MAX),(u128::MAX,1,2),(1<<127,1<<127,u128::MAX),(1,2,1),(1,1,0)]{let mut data=vec![];for v in [amount,num,den]{data.extend(v.to_le_bytes())}fee.push(Action{op:9,slot:0,height:0,data});}add(&mut cases,"u128-fee-extremes",fee);
    extended(&mut cases);
    final_cases(&mut cases);
    json!({"schema":"trnm.service-settlement.original-engine-fixtures.v1","fixtures":cases})
}
fn main(){let mode=std::env::args().nth(1).unwrap_or_default();if mode=="generate"{println!("{}",fixtures());}else if mode=="run"{let mut input=vec![];std::io::stdin().read_to_end(&mut input).unwrap();std::io::stdout().write_all(&original(&input)).unwrap();}else{panic!("expected generate or run")}}

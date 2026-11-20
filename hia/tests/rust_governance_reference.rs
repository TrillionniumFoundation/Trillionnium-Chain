//! Complete public-API adapter for the unchanged original GovernanceGuard.
//! Serialization supplies no business rules: every transition and event comes
//! from the actual crate, including clone, permission drift and log consumption.
use std::collections::HashMap;
use std::io::{Read,Write};
use trnm_governance_guard as governance;
use governance::GovernanceGuard;
#[path="rust_governance_wire.rs"] mod wire;
use wire::{word,read,status,proposal,bridge,raw_event,normalized_event};

fn main() {
    let mut raw=Vec::new();std::io::stdin().read_to_end(&mut raw).unwrap();
    assert!(raw.len()>=32 && &raw[..8]==b"GVS10001");
    assert_eq!(read(&raw,16),0);assert_eq!(read(&raw,24),0);
    let count=read(&raw,8);let mut cursor=32;
    let mut owners:HashMap<u64,GovernanceGuard>=HashMap::new();let mut serial=1;
    let mut output=Vec::from(&b"GVR10001"[..]);word(&mut output,count);word(&mut output,0);word(&mut output,0);
    for _ in 0..count {
        assert!(raw.len()-cursor>=96);
        let op=read(&raw,cursor);let handle=read(&raw,cursor+8);let id=read(&raw,cursor+16);
        let eta=read(&raw,cursor+24);let now=read(&raw,cursor+32);let flags=read(&raw,cursor+40);
        let lengths:[usize;5]=std::array::from_fn(|i|read(&raw,cursor+48+i*8) as usize);
        assert!(op<=17 && read(&raw,cursor+88)==0);cursor+=96;
        let mut fields=["";5];
        for i in 0..5 {fields[i]=std::str::from_utf8(&raw[cursor..cursor+lengths[i]]).unwrap();cursor+=lengths[i];}
        let [caller,a,b,c,d]=fields;let mut payload=Vec::new();
        let result=if op==0 {
            assert_eq!(handle,0);owners.insert(serial,GovernanceGuard::new(caller,a,eta));
            word(&mut payload,serial);serial+=1;0
        } else if !owners.contains_key(&handle) {64}
        else if op==16 {
            let clone=owners.get(&handle).unwrap().clone();owners.insert(serial,clone);
            word(&mut payload,serial);serial+=1;0
        } else if op==17 {owners.remove(&handle).unwrap();0}
        else {
            let gov=owners.get_mut(&handle).unwrap();
            match op {
                1 => status(gov.set_role(caller,a,flags&1!=0,flags&2!=0)),
                2 => status(gov.set_guardian(caller,a,flags!=0)),
                3 => status(gov.set_allowed_param_key(caller,a,flags!=0)),
                4 => match gov.propose(caller,a,b,c,eta,d,now) {
                    Ok(id)=>{word(&mut payload,id);0},Err(e)=>status(Err(e))},
                5 => status(gov.queue(caller,id)),
                6 => status(gov.execute(caller,id,now)),
                7 => status(gov.cancel(caller,id)),
                8 => status(gov.emergency_pause(caller,a)),
                9 => match gov.schedule_unpause(caller,eta,a,now) {
                    Ok(id)=>{word(&mut payload,id);0},Err(e)=>status(Err(e))},
                10 => status(gov.execute_unpause(caller,id,now)),
                11 => {proposal(&mut payload,gov.proposal(id));0},
                12 => {bridge(&mut payload,gov.bridge_state());0},
                13|14 => {
                    let events=if op==14 {gov.consume_audit_log()} else {gov.audit_log().to_vec()};
                    word(&mut payload,events.len() as u64);
                    for event in &events {raw_event(&mut payload,event);}0
                },
                15 => {
                    let events=gov.normalized_audit_log();word(&mut payload,events.len() as u64);
                    for event in &events {normalized_event(&mut payload,event);}0
                },
                _=>unreachable!(),
            }
        };
        for v in [op,handle,result,payload.len() as u64]{word(&mut output,v);}
        output.extend_from_slice(&payload);
    }
    assert_eq!(cursor,raw.len());let length=output.len() as u64;
    output[16..24].copy_from_slice(&length.to_le_bytes());
    std::io::stdout().write_all(&output).unwrap();
}

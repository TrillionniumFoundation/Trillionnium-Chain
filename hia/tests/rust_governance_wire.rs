//! Exact observation serialization shared by two independent original-Rust adapters.
use trnm_audit_events::AuditEvent;
use crate::governance::{Error,GovernanceBridgeState,GovernanceEvent,Proposal,ProposalKind,ProposalStatus};
pub fn word(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
pub fn read(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
pub fn status(result: Result<(), Error>) -> u64 {
    match result {
        Ok(()) => 0,
        Err(Error::Unauthorized) => 1, Err(Error::InvalidEta) => 2,
        Err(Error::InvalidParamKey) => 3, Err(Error::ProposalNotFound) => 4,
        Err(Error::NotQueued) => 5, Err(Error::NotReady) => 6,
        Err(Error::AlreadyFinalized) => 7, Err(Error::WrongProposalKind) => 8,
        Err(Error::SelfExecutionForbidden) => 9, Err(Error::PauseNotActive) => 10,
        Err(Error::GuardianExecutorConflict) => 11, Err(Error::WrongProposer) => 12,
        Err(Error::CurrentValueMismatch) => 13, Err(Error::ParamVersionMismatch) => 14,
        Err(Error::PauseRestoreAlreadyScheduled) => 15, Err(Error::CounterExhausted) => 16,
    }
}
fn kind(value: &ProposalKind) -> u64 {
    match value { ProposalKind::ParamChange => 0, ProposalKind::EmergencyUnpause => 1 }
}
pub fn proposal(out: &mut Vec<u8>, item: Option<&Proposal>) {
    let Some(p) = item else {word(out,0); return;};
    for v in [1,p.id,kind(&p.kind),match p.status {
        ProposalStatus::Pending => 0, ProposalStatus::Queued => 1,
        ProposalStatus::Executed => 2, ProposalStatus::Cancelled => 3},p.eta,
        u64::from(p.base_version.is_some()),p.base_version.unwrap_or(0),
        u64::from(p.executed_at.is_some()),p.executed_at.unwrap_or(0),
        u64::from(p.executor.is_some())] {word(out,v);}
    let fields=[p.proposer.as_str(),p.executor.as_deref().unwrap_or(""),p.param_key.as_str(),
        p.old_value.as_str(),p.new_value.as_str(),p.reason_hash.as_str()];
    for s in fields {word(out,s.len() as u64);}
    for s in fields {out.extend_from_slice(s.as_bytes());}
}
pub fn bridge(out: &mut Vec<u8>, state: &GovernanceBridgeState) {
    word(out,u64::from(state.emergency_paused));
    word(out,state.gov_params.len() as u64);word(out,state.param_versions.len() as u64);
    let mut params:Vec<_>=state.gov_params.iter().collect();params.sort_by(|a,b|a.0.cmp(b.0));
    let mut versions:Vec<_>=state.param_versions.iter().collect();versions.sort_by(|a,b|a.0.cmp(b.0));
    for (key,value) in params {
        word(out,key.len() as u64);word(out,value.len() as u64);
        out.extend_from_slice(key.as_bytes());out.extend_from_slice(value.as_bytes());
    }
    for (key,value) in versions {word(out,key.len() as u64);word(out,*value);out.extend_from_slice(key.as_bytes());}
}
pub fn raw_event(out: &mut Vec<u8>, event: &GovernanceEvent) {
    let mut words=[0u64;18];let mut fields=["";5];
    match event {
        GovernanceEvent::ProposalProposed{proposal_id,proposer,kind: k,param_key,eta} => {
            words[0]=0;words[1]=*proposal_id;words[2]=kind(k);words[3]=u64::from(param_key.is_some());
            words[10]=*eta;fields[0]=proposer;fields[1]=param_key.as_deref().unwrap_or("");
        },
        GovernanceEvent::ProposalQueued{proposal_id,actor} => {words[0]=1;words[1]=*proposal_id;fields[0]=actor;},
        GovernanceEvent::ProposalExecuted{proposal_id,actor,kind: k,param_key,old_value,new_value,version_before,version_after} => {
            words[0]=2;words[1]=*proposal_id;words[2]=kind(k);words[3]=u64::from(param_key.is_some());
            words[4]=u64::from(old_value.is_some());words[5]=u64::from(new_value.is_some());
            words[6]=u64::from(version_before.is_some());words[7]=version_before.unwrap_or(0);
            words[8]=u64::from(version_after.is_some());words[9]=version_after.unwrap_or(0);
            fields[0]=actor;fields[1]=param_key.as_deref().unwrap_or("");
            fields[2]=old_value.as_deref().unwrap_or("");fields[3]=new_value.as_deref().unwrap_or("");
        },
        GovernanceEvent::ProposalCancelled{proposal_id,actor} => {words[0]=3;words[1]=*proposal_id;fields[0]=actor;},
        GovernanceEvent::PauseSet{actor,previous_state,next_state,reason_hash} => {
            words[0]=4;words[11]=u64::from(*previous_state);words[12]=u64::from(*next_state);
            fields[0]=actor;fields[4]=reason_hash;
        },
        GovernanceEvent::PauseRestoreScheduled{proposal_id,proposer,eta,reason_hash} => {
            words[0]=5;words[1]=*proposal_id;words[10]=*eta;fields[0]=proposer;fields[4]=reason_hash;
        },
        GovernanceEvent::PauseRestoreExecuted{proposal_id,actor,reason_hash} => {
            words[0]=6;words[1]=*proposal_id;fields[0]=actor;fields[4]=reason_hash;
        },
        GovernanceEvent::AuditLogCleared => {words[0]=7;},
    }
    for (i,s) in fields.iter().enumerate(){words[13+i]=s.len() as u64;}
    for v in words {word(out,v);}
    for s in fields {out.extend_from_slice(s.as_bytes());}
}
pub fn normalized_event(out: &mut Vec<u8>, event: &AuditEvent) {
    let fields=[Some(event.source),Some(event.event_type),event.actor.as_deref(),
        event.object_id.as_deref(),event.related_id.as_deref(),event.reason.as_deref(),event.note.as_deref()];
    let size=96+fields.iter().map(|s|s.unwrap_or("").len()).sum::<usize>();
    let mut mask=0u64;
    for (bit,present) in [(0,event.actor.is_some()),(1,event.object_id.is_some()),(2,event.related_id.is_some()),
        (3,event.amount.is_some()),(4,event.reason.is_some()),(5,event.note.is_some())] {
        if present {mask|=1<<bit;}
    }
    out.extend_from_slice(b"NAER0001");word(out,size as u64);word(out,mask);
    out.extend_from_slice(&event.amount.unwrap_or(0).to_le_bytes());
    for field in fields {word(out,field.unwrap_or("").len() as u64);}
    for field in fields {out.extend_from_slice(field.unwrap_or("").as_bytes());}
}

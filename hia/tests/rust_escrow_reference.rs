//! Binary qualification adapter for the complete unchanged original crate.
//! Only public original methods decide balances, locks, errors, and events.
use std::collections::HashMap;
use std::io::{Read, Write};
use trnm_audit_events::AuditEvent;
use trnm_escrow_vault::{LockStatus, SettlementVault, VaultError, VaultEvent};

fn word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn amount(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn read(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn status(result: Result<(), VaultError>) -> u64 {
    match result {
        Ok(()) => 0,
        Err(VaultError::Unauthorized) => 1,
        Err(VaultError::Paused) => 2,
        Err(VaultError::AlreadyPaused) => 3,
        Err(VaultError::NotPaused) => 4,
        Err(VaultError::InvalidAmount) => 5,
        Err(VaultError::InvalidBeneficiary) => 6,
        Err(VaultError::InvalidRequestId) => 7,
        Err(VaultError::InsufficientBalance) => 8,
        Err(VaultError::DuplicateRequest) => 9,
        Err(VaultError::RequestNotFound) => 10,
        Err(VaultError::InvalidStateTransition) => 11,
        Err(VaultError::BalanceOverflow) => 12,
    }
}
fn raw_event(out: &mut Vec<u8>, event: &VaultEvent) {
    let (kind, value, caller, a, b, c): (u64, u128, &str, &str, &str, &str) = match event {
        VaultEvent::Deposited { caller, account, amount } => (1, *amount, caller, account, "", ""),
        VaultEvent::Locked { caller, request_id, account, amount } => (2, *amount, caller, request_id, account, ""),
        VaultEvent::Released { caller, request_id, account, amount } => (3, *amount, caller, request_id, account, ""),
        VaultEvent::Slashed { caller, request_id, account, beneficiary, amount } => (4, *amount, caller, request_id, account, beneficiary),
        VaultEvent::Transferred { caller, from, to, amount } => (5, *amount, caller, from, to, ""),
        VaultEvent::Paused { caller } => (6, 0, caller, "", "", ""),
        VaultEvent::Unpaused { caller } => (7, 0, caller, "", "", ""),
    };
    word(out, kind);
    amount(out, value);
    for field in [caller, a, b, c] { word(out, field.len() as u64); }
    for field in [caller, a, b, c] { out.extend_from_slice(field.as_bytes()); }
}
fn normalized_event(out: &mut Vec<u8>, event: &AuditEvent) {
    let fields = [Some(event.source), Some(event.event_type), event.actor.as_deref(),
        event.object_id.as_deref(), event.related_id.as_deref(), event.reason.as_deref(), event.note.as_deref()];
    let size = 96 + fields.iter().map(|s| s.unwrap_or("").len()).sum::<usize>();
    let mut mask = 0u64;
    for (bit, present) in [(0, event.actor.is_some()), (1, event.object_id.is_some()),
        (2, event.related_id.is_some()), (3, event.amount.is_some()), (4, event.reason.is_some()),
        (5, event.note.is_some())] {
        if present { mask |= 1u64 << bit; }
    }
    out.extend_from_slice(b"NAER0001");
    word(out, size as u64);
    word(out, mask);
    amount(out, event.amount.unwrap_or(0));
    for field in fields { word(out, field.unwrap_or("").len() as u64); }
    for field in fields { out.extend_from_slice(field.unwrap_or("").as_bytes()); }
}

fn main() {
    let mut raw = Vec::new();
    std::io::stdin().read_to_end(&mut raw).unwrap();
    assert!(raw.len() >= 32 && &raw[..8] == b"VES10001");
    assert_eq!(read(&raw, 16), 0);
    assert_eq!(read(&raw, 24), 0);
    let count = read(&raw, 8);
    let mut cursor = 32usize;
    let mut owners: HashMap<u64, SettlementVault> = HashMap::new();
    let mut serial = 1u64;
    let mut output = Vec::from(&b"VER10001"[..]);
    word(&mut output, count);
    word(&mut output, 0);
    word(&mut output, 0);
    for _ in 0..count {
        assert!(raw.len() - cursor >= 64);
        let op = read(&raw, cursor);
        let handle = read(&raw, cursor + 8);
        let value = u128::from_le_bytes(raw[cursor+16..cursor+32].try_into().unwrap());
        let lengths = [read(&raw,cursor+32) as usize, read(&raw,cursor+40) as usize, read(&raw,cursor+48) as usize];
        assert!(op <= 16 && read(&raw, cursor+56) == 0);
        cursor += 64;
        let mut fields = ["", "", ""];
        for i in 0..3 {
            fields[i] = std::str::from_utf8(&raw[cursor..cursor+lengths[i]]).unwrap();
            cursor += lengths[i];
        }
        let [caller, a, b] = fields;
        let mut payload = Vec::new();
        let result = if op == 0 {
            assert_eq!(handle,0);
            owners.insert(serial, SettlementVault::new(caller));
            word(&mut payload, serial);
            serial += 1;
            0
        } else if !owners.contains_key(&handle) {
            64
        } else if op == 15 {
            let copy = owners.get(&handle).unwrap().clone();
            owners.insert(serial, copy);
            word(&mut payload, serial);
            serial += 1;
            0
        } else if op == 16 {
            owners.remove(&handle).unwrap();
            0
        } else {
            let vault = owners.get_mut(&handle).unwrap();
            match op {
                1 => status(vault.deposit(caller,a,value)),
                2 => status(vault.lock(caller,a,b,value)),
                3 => status(vault.release(caller,a)),
                4 => status(vault.slash(caller,a,b)),
                5 => status(vault.transfer(caller,a,b,value)),
                6 => status(vault.pause(caller)),
                7 => status(vault.unpause(caller)),
                8 => { payload.extend_from_slice(vault.owner().as_bytes()); 0 },
                9 => { word(&mut payload,u64::from(vault.is_paused())); 0 },
                10 => { amount(&mut payload,vault.balance_of(a)); 0 },
                11 => {
                    if let Some(lock) = vault.lock_record(a) {
                        word(&mut payload,1);
                        word(&mut payload,match lock.status { LockStatus::Locked => 0, LockStatus::Released => 1, LockStatus::Slashed => 2 });
                        amount(&mut payload,lock.amount);
                        word(&mut payload,lock.account.len() as u64);
                        payload.extend_from_slice(lock.account.as_bytes());
                    } else { word(&mut payload,0); }
                    0
                },
                12 | 13 => {
                    if op == 12 {
                        word(&mut payload,vault.audit_log().len() as u64);
                        for event in vault.audit_log() {raw_event(&mut payload,event);}
                    } else {
                        let log = vault.consume_audit_log();
                        word(&mut payload,log.len() as u64);
                        for event in &log {raw_event(&mut payload,event);}
                    }
                    0
                },
                14 => {
                    let log = vault.normalized_audit_log();
                    word(&mut payload,log.len() as u64);
                    for event in &log {normalized_event(&mut payload,event);}
                    0
                },
                _ => unreachable!(),
            }
        };
        word(&mut output,op);
        word(&mut output,handle);
        word(&mut output,result);
        word(&mut output,payload.len() as u64);
        output.extend_from_slice(&payload);
    }
    assert_eq!(cursor,raw.len());
    let length = output.len() as u64;
    output[16..24].copy_from_slice(&length.to_le_bytes());
    std::io::stdout().write_all(&output).unwrap();
}

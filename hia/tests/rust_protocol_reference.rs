//! Test-only direct use of the original, unchanged protocol crate.
use std::io::{self, BufRead};
use trnm_protocol::pon_wire::{
    state_root_from_entries, Envelope, Header, StateRootInputError, WireError,
};

fn wire_code(error: WireError) -> u32 {
    match error {
        WireError::Length => 1,
        WireError::Version => 2,
        WireError::Noncanonical => 3,
        WireError::Limit => 4,
        WireError::KeyCollision => 5,
    }
}

// This only decodes the local HIA test descriptor. The complete tree operation
// below is the original protocol implementation, not a copied hash algorithm.
fn state_reference(raw: &[u8]) -> Result<[u8; 32], WireError> {
    if raw.len() < 8 {
        return Err(WireError::Length);
    }
    if &raw[..4] != b"SRV1" {
        return Err(WireError::Version);
    }
    let count = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
    if count > 65_536 {
        return Err(WireError::Limit);
    }
    let mut position: usize = 8;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let header = raw.get(position..position + 8).ok_or(WireError::Length)?;
        let key = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let value = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        if key > 160 || value > 4096 {
            return Err(WireError::Limit);
        }
        position += 8;
        let end = position + key + value;
        let bytes = raw.get(position..end).ok_or(WireError::Length)?;
        rows.push((bytes[..key].to_vec(), bytes[key..].to_vec()));
        position = end;
    }
    if position != raw.len() {
        return Err(WireError::Length);
    }
    match state_root_from_entries(rows.into_iter().map(Ok::<_, std::convert::Infallible>)) {
        Ok(root) => Ok(root),
        Err(StateRootInputError::Wire(error)) => Err(error),
        Err(StateRootInputError::Input(impossible)) => match impossible {},
    }
}

fn pnh1_encode_reference(raw: &[u8]) -> Result<Vec<u8>, WireError> {
    if raw.len() != 312 {
        return Err(WireError::Length);
    }
    let hash = |i: usize| raw[i * 32..(i + 1) * 32].try_into().unwrap();
    let scalar = |i: usize| {
        let start = 288 + i * 8;
        u64::from_le_bytes(raw[start..start + 8].try_into().unwrap())
    };
    Ok(Header {
        network: hash(0),
        parameters: hash(1),
        parent: hash(2),
        height: scalar(0),
        timestamp: scalar(1),
        target: hash(3),
        miner: hash(4),
        transactions: hash(5),
        state: hash(6),
        receipts: hash(7),
        work_task: hash(8),
        nonce: scalar(2),
    }
    .encode())
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("test input read");
        let state_request = line.strip_prefix("S ");
        let header_request = line.strip_prefix("H ");
        let encoded = state_request.or(header_request).unwrap_or(&line);
        let raw = if encoded == "-" {
            Vec::new()
        } else {
            assert!(encoded.len() % 2 == 0);
            (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).expect("test hex"))
                .collect()
        };
        if header_request.is_some() {
            match pnh1_encode_reference(&raw) {
                Ok(bytes) => {
                    let text = bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                    println!("0 {text}");
                }
                Err(error) => println!("{} -", wire_code(error)),
            }
            continue;
        }
        if state_request.is_some() {
            match state_reference(&raw) {
                Ok(root) => {
                    let text = root
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                    println!("0 {text}");
                }
                Err(error) => println!("{} -", wire_code(error)),
            }
            continue;
        }
        let code = match Envelope::decode(&raw) {
            Ok(value) => {
                assert_eq!(value.encode().expect("decoded value must re-encode"), raw);
                0
            }
            Err(error) => wire_code(error),
        };
        println!("{code}");
    }
}

//! The public CPS1 value API only, without a store, owner, or scheduler.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellPeriodicSnapshotPolicyV1};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    let mut raw = input.as_slice();
    while !raw.is_empty() {
        let size = u16::from_le_bytes(raw[..2].try_into().unwrap()) as usize;
        let policy = &raw[2..2 + size];
        raw = &raw[2 + size..];
        match CellPeriodicSnapshotPolicyV1::decode(policy) {
            Ok(v) => {
                v.validate().unwrap();
                let encoded = v.encode().unwrap();
                assert_eq!(encoded.len(), 152);
                output.write_all(&[0])?;
                output.write_all(&encoded)?;
                output.write_all(&v.commitment().unwrap())?;
            }
            Err(CellErrorV1::Invalid(reason)) => {
                let status = match reason {
                    "periodic snapshot policy namespace/length" => 100,
                    "periodic snapshot identity" => 101,
                    "periodic snapshot finite cadence" => 102,
                    "periodic snapshot cadence overflow" => 103,
                    _ => panic!("unexpected CPS1 validation error: {reason}"),
                };
                output.write_all(&[status])?;
                output.write_all(&[0; 184])?;
            }
            Err(e) => panic!("unexpected CPS1 error: {e}"),
        };
    }
    Ok(())
}

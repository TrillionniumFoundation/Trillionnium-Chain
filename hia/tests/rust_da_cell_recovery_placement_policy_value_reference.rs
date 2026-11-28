//! Locked original immutable typed construction; no placement actions.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{
    CellErrorV1, CellRecoveryFaultAxisV1, CellRecoveryFaultPolicyV1,
    CellRecoveryPlacementPolicyV1, CellRecoveryProviderPinV1,
};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    let mut rows = input.as_slice();
    while !rows.is_empty() {
        let len = u32::from_le_bytes(rows[..4].try_into().unwrap()) as usize;
        let (body, rest) = rows[4..].split_at(len);
        rows = rest;
        assert_eq!(&body[..8], b"NRPP0001");
        let n = usize::from(u16::from_be_bytes(body[8..10].try_into().unwrap()));
        let providers = body[10..10+n*160].chunks_exact(160).map(|pin| {
            CellRecoveryProviderPinV1 {
                provider_id: pin[..32].try_into().unwrap(),
                operator: pin[32..64].try_into().unwrap(),
                administrator: pin[64..96].try_into().unwrap(),
                failure_domain: pin[96..128].try_into().unwrap(),
                domain_evidence: pin[128..160].try_into().unwrap(),
            }
        }).collect();
        let fault = &body[10+n*160..];
        assert_eq!(fault.len(), 2 + usize::from(fault[1]));
        let axes = fault[2..].iter().map(|id| match id {
            1 => CellRecoveryFaultAxisV1::Operator,
            2 => CellRecoveryFaultAxisV1::Administrator,
            3 => CellRecoveryFaultAxisV1::FailureDomain,
            _ => panic!("oracle fixture axis is not an original typed enum"),
        }).collect();
        let policy = CellRecoveryFaultPolicyV1 { axes, maximum_lost_events: fault[0] };
        match CellRecoveryPlacementPolicyV1::new(providers, policy) {
            Ok(value) => {
                output.write_all(&[0])?;
                output.write_all(&value.commitment())?;
            }
            Err(CellErrorV1::Invalid(reason)) => {
                let status = match reason {
                    "recovery placement bounds" => 20,
                    "recovery fault axes" => 21,
                    "recovery provider order/duplicates" => 22,
                    "recovery provider identity" => 23,
                    _ => panic!("unexpected original policy refusal: {reason}"),
                };
                output.write_all(&[status])?;
                output.write_all(&[0;64])?;
            }
            Err(other) => panic!("unexpected original policy error: {other:?}"),
        }
    }
    Ok(())
}

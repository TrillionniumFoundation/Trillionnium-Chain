//! Pure declared fixture evaluation; no service, trust decision or observations.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{
    CellErrorV1, CellRecoveryFaultAxisV1, CellRecoveryFaultPolicyV1, CellRecoveryPartV1,
    CellRecoveryPlacementV1, CellRecoveryProviderPinV1, evaluate_recovery_placement,
};

fn read<const N: usize>(s: &[u8], offset: usize) -> [u8; N] {
    s[offset..offset+N].try_into().unwrap()
}

fn axis(v: u8) -> CellRecoveryFaultAxisV1 {
    match v {
        1 => CellRecoveryFaultAxisV1::Operator,
        2 => CellRecoveryFaultAxisV1::Administrator,
        3 => CellRecoveryFaultAxisV1::FailureDomain,
        _ => panic!("not a representable original axis"),
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    let mut rows = input.as_slice();
    while !rows.is_empty() {
        let n = u32::from_le_bytes(read(rows, 0)) as usize;
        let (b, rest) = rows[4..].split_at(n);
        rows = rest;
        assert_eq!(&b[..8], b"NRPE0001");
        let nprov = usize::from(u16::from_be_bytes(read(b, 8)));
        let nplaces = usize::from(u16::from_be_bytes(read(b, 10)));
        let n_axes = usize::from(b[13]);
        let budget = u64::from_be_bytes(read(b, 14));
        let p = 22 + n_axes;
        let m = p + 160*nprov;
        assert_eq!(m + 34*nplaces, b.len());
        let faults = CellRecoveryFaultPolicyV1 {
            maximum_lost_events: b[12],
            axes: b[22..p].iter().copied().map(axis).collect(),
        };
        let providers: Vec<_> = b[p..m].chunks_exact(160).map(|v| CellRecoveryProviderPinV1 {
            provider_id: read(v, 0), operator: read(v, 32),
            administrator: read(v, 64), failure_domain: read(v, 96), domain_evidence: read(v, 128),
        }).collect();
        let placements: Vec<_> = b[m..].chunks_exact(34).map(|v| {
            let code = u16::from_be_bytes(read(v, 32));
            let part = if code == 0 { CellRecoveryPartV1::WholeChunk }
                       else { CellRecoveryPartV1::Rs46((code-1).try_into().unwrap()) };
            CellRecoveryPlacementV1 { provider_id: read(v, 0), part }
        }).collect();
        let mut report = [0u8; 90];
        let status = match evaluate_recovery_placement(&providers, &placements, &faults, budget) {
            Ok(r) => {
                report[..6].copy_from_slice(&[
                    u8::from(r.recoverable_now()), u8::from(r.survives_declared_faults()),
                    r.minimum_distinct_shards(), r.worst_case_distinct_shards(),
                    u8::from(r.worst_case_whole_chunk_survives()),
                    r.worst_case_events().len().try_into().unwrap(),
                ]);
                report[8..16].copy_from_slice(&r.scenarios().to_le_bytes());
                report[16..24].copy_from_slice(&r.steps().to_le_bytes());
                for (i, e) in r.worst_case_events().iter().enumerate() {
                    let at = 24+i*33;
                    report[at] = match e.axis {
                        CellRecoveryFaultAxisV1::Operator => 1,
                        CellRecoveryFaultAxisV1::Administrator => 2,
                        CellRecoveryFaultAxisV1::FailureDomain => 3,
                    };
                    report[at+1..at+33].copy_from_slice(&e.identity);
                }
                0
            }
            Err(CellErrorV1::Invalid(reason)) => match reason {
                "recovery placement bounds" => 20,
                "recovery fault axes" => 21,
                "recovery provider order/duplicates" => 22,
                "recovery provider identity" => 23,
                "recovery placement order/duplicates" => 24,
                "recovery RS46 shard index" => 25,
                "recovery unknown provider" => 26,
                "recovery placement evaluation budget" => 27,
                _ => panic!("unexpected original decision: {reason}"),
            }
            Err(other) => panic!("unexpected original error: {other:?}"),
        };
        output.write_all(&[status])?;
        output.write_all(&report)?;
    }
    Ok(())
}

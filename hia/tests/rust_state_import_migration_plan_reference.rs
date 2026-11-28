use std::io::Read;

fn slice_digest(frame: &[u8], at: usize) -> Digest32V0 {
    Digest32V0(frame[at..at + 32].try_into().unwrap())
}

fn plan_from(frame: &[u8]) -> MigrationPlanV0 {
    MigrationPlanV0 {
        source_chain_id: slice_digest(frame, 0),
        source_protocol_digest: slice_digest(frame, 32),
        source_schema_digest: slice_digest(frame, 64),
        source_height: u64::from_be_bytes(frame[96..104].try_into().unwrap()),
        source_export_header_digest: slice_digest(frame, 104),
        target_chain_id: slice_digest(frame, 136),
        target_protocol_digest: slice_digest(frame, 168),
        target_schema_digest: slice_digest(frame, 200),
        target_genesis_id: slice_digest(frame, 232),
        no_fallback: frame[264] == 1,
        downgrade_prohibited: frame[265] == 1,
        plan_digest: slice_digest(frame, 266),
    }
}

fn main() {
    let (rows, retained, _) = verified_fixture();
    let old = retained.source_binding_v0();
    let mut exports = Vec::new();
    for (i, source_height) in [100, 1, u64::MAX].into_iter().enumerate() {
        let mut header = FinalizedExportHeaderV0 {
            source_chain_id: d((i + 1) as u8),
            source_protocol_digest: d((i + 4) as u8),
            source_schema_digest: d((i + 7) as u8),
            source_height,
            source_state_root: old.source_state_root(),
            source_finality_proof_digest: old.source_finality_proof_digest(),
            row_count: rows.len() as u64,
            export_root: old.export_root(),
            header_digest: d(0),
        };
        header.header_digest = header.canonical_digest();
        exports.push(verify_export_v0(&AcceptFinality, header, &rows).unwrap());
    }
    let mut out = std::io::stdout().lock();
    if std::env::args_os().nth(1).is_some() {
        for export in &exports {
            let b = export.source_binding_v0();
            for part in [&b.source_chain_id().0, &b.source_protocol_digest().0, &b.source_schema_digest().0] {
                out.write_all(part).unwrap();
            }
            out.write_all(&b.source_height().to_be_bytes()).unwrap();
            out.write_all(&b.export_header_digest().0).unwrap();
        }
    } else {
        let mut wire = Vec::new();
        std::io::stdin().read_to_end(&mut wire).unwrap();
        assert_eq!(wire.len() % 299, 0);
        for packet in wire.chunks_exact(299) {
            let plan = plan_from(&packet[1..]);
            assert!(packet[265] <= 1 && packet[266] <= 1);
            let result = plan.validate(&exports[usize::from(packet[0])]);
            let status = match result {
                Ok(()) => 0,
                Err(MigrationErrorV0::InvalidMigrationPlan) => 101,
                Err(error) => panic!("unexpected original error: {error}"),
            };
            out.write_all(&[status]).unwrap();
            out.write_all(&plan.canonical_digest().0).unwrap();
        }
    }
}

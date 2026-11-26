fn put(out: &mut Vec<u8>, part: Digest32V0) {
    out.extend(part.0);
}

fn main() {
    let mut records = Vec::new();
    let mut result = Vec::new();
    let (_, initial, template) = verified_fixture();
    for (index, (count, height)) in [(1u8, 1u64), (2, 100), (3, 0x8000_0000_0000_0000), (17, u64::MAX)]
        .into_iter().enumerate()
    {
        let rows: Vec<_> = (1..=count).map(row).collect();
        let mut header = initial.header();
        header.source_chain_id = d(30 + index as u8);
        header.source_height = height;
        header.row_count = rows.len() as u64;
        header.export_root = merkle_root_v0(&rows.iter().map(|r| r.row_digest).collect::<Vec<_>>());
        header.header_digest = header.canonical_digest();
        let export = verify_export_v0(&AcceptFinality, header, &rows).unwrap();
        let binding = export.source_binding_v0();
        let mut plan = template;
        plan.source_chain_id = header.source_chain_id;
        plan.source_height = height;
        plan.source_export_header_digest = header.header_digest;
        plan.plan_digest = plan.canonical_digest();
        let projection = project_and_recompute_v0(&plan, &export, &rows, &IdentityProjector, &HashRoot)
            .expect("actual original fixture projection");
        let mut encoded = Vec::new();
        put(&mut encoded, binding.source_chain_id());
        put(&mut encoded, binding.source_protocol_digest());
        encoded.extend(binding.source_height().to_be_bytes());
        put(&mut encoded, binding.source_state_root());
        put(&mut encoded, binding.source_schema_digest());
        put(&mut encoded, binding.source_finality_proof_digest());
        put(&mut encoded, binding.export_header_digest());
        put(&mut encoded, binding.export_root());
        put(&mut encoded, binding.ordered_rows_digest());
        encoded.extend(binding.row_count().to_be_bytes());
        assert_eq!(encoded.len(), 272);
        assert_eq!(binding.binding_digest(), binding.canonical_digest());
        put(&mut encoded, binding.binding_digest());
        put(&mut encoded, projection.plan_digest);
        put(&mut encoded, projection.source_export_root);
        put(&mut encoded, projection.source_ordered_rows_digest);
        encoded.extend(projection.target_row_count.to_be_bytes());
        put(&mut encoded, projection.target_rows_digest);
        put(&mut encoded, projection.target_state_root);
        put(&mut encoded, projection.target_genesis_id);
        put(&mut encoded, projection.canonical_digest());
        assert_eq!(encoded.len(), 536);
        result.extend(encoded);
        records.push((export, binding));
    }
    for (_, binding) in &records {
        for (export, _) in &records {
            result.push(match binding.validate_against(export) {
                Ok(()) => 0,
                Err(MigrationErrorV0::InvalidSourceBinding) => 101,
                Err(err) => panic!("Unexpected original handoff binding outcome {err}"),
            });
        }
    }
    std::io::stdout().lock().write_all(&result).unwrap();
}

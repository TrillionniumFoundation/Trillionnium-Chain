fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args[1].to_str().unwrap();
    let path = std::path::Path::new(&args[2]);
    if mode == "read" {
        let owner = SqliteMigrationHandoffStoreV0::open_existing(path)?;
        let record = owner.readback_v0()?;
        assert_eq!(record.canonical_digest(), record.record_digest);
        let mut out = std::io::stdout().lock();
        out.write_all(&record.revision.to_be_bytes())?;
        out.write_all(&record.record_digest.0)?;
        return Ok(());
    }

    // The fixture types and authority admission are extracted byte-for-byte
    // from the original crate's own cfg(test) module by the test builder.
    let (rows, export, plan) = verified_fixture();
    let binding = export.source_binding_v0();
    let source_raw = SourceCheckpointContextV0 {
        chain_id: d(1), protocol_digest: d(2), checkpoint_digest: d(10), block_id: d(11),
        height: 100, epoch: 1, state_root: d(3), validator_set_digest: d(12),
        finality_proof_digest: d(13),
    };
    let source = verify_source_checkpoint_context_v0(&AcceptFinality, source_raw)?;
    match mode {
        "init" => {
            let record = MigrationHandoffRecordV0::new_verified_source(&plan, &binding, &source, 99)?;
            SqliteMigrationHandoffStoreV0::initialize(path, record)?;
        }
        "project" => {
            let projection =
                project_and_recompute_v0(&plan, &export, &rows, &IdentityProjector, &HashRoot)?;
            let target_raw = SourceCheckpointContextV0 {
                chain_id: d(1), protocol_digest: d(2), checkpoint_digest: d(14), block_id: d(15),
                height: 101, epoch: 1, state_root: projection.target_state_root,
                validator_set_digest: d(16), finality_proof_digest: d(17),
            };
            let target = verify_source_checkpoint_context_v0(&AcceptFinality, target_raw)?;
            let owner = SqliteMigrationHandoffStoreV0::open_existing(path)?;
            owner.projected_delta_v0(&projection, &source, &target)?;
        }
        _ => return Err("only disposable original handoff init/project/read".into()),
    }
    Ok(())
}

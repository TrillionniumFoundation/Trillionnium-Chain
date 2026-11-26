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
    let (rows, mut export, mut plan) = verified_fixture();
    let installed_fixture = mode.ends_with("-installed");
    let base = vec![IdentityProjector.project(&rows[0])?.expect("retained fixture row")];
    let source_root = if installed_fixture {
        let root = HashRoot.recompute_target_root(plan.target_schema_digest, base.iter())?;
        let old = export.source_binding_v0();
        let mut adjusted = FinalizedExportHeaderV0 {
            source_chain_id: old.source_chain_id(), source_protocol_digest: old.source_protocol_digest(),
            source_height: old.source_height(), source_state_root: root,
            source_schema_digest: old.source_schema_digest(),
            source_finality_proof_digest: old.source_finality_proof_digest(),
            row_count: rows.len() as u64, export_root: old.export_root(), header_digest: d(0),
        };
        adjusted.header_digest = adjusted.canonical_digest();
        export = verify_export_v0(&AcceptFinality, adjusted, &rows)?;
        plan.source_export_header_digest = adjusted.header_digest;
        plan.plan_digest = plan.canonical_digest();
        root
    } else {
        d(3)
    };
    let binding = export.source_binding_v0();
    let source_raw = SourceCheckpointContextV0 {
        chain_id: d(1), protocol_digest: d(2), checkpoint_digest: d(10), block_id: d(11),
        height: 100, epoch: 1, state_root: source_root, validator_set_digest: d(12),
        finality_proof_digest: d(13),
    };
    let source = verify_source_checkpoint_context_v0(&AcceptFinality, source_raw)?;
    match mode {
        "init" | "init-installed" => {
            let record = MigrationHandoffRecordV0::new_verified_source(&plan, &binding, &source, 99)?;
            SqliteMigrationHandoffStoreV0::initialize(path, record)?;
        }
        "project" | "project-installed" | "install-installed" | "cas-installed" => {
            let projection =
                project_and_recompute_v0(&plan, &export, &rows, &IdentityProjector, &HashRoot)?;
            let target_raw = SourceCheckpointContextV0 {
                chain_id: d(1), protocol_digest: d(2), checkpoint_digest: d(14), block_id: d(15),
                height: 101, epoch: 1, state_root: projection.target_state_root,
                validator_set_digest: d(16), finality_proof_digest: d(17),
            };
            let target = verify_source_checkpoint_context_v0(&AcceptFinality, target_raw)?;
            let owner = SqliteMigrationHandoffStoreV0::open_existing(path)?;
            if mode.starts_with("project") {
                owner.projected_delta_v0(&projection, &source, &target)?;
            } else {
                let installed = path.with_extension("fixture-state.sqlite");
                if mode == "install-installed" {
                    let delta_state = SqliteIncrementalStateStoreV0::initialize(
                        &installed, plan.plan_digest, plan.target_schema_digest, source_raw, &base, &HashRoot,
                    )?;
                    let delta = derive_incremental_delta_v0(
                        plan.plan_digest, plan.target_schema_digest, source_raw, target_raw,
                        &base, &projection.rows, &HashRoot,
                    )?;
                    assert_eq!(delta.entries.len(), 1);
                    let receipt = delta_state.apply_delta_v0(&delta, &HashRoot)?;
                    let installed_rows = delta_state.read_rows_v0()?;
                    assert_eq!(projection.rows, installed_rows);
                    let readback = SqliteIncrementalStateStoreV0::open_existing(
                        &installed, plan.plan_digest, plan.target_schema_digest,
                    )?.readback_v0()?;
                    // The isolated fixture supplies the store label; the receipt and
                    // readback come from the unchanged original SQLite owner.
                    let fixture_identity = Digest32V0::hash(
                        b"test.disposable-state-store", &[&receipt.delta_digest.0],
                    );
                    owner.durable_install_v0(fixture_identity, receipt, readback)?;
                } else {
                    let readback = SqliteIncrementalStateStoreV0::open_existing(
                        &installed, plan.plan_digest, plan.target_schema_digest,
                    )?.readback_v0()?;
                    owner.readback_cas_v0(readback)?;
                }
            }
        }
        _ => return Err("only disposable original handoff init/project/read/fixture-install/fixture-cas".into()),
    }
    Ok(())
}

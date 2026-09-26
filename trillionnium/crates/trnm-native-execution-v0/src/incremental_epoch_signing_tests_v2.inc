// Reuse actual native C18/C28 commits, original signed proofs and cold owners.
// This exercises the M07 producer; no test-only token is used as M03 custody.
fn schema11_signing_readback_checks(
    app: &DurableNativeApplicationV0,
    receipt: &crate::CommittedIncrementalEpochPreHandoffV2,
    header: &BlockHeader,
    original_proof: &[u8],
) -> [u8; 32] {
    use trnm_consensus_types::Cev0AdmissionBudgetV0;
    let before = std::fs::read(app.path()).unwrap();
    let sidecar = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(app.path());
    let sidecar_before = std::fs::read(&sidecar).unwrap();
    let mut ordinary_meter = Cev0AdmissionBudgetV0::protocol_v0();
    let _ = app.confirm_incremental_epoch_pre_handoff_v2(
        *header.id().as_bytes(),
        receipt.p_digest(),
        &mut ordinary_meter,
    )
    .unwrap();
    let work = ordinary_meter.signature_work();
    assert!(work > 0);
    // Exactly the same owner audit work, retaining incoming caller work. A
    // second target verification or internal fresh meter would fail this test.
    let mut meter = Cev0AdmissionBudgetV0::new(ordinary_meter.maximum_root_bytes(), work + 7);
    meter.charge_signature_work(7).unwrap();
    let confirmed = app
        .confirm_incremental_handoff_signing_v2(receipt, &mut meter)
        .unwrap();
    assert_eq!(meter.signature_work(), work + 7);
    assert_eq!(confirmed.checkpoint_header(), header);
    assert_eq!(confirmed.checkpoint_finality_bytes(), original_proof);
    assert_eq!(
        confirmed.checkpoint_receipt().p_digest(),
        receipt.p_digest()
    );
    assert_eq!(
        confirmed.checkpoint_receipt().generation(),
        receipt.generation()
    );
    assert_eq!(
        confirmed.strict_context().binding_ref(),
        receipt.strict_binding()
    );
    assert_eq!(
        confirmed
            .strict_context()
            .descriptor()
            .fields()
            .checkpoint_block_id,
        header.id()
    );
    let cut = confirmed.committed_owner_cut_ref_v2();
    assert_ne!(cut, receipt.record_digest());
    assert_ne!(cut, receipt.strict_binding());
    let retry = app
        .confirm_incremental_handoff_signing_v2(
            confirmed.checkpoint_receipt(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(retry.committed_owner_cut_ref_v2(), cut);
    let mut insufficient =
        Cev0AdmissionBudgetV0::new(ordinary_meter.maximum_root_bytes(), work - 1);
    assert!(app
        .confirm_incremental_handoff_signing_v2(receipt, &mut insufficient)
        .is_err());
    assert!(insufficient.signature_work() > 0);
    assert_eq!(std::fs::read(app.path()).unwrap(), before);
    assert_eq!(std::fs::read(&sidecar).unwrap(), sidecar_before);

    // The original affine confirmation cannot hide an independently rehashed
    // strict-binding substitution in the same live owner's committed row.
    let c = Connection::open(app.path()).unwrap();
    let mut row: Vec<rusqlite::types::Value> = c.query_row(
        "SELECT checkpoint_block,p_digest,commit_sequence,checkpoint_head,predecessor_edge,prefix,context_digest,checkpoint_finality,descriptor,next_epoch_commitment,new_validator_set,new_parameters,strict_binding FROM native_incremental_epoch_pre_handoff_v2 WHERE checkpoint_block=?1",
        [header.id().as_bytes().as_slice()], |r| (0..13).map(|i| r.get(i)).collect(),
    ).unwrap();
    row[12] = rusqlite::types::Value::Blob([0x37; 32].to_vec());
    let checksum = schema11_test_row_checksum(
        &c,
        "trnm.native-application.incremental-epoch-pre-handoff.v2",
        &row,
        &[7, 8, 9, 10, 11],
        &[],
    );
    c.execute(
        "UPDATE native_incremental_epoch_pre_handoff_v2 SET strict_binding=?1,checksum=?2 WHERE checkpoint_block=?3",
        params![row[12], checksum.as_slice(), header.id().as_bytes().as_slice()],
    ).unwrap();
    drop(c);
    let corrupt = std::fs::read(app.path()).unwrap();
    assert!(app
        .confirm_incremental_handoff_signing_v2(
            confirmed.checkpoint_receipt(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    assert_eq!(std::fs::read(app.path()).unwrap(), corrupt);
    assert_eq!(std::fs::read(&sidecar).unwrap(), sidecar_before);
    std::fs::write(app.path(), &before).unwrap();
    let restored = app
        .confirm_incremental_handoff_signing_v2(receipt, &mut Cev0AdmissionBudgetV0::protocol_v0())
        .unwrap();
    assert_eq!(restored.committed_owner_cut_ref_v2(), cut);
    cut
}

#[test]
fn later_checkpoint_selection_uses_current_committed_cutoff_without_writes() {
    use sha2::{Digest, Sha256};
    let directory = tempfile::tempdir().unwrap();
    let fixture = build_later_pre_handoff_fixture(&directory.path().join("selection.db"), &[]);
    let app = &fixture.application;
    let before = Sha256::digest(std::fs::read(app.path()).unwrap());
    let context = app.inspect_later_epoch_checkpoint_context_v1().unwrap();
    let cutoff = app.read_finalized_by_height_v1(HeightV0::new(15)).unwrap();
    let selected = app
        .compute_later_epoch_selection_v1(HeightV0::new(15))
        .unwrap();
    assert_eq!(selected.next_epoch_commitment(), &fixture.commitment);
    assert_eq!(selected.new_validator_set(), &fixture.new_set);
    assert_eq!(selected.new_parameters(), &fixture.old_parameters);
    assert_eq!(selected.cutoff_head(), &cutoff.finalized_head_v1().unwrap());
    assert_eq!(selected.cutoff_p_digest(), cutoff.p_digest_v1());
    assert_eq!(
        Some(selected.cutoff_commit_sequence()),
        cutoff.commit_sequence_v1()
    );
    assert_eq!(selected.observed_context_digest(), context.context_digest());
    let stored_sequence: Vec<u8> = rusqlite::Connection::open_with_flags(
        app.path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT p_sequence FROM native_durable_execution_p_v1 WHERE block_id=?1",
        [selected.cutoff_head().block_id().as_bytes().as_slice()],
        |r| r.get(0),
    )
    .unwrap();
    assert_eq!(stored_sequence, selected.cutoff_p_sequence().to_be_bytes());
    for wrong in [0, 14, 16, 18, u64::MAX] {
        assert!(app
            .compute_later_epoch_selection_v1(HeightV0::new(wrong))
            .is_err());
    }
    assert_eq!(Sha256::digest(std::fs::read(app.path()).unwrap()), before);

    // Existing inert choices do not let a new call ignore damaged native state.
    let sql = rusqlite::Connection::open(app.path()).unwrap();
    assert_eq!(
        sql.execute(
            "UPDATE native_durable_execution_p_v1 SET target_snapshot=x'00' WHERE target_height=?1",
            [15u64.to_be_bytes().as_slice()],
        )
        .unwrap(),
        1
    );
    drop(sql);
    let corrupted = Sha256::digest(std::fs::read(app.path()).unwrap());
    assert_ne!(corrupted, before);
    assert!(app
        .compute_later_epoch_selection_v1(HeightV0::new(15))
        .is_err());
    assert_eq!(
        Sha256::digest(std::fs::read(app.path()).unwrap()),
        corrupted
    );
}

#[test]
fn later_checkpoint_selection_rejects_historic_and_uncommitted_cutoffs() {
    use sha2::{Digest, Sha256};
    let directory = tempfile::tempdir().unwrap();
    let fixture = build_later_descendant_fixture(&directory.path().join("next-epoch.db"));
    let app = &fixture.application;
    let context = app.inspect_later_epoch_checkpoint_context_v1().unwrap();
    assert_eq!(context.epoch().get(), 2);
    assert!(context.cutoff_height().get() > context.application_head().height().get());
    let before = Sha256::digest(std::fs::read(app.path()).unwrap());
    assert!(app.read_finalized_by_height_v1(HeightV0::new(15)).is_ok());
    assert!(app
        .compute_later_epoch_selection_v1(HeightV0::new(15))
        .is_err());
    assert!(app
        .compute_later_epoch_selection_v1(HeightV0::new(context.cutoff_height().get()))
        .is_err());
    assert_eq!(Sha256::digest(std::fs::read(app.path()).unwrap()), before);
}

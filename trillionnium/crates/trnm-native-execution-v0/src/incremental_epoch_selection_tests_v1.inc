#[test]
fn schema7_incremental_cutoff_selection_uses_committed_sparse_state_without_writes() {
    use descendant::IncrementalEpochParentV1 as Parent;
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("native.sqlite3");
    let (app, edge, first, proof, mut descendants) = setup(&path);
    let first_commit = app
        .commit_incremental_epoch_finality_bytes_v1(
            &first,
            &proof,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(first_commit.head(), &first.target_head().unwrap());
    assert!(app
        .compute_incremental_epoch_selection_v1(HeightV0::new(15))
        .is_err());
    for height in 14..=17 {
        let next = empty_descendant(
            &app,
            &edge,
            Parent::Descendant(descendants.last().unwrap()),
            height * 1000,
        );
        descendants.push(next);
        let index = descendants.len() - 3;
        let parent = if index == 0 {
            first.header().unwrap()
        } else {
            descendants[index - 1].header().unwrap()
        };
        let finality =
            crate::poco_checkpoint::native_checkpoint_fixture_v1::ordinary_epoch_finality(
                &edge,
                &parent,
                &[
                    descendants[index].header().unwrap(),
                    descendants[index + 1].header().unwrap(),
                    descendants[index + 2].header().unwrap(),
                ],
            );
        if height == 17 {
            // C15 already exists as an exact Prepared P; it is not a cutoff
            // authority until its genuine original finality is committed.
            assert!(app
                .compute_incremental_epoch_selection_v1(HeightV0::new(15))
                .is_err());
        }
        let committed = app
            .commit_incremental_epoch_descendant_finality_bytes_v1(
                &descendants[index],
                &finality,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(committed.head().height().get(), height - 2);
    }
    let original = std::fs::read(&path).unwrap();
    let result = app
        .compute_incremental_epoch_selection_v1(HeightV0::new(15))
        .unwrap();
    let cutoff = app
        .reopen_prepared_incremental_epoch_descendant_v1(
            *descendants[3].target_head().unwrap().block_id().as_bytes(),
            descendants[3].p_digest(),
        )
        .unwrap();
    assert_eq!(result.cutoff_head(), &cutoff.target_head().unwrap());
    assert_eq!(result.cutoff_p_digest(), cutoff.p_digest());
    assert_eq!(result.cutoff_p_sequence(), cutoff.persist_sequence());
    assert_eq!(
        Some(result.cutoff_commit_sequence()),
        cutoff.commit_sequence()
    );
    assert_eq!(result.observed_head(), result.cutoff_head());
    assert_eq!(result.edge_binding(), edge.authorization_id());
    assert_eq!(
        result.next_epoch_commitment().fields().old_epoch,
        edge.new_validator_set().epoch()
    );
    assert_eq!(
        result
            .next_epoch_commitment()
            .fields()
            .snapshot_cutoff_height
            .get(),
        15
    );
    assert_eq!(
        result
            .next_epoch_commitment()
            .fields()
            .snapshot_state_root
            .as_bytes(),
        result.cutoff_head().state_root().as_bytes()
    );
    assert_eq!(
        result
            .next_epoch_commitment()
            .fields()
            .new_validator_set_hash,
        result.new_validator_set().id()
    );
    assert_eq!(
        result
            .next_epoch_commitment()
            .fields()
            .new_consensus_parameters_hash,
        result.new_parameters().hash()
    );
    for height in [0, 8, 11, 14, 16, 18, u64::MAX] {
        assert!(app
            .compute_incremental_epoch_selection_v1(HeightV0::new(height))
            .is_err());
    }
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let c = Connection::open(&path).unwrap();
    let (snapshot, pending): (u64, u64) = c.query_row(
        "SELECT length(authenticated_snapshot),(SELECT count(*) FROM native_incremental_p_v1 WHERE status=0) FROM native_application_metadata_v0 WHERE singleton=1", [], |r| Ok((r.get(0)?,r.get(1)?)),
    ).unwrap();
    assert_eq!((snapshot, pending), (0, 2));
    drop(c);
    drop(app);
    let reopened =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let cold = reopened
        .compute_incremental_epoch_selection_v1(HeightV0::new(15))
        .unwrap();
    assert_eq!(cold.next_epoch_commitment(), result.next_epoch_commitment());
    assert_eq!(cold.new_validator_set(), result.new_validator_set());
    assert_eq!(cold.new_parameters(), result.new_parameters());
    assert_eq!(
        cold.observed_owner_checksum(),
        result.observed_owner_checksum()
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);

    // A genuine proof for a different committed block cannot replace C15's
    // proof, even when the local row checksum is recomputed consistently.
    let c = Connection::open(&path).unwrap();
    let row = edge_row(&c).unwrap();
    let prior = descendant::load_commit(
        &c,
        *descendants[2].target_head().unwrap().block_id().as_bytes(),
    )
    .unwrap()
    .unwrap();
    let mut changed = descendant::load_commit(&c, *cold.cutoff_head().block_id().as_bytes())
        .unwrap()
        .unwrap();
    changed.proof = prior.proof;
    let checksum = hash_domain(
        "trnm.native-application.incremental-epoch-descendant-commit.v1",
        &[
            &reopened.config.store_id,
            &row.checksum,
            &changed.block,
            &changed.p_digest,
            &changed.sequence.to_be_bytes(),
            &head_bytes(&changed.head),
            &sha256_v0(&changed.proof),
        ],
    );
    c.execute("UPDATE native_incremental_epoch_descendant_commit_v1 SET proof=?1,checksum=?2 WHERE block=?3",
        params![changed.proof,checksum.as_slice(),changed.block.as_slice()]).unwrap();
    drop(c);
    let corrupted = std::fs::read(&path).unwrap();
    assert!(reopened
        .compute_incremental_epoch_selection_v1(HeightV0::new(15))
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), corrupted);
    drop(reopened);
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    std::fs::write(&path, &original).unwrap();
    let reopened =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let c = Connection::open(&path).unwrap();
    c.execute(
        "UPDATE ni_roots SET root=?1 WHERE block_id=?2",
        params![
            [0x7b_u8; 32].as_slice(),
            cold.cutoff_head().block_id().as_bytes().as_slice()
        ],
    )
    .unwrap();
    drop(c);
    let corrupted = std::fs::read(&path).unwrap();
    assert!(reopened
        .compute_incremental_epoch_selection_v1(HeightV0::new(15))
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), corrupted);
}

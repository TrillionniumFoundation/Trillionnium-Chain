type OrdinaryCutoffCaseV3 = (
    tempfile::TempDir,
    super::EpochOrdinaryContinuationRuntimeV3<Watermark, Watermark>,
    Key,
    Option<SignedProposalV0>,
);

#[inline(never)]
fn ordinary_cutoff_begin_v3(case: Box<FirstApplyCaseV2>) -> Box<OrdinaryCutoffCaseV3> {
    let (directory, settled, key) = *first_apply_settle_v2(case);
    let owner = settled.into_ordinary_continuation_v3().unwrap();
    assert_eq!(owner.inner.prepared.len(), 2);
    assert_eq!(owner.cutoff_height, 15);
    Box::new((directory, owner, key, None))
}

#[inline(never)]
fn ordinary_cutoff_advance_v3(case: Box<OrdinaryCutoffCaseV3>) -> Box<OrdinaryCutoffCaseV3> {
    let (directory, mut owner, mut key, mut last_proposal) = *case;
    let initial_calls = key.calls;
    for target_height in 12..=15 {
        assert!(owner.settled_cutoff_checkpoint_v3().is_err());
        let proposal = first_apply_child_proposal_v2(&owner.inner);
        assert_eq!(proposal.block().header().height().get(), target_height + 2);
        let calls = key.calls;
        last_proposal = Some(proposal.clone());
        owner = owner.execute_ordinary_proposal_v3(proposal).unwrap();
        assert_eq!(key.calls, calls);
        let (next, vote) = owner.sign_ordinary_vote_v3(&mut key).unwrap();
        owner = next;
        assert_eq!(key.calls, calls + 1);
        assert!(matches!(
            vote,
            trnm_consensus_core::OutboundMessage::Vote(_)
        ));
        assert_eq!(owner.inner.prepared.len(), 3);
        let head = owner
            .inner
            .runtime
            .application
            .confirmed_committed_head_v0()
            .unwrap();
        assert_eq!(head.height().get(), target_height - 1);
        let lookahead: Vec<_> = owner.inner.prepared[1..]
            .iter()
            .map(|p| (p.prepared.header().unwrap().id(), p.prepared.p_digest()))
            .collect();
        let last = owner.inner.prepared[2].prepared.header().unwrap();
        let qc = first_apply_qc_v2(&last, owner.inner.runtime.edge.new_validator_set());
        owner = owner.observe_ordinary_finality_qc_v3(qc).unwrap();
        assert_eq!(
            owner
                .inner
                .runtime
                .driver
                .state()
                .finalized()
                .height()
                .get(),
            target_height
        );
        assert_eq!(
            owner
                .inner
                .runtime
                .driver
                .state()
                .application_applied()
                .height()
                .get(),
            target_height - 1
        );
        owner = owner
            .apply_ordinary_front_v3(
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let state = owner.inner.runtime.driver.state();
        assert_eq!(state.application_applied(), state.finalized());
        assert_eq!(state.application_applied().height().get(), target_height);
        assert!(state.finalization_queue().is_empty());
        assert_eq!(owner.inner.prepared.len(), 2);
        let read = owner
            .inner
            .runtime
            .journal
            .fresh_read_v1(owner.inner.runtime.pin)
            .unwrap();
        assert_eq!(read.state_v1(), state);
        assert!(read
            .transition_context_v1()
            .native_finalization_applied_transition()
            .is_some());
        for (index, (block, digest)) in lookahead.into_iter().enumerate() {
            let retained = &owner.inner.prepared[index].prepared;
            assert_eq!(retained.header().unwrap().id(), block);
            assert_eq!(retained.p_digest(), digest);
        }
    }
    assert_eq!(key.calls, initial_calls + 4);
    // The advancing loop already checks the retained in-memory identity after
    // every commit. Reopen the final two retained descendants once here rather
    // than repeating a complete SQLite/history audit eight times. Dedicated
    // storage tests continue to cover each crash/reopen boundary separately.
    for retained in &owner.inner.prepared {
        assert_eq!(
            owner
                .inner
                .runtime
                .application
                .confirm_prepared_epoch_execution_v1(&retained.prepared)
                .unwrap()
                .commit_sequence(),
            None
        );
    }
    Box::new((directory, owner, key, last_proposal))
}

#[inline(never)]
fn ordinary_cutoff_finish_v3(case: Box<OrdinaryCutoffCaseV3>) {
    let (_directory, mut owner, key, last_proposal) = *case;
    let checkpoint = owner.settled_cutoff_checkpoint_v3().unwrap();
    let head = owner
        .inner
        .runtime
        .application
        .confirmed_committed_head_v0()
        .unwrap();
    assert_eq!(head.height().get(), 15);
    assert_eq!(
        checkpoint.fields().application.block_id,
        *head.block_id().as_bytes()
    );
    assert_eq!(
        owner.inner.prepared[0]
            .prepared
            .header()
            .unwrap()
            .height()
            .get(),
        16
    );
    assert_eq!(
        owner.inner.prepared[1]
            .prepared
            .header()
            .unwrap()
            .height()
            .get(),
        17
    );
    let application = &owner.inner.runtime.application;
    let current = application
        .confirm_current_epoch_execution_v1(*head.block_id().as_bytes())
        .unwrap();
    assert_eq!(
        current.commit_sequence(),
        Some(checkpoint.fields().application.commit_sequence)
    );
    assert_eq!(
        current.prepared().p_digest(),
        checkpoint.fields().application.p_digest
    );
    // A real retained prepared descendant cannot acquire current-commit status.
    let pending = owner.inner.prepared[0].prepared.header().unwrap().id();
    assert!(application
        .confirm_current_epoch_execution_v1(*pending.as_bytes())
        .is_err());
    // Nor can an earlier genuinely committed row masquerade as the current head.
    let history = rusqlite::Connection::open_with_flags(
        application.path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let prior: Vec<u8> = history.query_row(
        "SELECT block_id FROM native_durable_execution_p_v1 WHERE target_height=?1 AND status=1",
        [12u64.to_be_bytes().as_slice()], |row| row.get(0),
    ).unwrap();
    drop(history);
    assert!(application
        .confirm_current_epoch_execution_v1(prior.try_into().unwrap())
        .is_err());
    // Failed queries cannot change the live head or invalidate the original cut.
    assert_eq!(application.confirmed_committed_head_v0().unwrap(), head);
    let paths = [
        owner.inner.runtime.application.path().to_path_buf(),
        owner.inner.runtime.journal.path_v1().to_path_buf(),
        owner.inner.runtime.ordinary.path().to_path_buf(),
        owner
            .inner
            .runtime
            .checkpoint_store
            .database_path()
            .to_path_buf(),
    ];
    let before: Vec<_> = paths
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    let logical_before: Vec<_> = paths
        .iter()
        .map(|path| sqlite_logical_image_v3(path))
        .collect();
    let calls = key.calls;
    let error = owner
        .execute_ordinary_proposal_v3(last_proposal.unwrap())
        .err()
        .expect(
            "completed cutoff must reject an independently valid signed proposal before execution",
        );
    assert!(error
        .to_string()
        .contains("ordinary cutoff continuation is complete"));
    assert_eq!(key.calls, calls);
    for (index, ((path, original), logical)) in
        paths.iter().zip(before).zip(logical_before).enumerate()
    {
        assert!(
            sqlite_logical_image_v3(path) == logical,
            "cutoff refusal changed logical rows in {}",
            path.display()
        );
        // The signer owns a persistent WAL connection. Dropping the consumed
        // rejected owner checkpoints already-committed WAL frames into its
        // main file; that changes layout, not a single logical record.
        if index != 2 {
            assert!(
                std::fs::read(path).unwrap() == original,
                "cutoff refusal changed {}",
                path.display()
            );
        }
    }
}

#[test]
fn actual_epoch_ordinary_continuation_commits_real_cutoff_with_two_prepared_children_v3() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    ordinary_cutoff_finish_v3(ordinary_cutoff_advance_v3(ordinary_cutoff_begin_v3(first)));
}

#[inline(never)]
fn ordinary_progressed_replacement_rejects_v3(
    case: Box<OrdinaryCutoffCaseV3>,
    watermark: Watermark,
) {
    let (_directory, owner, mut key, _) = *case;
    let proposal = first_apply_child_proposal_v2(&owner.inner);
    let owner = owner.execute_ordinary_proposal_v3(proposal).unwrap();
    assert_eq!(
        owner.inner.runtime.checkpoint.fields().application.height,
        11
    );
    let path = owner.inner.runtime.application.path().to_path_buf();
    let expected_bytes = std::fs::read(&path).unwrap();
    let sequence = watermark.0.lock().unwrap().0.unwrap().sequence();
    assert!(
        sequence > 1,
        "exercise the progressed, not pre-K key boundary"
    );
    *watermark.3.lock().unwrap() = Some((path.clone(), sequence + 1));
    let calls = key.calls;
    assert!(owner.sign_ordinary_vote_v3(&mut key).is_err());
    assert!(
        watermark.3.lock().unwrap().is_none(),
        "external callback replaced the real application namespace"
    );
    assert_eq!(
        key.calls, calls,
        "progressed owner substitution must reject before key entry"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        expected_bytes,
        "replacement retained genuine valid application bytes"
    );
    let application =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    assert_eq!(
        application
            .confirmed_committed_head_v0()
            .unwrap()
            .height()
            .get(),
        11,
        "replacement is a real valid progressed database, not malformed test state"
    );
}

#[test]
fn actual_epoch_ordinary_progressed_native_replacement_rejects_before_key_v3() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    let watermark = unsigned.3.new_watermark.clone();
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    ordinary_progressed_replacement_rejects_v3(ordinary_cutoff_begin_v3(first), watermark);
}

#[derive(PartialEq)]
struct SqliteTableImageV3 {
    name: String,
    rows: Vec<Vec<rusqlite::types::Value>>,
}

fn sqlite_logical_image_v3(path: &std::path::Path) -> Vec<SqliteTableImageV3> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables.insert(0, "sqlite_master".to_owned());
    tables
        .into_iter()
        .map(|name| {
            let quoted = format!("\"{}\"", name.replace('"', "\"\""));
            let columns = connection
                .prepare(&format!("SELECT * FROM {quoted} LIMIT 0"))
                .unwrap()
                .column_count();
            let order = (1..=columns)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {quoted} ORDER BY {order}"))
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            SqliteTableImageV3 { name, rows }
        })
        .collect()
}

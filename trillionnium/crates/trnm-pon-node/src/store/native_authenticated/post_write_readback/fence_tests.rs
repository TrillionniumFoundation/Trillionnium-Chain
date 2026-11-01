use super::*;

#[test]
fn four_original_roles_are_bounded_and_a_fifth_root_never_becomes_a_receipt() {
    let mut f = fixture();
    let mut ids = vec![f.node.settings.genesis()];
    for height in 1..=5 {
        let packet = f
            .node
            .make_consensus_maintenance(
                *ids.last().unwrap(),
                vec![],
                crate::development_public(height).unwrap(),
                height + 10,
                4096,
            )
            .unwrap();
        ids.push(f.node.admit(&packet, 100_000).unwrap());
    }
    f.node.activate_observed(ids[2], 100_000).unwrap();
    let states: Vec<_> = ids.iter().map(|id| f.node.state_at(*id).unwrap()).collect();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[4]);
    verify(&f.node, ids[4], &states[4], &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(scope.ids, [Some(ids[4]), Some(ids[0]), Some(ids[3]), None]);
    f.node
        .read_active_with_readback(&mut || Ok(()), Some(&mut scope))
        .unwrap();
    assert_eq!(
        scope.ids,
        [Some(ids[4]), Some(ids[0]), Some(ids[3]), Some(ids[2])]
    );
    for index in [0, 2, 3, 4] {
        verify(&f.node, ids[index], &states[index], &mut scope, &mut || {
            Ok(())
        })
        .unwrap();
        let before = graphs(&f.node);
        verify(&f.node, ids[index], &states[index], &mut scope, &mut || {
            Ok(())
        })
        .unwrap();
        assert_eq!(graphs(&f.node), before);
    }
    let before = graphs(&f.node);
    for _ in 0..2 {
        verify(&f.node, ids[1], &states[1], &mut scope, &mut || Ok(())).unwrap();
    }
    assert_eq!(graphs(&f.node) - before, 2);
    assert_eq!(
        scope.ids,
        [Some(ids[4]), Some(ids[0]), Some(ids[3]), Some(ids[2])]
    );
}

#[test]
fn trusted_reset_exposes_preexisting_catalog_and_prepared_vm_divergence() {
    for capacity in [0, 16] {
        let f = fixture();
        f.node.db.set_prepared_statement_cache_capacity(capacity);
        let genesis = f.node.settings.genesis();
        super::super::super::verify_state_with_cache(
            &f.node.db,
            &f.node.settings,
            genesis,
            &f.node.settings.initial,
            &mut || Ok(()),
            Some(&f.node.authenticated_arithmetic),
        )
        .unwrap();
        f.node.db.execute_batch(
            "PRAGMA writable_schema=ON;
             UPDATE main.sqlite_schema SET rootpage=(SELECT rootpage FROM main.sqlite_schema WHERE name='native_state_commitments') WHERE name='archive_nodes';
             PRAGMA writable_schema=OFF",
        ).unwrap();
        assert_eq!(
            &crate::store::schema(&f.node.db).unwrap(),
            f.node.post_write_schema.as_ref().unwrap()
        );
        super::super::super::verify_state_with_cache(
            &f.node.db,
            &f.node.settings,
            genesis,
            &f.node.settings.initial,
            &mut || Ok(()),
            Some(&f.node.authenticated_arithmetic),
        )
        .unwrap();
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = capture(&f.node, genesis);
        let error = verify(
            &f.node,
            genesis,
            &f.node.settings.initial,
            &mut scope,
            &mut || Ok(()),
        )
        .unwrap_err();
        assert!(error.requires_owner_stop());
        assert!(scope.graphs.iter().all(Option::is_none));
        assert_eq!(scope.hits, 0);
    }
}

#[test]
fn final_callback_after_a_first_match_falls_back_to_the_actual_original_graph() {
    let f = fixture();
    let genesis = f.node.settings.genesis();
    let mut scope = mint_genesis(&f.node);
    let mut callbacks = 0;
    verify(
        &f.node,
        genesis,
        &f.node.settings.initial,
        &mut scope,
        &mut || {
            callbacks += 1;
            Ok(())
        },
    )
    .unwrap();
    drop(scope);
    let mut scope = capture(&f.node, genesis);
    verify(
        &f.node,
        genesis,
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    assert!(!scope.consumed);
    let root = load_observed(&f.node.db, genesis, None)
        .unwrap()
        .accounts
        .node
        .unwrap();
    let mut current = 0;
    let error = verify(
        &f.node,
        genesis,
        &f.node.settings.initial,
        &mut scope,
        &mut || {
            current += 1;
            if current == callbacks {
                f.node.db.execute(
                    "UPDATE archive_nodes SET data=x'00' WHERE id=?",
                    [root.as_slice()],
                )?;
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_ACCOUNT_STORE"));
    assert_eq!(scope.hits, 0);
    assert!(!scope.enabled);
}

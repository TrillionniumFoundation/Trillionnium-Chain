//! The actual signed two-Root fixture and unchanged complete SQL verifier are
//! the reference. These are transaction-local controls, never F0 qualification.
use super::*;

struct BeforeAppend<'db> {
    owner: TransactionScope<'db>,
    graph: PostWriteReadback<'db>,
    parent: Record,
    record: Record,
    rows: Vec<crate::store::Delta>,
}

struct PreparedAppend<'db> {
    owner: TransactionScope<'db>,
    publication: PublicationParent<'db>,
    record: Record,
    rows: Vec<crate::store::Delta>,
}

fn before_append(f: &TwoRoots) -> BeforeAppend<'_> {
    let node = &f.fixture.node;
    let record = load_observed(&node.db, f.child, None).unwrap();
    let parent = load_observed(&node.db, f.parent, None).unwrap();
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let owner = TransactionScope::capture(&node.db).unwrap();
    assert_eq!(
        node.db
            .execute(
                "DELETE FROM native_state_commitments WHERE block=?",
                [f.child.as_slice()],
            )
            .unwrap(),
        1,
    );
    let rows =
        crate::store::native_authenticated::deltas_with_progress(&node.db, f.child, &mut || Ok(()))
            .unwrap();
    assert!(rows.iter().any(|row| row.0.starts_with("account:")));
    let mut graph = PostWriteReadback::new(
        &node.db,
        &node.settings,
        f.parent,
        &owner,
        node.post_write_schema.as_ref().unwrap(),
    )
    .unwrap()
    .unwrap();
    verify(node, f.parent, &f.before, &mut graph, &mut || Ok(())).unwrap();
    assert!(graph
        .frontier
        .as_ref()
        .unwrap()
        .is_for(parent.id, &parent.accounts));
    assert!(graph.graphs[0].as_ref().unwrap().source.is_none());
    assert!(!graph.consumed);
    BeforeAppend {
        owner,
        graph,
        parent,
        record,
        rows,
    }
}

impl<'db> BeforeAppend<'db> {
    fn apply(
        self,
        node: &'db Node,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PreparedAppend<'db>> {
        let (accounts, publication) = PostWriteReadback::apply_publication_accounts(
            &node.db,
            &self.parent,
            &self.rows,
            progress,
            Some(self.graph),
        )?;
        assert_eq!(accounts, self.record.accounts);
        Ok(PreparedAppend {
            owner: self.owner,
            publication,
            record: self.record,
            rows: self.rows,
        })
    }
}

impl<'db> PreparedAppend<'db> {
    fn save(mut self, node: &'db Node) -> Result<PostWriteReadback<'db>> {
        PostWriteReadback::save_publication_record(
            &node.db,
            &node.settings,
            &mut self.record,
            &self.rows,
            self.publication,
            Some((&self.owner, node.post_write_schema.as_ref().unwrap())),
        )?
        .ok_or_else(|| "APPEND_TEST_SCOPE_MISSING".into())
    }
}

fn actual_callbacks(f: &TwoRoots, scope: Option<&mut PostWriteReadback<'_>>) -> Result<u64> {
    let node = &f.fixture.node;
    let mut calls = 0;
    let mut progress = || {
        calls += 1;
        Ok(())
    };
    match scope {
        Some(scope) => verify(node, f.child, &f.after, scope, &mut progress)?,
        None => reference(node, f.child, &f.after, &mut progress)?,
    }
    Ok(calls)
}

#[test]
fn actual_native_appends_preserve_only_the_original_parent_frontier() {
    let f = two_roots();
    let node = &f.fixture.node;
    let prepared = before_append(&f).apply(node, &mut || Ok(())).unwrap();
    let inserts = prepared.publication.appends.as_ref().unwrap().inserts();
    assert!(inserts > 0);
    let source = prepared.publication.graph.as_ref().unwrap().graphs[0]
        .as_ref()
        .unwrap()
        .record
        .clone();
    let mut scope = prepared.save(node).unwrap();
    assert!(scope.append_insert_seeded);
    assert!(!scope.metadata_insert_seeded);
    assert_eq!(
        scope.ids,
        [
            Some(f.child),
            Some(node.settings.genesis()),
            Some(f.parent),
            None
        ]
    );
    assert!(scope.graphs[0].is_none());
    assert_eq!(scope.graphs[2].as_ref().unwrap().record, source);
    assert!(scope.graphs[2].as_ref().unwrap().source.is_none());
    assert!(scope
        .frontier
        .as_ref()
        .unwrap()
        .is_for(source.id, &source.accounts));
    assert!(scope.frontier.as_ref().unwrap().occupied_slots() <= 16);
    let original = actual_callbacks(&f, None).unwrap();
    let candidate = actual_callbacks(&f, Some(&mut scope)).unwrap();
    assert!(candidate > 5 && candidate < original);
    assert_eq!(scope.partial_uses, 1);
    assert!(scope.subtree_hits > 0);
    assert_eq!(scope.graphs[0].as_ref().unwrap().source, Some(source.id));
    assert!(scope
        .frontier
        .as_ref()
        .unwrap()
        .is_for(source.id, &source.accounts));
    println!("native_append actual_inserts={inserts} original_callbacks={original} candidate_callbacks={candidate} subtree_hits={}", scope.subtree_hits);
    node.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(node.state_at(f.child).unwrap(), f.after);
}

#[test]
fn append_callbacks_extra_failed_no_row_and_reversed_ddl_keep_the_full_reader() {
    for effect in ["no-row", "same-row", "ddl", "failed"] {
        let f = two_roots();
        let node = &f.fixture.node;
        let before = before_append(&f);
        let mut called = false;
        let prepared = before.apply(node, &mut || {
            if !called {
                called = true;
                match effect {
                    "no-row" => { node.db.execute("UPDATE archive_nodes SET data=data WHERE 0", [])?; }
                    "same-row" => { node.db.execute("UPDATE archive_nodes SET data=data", [])?; }
                    "ddl" => node.db.execute_batch("CREATE TABLE append_extra(x); DROP TABLE append_extra")?,
                    "failed" => assert!(node.db.execute(
                        "INSERT INTO archive_nodes(id,data) SELECT id,data FROM archive_nodes LIMIT 1", [],
                    ).is_err()),
                    _ => unreachable!(),
                }
            }
            Ok(())
        }).unwrap();
        assert!(called);
        assert!(prepared.publication.appends.is_some());
        let mut scope = prepared.save(node).unwrap();
        assert!(!scope.append_insert_seeded, "{effect}");
        assert!(scope.frontier.is_none(), "{effect}");
        assert_eq!(
            actual_callbacks(&f, Some(&mut scope)).unwrap(),
            actual_callbacks(&f, None).unwrap(),
            "{effect}"
        );
        assert_eq!(scope.partial_uses, 0);
        node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn append_metadata_boundaries_reject_extra_writes_and_hidden_descendant_damage() {
    for stage in [
        MetadataInsertStage::BeforeSave,
        MetadataInsertStage::AfterSave,
        MetadataInsertStage::AfterCapture,
        MetadataInsertStage::AfterSeed,
    ] {
        for damage in [false, true] {
            let f = two_roots();
            let node = &f.fixture.node;
            let fork = shared_frontier_fork(&f);
            let descendant = child_id(&raw(&node.db, fork), 35);
            let prepared = before_append(&f).apply(node, &mut || Ok(())).unwrap();
            let _hook = MetadataHookGuard::install(move |db, observed| {
                if observed == stage {
                    if damage {
                        assert_eq!(
                            db.execute(
                                "DELETE FROM archive_nodes WHERE id=?",
                                [descendant.as_slice()]
                            )?,
                            1
                        );
                    } else {
                        db.execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
                    }
                }
                Ok(())
            });
            let mut scope = prepared.save(node).unwrap();
            if stage != MetadataInsertStage::AfterSeed {
                assert!(!scope.append_insert_seeded, "{stage:?}");
            }
            let reference = actual_callbacks(&f, None);
            let candidate = actual_callbacks(&f, Some(&mut scope));
            if damage {
                assert_eq!(
                    candidate.unwrap_err().to_string(),
                    reference.unwrap_err().to_string(),
                    "{stage:?}"
                );
            } else {
                assert_eq!(candidate.unwrap(), reference.unwrap(), "{stage:?}");
            }
            assert_eq!(scope.partial_uses, 0);
            assert_eq!(scope.hits, 0);
            node.db.execute_batch("ROLLBACK").unwrap();
        }
    }
}

#[test]
fn append_receipt_rejects_another_scope_even_with_the_same_actual_write_count() {
    let f = two_roots();
    let node = &f.fixture.node;
    let prepared = before_append(&f);
    let mut other = capture(node, f.parent);
    verify(node, f.parent, &f.before, &mut other, &mut || Ok(())).unwrap();
    let mut applied = prepared.apply(node, &mut || Ok(())).unwrap();
    let fact = applied.publication.appends.as_ref().unwrap();
    assert_eq!(
        other.scope.executed_writes_since_capture(&node.db).unwrap(),
        fact.inserts()
    );
    let parent = other.graphs[0].as_ref().unwrap();
    assert!(!fact.is_for(
        &other.graph_scope,
        parent.record.id,
        &parent.record.accounts,
        &applied.record.accounts
    ));
    applied.publication.graph = Some(other);
    let mut scope = applied.save(node).unwrap();
    assert!(!scope.append_insert_seeded);
    assert!(scope.frontier.is_none());
    assert_eq!(
        actual_callbacks(&f, Some(&mut scope)).unwrap(),
        actual_callbacks(&f, None).unwrap()
    );
    node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn append_requires_the_actual_passive_archive_schema_even_with_matching_expected_catalog() {
    for sql in [
        "CREATE INDEX append_extra ON archive_nodes(id)",
        "CREATE INDEX append_extra ON archive_nodes(length(data))",
        "CREATE INDEX append_extra ON archive_nodes(data) WHERE length(data)>0",
        "CREATE TRIGGER append_extra AFTER INSERT ON archive_nodes BEGIN UPDATE archive_nodes SET data=data WHERE 0; END",
    ] {
        let mut f = two_roots();
        f.fixture.node.db.execute_batch(sql).unwrap();
        f.fixture.node.post_write_schema = Some(crate::store::schema(&f.fixture.node.db).unwrap());
        let node = &f.fixture.node;
        let prepared = before_append(&f).apply(node, &mut || Ok(())).unwrap();
        assert!(prepared.publication.appends.is_none(), "{sql}");
        let mut scope = prepared.save(node).unwrap();
        assert!(!scope.append_insert_seeded, "{sql}");
        assert!(scope.frontier.is_none());
        assert_eq!(actual_callbacks(&f, Some(&mut scope)).unwrap(), actual_callbacks(&f, None).unwrap(), "{sql}");
        node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn append_keeps_original_transaction_aba_and_callback_cancellation_refusals() {
    for sql in [
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT append_aba; RELEASE append_aba",
        "SAVEPOINT append_aba; ROLLBACK TO append_aba; RELEASE append_aba",
    ] {
        let f = two_roots();
        let node = &f.fixture.node;
        let before = before_append(&f);
        let mut called = false;
        let prepared = before
            .apply(node, &mut || {
                if !called {
                    called = true;
                    node.db.execute_batch(sql)?;
                }
                Ok(())
            })
            .unwrap();
        let error = prepared.save(node).err().unwrap();
        assert!(
            error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"),
            "{sql}: {error}"
        );
        node.db.execute_batch("ROLLBACK").unwrap();
    }
    let probe = two_roots();
    let mut callbacks = 0;
    let prepared = before_append(&probe)
        .apply(&probe.fixture.node, &mut || {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert!(callbacks > 1);
    drop(prepared);
    probe.fixture.node.db.execute_batch("ROLLBACK").unwrap();
    for cancel_at in [1, callbacks] {
        let f = two_roots();
        let node = &f.fixture.node;
        let mut current = 0;
        let error = before_append(&f)
            .apply(node, &mut || {
                current += 1;
                if current == cancel_at {
                    Err("APPEND_TEST_CANCELLED".into())
                } else {
                    Ok(())
                }
            })
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "APPEND_TEST_CANCELLED");
        assert_eq!(
            node.db
                .query_row(
                    "SELECT COUNT(*) FROM native_state_commitments WHERE block=?",
                    [f.child.as_slice()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        node.db.execute_batch("ROLLBACK").unwrap();
    }
}

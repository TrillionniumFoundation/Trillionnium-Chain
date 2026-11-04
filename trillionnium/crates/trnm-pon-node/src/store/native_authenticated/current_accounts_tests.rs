//! Same-operation account parsing controls on the actual Node and SQLite graph.
//! These are finite local observations, not a service or throughput qualification.
use super::*;
use crate::account_archive_execution::state_witness::CurrentAccounts;
use crate::account_archive_prototype::take_account_parse_observation;
use crate::Node;
use serde_json::json;

struct Fixture {
    node: Node,
    _directory: tempfile::TempDir,
}

fn fixture(extra_accounts: u64) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    for index in 0..extra_accounts {
        settings.initial.insert(
            format!(
                "account:{}",
                hex::encode(hash(
                    b"current-accounts-zero-balance",
                    &[&index.to_le_bytes()]
                ))
            ),
            json!({"balance": 0, "nonce": 7}),
        );
    }
    settings.genesis = hash(
        b"current-accounts-explicit-fixture",
        &[&settings.genesis, &root(&settings.initial).unwrap()],
    );
    let node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    Fixture {
        node,
        _directory: directory,
    }
}

fn verify(
    node: &Node,
    state: &State,
    cache: Option<&ArithmeticCache>,
    stop: Option<usize>,
) -> (std::result::Result<(), String>, usize) {
    let mut checkpoints = 0;
    let result = verify_state_with_cache(
        &node.db,
        &node.settings,
        node.settings.genesis(),
        state,
        &mut || {
            let index = checkpoints;
            checkpoints += 1;
            if stop == Some(index) {
                return Err(Error::from("CURRENT_ACCOUNTS_CANCEL"));
            }
            Ok(())
        },
        cache,
    )
    .map_err(|error| error.to_string());
    (result, checkpoints)
}

fn graph(
    node: &Node,
    account_root: &Root,
    state: &State,
    current_accounts: Option<&CurrentAccounts<'_>>,
    lifts: Option<&native_store::LiftCache>,
    stop: Option<usize>,
) -> (std::result::Result<(), String>, usize) {
    let mut checkpoints = 0;
    let mut progress = || {
        let index = checkpoints;
        checkpoints += 1;
        if stop == Some(index) {
            return Err(Error::from("CURRENT_ACCOUNTS_CANCEL"));
        }
        Ok(())
    };
    let result = match current_accounts {
        Some(current_accounts) => native_store::verify_with_current_accounts(
            &node.db,
            account_root,
            state,
            &mut progress,
            lifts,
            current_accounts,
        ),
        None => {
            native_store::verify_with_lifts(&node.db, account_root, state, &mut progress, lifts)
        }
    }
    .map_err(|error| error.to_string());
    (result, checkpoints)
}

#[test]
fn cold_complete_reuses_actual_account_parse_and_keeps_all_graph_checkpoints() {
    for extra_accounts in [0, 64, 1_024] {
        let fixture = fixture(extra_accounts);
        let node = &fixture.node;
        let state = &node.settings.initial;
        let changes = node.db.total_changes();
        take_account_parse_observation();
        let reference = verify(node, state, None, None);
        assert!(reference.0.is_ok(), "{reference:?}");
        let reference_parses = take_account_parse_observation();
        assert_eq!(reference_parses, (2, state.len() * 2));

        let cache = ArithmeticCache::default();
        let cold = verify(node, state, Some(&cache), None);
        assert_eq!(cold, reference);
        let cold_parses = take_account_parse_observation();
        assert_eq!(cold_parses, (1, state.len()));

        // A complete-cache hit retains no account projection. The real graph
        // still parses the complete actual State, with every original callback.
        let warm = verify(node, state, Some(&cache), None);
        assert_eq!(warm, reference);
        let warm_parses = take_account_parse_observation();
        assert_eq!(warm_parses, (1, state.len()));
        assert_eq!(node.db.total_changes(), changes);

        // Use two fresh arithmetic caches in the same actual writer. The control
        // discards only this call's projection; both scoped verifiers read the
        // complete SQL graph and retain every original checkpoint.
        node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let owner = TransactionScope::capture(&node.db).unwrap();
        let run_scoped = |reuse_projection: bool| {
            let scoped_cache = ArithmeticCache::default();
            if !reuse_projection {
                scoped_cache.discard_current_accounts_for_control();
            }
            let mut scope = PostWriteReadback::new(
                &node.db,
                &node.settings,
                node.settings.genesis(),
                &owner,
                node.post_write_schema.as_ref().unwrap(),
            )
            .unwrap()
            .unwrap();
            take_account_parse_observation();
            let mut checkpoints = 0;
            let result = verify_state_with_readback(
                &node.db,
                &node.settings,
                node.settings.genesis(),
                state,
                &mut || {
                    checkpoints += 1;
                    Ok(())
                },
                Some(&scoped_cache),
                Some(&mut scope),
            )
            .map_err(|error| error.to_string());
            let parses = take_account_parse_observation();
            ((result, checkpoints), parses)
        };
        let scoped_control = run_scoped(false);
        assert_eq!(scoped_control.0, reference);
        assert_eq!(scoped_control.1, reference_parses);
        let scoped_current = run_scoped(true);
        assert_eq!(scoped_current.0, scoped_control.0);
        assert_eq!(scoped_current.1, (1, state.len()));
        node.db.execute_batch("ROLLBACK").unwrap();
        assert_eq!(node.db.total_changes(), changes);

        println!(
            "{}",
            json!({
                "schema": "trnm-current-account-parse-observation-v1",
                "state_keys": state.len(),
                "extra_zero_balance_accounts": extra_accounts,
                "reference_parser_calls": reference_parses.0,
                "reference_scanned_rows": reference_parses.1,
                "cold_parser_calls": cold_parses.0,
                "cold_scanned_rows": cold_parses.1,
                "warm_parser_calls": warm_parses.0,
                "warm_scanned_rows": warm_parses.1,
                "unchanged_verification_checkpoints": reference.1,
                "public_service_qualified": false,
            })
        );
    }
}

#[test]
fn current_projection_is_bound_to_exact_state_and_never_hides_account_changes() {
    let fixture = fixture(16);
    let node = &fixture.node;
    let state = &node.settings.initial;
    let cache = ArithmeticCache::default();
    let (commitment, projection) = cache
        .complete_with_current_accounts(&node.settings, state)
        .unwrap();
    let projection = projection.unwrap();
    let record = load(&node.db, node.settings.genesis()).unwrap();
    assert_eq!(commitment, record.state);
    assert!(projection.values_for(state).is_some());

    let identical = state.clone();
    assert!(projection.values_for(&identical).is_none());
    take_account_parse_observation();
    let identical_result = graph(
        node,
        &record.accounts,
        &identical,
        Some(&projection),
        Some(&cache.lifts),
        None,
    );
    assert!(identical_result.0.is_ok());
    assert_eq!(take_account_parse_observation(), (1, identical.len()));

    let account_key = state
        .keys()
        .find(|key| key.starts_with("account:"))
        .unwrap()
        .clone();
    let mut changed_nonce = state.clone();
    let nonce = changed_nonce[&account_key]["nonce"].as_u64().unwrap();
    changed_nonce.get_mut(&account_key).unwrap()["nonce"] = json!(nonce + 1);
    let mut removed = state.clone();
    removed.remove(&account_key);
    let mut added = state.clone();
    added.insert(
        format!("account:{}", hex::encode([0xfa; 32])),
        json!({"balance": 0, "nonce": 0}),
    );
    let mut bad_number = state.clone();
    bad_number.get_mut(&account_key).unwrap()["nonce"] = json!(1.0);
    let mut bad_owner = state.clone();
    bad_owner.insert(
        format!("account:{}", "G".repeat(64)),
        json!({"balance": 0, "nonce": 0}),
    );
    for changed in [changed_nonce, removed, added, bad_number, bad_owner] {
        assert!(projection.values_for(&changed).is_none());
        let reference = graph(
            node,
            &record.accounts,
            &changed,
            None,
            Some(&cache.lifts),
            None,
        );
        let candidate = graph(
            node,
            &record.accounts,
            &changed,
            Some(&projection),
            Some(&cache.lifts),
            None,
        );
        assert!(reference.0.is_err());
        assert_eq!(candidate, reference);
    }

    let (_, hit_projection) = cache
        .complete_with_current_accounts(&node.settings, state)
        .unwrap();
    assert!(hit_projection.is_none());
}

#[test]
fn current_projection_preserves_complete_root_and_late_error_priority() {
    let fixture = fixture(16);
    let node = &fixture.node;
    let mut changed_root = node.settings.initial.clone();
    changed_root.insert("current-accounts-test".into(), json!(true));
    let mut late_noncanonical = changed_root.clone();
    late_noncanonical.insert("zz-current-accounts-float".into(), json!(1.5));
    let mut bad_account_and_root = late_noncanonical.clone();
    bad_account_and_root.insert(
        format!("account:{}", "G".repeat(64)),
        json!({"balance": 0, "nonce": 0}),
    );
    for changed in [changed_root, late_noncanonical, bad_account_and_root] {
        let reference = verify(node, &changed, None, None);
        let cache = ArithmeticCache::default();
        let candidate = verify(node, &changed, Some(&cache), None);
        assert!(reference.0.is_err());
        assert_eq!(candidate, reference);
    }
}

#[test]
fn current_projection_rereads_corrupt_sql_and_preserves_every_cancellation() {
    let fixture = fixture(32);
    let node = &fixture.node;
    let state = &node.settings.initial;
    let record = load(&node.db, node.settings.genesis()).unwrap();
    let cache = ArithmeticCache::default();
    let (_, projection) = cache
        .complete_with_current_accounts(&node.settings, state)
        .unwrap();
    let projection = projection.unwrap();
    let reference = graph(
        node,
        &record.accounts,
        state,
        None,
        Some(&cache.lifts),
        None,
    );
    assert!(reference.0.is_ok());
    assert!(reference.1 > 2);
    assert_eq!(
        graph(
            node,
            &record.accounts,
            state,
            Some(&projection),
            Some(&cache.lifts),
            None,
        ),
        reference
    );
    for stop in 0..reference.1 {
        let expected = graph(
            node,
            &record.accounts,
            state,
            None,
            Some(&cache.lifts),
            Some(stop),
        );
        let observed = graph(
            node,
            &record.accounts,
            state,
            Some(&projection),
            Some(&cache.lifts),
            Some(stop),
        );
        assert!(expected.0.is_err());
        assert_eq!(expected.1, stop + 1);
        assert_eq!(observed, expected);
    }

    // The projection predates both writes. Root and non-root rows must still
    // be fetched from current SQL; no successful graph verdict is retained.
    let root_id = record.accounts.node.unwrap();
    let child_id: Vec<u8> = node
        .db
        .query_row(
            "SELECT id FROM archive_nodes WHERE id!=? ORDER BY id LIMIT 1",
            [root_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    for id in [root_id.to_vec(), child_id] {
        let original: Vec<u8> = node
            .db
            .query_row(
                "SELECT data FROM archive_nodes WHERE id=?",
                [id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        for delete in [false, true] {
            if delete {
                node.db
                    .execute("DELETE FROM archive_nodes WHERE id=?", [id.as_slice()])
                    .unwrap();
            } else {
                node.db
                    .execute(
                        "UPDATE archive_nodes SET data=? WHERE id=?",
                        params![vec![0u8], id.as_slice()],
                    )
                    .unwrap();
            }
            let expected = graph(
                node,
                &record.accounts,
                state,
                None,
                Some(&cache.lifts),
                None,
            );
            let observed = graph(
                node,
                &record.accounts,
                state,
                Some(&projection),
                Some(&cache.lifts),
                None,
            );
            assert!(expected.0.is_err());
            assert_eq!(observed, expected);
            node.db
                .execute(
                    "INSERT OR REPLACE INTO archive_nodes(id,data) VALUES(?,?)",
                    params![id.as_slice(), &original],
                )
                .unwrap();
        }
    }
    let repaired = graph(
        node,
        &record.accounts,
        state,
        Some(&projection),
        Some(&cache.lifts),
        None,
    );
    assert!(repaired.0.is_ok());
}

#[test]
fn cold_full_validation_projection_abba_observation_without_timing_gate() {
    for extra_accounts in [64, 1_024] {
        let fixture = fixture(extra_accounts);
        let node = &fixture.node;
        let state = &node.settings.initial;
        let expected = verify(node, state, None, None);
        assert!(expected.0.is_ok());
        let mut samples = Vec::new();
        for round in 0..3 {
            for reuse in [false, true, true, false] {
                // Both variants use identical fresh native arithmetic caches.
                // Only the control discards this call's account projection,
                // forcing the original parser before the full SQL graph walk.
                let cache = ArithmeticCache::default();
                if !reuse {
                    cache.discard_current_accounts_for_control();
                }
                take_account_parse_observation();
                let start = std::time::Instant::now();
                let result = verify(
                    std::hint::black_box(node),
                    std::hint::black_box(state),
                    Some(&cache),
                    None,
                );
                std::hint::black_box(&result);
                let wall_ns = start.elapsed().as_nanos();
                let (parser_calls, scanned_rows) = take_account_parse_observation();
                assert_eq!(result, expected);
                let expected_calls = if reuse { 1 } else { 2 };
                assert_eq!(parser_calls, expected_calls);
                assert_eq!(scanned_rows, expected_calls * state.len());
                samples.push(json!({
                    "round": round,
                    "reuse_current_accounts": reuse,
                    "wall_ns": wall_ns,
                    "parser_calls": parser_calls,
                    "scanned_rows": scanned_rows,
                    "verification_checkpoints": result.1,
                }));
            }
        }
        println!(
            "{}",
            json!({
                "schema": "trnm-current-account-full-validation-observation-v1",
                "state_keys": state.len(),
                "extra_zero_balance_accounts": extra_accounts,
                "samples": samples,
                "scope": "complete verify_state_with_cache call with fresh identical arithmetic caches, current record/block/delta checks, all roots and full SQL account graph; test-only parser counters are compiled in",
                "excludes": "Node opening, block execution/admission, network, writer contention, client confirmation and RSS",
                "public_service_qualified": false,
            })
        );
    }
}

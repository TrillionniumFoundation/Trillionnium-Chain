//! Differential storage tests. The old per-account insertion is retained only
//! here as a reference; no production fallback or history-pruning path exists.
use super::*;
use crate::account_archive_prototype::{multiproof, Context};
use crate::ErrorCode;
use serde_json::json;
use trnm_protocol::pon_wire::hash;

fn owner(index: u64) -> Hash {
    hash(b"native-account-batch-test-owner", &[&index.to_le_bytes()])
}

fn key(index: u64) -> String {
    format!("account:{}", hex::encode(owner(index)))
}

fn initial(count: u64) -> State {
    (0..count)
        .map(|index| {
            (
                key(index),
                json!({"balance":1_000 + index,"nonce":index % 7}),
            )
        })
        .collect()
}

fn rows(before: &State, after: &State) -> Vec<crate::store::Delta> {
    before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|key| {
            let old = before
                .get(key)
                .map(|value| serde_json::to_vec(value).unwrap());
            let new = after
                .get(key)
                .map(|value| serde_json::to_vec(value).unwrap());
            (old != new).then(|| (key.clone(), old, new))
        })
        .collect()
}

fn stored(db: &Connection) -> BTreeMap<Hash, Vec<u8>> {
    db.prepare("SELECT id,data FROM archive_nodes ORDER BY id")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .unwrap()
        .map(|row| {
            let (id, raw) = row.unwrap();
            (id.try_into().unwrap(), raw)
        })
        .collect()
}

fn reachable(db: &Connection, roots: &[Root]) -> BTreeSet<Hash> {
    let empty = super::super::empty_hashes();
    let mut pending = roots
        .iter()
        .filter_map(|root| load_root(db, root, &empty).unwrap())
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    while let Some(node) = pending.pop() {
        if !seen.insert(node.id) {
            continue;
        }
        if matches!(node.kind, Kind::Fork { .. }) {
            pending.push(super::super::child(db, &node, false, &empty).unwrap());
            pending.push(super::super::child(db, &node, true, &empty).unwrap());
        }
    }
    seen
}

/// The exact earlier insertion order: each changed leaf copies and immediately
/// saves its path, even when the following leaf replaces that intermediate root.
fn serial_reference(db: &Connection, parent: &Root, changes: &[crate::store::Delta]) -> Root {
    let empty = super::super::empty_hashes();
    let original = load_root(db, parent, &empty).unwrap();
    let mut next = original.clone();
    let mut count = parent.count;
    let mut balance = i128::from(parent.balance);
    for (key, before, after) in changes {
        if !key.starts_with("account:") {
            continue;
        }
        let (owner, account) = account(key, after.as_ref().unwrap()).unwrap();
        let prior = before
            .as_ref()
            .map(|bytes| super::account(key, bytes).unwrap().1);
        assert_eq!(lookup(db, original.clone(), owner, &empty).unwrap(), prior);
        assert!(prior.is_none_or(|prior| account.nonce >= prior.nonce));
        count += u64::from(prior.is_none());
        balance -= i128::from(prior.map_or(0, |prior| prior.balance));
        balance += i128::from(account.balance);
        let leaf = Node::account(owner, account);
        super::super::save_node(db, &leaf).unwrap();
        next = Some(super::super::insert(db, next.as_ref(), leaf, &empty, &mut || Ok(())).unwrap());
    }
    Root {
        node: next.as_ref().map(|node| node.id),
        digest: next.as_ref().map_or(empty[0], |node| node.lift(0, &empty)),
        count,
        balance: balance.try_into().unwrap(),
    }
}

fn query(db: &Connection, root: &Root, state: &State, branch: u64) -> Vec<u8> {
    let context = Context {
        network: [21; 32],
        parameters: [22; 32],
        genesis: [23; 32],
    };
    let checkpoint = query_checkpoint(
        db,
        context,
        hash(
            b"native-account-batch-test-branch",
            &[&branch.to_le_bytes()],
        ),
        branch,
        trnm_mvcc_fee::pon_executor::root(state).unwrap(),
        root,
    )
    .unwrap();
    let requested = [owner(0), owner(7), owner(17), owner(500)];
    let (proof, _) = multiproof::from_native_database(db, &checkpoint, &requested, &|_| {
        Ok::<_, crate::account_archive_prototype::ArchiveError>(())
    })
    .unwrap();
    let checked = multiproof::CheckedMultiproof::verify(context, &checkpoint, &proof).unwrap();
    for (index, identity) in requested.into_iter().enumerate() {
        let name = format!("account:{}", hex::encode(identity));
        let expected = state.get(&name).map(|value| Account {
            balance: value["balance"].as_u64().unwrap(),
            nonce: value["nonce"].as_u64().unwrap(),
        });
        assert_eq!(
            checked.account(identity).unwrap(),
            expected,
            "query {index}"
        );
    }
    proof.encode().unwrap()
}

#[test]
fn batched_paths_match_serial_versions_and_keep_every_insert_reachable() {
    let mut totals = (0usize, 0usize);
    for initial_count in [0u64, 1, 31, 257] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("batch.sqlite");
        let db = Connection::open(&path).unwrap();
        let reference = Connection::open_in_memory().unwrap();
        for connection in [&db, &reference] {
            connection
                .execute_batch(crate::store::native_authenticated::DDL)
                .unwrap();
        }
        let first = initial(initial_count);
        let first_root = seed(&db, &first, &mut || Ok(())).unwrap();
        assert_eq!(
            first_root,
            seed(&reference, &first, &mut || Ok(())).unwrap()
        );
        let mut states = vec![first];
        let mut roots = vec![first_root];
        let mut serial_roots = roots.clone();
        for (index, parent) in [0usize, 0, 1, 2, 3, 0, 5, 4].into_iter().enumerate() {
            let mut after = states[parent].clone();
            for update in 0..41u64 {
                let account = after
                    .entry(key((update * 17 + index as u64 * 13) % (initial_count + 83)))
                    .or_insert_with(|| json!({"balance":0,"nonce":0}));
                account["balance"] = json!(account["balance"].as_u64().unwrap() + 11 + update);
                account["nonce"] = json!(account["nonce"].as_u64().unwrap() + 1);
            }
            let changes = rows(&states[parent], &after);
            let old_rows = stored(&db);
            let transaction = db.unchecked_transaction().unwrap();
            let next = apply(&transaction, &roots[parent], &changes, &mut || Ok(())).unwrap();
            verify(&transaction, &next, &after, &mut || Ok(())).unwrap();
            transaction.commit().unwrap();
            let expected = serial_reference(&reference, &serial_roots[parent], &changes);
            assert_eq!(next, expected);
            let new_rows = stored(&db);
            assert!(old_rows
                .iter()
                .all(|(id, bytes)| new_rows.get(id) == Some(bytes)));
            let next_reachable = reachable(&db, std::slice::from_ref(&next));
            for identity in new_rows.keys().filter(|id| !old_rows.contains_key(*id)) {
                assert!(next_reachable.contains(identity));
            }
            states.push(after);
            roots.push(next);
            serial_roots.push(expected);
            // Every version and side branch is retained, including genesis.
            for (version, state) in states.iter().enumerate() {
                verify(&db, &roots[version], state, &mut || Ok(())).unwrap();
                verify(&reference, &serial_roots[version], state, &mut || Ok(())).unwrap();
                assert_eq!(
                    query(&db, &roots[version], state, version as u64),
                    query(&reference, &serial_roots[version], state, version as u64),
                );
            }
            assert_eq!(reachable(&db, &roots), new_rows.keys().copied().collect());
        }
        // Empty/non-account deltas cannot create a new account version.
        let before = stored(&db);
        let no_accounts = vec![("meta:test-only".into(), None, Some(b"1".to_vec()))];
        assert_eq!(
            apply(&db, roots.last().unwrap(), &no_accounts, &mut || Ok(())).unwrap(),
            *roots.last().unwrap()
        );
        assert_eq!(stored(&db), before);
        totals.0 += before.len();
        totals.1 += stored(&reference).len();
        drop(db);
        let reopened = Connection::open(&path).unwrap();
        assert_eq!(stored(&reopened), before);
        for (version, state) in states.iter().enumerate() {
            verify(&reopened, &roots[version], state, &mut || Ok(())).unwrap();
            assert_eq!(
                query(&reopened, &roots[version], state, version as u64),
                query(&reference, &serial_roots[version], state, version as u64),
            );
        }
    }
    assert!(totals.0 < totals.1);
    eprintln!(
        "native batch component: persisted_nodes={}, serial_reference_nodes={}, prior_versions_deleted=0, new_unreachable_nodes=0; synthetic storage states, not admitted blocks",
        totals.0, totals.1
    );
}

#[test]
fn batched_paths_cancel_and_sql_refusal_roll_back_partial_writes_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("batch.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let before_state = initial(31);
    let parent = seed(&db, &before_state, &mut || Ok(())).unwrap();
    let mut after = before_state.clone();
    for update in 0..24 {
        after.insert(key(update), json!({"balance":7 + update,"nonce":19}));
    }
    for update in 31..43 {
        after.insert(key(update), json!({"balance":update,"nonce":1}));
    }
    let changes = rows(&before_state, &after);
    let before = stored(&db);
    let mut checkpoints = 0;
    let transaction = db.unchecked_transaction().unwrap();
    apply(&transaction, &parent, &changes, &mut || {
        checkpoints += 1;
        Ok(())
    })
    .unwrap();
    assert!(stored(&db).len() > before.len());
    transaction.rollback().unwrap();
    let mut cancelled_after_write = false;
    for cut in [1usize, changes.len() + 1, checkpoints / 2, checkpoints] {
        let transaction = db.unchecked_transaction().unwrap();
        let mut calls = 0;
        let failure = apply(&transaction, &parent, &changes, &mut || {
            calls += 1;
            if calls == cut {
                Err(Error::new(ErrorCode::PublicRequestCancelled))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(failure.is(ErrorCode::PublicRequestCancelled));
        assert!(!failure.requires_owner_stop());
        assert_eq!(calls, cut);
        cancelled_after_write |= stored(&db).len() > before.len();
        transaction.rollback().unwrap();
        assert_eq!(stored(&db), before);
    }
    assert!(cancelled_after_write);
    db.execute_batch(
        "CREATE TEMP TRIGGER reject_batch_fork BEFORE INSERT ON archive_nodes
         WHEN substr(NEW.data,1,1)=X'01'
         BEGIN SELECT RAISE(ABORT,'batch fork write refused'); END;",
    )
    .unwrap();
    let transaction = db.unchecked_transaction().unwrap();
    let error = apply(&transaction, &parent, &changes, &mut || Ok(())).unwrap_err();
    assert!(error.requires_owner_stop());
    assert!(stored(&db).len() > before.len());
    transaction.rollback().unwrap();
    assert_eq!(stored(&db), before);
    db.execute_batch("DROP TRIGGER reject_batch_fork").unwrap();
    let transaction = db.unchecked_transaction().unwrap();
    let next = apply(&transaction, &parent, &changes, &mut || Ok(())).unwrap();
    transaction.commit().unwrap();
    let committed = stored(&db);
    assert_eq!(
        reachable(&db, &[parent.clone(), next.clone()]),
        committed.keys().copied().collect()
    );
    drop(db);
    let reopened = Connection::open(&path).unwrap();
    assert_eq!(stored(&reopened), committed);
    verify(&reopened, &parent, &before_state, &mut || Ok(())).unwrap();
    verify(&reopened, &next, &after, &mut || Ok(())).unwrap();
    query(&reopened, &parent, &before_state, 0);
    query(&reopened, &next, &after, 1);
}

#[test]
fn batched_paths_keep_original_parent_nonce_and_no_deletion_checks() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let state = initial(2);
    let parent = seed(&db, &state, &mut || Ok(())).unwrap();
    let before = stored(&db);
    let old = serde_json::to_vec(&state[&key(1)]).unwrap();
    for changes in [
        vec![(key(1), Some(old.clone()), None)],
        vec![(
            key(1),
            Some(old.clone()),
            Some(br#"{"balance":9,"nonce":0}"#.to_vec()),
        )],
        vec![(key(1), None, Some(br#"{"balance":9,"nonce":1}"#.to_vec()))],
        vec![
            (
                key(1),
                Some(old.clone()),
                Some(br#"{"balance":9,"nonce":2}"#.to_vec()),
            ),
            (
                key(1),
                Some(old),
                Some(br#"{"balance":9,"nonce":2}"#.to_vec()),
            ),
        ],
    ] {
        let transaction = db.unchecked_transaction().unwrap();
        assert!(apply(&transaction, &parent, &changes, &mut || Ok(()))
            .unwrap_err()
            .requires_owner_stop());
        transaction.rollback().unwrap();
        assert_eq!(stored(&db), before);
        verify(&db, &parent, &state, &mut || Ok(())).unwrap();
    }
}

fn signed(settings: &crate::Settings, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    let mut transaction = trnm_protocol::pon_wire::Envelope {
        network: settings.network(),
        sender: crate::development_public(0).unwrap(),
        nonce,
        expiry: 2_000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}

#[test]
#[ignore = "explicit release full-capacity gate in both head and prospective-merge CI"]
fn native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover() {
    use crate::{Node as NativeNode, Settings};
    use trnm_mvcc_fee::{continuity_v1, pon_executor::root};

    if cfg!(debug_assertions) {
        panic!("the full 65,536-key native acceptance gate requires --release --exact --ignored");
    }
    let started = std::time::Instant::now();
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_0 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"genesis_and_both_nodes_open","height":0,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    let mut settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let dormant = format!(
        "account:{}",
        hex::encode(hash(
            b"native-authenticated-full-capacity",
            &[&0u64.to_le_bytes()]
        ))
    );
    // A distinct, explicitly preallocated test genesis. Every filler row is an
    // actual retained account with nonce 7; no smaller key limit, skipped height
    // or generated-account history is substituted for this capacity boundary.
    for index in 0u64.. {
        if settings.initial.len() == continuity_v1::MAX_KEYS - 20 - 1 {
            break;
        }
        settings.initial.insert(
            format!(
                "account:{}",
                hex::encode(hash(
                    b"native-authenticated-full-capacity",
                    &[&index.to_le_bytes()]
                ))
            ),
            json!({"balance":0,"nonce":7}),
        );
    }
    continuity_v1::check_state(&settings.initial, 0, &settings.app).unwrap();
    settings.genesis = hash(
        b"genesis",
        &[
            &settings.network(),
            &settings.parameters(),
            &root(&settings.initial).unwrap(),
            &settings.genesis_time().to_le_bytes(),
        ],
    );
    let directory = tempfile::tempdir().unwrap();
    let producer_directory = directory.path().join("producer");
    let validator_directory = directory.path().join("authenticated");
    let mut producer = NativeNode::open(&producer_directory, settings.clone(), 1).unwrap();
    let mut validator =
        NativeNode::open_with_authenticated_state(&validator_directory, settings.clone(), 1)
            .unwrap();
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"genesis_and_both_nodes_open","height":0,"elapsed_seconds":pon_phase_clock_0.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    let miner = crate::development_public(0).unwrap();
    let miner_key = format!("account:{}", hex::encode(miner));
    let consumer = crate::development_public(1).unwrap();
    let provider = crate::development_public(2).unwrap();
    let units = 1u64;
    let deadline = 21u64;
    let quota = hash(
        b"quota-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &miner,
            &1u64.to_le_bytes(),
            &consumer,
            &provider,
            &units.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let quota_key = format!("quota:{}", hex::encode(quota));
    let mut payload = quota.to_vec();
    payload.extend(consumer);
    payload.extend(provider);
    payload.extend(units.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    let open = signed(&settings, 1, 10, payload);
    eprintln!(
        "authenticated full capacity: initialized real {}-key test genesis in {:?}",
        settings.initial.len(),
        started.elapsed()
    );
    for height in 1..=20u64 {
        // BEGIN PON_CAPACITY_PHASE_V1
        let pon_phase_clock_1 = std::time::Instant::now();
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"begin","phase":"producer_make","height":height,"elapsed_seconds":0.0})
        );
        // END PON_CAPACITY_PHASE_V1
        let packet = producer
            .make_consensus_maintenance(
                producer.active().unwrap().0,
                if height == 1 {
                    vec![open.clone()]
                } else {
                    vec![]
                },
                miner,
                1 + height * 10,
                4096,
            )
            .unwrap();
        // BEGIN PON_CAPACITY_PHASE_V1
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"end","phase":"producer_make","height":height,"elapsed_seconds":pon_phase_clock_1.elapsed().as_secs_f64()})
        );
        // END PON_CAPACITY_PHASE_V1
        // BEGIN PON_CAPACITY_PHASE_V1
        let pon_phase_clock_2 = std::time::Instant::now();
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"begin","phase":"producer_admit","height":height,"elapsed_seconds":0.0})
        );
        // END PON_CAPACITY_PHASE_V1
        let id = producer.admit(&packet, 100_000).unwrap();
        // BEGIN PON_CAPACITY_PHASE_V1
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"end","phase":"producer_admit","height":height,"elapsed_seconds":pon_phase_clock_2.elapsed().as_secs_f64()})
        );
        // END PON_CAPACITY_PHASE_V1
        // BEGIN PON_CAPACITY_PHASE_V1
        let pon_phase_clock_3 = std::time::Instant::now();
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"begin","phase":"producer_activate","height":height,"elapsed_seconds":0.0})
        );
        // END PON_CAPACITY_PHASE_V1
        producer.activate(id).unwrap();
        // BEGIN PON_CAPACITY_PHASE_V1
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"end","phase":"producer_activate","height":height,"elapsed_seconds":pon_phase_clock_3.elapsed().as_secs_f64()})
        );
        // END PON_CAPACITY_PHASE_V1
        // BEGIN PON_CAPACITY_PHASE_V1
        let pon_phase_clock_4 = std::time::Instant::now();
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"begin","phase":"validator_admit","height":height,"elapsed_seconds":0.0})
        );
        // END PON_CAPACITY_PHASE_V1
        assert_eq!(validator.admit(&packet, 100_000).unwrap(), id);
        // BEGIN PON_CAPACITY_PHASE_V1
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"end","phase":"validator_admit","height":height,"elapsed_seconds":pon_phase_clock_4.elapsed().as_secs_f64()})
        );
        // END PON_CAPACITY_PHASE_V1
        // BEGIN PON_CAPACITY_PHASE_V1
        let pon_phase_clock_5 = std::time::Instant::now();
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"begin","phase":"validator_activate","height":height,"elapsed_seconds":0.0})
        );
        // END PON_CAPACITY_PHASE_V1
        assert_eq!(validator.activate(id).unwrap(), id);
        // BEGIN PON_CAPACITY_PHASE_V1
        eprintln!(
            "pon_capacity_phase_v1 {}",
            json!({"event":"end","phase":"validator_activate","height":height,"elapsed_seconds":pon_phase_clock_5.elapsed().as_secs_f64()})
        );
        // END PON_CAPACITY_PHASE_V1
        eprintln!(
            "authenticated full capacity: actual admitted height {height}, elapsed {:?}",
            started.elapsed()
        );
    }
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_6 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"h20_full_state_and_capacity_checks","height":20,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    let full = validator.read_active().unwrap();
    assert_eq!(full, producer.read_active().unwrap());
    assert_eq!(full.2.len(), continuity_v1::MAX_KEYS);
    assert_eq!(
        continuity_v1::capacity(&full.2, 20, &settings.app)
            .unwrap()
            .required_keys,
        continuity_v1::MAX_KEYS
    );
    assert_eq!(full.2[&dormant]["nonce"], 7);
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"h20_full_state_and_capacity_checks","height":20,"elapsed_seconds":pon_phase_clock_6.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    let recipient = crate::development_public(4).unwrap();
    let recipient_key = format!("account:{}", hex::encode(recipient));
    let mut payload = recipient.to_vec();
    payload.extend(1u64.to_le_bytes());
    let enter = signed(&settings, 2, 1, payload);
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_7 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"h21_growth_rejection_and_rollback_checks","height":21,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    // The h21 refund consumes no new key, but its expired quota row cannot be
    // reclaimed until h22. Rejected optional growth rolls back that prologue.
    assert_eq!(
        validator
            .make_consensus_maintenance(full.0, vec![enter.clone()], miner, 211, 4096)
            .unwrap_err()
            .to_string(),
        "STATE_CAPACITY"
    );
    assert_eq!(validator.read_active().unwrap(), full);
    assert_eq!(validator.next_nonce(miner).unwrap(), 2);
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"h21_growth_rejection_and_rollback_checks","height":21,"elapsed_seconds":pon_phase_clock_7.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_8 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"h21_refund_and_state_checks","height":21,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    let packet = producer
        .make_consensus_maintenance(full.0, vec![], miner, 211, 4096)
        .unwrap();
    let refunded_id = producer.admit(&packet, 100_000).unwrap();
    producer.activate(refunded_id).unwrap();
    assert_eq!(validator.admit(&packet, 100_000).unwrap(), refunded_id);
    validator.activate(refunded_id).unwrap();
    let refunded = validator.read_active().unwrap();
    assert_eq!(refunded, producer.read_active().unwrap());
    assert_eq!(refunded.2.len(), continuity_v1::MAX_KEYS);
    assert_eq!(refunded.2[&quota_key]["remaining"], 0);
    assert_eq!(refunded.2[&quota_key]["status"], "expired");
    assert!(!refunded.2.contains_key(&recipient_key));
    let mature: u64 = full
        .2
        .iter()
        .filter(|(name, value)| name.starts_with("reward:") && value["maturity"] == 21)
        .map(|(_, value)| value["amount"].as_u64().unwrap())
        .sum();
    assert_eq!(
        refunded.2[&miner_key]["balance"].as_u64().unwrap(),
        full.2[&miner_key]["balance"].as_u64().unwrap()
            + mature
            + full.2[&quota_key]["remaining"].as_u64().unwrap()
    );
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"h21_refund_and_state_checks","height":21,"elapsed_seconds":pon_phase_clock_8.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_9 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"h22_reentry_state_and_membership_proof","height":22,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    let packet = producer
        .make_consensus_maintenance(refunded_id, vec![enter], miner, 221, 4096)
        .unwrap();
    let entered_id = producer.admit(&packet, 100_000).unwrap();
    producer.activate(entered_id).unwrap();
    assert_eq!(validator.admit(&packet, 100_000).unwrap(), entered_id);
    validator.activate(entered_id).unwrap();
    let entered = validator.read_active().unwrap();
    assert_eq!(entered, producer.read_active().unwrap());
    assert_eq!(entered.2.len(), continuity_v1::MAX_KEYS);
    assert!(!entered.2.contains_key(&quota_key));
    assert_eq!(entered.2[&recipient_key]["balance"], 1);
    assert_eq!(entered.2[&dormant]["nonce"], 7);
    assert_eq!(validator.next_nonce(miner).unwrap(), 3);
    let (checkpoint, proof, _) = validator
        .authenticated_account_multiproof(entered_id, &[recipient])
        .unwrap();
    assert_eq!(
        multiproof::CheckedMultiproof::verify(
            Context {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis()
            },
            &checkpoint,
            &proof
        )
        .unwrap()
        .account(recipient)
        .unwrap(),
        Some(Account {
            balance: 1,
            nonce: 0
        })
    );
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"h22_reentry_state_and_membership_proof","height":22,"elapsed_seconds":pon_phase_clock_9.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_10 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"side_branch_construction_and_admission","height":23,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    // A real equal-work side block remains unselected. Only its strictly
    // heavier child starts the ordinary resumable reorganization.
    let fork22 = producer
        .make_consensus_maintenance(refunded_id, vec![], miner, 222, 4096)
        .unwrap();
    let fork22_id = producer.admit(&fork22, 100_000).unwrap();
    assert_eq!(validator.admit(&fork22, 100_000).unwrap(), fork22_id);
    assert_eq!(validator.activate(fork22_id).unwrap(), entered_id);
    let fork23 = producer
        .make_consensus_maintenance(fork22_id, vec![], miner, 231, 4096)
        .unwrap();
    let fork23_id = producer.admit(&fork23, 100_000).unwrap();
    assert_eq!(validator.admit(&fork23, 100_000).unwrap(), fork23_id);
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"side_branch_construction_and_admission","height":23,"elapsed_seconds":pon_phase_clock_10.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_11 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"reorganization_fault_and_old_state_check","height":23,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    let mut cuts = 0;
    let error = validator
        .activate_with_fault(
            fork23_id,
            Some(&mut |point| {
                if point == "detach:0" {
                    cuts += 1;
                    Err(Error::from("AUTHENTICATED_FULL_CAPACITY_REORG_CUT"))
                } else {
                    Ok(())
                }
            }),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "AUTHENTICATED_FULL_CAPACITY_REORG_CUT");
    assert_eq!(cuts, 1);
    assert_eq!(validator.read_active().unwrap(), entered);
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"reorganization_fault_and_old_state_check","height":23,"elapsed_seconds":pon_phase_clock_11.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    drop(validator);
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_12 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"first_cold_reopen_recovery_and_proof","height":23,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    let validator =
        NativeNode::open_with_authenticated_state(&validator_directory, settings.clone(), 1)
            .unwrap();
    producer.activate(fork23_id).unwrap();
    let recovered = validator.read_active().unwrap();
    assert_eq!(recovered, producer.read_active().unwrap());
    assert_eq!(recovered.0, fork23_id);
    assert_eq!(recovered.2.len(), continuity_v1::MAX_KEYS - 1);
    assert!(!recovered.2.contains_key(&recipient_key));
    assert!(!recovered.2.contains_key(&quota_key));
    assert_eq!(recovered.2[&dormant]["nonce"], 7);
    assert_eq!(validator.next_nonce(miner).unwrap(), 2);
    let (checkpoint, proof, _) = validator
        .authenticated_account_multiproof(fork23_id, &[recipient])
        .unwrap();
    assert_eq!(
        multiproof::CheckedMultiproof::verify(
            Context {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis()
            },
            &checkpoint,
            &proof
        )
        .unwrap()
        .account(recipient)
        .unwrap(),
        None
    );
    // Retained old branch bytes and its admitted root remain available. The
    // pre-reorg membership proof stays bound to that old checkpoint only.
    assert_eq!(
        validator.packet(entered_id).unwrap().header.state,
        root(&entered.2).unwrap()
    );
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"first_cold_reopen_recovery_and_proof","height":23,"elapsed_seconds":pon_phase_clock_12.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    drop(validator);
    // BEGIN PON_CAPACITY_PHASE_V1
    let pon_phase_clock_13 = std::time::Instant::now();
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"begin","phase":"second_cold_reopen_final_state_check","height":23,"elapsed_seconds":0.0})
    );
    // END PON_CAPACITY_PHASE_V1
    let reopened =
        NativeNode::open_with_authenticated_state(&validator_directory, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), recovered);
    // BEGIN PON_CAPACITY_PHASE_V1
    eprintln!(
        "pon_capacity_phase_v1 {}",
        json!({"event":"end","phase":"second_cold_reopen_final_state_check","height":23,"elapsed_seconds":pon_phase_clock_13.elapsed().as_secs_f64()})
    );
    // END PON_CAPACITY_PHASE_V1
    eprintln!("authenticated full capacity: accepted_native_packets=24, signed_transactions=2, rejected_growth=1, full_keys=65536, quota_refund=1, recipient_reentry=1, reorg_cut=detach:0, cold_reopens=2, synthetic_preallocated_genesis=true, elapsed {:?}", started.elapsed());
}

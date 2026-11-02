//! Actual SQLite history facts inside one original writer. These controls do
//! not qualify cross-transaction O(H), service deadlines or a persistent anchor.
use super::super::{
    verify_history_with_cache, verify_history_with_readback, verify_state_with_readback,
};
use super::*;
use crate::Node;

struct Fixture {
    node: Node,
    directory: tempfile::TempDir,
    chain: Vec<Hash>,
}

fn append(node: &mut Node, parent: Hash, miner: u64, timestamp: u64) -> Hash {
    let packet = node
        .make_consensus_maintenance(
            parent,
            vec![],
            crate::development_public(miner).unwrap(),
            timestamp,
            4096,
        )
        .unwrap();
    node.admit(&packet, 100_000).unwrap()
}

fn fixture(height: u64) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    let mut chain = vec![node.settings.genesis()];
    for height in 1..=height {
        chain.push(append(
            &mut node,
            *chain.last().unwrap(),
            height,
            10 + height,
        ));
    }
    node.activate_observed(*chain.last().unwrap(), 100_000)
        .unwrap();
    Fixture {
        node,
        directory,
        chain,
    }
}

fn begin_scope(node: &Node, child: Hash) -> PostWriteReadback<'_> {
    let state = node.state_at(child).unwrap();
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let owner = TransactionScope::capture(&node.db).unwrap();
    let mut scope = PostWriteReadback::new(
        &node.db,
        &node.settings,
        child,
        &owner,
        node.post_write_schema.as_ref().unwrap(),
    )
    .unwrap()
    .unwrap();
    verify_state_with_readback(
        &node.db,
        &node.settings,
        child,
        &state,
        &mut || Ok(()),
        Some(&node.authenticated_arithmetic),
        Some(&mut scope),
    )
    .unwrap();
    assert!(scope.histories.iter().all(Option::is_none));
    scope
}

fn history(
    node: &Node,
    block: Hash,
    scope: &mut PostWriteReadback<'_>,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    verify_history_with_readback(
        &node.db,
        &node.settings,
        block,
        progress,
        Some(&node.authenticated_arithmetic),
        Some(scope),
    )
}

fn packet_reads(node: &Node) -> u64 {
    node.native_history_arithmetic_observation()["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["stage"] == "packet")
        .unwrap()["totals"]["calls"]
        .as_u64()
        .unwrap()
}

#[test]
fn native_same_writer_suffix_reuse_keeps_first_complete_history_and_actual_anchor_read() {
    let f = fixture(4);
    let tip = f.chain[4];
    let mut scope = begin_scope(&f.node, tip);
    let before = packet_reads(&f.node);
    history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
    let complete_reads = packet_reads(&f.node) - before;
    assert_eq!(complete_reads, 6); // Five retained blocks plus full genesis State.
    assert_eq!(scope.history_hits, 0);
    assert_eq!(scope.history_match_epoch_checks, 0);
    assert!(!scope.consumed);
    let before = packet_reads(&f.node);
    history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(packet_reads(&f.node) - before, 1);
    assert_eq!(scope.history_hits, 1);
    assert_eq!(scope.history_match_epoch_checks, 2); // Before/after the hit checkpoint.
    assert!(scope.consumed);
    assert!(scope.histories.iter().flatten().count() <= 4);
    scope.validate_consumed(&f.node.db).unwrap();
}

#[test]
fn native_fork_history_reuses_only_its_actual_verified_common_ancestor() {
    let mut f = fixture(2);
    let branch2 = append(&mut f.node, f.chain[1], 91, 25);
    let branch3 = append(&mut f.node, branch2, 92, 26);
    let mut scope = begin_scope(&f.node, f.chain[2]);
    history(&f.node, f.chain[2], &mut scope, &mut || Ok(())).unwrap();
    let before = packet_reads(&f.node);
    history(&f.node, branch3, &mut scope, &mut || Ok(())).unwrap();
    // Both new fork blocks and the actual non-genesis common ancestor are read.
    assert_eq!(packet_reads(&f.node) - before, 3);
    assert_eq!(scope.history_hits, 1);
    assert_eq!(scope.history_match_epoch_checks, 2);
    verify_history_with_cache(
        &f.node.db,
        &f.node.settings,
        branch3,
        &mut || Ok(()),
        Some(&f.node.authenticated_arithmetic),
    )
    .unwrap();
    assert!(scope
        .histories
        .iter()
        .flatten()
        .all(|record| record.block != branch2 && record.block != branch3));
}

#[test]
fn partial_cancelled_history_never_mints_a_suffix() {
    let f = fixture(4);
    let tip = f.chain[4];
    let mut scope = begin_scope(&f.node, tip);
    let initial_reads = packet_reads(&f.node);
    let error = history(&f.node, tip, &mut scope, &mut || {
        if packet_reads(&f.node) >= initial_reads + 2 {
            Err("HISTORY_SUFFIX_CANCELLED".into())
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "HISTORY_SUFFIX_CANCELLED");
    assert!(scope.histories.iter().all(Option::is_none));
    assert_eq!(scope.history_hits, 0);
    let before = packet_reads(&f.node);
    history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(packet_reads(&f.node) - before, 6);
    assert_eq!(scope.history_hits, 0);
}

#[test]
fn no_row_write_reversed_ddl_and_schema_change_do_not_reuse_or_restamp_history() {
    for sql in [
        "UPDATE native_state_commitments SET data=data WHERE 0",
        "CREATE TABLE history_probe(x); DROP TABLE history_probe",
        "CREATE TEMP TABLE history_probe(x)",
        "PRAGMA writable_schema=ON",
    ] {
        let f = fixture(3);
        let tip = f.chain[3];
        let mut scope = begin_scope(&f.node, tip);
        history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
        assert!(!scope.consumed);
        f.node.db.execute_batch(sql).unwrap();
        for _ in 0..2 {
            let before = packet_reads(&f.node);
            history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
            assert_eq!(packet_reads(&f.node) - before, 5, "{sql}");
        }
        assert!(!scope.enabled);
        assert!(scope.histories.iter().all(Option::is_none));
        assert_eq!(scope.history_hits, 0);
    }
}

#[test]
fn changed_old_ancestor_is_rechecked_after_a_full_history_fact() {
    let f = fixture(4);
    let tip = f.chain[4];
    let mut scope = begin_scope(&f.node, tip);
    history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(
        f.node
            .db
            .execute(
                "UPDATE native_state_commitments SET data=x'00' WHERE block=?",
                [f.chain[1].as_slice()],
            )
            .unwrap(),
        1
    );
    assert!(history(&f.node, tip, &mut scope, &mut || Ok(())).is_err());
    assert!(!scope.enabled);
    assert_eq!(scope.history_hits, 0);
}

#[test]
fn first_hit_callback_write_restarts_complete_history_from_requested_block() {
    let f = fixture(4);
    let tip = f.chain[4];
    let callbacks = {
        let mut probe = begin_scope(&f.node, tip);
        history(&f.node, tip, &mut probe, &mut || Ok(())).unwrap();
        let mut callbacks = 0;
        history(&f.node, tip, &mut probe, &mut || {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
        callbacks
    };
    f.node.db.execute_batch("ROLLBACK").unwrap();
    let mut scope = begin_scope(&f.node, tip);
    history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
    let mut current = 0;
    let error = history(&f.node, tip, &mut scope, &mut || {
        current += 1;
        if current == callbacks {
            f.node.db.execute(
                "UPDATE native_state_commitments SET data=x'00' WHERE block=?",
                [f.chain[1].as_slice()],
            )?;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(
        current > callbacks,
        "the original complete path must run again"
    );
    assert_ne!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
    assert!(!scope.enabled);
    assert_eq!(scope.history_hits, 0);
    assert!(scope.histories.iter().all(Option::is_none));
}

#[test]
fn history_hit_keeps_actual_cancellation_and_last_callback_write_fences() {
    let f = fixture(3);
    let tip = f.chain[3];
    let mut scope = begin_scope(&f.node, tip);
    history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
    let mut callbacks = 0;
    history(&f.node, tip, &mut scope, &mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    for stop in [1, callbacks] {
        let hits = scope.history_hits;
        let mut current = 0;
        let error = history(&f.node, tip, &mut scope, &mut || {
            current += 1;
            if current == stop {
                Err("HISTORY_SUFFIX_CANCELLED".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "HISTORY_SUFFIX_CANCELLED");
        assert_eq!(scope.history_hits, hits);
    }
    let mut current = 0;
    let error = history(&f.node, tip, &mut scope, &mut || {
        current += 1;
        if current == callbacks {
            f.node
                .db
                .execute("UPDATE native_state_commitments SET data=data WHERE 0", [])?;
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(current, callbacks);
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
}

#[test]
fn history_scope_rejects_other_connection_and_transaction_aba() {
    for sql in [
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT probe; RELEASE probe",
        "SAVEPOINT probe; ROLLBACK TO probe; RELEASE probe",
    ] {
        let f = fixture(2);
        let tip = f.chain[2];
        let mut scope = begin_scope(&f.node, tip);
        history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
        f.node.db.execute_batch(sql).unwrap();
        let error = history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap_err();
        assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
    }
    let f = fixture(2);
    let other = fixture(2);
    assert_eq!(f.chain, other.chain);
    let mut scope = begin_scope(&f.node, f.chain[2]);
    history(&f.node, f.chain[2], &mut scope, &mut || Ok(())).unwrap();
    other.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = history(&other.node, other.chain[2], &mut scope, &mut || Ok(())).unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
}

#[test]
fn cold_reopen_does_not_inherit_suffix_facts_and_rejects_old_history_damage() {
    let f = fixture(4);
    let tip = f.chain[4];
    {
        let mut scope = begin_scope(&f.node, tip);
        history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
        history(&f.node, tip, &mut scope, &mut || Ok(())).unwrap();
        assert_eq!(scope.history_hits, 1);
    }
    f.node.db.execute_batch("ROLLBACK").unwrap();
    let settings = f.node.settings.clone();
    let expected = f.node.read_active().unwrap();
    drop(f.node);
    let reopened =
        Node::open_with_authenticated_state(f.directory.path(), settings.clone(), 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), expected);
    let before = packet_reads(&reopened);
    verify_history_with_cache(
        &reopened.db,
        &reopened.settings,
        tip,
        &mut || Ok(()),
        Some(&reopened.authenticated_arithmetic),
    )
    .unwrap();
    assert_eq!(packet_reads(&reopened) - before, 6);
    drop(reopened);
    let outside = Connection::open(f.directory.path().join("native.sqlite")).unwrap();
    outside
        .execute(
            "UPDATE native_state_commitments SET data=x'00' WHERE block=?",
            [f.chain[1].as_slice()],
        )
        .unwrap();
    drop(outside);
    assert!(Node::open_with_authenticated_state(f.directory.path(), settings, 1).is_err());
}

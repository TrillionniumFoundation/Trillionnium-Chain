//! Actual parent/active readback inside one original SQLite write transaction.
//! These controls do not qualify the fixed-Host History service budget.
use super::*;
use crate::account_archive_prototype::native_store::AccountGraphKind;
use crate::Node;
use std::cell::Cell;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

struct Fixture {
    node: Node,
    directory: tempfile::TempDir,
    active: Hash,
    parent: Hash,
    child: Hash,
}

fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = crate::development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: crate::development_public(0).unwrap(),
        nonce,
        expiry: 10_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    let mut previous = node.settings.genesis();
    let mut blocks = Vec::new();
    for nonce in 1..=3 {
        let packet = node
            .make_consensus_maintenance(
                previous,
                vec![transfer(&node.settings, nonce)],
                crate::development_public(0).unwrap(),
                10 + nonce,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        if nonce == 1 {
            node.activate(id).unwrap();
        }
        blocks.push(id);
        previous = id;
    }
    Fixture {
        node,
        directory,
        active: blocks[0],
        parent: blocks[1],
        child: blocks[2],
    }
}

#[derive(Default)]
struct Counts {
    boundaries: usize,
    graphs: usize,
    nodes: usize,
}
impl NativeProgress for Counts {
    fn checkpoint(&mut self) -> Result<()> {
        self.boundaries += 1;
        Ok(())
    }
    fn account_graph(&mut self, point: native_store::AccountGraphPoint) -> Result<()> {
        match point.kind() {
            AccountGraphKind::Enter => self.graphs += 1,
            AccountGraphKind::BeforeNode { .. } => self.nodes += 1,
            _ => {}
        }
        Ok(())
    }
}

fn start(fixture: &Fixture) -> PostWriteReadback<'_> {
    let node = &fixture.node;
    let owner = TransactionScope::capture(&node.db).unwrap();
    PostWriteReadback::new(
        &node.db,
        &node.settings,
        fixture.child,
        &owner,
        node.post_write_schema.as_ref().unwrap(),
    )
    .unwrap()
    .unwrap()
}

fn verify(
    node: &Node,
    block: Hash,
    state: &State,
    readback: &mut PostWriteReadback<'_>,
    progress: &mut dyn NativeProgress,
) -> Result<()> {
    verify_state_with_readback(
        &node.db,
        &node.settings,
        block,
        state,
        progress,
        Some(&node.authenticated_arithmetic),
        Some(readback),
    )
}

#[test]
fn actual_parent_and_active_reuse_preserves_signed_state_and_cold_reopen() {
    let mut f = fixture();
    let before = f.node.read_active().unwrap();
    let parent = f.node.state_at(f.parent).unwrap();
    let child = f.node.state_at(f.child).unwrap();
    let records = [f.active, f.parent, f.child].map(|id| {
        (
            load_observed(&f.node.db, id, None).unwrap(),
            deltas(&f.node.db, id).unwrap(),
        )
    });
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut readback = start(&f);
    let mut counts = Counts::default();
    for (id, state) in [
        (f.node.settings.genesis(), &f.node.settings.initial),
        (f.child, &child),
        (f.parent, &parent),
    ] {
        verify(&f.node, id, state, &mut readback, &mut counts).unwrap();
    }
    assert_eq!(
        f.node
            .state_at_with_post_write_readback(f.active, &mut counts, &mut readback)
            .unwrap(),
        before.2
    );
    assert_eq!(
        counts.graphs, 4,
        "all four distinct actual graphs must run first"
    );
    assert!(counts.nodes > 0);
    let boundaries = counts.boundaries;
    let actual_parent = f
        .node
        .state_at_with_post_write_readback(f.parent, &mut counts, &mut readback)
        .unwrap();
    assert_eq!(actual_parent, parent);
    assert_eq!(
        counts.graphs, 4,
        "the same transaction's fully verified parent must not be walked twice"
    );
    let actual_active = f
        .node
        .state_at_with_post_write_readback(f.active, &mut counts, &mut readback)
        .unwrap();
    assert_eq!(actual_active, before.2);
    f.node
        .check_active_before_commit_with_readback(&mut counts, Some(&mut readback))
        .unwrap();
    assert_eq!(
        counts.graphs, 4,
        "active and genesis reuse only their actual graphs"
    );
    assert_eq!(readback.hits, 4);
    assert!(
        counts.boundaries > boundaries,
        "the original callbacks still execute"
    );
    readback.validate_consumed(&f.node.db).unwrap();
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.node.read_active().unwrap(), before);
    f.node.activate(f.child).unwrap();
    let installed = f.node.read_active().unwrap();
    assert_eq!(installed.0, f.child);
    assert_eq!(installed.2, child);
    assert_eq!(
        [f.active, f.parent, f.child].map(|id| (
            load_observed(&f.node.db, id, None).unwrap(),
            deltas(&f.node.db, id).unwrap()
        )),
        records
    );
    let settings = f.node.settings.clone();
    drop(f.node);
    let reopened = Node::open_with_authenticated_state(f.directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), installed);
    assert_eq!(reopened.state_at(f.parent).unwrap(), parent);
}

#[test]
fn active_read_mutation_before_or_after_consumption_rolls_back_actual_state() {
    for after_consumption in [false, true] {
        let mut f = fixture();
        let before = f.node.read_active().unwrap();
        let child = f.node.state_at(f.child).unwrap();
        let slot = f.node.slot().unwrap();
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut readback = start(&f);
        let mut counts = Counts::default();
        f.node
            .state_at_with_post_write_readback(f.active, &mut counts, &mut readback)
            .unwrap();
        let mut probe = Counts::default();
        f.node
            .state_at_with_post_write_readback(f.active, &mut probe, &mut readback)
            .unwrap();
        // A second scope starts with no consumed receipt for the before case.
        drop(readback);
        let mut readback = start(&f);
        f.node
            .state_at_with_post_write_readback(f.active, &mut counts, &mut readback)
            .unwrap();
        let at = if after_consumption {
            probe.boundaries
        } else {
            1
        };
        let calls = Cell::new(0);
        let error = f
            .node
            .state_at_with_post_write_readback(
                f.active,
                &mut || {
                    calls.set(calls.get() + 1);
                    if calls.get() == at {
                        f.node.db.execute(
                            "INSERT INTO kv(slot,key,value) VALUES(?1,?2,?3)",
                            params![
                                slot,
                                "retained:parent-readback-full-state",
                                b"null".as_slice()
                            ],
                        )?;
                    }
                    Ok(())
                },
                &mut readback,
            )
            .unwrap_err();
        assert!(error.requires_owner_stop());
        if after_consumption {
            assert_eq!(calls.get(), probe.boundaries);
            assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
            assert!(readback.hits > 0);
        } else {
            assert_eq!(readback.hits, 0);
        }
        drop(readback);
        f.node.db.execute_batch("ROLLBACK").unwrap();
        assert_eq!(f.node.read_active().unwrap(), before);
        // Cold open legitimately recovers the already admitted heavier child.
        // First prove rollback kept the original live State, then publish that
        // unchanged valid child through the original activation before reopen.
        f.node.activate(f.child).unwrap();
        let installed = f.node.read_active().unwrap();
        assert_eq!(installed.0, f.child);
        assert_eq!(installed.2, child);
        let settings = f.node.settings.clone();
        drop(f.node);
        let reopened =
            Node::open_with_authenticated_state(f.directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), installed);
    }
}

#[test]
fn unrelated_fifth_root_never_acquires_a_parent_or_active_receipt() {
    let mut f = fixture();
    let packet = f
        .node
        .make_consensus_maintenance(
            f.node.settings.genesis(),
            vec![],
            crate::development_public(1).unwrap(),
            20,
            4096,
        )
        .unwrap();
    let unrelated = f.node.admit(&packet, 100_000).unwrap();
    let state = f.node.state_at(unrelated).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut readback = start(&f);
    let mut counts = Counts::default();
    for _ in 0..2 {
        verify(&f.node, unrelated, &state, &mut readback, &mut counts).unwrap();
    }
    assert_eq!(
        counts.graphs, 2,
        "the four-root bound cannot learn an unrelated root"
    );
    assert_eq!(readback.hits, 0);
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

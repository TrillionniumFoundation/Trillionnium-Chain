//! Actual PQ key/root proofs, with no production deployment or exec claim.
use super::proof_state::State;
use super::proof_test_keys as fixture;
use super::proof_wire::{self, Publication};
use trnm_release_bundle::pq_release::{PqReleaseAuthorityV1, PqReleaseRoleV1};

#[test]
fn all_three_service_keys_are_excluded_from_offline_root_and_every_online_role() {
    let (root, _) = fixture::root(1, 1, 30, [0; 32]);
    let services = [fixture::key(80), fixture::key(81), fixture::key(82)];
    let ids = services.each_ref().map(|key| key.public_key_id());
    super::root_separation::require(&root.kernel().unwrap(), &ids).unwrap();
    for key in &services {
        for role in 0..=4 {
            let mut changed = root.clone();
            if role == 0 {
                changed.offline_root = fixture::keys(key);
            } else {
                changed.roles.insert(role, fixture::keys(key));
            }
            let valid_root = changed.kernel().unwrap();
            assert!(super::root_separation::require(&valid_root, &ids).is_err());
            assert!(State::initial(&fixture::context(&changed, ids), 10).is_err());
        }
    }
}

#[test]
fn valid_dual_quorum_successor_cannot_reuse_an_independent_service_key() {
    let (old, old_keys) = fixture::root(1, 1, 30, [0; 32]);
    let services = [fixture::key(80), fixture::key(81), fixture::key(82)];
    let ids = services.each_ref().map(|key| key.public_key_id());
    let context = fixture::context(&old, ids);
    let (mut next, next_keys) = fixture::root(20, 2, 100, context.initial_root_pin);
    next.roles.insert(1, fixture::keys(&services[0]));
    let old_proof = vec![fixture::signed(&old_keys[0], &next)];
    let new_proof = vec![fixture::signed(&next_keys[0], &next)];
    let mut kernel = PqReleaseAuthorityV1::bootstrap_pinned(
        context.initial_root.clone(),
        context.initial_root_pin,
        10,
    )
    .unwrap();
    kernel
        .rotate_root(
            next.kernel().unwrap(),
            &proof_wire::signatures(&old_proof).unwrap(),
            &proof_wire::signatures(&new_proof).unwrap(),
            40,
        )
        .unwrap();
    let mut state = State::initial(&context, 10).unwrap();
    assert!(state
        .prepare_publication(
            &context,
            Publication::RootRotation {
                root: next,
                old_signatures: old_proof,
                new_signatures: new_proof,
            },
            40
        )
        .is_err());
    assert_eq!(state.authority.root_digest(), context.initial_root_pin);
    assert!(state.index.records.is_empty());
}

#[test]
fn expired_old_root_keeps_dual_quorum_recovery_and_cold_proof_replay() {
    let (old, old_keys) = fixture::root(1, 1, 30, [0; 32]);
    let ids = [fixture::key(80), fixture::key(81), fixture::key(82)]
        .each_ref()
        .map(|key| key.public_key_id());
    let context = fixture::context(&old, ids);
    let (next, next_keys) = fixture::root(20, 2, 100, context.initial_root_pin);
    let mut state = State::initial(&context, 10).unwrap();
    assert!(state.check_root_time(40).is_err());
    assert!(state
        .check_role(PqReleaseRoleV1::NodeSoftware, [7; 32], 40)
        .is_err());
    let record = state
        .prepare_publication(
            &context,
            Publication::RootRotation {
                old_signatures: vec![fixture::signed(&old_keys[0], &next)],
                new_signatures: vec![fixture::signed(&next_keys[0], &next)],
                root: next,
            },
            40,
        )
        .unwrap();
    state.check_root_time(40).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("owner");
    let files = super::files::Files::create(&path).unwrap();
    assert_eq!(
        super::records::put(&files, &record).unwrap(),
        state.index.records[0]
    );
    let reopened = State::replay(&files, &state.index.encode().unwrap(), &context).unwrap();
    assert_eq!(reopened.authority.root_generation(), 2);
    assert_eq!(
        reopened.index.encode().unwrap(),
        state.index.encode().unwrap()
    );
    assert!(reopened.check_root_time(100).is_err());
}

#[test]
fn expired_root_recovery_requires_both_real_quorums_and_a_fresh_successor() {
    let (old, old_keys) = fixture::root(1, 1, 30, [0; 32]);
    let ids = [fixture::key(80), fixture::key(81), fixture::key(82)]
        .each_ref()
        .map(|key| key.public_key_id());
    let context = fixture::context(&old, ids);
    for cut in 0..5 {
        let (next, next_keys) = fixture::root(
            20,
            2,
            if cut == 4 { 40 } else { 100 },
            context.initial_root_pin,
        );
        let mut old_proof = vec![fixture::signed(&old_keys[0], &next)];
        let mut new_proof = vec![fixture::signed(&next_keys[0], &next)];
        match cut {
            0 => old_proof.clear(),
            1 => new_proof.clear(),
            2 => old_proof[0].signature[0] ^= 1,
            3 => new_proof[0].signature[0] ^= 1,
            _ => {}
        }
        let mut state = State::initial(&context, 10).unwrap();
        assert!(state
            .prepare_publication(
                &context,
                Publication::RootRotation {
                    root: next,
                    old_signatures: old_proof,
                    new_signatures: new_proof,
                },
                40
            )
            .is_err());
        assert_eq!(state.authority.root_digest(), context.initial_root_pin);
        assert!(state.index.records.is_empty());
    }
}

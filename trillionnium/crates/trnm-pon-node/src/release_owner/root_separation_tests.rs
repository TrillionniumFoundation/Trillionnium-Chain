//! Actual PQ key/root proofs, with no production deployment or exec claim.
use super::proof_state::State;
use super::proof_test_keys as fixture;
use super::proof_wire::{self, Publication};
use trnm_release_bundle::pq_release::{PqReleaseAuthorityV1, PqReleaseRoleV1};

#[test]
fn canonical_role_keys_replay_at_every_tagged_proof_boundary() {
    fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        let bytes = super::codec::encode(value, super::records::MAX_RECORD_BYTES).unwrap();
        let decoded = super::codec::decode(&bytes, super::records::MAX_RECORD_BYTES).unwrap();
        assert_eq!(
            bytes,
            super::codec::encode(&decoded, super::records::MAX_RECORD_BYTES).unwrap()
        );
        decoded
    }
    let (root, keys) = fixture::root(1, 1, 30, [0; 32]);
    let digest = root.kernel().unwrap().digest().unwrap();
    let decoded = round_trip(&root);
    assert_eq!(decoded.kernel().unwrap().digest().unwrap(), digest);
    let publication = round_trip(&Publication::RootRotation {
        old_signatures: vec![fixture::signed(&keys[0], &root)],
        new_signatures: vec![fixture::signed(&keys[0], &root)],
        root,
    });
    let observed = round_trip(&proof_wire::ObservedPublication {
        schema_version: 1,
        publication,
        observed_at: 10,
        resulting_checkpoint: [9; 32],
    });
    let record = super::records::Record::Publication(observed);
    let decoded = round_trip(&record);
    assert_eq!(decoded.digest().unwrap(), record.digest().unwrap());
    let super::records::Record::Publication(observed) = decoded else {
        panic!("publication record changed type")
    };
    let Publication::RootRotation { root, .. } = observed.publication else {
        panic!("rotation changed type")
    };
    assert_eq!(root.kernel().unwrap().digest().unwrap(), digest);
}

#[test]
fn root_role_keys_refuse_aliases_unknown_codes_and_duplicates_in_tagged_proofs() {
    fn reject_at_every_boundary(root: &str) {
        assert!(serde_json::from_str::<proof_wire::Root>(root).is_err());
        let publication = format!(
            "{{\"kind\":\"RootRotation\",\"root\":{root},\"old_signatures\":[],\"new_signatures\":[]}}"
        );
        assert!(serde_json::from_str::<Publication>(&publication).is_err());
        let checkpoint = serde_json::to_string(&[9_u8; 32]).unwrap();
        let fields = format!(
            "\"schema_version\":1,\"publication\":{publication},\"observed_at\":10,\"resulting_checkpoint\":{checkpoint}"
        );
        assert!(
            serde_json::from_str::<proof_wire::ObservedPublication>(&format!("{{{fields}}}"))
                .is_err()
        );
        assert!(serde_json::from_str::<super::records::Record>(&format!(
            "{{\"record\":\"Publication\",{fields}}}"
        ))
        .is_err());
    }
    let (root, _) = fixture::root(1, 1, 30, [0; 32]);
    let raw = serde_json::to_string(&root).unwrap();
    for key in [
        "0", "5", "255", "256", "01", "+1", "-1", " 1", "1 ", "1.0", "",
    ] {
        let changed = raw.replacen("\"roles\":{\"1\":", &format!("\"roles\":{{\"{key}\":"), 1);
        assert_ne!(changed, raw);
        reject_at_every_boundary(&changed);
    }
    let duplicate = format!(
        "\"roles\":{{\"1\":{},",
        serde_json::to_string(&root.roles[&1]).unwrap()
    );
    reject_at_every_boundary(&raw.replacen("\"roles\":{", &duplicate, 1));
}

#[test]
fn role_decoding_preserves_complete_root_and_canonical_record_requirements() {
    let (mut root, _) = fixture::root(1, 1, 30, [0; 32]);
    root.roles.remove(&4);
    let raw = super::codec::encode(&root, super::records::MAX_RECORD_BYTES).unwrap();
    let decoded: proof_wire::Root =
        super::codec::decode(&raw, super::records::MAX_RECORD_BYTES).unwrap();
    assert!(decoded.kernel().is_err());
    let (root, _) = fixture::root(1, 1, 30, [0; 32]);
    let canonical = serde_json::to_string(&root).unwrap();
    let noncanonical = canonical.replacen("\"roles\":{", "\"roles\": {", 1);
    assert_ne!(canonical, noncanonical);
    assert!(serde_json::from_str::<proof_wire::Root>(&noncanonical).is_ok());
    assert!(super::codec::decode::<proof_wire::Root>(
        noncanonical.as_bytes(),
        super::records::MAX_RECORD_BYTES
    )
    .is_err());
}

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

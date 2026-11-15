use super::*;
use trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;

#[derive(Debug, Eq, PartialEq)]
struct AuthorityState {
    root: PqReleaseRootV1,
    verifier_pins: BTreeMap<ReleaseKeyIdV1, (ReleaseKeyIdV1, Vec<u8>)>,
    root_digest: ReleaseDigestV1,
    checkpoint: ReleaseDigestV1,
    versions: BTreeMap<PqReleaseRoleV1, u64>,
    current: BTreeMap<PqReleaseRoleV1, (ReleaseDigestV1, u64, u64)>,
    history: BTreeSet<(PqReleaseRoleV1, ReleaseDigestV1)>,
    retired: BTreeSet<ReleaseKeyIdV1>,
    time_floor: u64,
    event_count: usize,
}

impl AuthorityState {
    fn read(authority: &PqReleaseAuthorityV1) -> Self {
        Self {
            root: authority.root.clone(),
            verifier_pins: authority
                .verifiers
                .iter()
                .map(|(id, verifier)| {
                    (
                        *id,
                        (verifier.public_key_id(), verifier.public_spki().to_vec()),
                    )
                })
                .collect(),
            root_digest: authority.root_digest,
            checkpoint: authority.checkpoint,
            versions: authority.versions.clone(),
            current: authority
                .current
                .iter()
                .map(|(role, current)| {
                    (
                        *role,
                        (current.content, current.root_generation, current.expires_at),
                    )
                })
                .collect(),
            history: authority.history.clone(),
            retired: authority.retired.clone(),
            time_floor: authority.time_floor,
            event_count: authority.event_count,
        }
    }
}

fn populated(f: &Fixture) -> PqReleaseAuthorityV1 {
    let mut authority = authority(f);
    accept(f, &mut authority, PqReleaseRoleV1::NodeSoftware, 20);
    authority
}

fn successor(authority: &PqReleaseAuthorityV1, f: &Fixture) -> PqReleaseRootV1 {
    let mut root = f.root.clone();
    root.generation = authority.root_generation() + 1;
    root.previous_root_digest = authority.root_digest();
    root
}

fn corrupt_first(proof: &[PqReleaseSignatureV1]) -> Vec<PqReleaseSignatureV1> {
    let mut corrupted = proof.to_vec();
    // Change the challenge, preserving the complete fixed-width encoding. A
    // mathematical check of this first signature fails before any later entry
    // in the original interleaved implementation can be inspected.
    assert_eq!(corrupted[0].signature.len(), ML_DSA_65_SIGNATURE_BYTES);
    corrupted[0].signature[0] ^= 1;
    corrupted
}

fn reject_release(
    authority: &mut PqReleaseAuthorityV1,
    metadata: &PqReleaseMetadataV1,
    proof: &[PqReleaseSignatureV1],
    error: PqReleaseErrorV1,
) {
    let before = AuthorityState::read(authority);
    assert_eq!(authority.accept(metadata, proof, 21), Err(error));
    assert_eq!(AuthorityState::read(authority), before);
}

fn reject_rotation(
    authority: &mut PqReleaseAuthorityV1,
    next: &PqReleaseRootV1,
    old: &[PqReleaseSignatureV1],
    new: &[PqReleaseSignatureV1],
    error: PqReleaseErrorV1,
) {
    let before = AuthorityState::read(authority);
    assert_eq!(
        authority.rotate_root(next.clone(), old, new, 21),
        Err(error)
    );
    assert_eq!(AuthorityState::read(authority), before);
}

#[test]
fn release_preflights_late_duplicate_before_invalid_first_signature() {
    let f = fixture(0);
    let mut authority = populated(&f);
    let metadata = metadata(&authority, PqReleaseRoleV1::NodeSoftware, 21);
    let mut proof = corrupt_first(&sign_metadata(&f, &metadata));
    proof[1].key_id = proof[0].key_id;
    reject_release(
        &mut authority,
        &metadata,
        &proof,
        PqReleaseErrorV1::DuplicateSigner,
    );
}

#[test]
fn release_preflights_late_unknown_before_invalid_first_signature() {
    let f = fixture(0);
    let mut authority = populated(&f);
    let metadata = metadata(&authority, PqReleaseRoleV1::NodeSoftware, 21);
    let mut proof = corrupt_first(&sign_metadata(&f, &metadata));
    // The retained map contains this key, but the current online role does not.
    proof[1].key_id = *f.root.offline_root.keys.first_key_value().unwrap().0;
    reject_release(
        &mut authority,
        &metadata,
        &proof,
        PqReleaseErrorV1::UnknownSigner,
    );
}

#[test]
fn release_preflights_late_cache_pin_faults_before_invalid_first_signature() {
    let f = fixture(0);
    for fault in 0..3 {
        let mut authority = populated(&f);
        let role = PqReleaseRoleV1::NodeSoftware;
        let metadata = metadata(&authority, role, 21);
        let proof = corrupt_first(&sign_metadata(&f, &metadata));
        let last_id = proof[1].key_id;
        // These are private invariant faults, not new production mutation APIs.
        // Check a missing entry, a verifier for another pin, and mismatched SPKI.
        match fault {
            0 => {
                Arc::get_mut(&mut authority.verifiers)
                    .unwrap()
                    .remove(&last_id)
                    .unwrap();
            }
            1 => {
                let (other_id, other_spki) = f.root.offline_root.keys.first_key_value().unwrap();
                Arc::get_mut(&mut authority.verifiers).unwrap().insert(
                    last_id,
                    PqNativeVerifier::from_pinned_spki(other_spki, *other_id).unwrap(),
                );
            }
            2 => {
                authority
                    .root
                    .roles
                    .get_mut(&role)
                    .unwrap()
                    .keys
                    .get_mut(&last_id)
                    .unwrap()[30] ^= 1;
            }
            _ => unreachable!(),
        }
        reject_release(
            &mut authority,
            &metadata,
            &proof,
            PqReleaseErrorV1::InvalidKey,
        );
    }
}

#[test]
fn rotation_preflights_successor_counts_before_old_signature_math() {
    let f = fixture(0);
    let mut authority = populated(&f);
    let next_keys = fixture(20);
    let next = successor(&authority, &next_keys);
    let message = next.signing_message().unwrap();
    let old = corrupt_first(&signatures(&f, &f.root.offline_root, &message));
    let new = signatures(&next_keys, &next.offline_root, &message);
    for invalid in [
        Vec::new(),
        new[..1].to_vec(),
        vec![new[0].clone(); MAX_RELEASE_KEYS_V1 + 1],
    ] {
        reject_rotation(
            &mut authority,
            &next,
            &old,
            &invalid,
            PqReleaseErrorV1::InsufficientSignatures,
        );
    }
}

#[test]
fn rotation_preflights_successor_duplicate_before_old_signature_math() {
    let f = fixture(0);
    let mut authority = populated(&f);
    let next_keys = fixture(20);
    let next = successor(&authority, &next_keys);
    let message = next.signing_message().unwrap();
    let old = corrupt_first(&signatures(&f, &f.root.offline_root, &message));
    let mut new = signatures(&next_keys, &next.offline_root, &message);
    new[1].key_id = new[0].key_id;
    reject_rotation(
        &mut authority,
        &next,
        &old,
        &new,
        PqReleaseErrorV1::DuplicateSigner,
    );
}

#[test]
fn rotation_preflights_successor_unknown_before_old_signature_math() {
    let f = fixture(0);
    let mut authority = populated(&f);
    let next_keys = fixture(20);
    let next = successor(&authority, &next_keys);
    let message = next.signing_message().unwrap();
    let old = corrupt_first(&signatures(&f, &f.root.offline_root, &message));
    let mut new = signatures(&next_keys, &next.offline_root, &message);
    // An old-root signer cannot count toward the independently pinned new root.
    new[1].key_id = old[1].key_id;
    reject_rotation(
        &mut authority,
        &next,
        &old,
        &new,
        PqReleaseErrorV1::UnknownSigner,
    );
}

#[test]
fn release_counts_lengths_and_bad_extra_signatures_still_fail_closed() {
    let mut f = fixture(0);
    let mut authority = populated(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let candidate = metadata(&authority, role, 21);
    let proof = sign_metadata(&f, &candidate);
    for invalid in [
        proof[..1].to_vec(),
        vec![proof[0].clone(); MAX_RELEASE_KEYS_V1 + 1],
    ] {
        reject_release(
            &mut authority,
            &candidate,
            &invalid,
            PqReleaseErrorV1::InsufficientSignatures,
        );
    }

    f.root.roles.get_mut(&role).unwrap().threshold = 1;
    let mut authority = populated(&f);
    let candidate = metadata(&authority, role, 21);
    let valid = sign_metadata(&f, &candidate);
    for position in 0..valid.len() {
        for grow in [false, true] {
            let mut invalid = valid.clone();
            if grow {
                invalid[position].signature.push(0);
            } else {
                invalid[position].signature.pop();
            }
            reject_release(
                &mut authority,
                &candidate,
                &invalid,
                PqReleaseErrorV1::SignatureRejected,
            );
        }
    }
    let mut bad_extra = valid.clone();
    bad_extra[1].signature[0] ^= 1;
    reject_release(
        &mut authority,
        &candidate,
        &bad_extra,
        PqReleaseErrorV1::SignatureRejected,
    );
    assert_eq!(
        authority.accept(&candidate, &valid, 21).unwrap().version(),
        2
    );
}

#[test]
fn rotation_still_verifies_every_extra_old_and_new_signature() {
    let mut f = fixture(0);
    f.root.offline_root.threshold = 1;
    let mut authority = populated(&f);
    let mut next_keys = fixture(20);
    next_keys.root.offline_root.threshold = 1;
    let next = successor(&authority, &next_keys);
    let message = next.signing_message().unwrap();
    let old = signatures(&f, &f.root.offline_root, &message);
    let new = signatures(&next_keys, &next.offline_root, &message);
    for corrupt_old in [true, false] {
        let mut old_proof = old.clone();
        let mut new_proof = new.clone();
        if corrupt_old {
            old_proof[1].signature[0] ^= 1;
        } else {
            new_proof[1].signature[0] ^= 1;
        }
        reject_rotation(
            &mut authority,
            &next,
            &old_proof,
            &new_proof,
            PqReleaseErrorV1::SignatureRejected,
        );
    }
    authority.rotate_root(next, &old, &new, 21).unwrap();
    assert_eq!(authority.root_generation(), 2);
    assert_eq!(authority.retired, f.root.all_keys());
}

#[test]
fn successful_release_rotation_and_recovery_preserve_complete_authority_state() {
    let f = fixture(0);
    let mut authority = authority(&f);
    let first = metadata(&authority, PqReleaseRoleV1::NodeSoftware, 20);
    let first_proof = sign_metadata(&f, &first);
    authority.accept(&first, &first_proof, 20).unwrap();

    let next_keys = fixture(20);
    let next = successor(&authority, &next_keys);
    let message = next.signing_message().unwrap();
    let old = signatures(&f, &f.root.offline_root, &message);
    let new = signatures(&next_keys, &next.offline_root, &message);
    authority.rotate_root(next.clone(), &old, &new, 21).unwrap();
    assert_eq!(
        authority.check_current(first.role, first.content, authority.checkpoint(), 21),
        Err(PqReleaseErrorV1::WrongAuthority)
    );

    // Identical content requires a fresh authorization from the current roster.
    let current = metadata(&authority, first.role, 20);
    reject_release(
        &mut authority,
        &current,
        &sign_metadata(&f, &current),
        PqReleaseErrorV1::UnknownSigner,
    );
    let current_proof = sign_metadata(&next_keys, &current);
    authority.accept(&current, &current_proof, 22).unwrap();
    let events = vec![
        PqReleaseEventV1::Release {
            metadata: first,
            signatures: first_proof,
            observed_at: 20,
        },
        PqReleaseEventV1::RootRotation {
            root: next,
            old_signatures: old,
            new_signatures: new,
            observed_at: 21,
        },
        PqReleaseEventV1::Release {
            metadata: current.clone(),
            signatures: current_proof,
            observed_at: 22,
        },
    ];
    let recovered = PqReleaseAuthorityV1::recover_pinned(
        f.root.clone(),
        f.root.digest().unwrap(),
        10,
        &events,
        authority.checkpoint(),
    )
    .unwrap();
    assert_eq!(
        AuthorityState::read(&recovered),
        AuthorityState::read(&authority)
    );
    recovered
        .check_current(current.role, current.content, recovered.checkpoint(), 22)
        .unwrap();
    assert_eq!(
        recovered.check_current(
            current.role,
            current.content,
            recovered.checkpoint(),
            current.expires_at,
        ),
        Err(PqReleaseErrorV1::Expired)
    );
}

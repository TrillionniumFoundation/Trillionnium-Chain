//! Only test fixtures; never a deployment/root loader.
use super::frontier::Digest32;
use super::proof_state::Context;
use super::proof_wire::{Keys, PublicKey, Root, Signature};
use std::collections::BTreeMap;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use zeroize::Zeroizing;

pub(super) fn key(seed: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([seed; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let id = trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki(&spki).unwrap();
    PqNativeSigningKey::from_owned_seed(seed, id).unwrap()
}
pub(super) fn keys(key: &PqNativeSigningKey) -> Keys {
    Keys {
        threshold: 1,
        keys: vec![PublicKey {
            key_id: key.public_key_id(),
            spki: key.public_spki().to_vec(),
        }],
    }
}
pub(super) fn root(
    seed: u8,
    generation: u64,
    expires_at: u64,
    previous: Digest32,
) -> (Root, Vec<PqNativeSigningKey>) {
    let signing: Vec<_> = (seed..seed + 5).map(key).collect();
    let roles: BTreeMap<_, _> = (1..=4)
        .map(|role| (role, keys(&signing[usize::from(role)])))
        .collect();
    (
        Root {
            schema_version: 1,
            network_id: [19; 32],
            generation,
            expires_at,
            previous_root_digest: previous,
            offline_root: keys(&signing[0]),
            roles,
        },
        signing,
    )
}
pub(super) fn signed(key: &PqNativeSigningKey, successor: &Root) -> Signature {
    Signature {
        key_id: key.public_key_id(),
        signature: key
            .sign_exact_message(&successor.kernel().unwrap().signing_message().unwrap())
            .unwrap()
            .to_vec(),
    }
}
pub(super) fn context(root: &Root, service_keys: [Digest32; 3]) -> Context {
    let initial_root = root.kernel().unwrap();
    Context {
        namespace: [23; 32],
        configuration_pin: [24; 32],
        initial_root_file: [25; 32],
        initial_root_pin: initial_root.digest().unwrap(),
        initial_root,
        service_keys,
        required_packages: vec![(b"node-fixture".to_vec(), b"1".to_vec())],
    }
}

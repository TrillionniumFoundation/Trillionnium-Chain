// Qualification only. All seed bytes originate inside this offline process.
// Standard output contains only typed public identity/observations/signatures.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Write},
};
use trnm_crypto_primitives::pq_auth::{PqNativeError, PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use trnm_release_bundle::pq_release::{
    PqReleaseAuthorityV1, PqReleaseMetadataV1, PqReleaseRoleKeysV1, PqReleaseRoleV1,
    PqReleaseRootV1,
};
use zeroize::Zeroizing;

const ROLES: [PqReleaseRoleV1; 4] = [
    PqReleaseRoleV1::NodeSoftware,
    PqReleaseRoleV1::ProtocolConfiguration,
    PqReleaseRoleV1::CellManifest,
    PqReleaseRoleV1::CellActivation,
];

fn ephemeral(random: &mut File) -> PqNativeSigningKey {
    let mut seed = Zeroizing::new([0; 32]);
    random.read_exact(seed.as_mut()).unwrap();
    let public = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqNativeSigningKey::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&public).unwrap()).unwrap()
}

fn role_key(key: &PqNativeSigningKey) -> PqReleaseRoleKeysV1 {
    PqReleaseRoleKeysV1 {
        threshold: 1,
        keys: BTreeMap::from([(key.public_key_id(), key.public_spki().to_vec())]),
    }
}

fn issue(input: &[u8], out: &mut impl Write) {
    assert_eq!(input.len(), 187);
    let role = ROLES[usize::from(input[0] - 1)];
    let metadata = PqReleaseMetadataV1 {
        role,
        network_id: input[1..33].try_into().unwrap(),
        root_generation: u64::from_le_bytes(input[33..41].try_into().unwrap()),
        role_version: u64::from_le_bytes(input[41..49].try_into().unwrap()),
        expires_at: u64::from_le_bytes(input[49..57].try_into().unwrap()),
        expected_checkpoint: input[57..89].try_into().unwrap(),
        previous_content: match input[89] {
            0 => None,
            1 => Some(input[90..122].try_into().unwrap()),
            _ => panic!("noncanonical optional tag"),
        },
        content: input[122..154].try_into().unwrap(),
        approved_content_rollback: match input[154] {
            0 => false,
            1 => true,
            _ => panic!("noncanonical boolean"),
        },
    };
    let mut random = File::open("/dev/urandom").unwrap();
    let signing = ephemeral(&mut random);
    let roles = ROLES
        .into_iter()
        .map(|r| {
            (
                r,
                if r == role {
                    role_key(&signing)
                } else {
                    role_key(&ephemeral(&mut random))
                },
            )
        })
        .collect();
    let root = PqReleaseRootV1 {
        network_id: input[155..187].try_into().unwrap(),
        generation: 1,
        expires_at: 1000,
        previous_root_digest: [0; 32],
        offline_root: role_key(&ephemeral(&mut random)),
        roles,
    };
    let root_pin = root.digest().unwrap();
    let authority = PqReleaseAuthorityV1::bootstrap_pinned(root, root_pin, 0).unwrap();
    let message = metadata.signing_message();
    out.write_all(&message).unwrap();
    for r in ROLES {
        out.write_all(&authority.bundle_signer_identity(r)).unwrap();
    }
    out.write_all(&signing.public_key_id()).unwrap();
    out.write_all(signing.public_spki()).unwrap();
    out.write_all(&signing.sign_exact_message(&message).unwrap())
        .unwrap();
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = input.split_at(n);
    *input = tail;
    head
}

fn field<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_le_bytes(take(input, 4).try_into().unwrap());
    take(input, n as usize)
}

fn verify(mut input: &[u8], out: &mut impl Write) {
    while !input.is_empty() {
        let id = take(&mut input, 32).try_into().unwrap();
        let spki = field(&mut input);
        let message = field(&mut input);
        let signature = field(&mut input);
        let checked = PqNativeVerifier::from_pinned_spki(spki, id)
            .and_then(|v| v.verify_exact_message(message, signature));
        match checked {
            Ok(observation) => {
                out.write_all(&[0]).unwrap();
                out.write_all(observation.signer_key_id()).unwrap();
                out.write_all(observation.authenticated_message()).unwrap();
            }
            Err(error) => {
                let code = match error {
                    PqNativeError::Frame(_) => 1,
                    PqNativeError::KeyAlgorithm => 2,
                    PqNativeError::KeyPin => 3,
                    PqNativeError::SignatureRejected => 4,
                };
                out.write_all(&[code]).unwrap();
            }
        }
    }
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut out = io::stdout().lock();
    match std::env::args().nth(1).as_deref() {
        Some("issue") => issue(&input, &mut out),
        Some("verify") => verify(&input, &mut out),
        _ => panic!("expected qualification mode"),
    }
}

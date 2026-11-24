// Qualification only. An exact extraction of the original private quorum
// functions is appended to this adapter by qualify_release_pq_quorum.py.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Write},
};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES};
use trnm_release_bundle::pq_release::{
    PqReleaseAuthorityV1, PqReleaseErrorV1, PqReleaseMetadataV1, PqReleaseRoleKeysV1,
    PqReleaseRoleV1, PqReleaseRootV1, PqReleaseSignatureV1, ReleaseKeyIdV1, MAX_RELEASE_KEYS_V1,
};
use zeroize::Zeroizing;

const ROLE: PqReleaseRoleV1 = PqReleaseRoleV1::NodeSoftware;
const GENERATION: u64 = 1;
const SPKI: usize = 1974;
const KEY_ROW: usize = 32 + SPKI;
const SIG_ROW: usize = 32 + 2 + 4096;
const FIXED: usize = 232;

fn ephemeral(random: &mut File) -> PqNativeSigningKey {
    let mut seed = Zeroizing::new([0; 32]);
    random.read_exact(seed.as_mut()).unwrap();
    let public = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqNativeSigningKey::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&public).unwrap()).unwrap()
}

fn roster(keys: &[PqNativeSigningKey], threshold: u16) -> PqReleaseRoleKeysV1 {
    PqReleaseRoleKeysV1 {
        threshold,
        keys: keys
            .iter()
            .map(|key| (key.public_key_id(), key.public_spki().to_vec()))
            .collect(),
    }
}

fn issue(input: &[u8], out: &mut impl Write) {
    assert!(input.is_empty());
    let mut random = File::open("/dev/urandom").unwrap();
    let mut keys: Vec<_> = (0..MAX_RELEASE_KEYS_V1)
        .map(|_| ephemeral(&mut random))
        .collect();
    keys.sort_by_key(PqNativeSigningKey::public_key_id);
    let outsiders: Vec<_> = (0..4).map(|_| ephemeral(&mut random)).collect();
    let network = [0xa1; 32];
    let root = PqReleaseRootV1 {
        network_id: network,
        generation: GENERATION,
        expires_at: 100,
        previous_root_digest: [0; 32],
        offline_root: roster(&outsiders[..1], 1),
        roles: BTreeMap::from([
            (ROLE, roster(&keys, 2)),
            (
                PqReleaseRoleV1::ProtocolConfiguration,
                roster(&outsiders[1..2], 1),
            ),
            (PqReleaseRoleV1::CellManifest, roster(&outsiders[2..3], 1)),
            (PqReleaseRoleV1::CellActivation, roster(&outsiders[3..], 1)),
        ]),
    };
    let root_pin = root.digest().unwrap();
    let mut authority = PqReleaseAuthorityV1::bootstrap_pinned(root, root_pin, 0).unwrap();
    let metadata = PqReleaseMetadataV1 {
        network_id: network,
        role: ROLE,
        root_generation: GENERATION,
        role_version: 1,
        expires_at: 90,
        expected_checkpoint: authority.checkpoint(),
        previous_content: None,
        content: [0x71; 32],
        approved_content_rollback: false,
    };
    let message = metadata.signing_message();
    // Positive synthetic reference through the actual original owner. This owner
    // and test keys never leave this process or touch installed/release state.
    let signed: Vec<_> = keys
        .iter()
        .chain([&outsiders[1]])
        .map(|key| PqReleaseSignatureV1 {
            key_id: key.public_key_id(),
            signature: key.sign_exact_message(&message).unwrap().to_vec(),
        })
        .collect();
    authority.accept(&metadata, &signed[..2], 0).unwrap();
    out.write_all(&[ROLE as u8]).unwrap();
    out.write_all(&network).unwrap();
    for u in [GENERATION, 1, 90] {
        out.write_all(&u.to_le_bytes()).unwrap();
    }
    out.write_all(&metadata.expected_checkpoint).unwrap();
    out.write_all(&[0; 33]).unwrap();
    out.write_all(&metadata.content).unwrap();
    out.write_all(&[0]).unwrap();
    out.write_all(&message).unwrap();
    for (key, signature) in keys.iter().chain([&outsiders[1]]).zip(signed) {
        out.write_all(&signature.key_id).unwrap();
        out.write_all(key.public_spki()).unwrap();
        out.write_all(&signature.signature).unwrap();
    }
}

fn verify(frame: &[u8]) -> u8 {
    let key_count = usize::from(u16::from_le_bytes(frame[..2].try_into().unwrap()));
    let sig_count = usize::from(u16::from_le_bytes(frame[2..4].try_into().unwrap()));
    let threshold = u16::from_le_bytes(frame[4..6].try_into().unwrap());
    assert_eq!(
        frame.len(),
        FIXED + key_count * KEY_ROW + sig_count * SIG_ROW
    );
    let sig_at = FIXED + key_count * KEY_ROW;
    let role_keys = frame[FIXED..sig_at]
        .chunks_exact(KEY_ROW)
        .map(|row| {
            (
                ReleaseKeyIdV1::try_from(&row[..32]).unwrap(),
                row[32..].to_vec(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let verifiers = role_keys
        .iter()
        .filter_map(|(id, spki)| {
            PqNativeVerifier::from_pinned_spki(spki, *id)
                .ok()
                .map(|v| (*id, v))
        })
        .collect();
    let role = PqReleaseRoleKeysV1 {
        threshold,
        keys: role_keys,
    };
    let signatures: Vec<_> = frame[sig_at..]
        .chunks_exact(SIG_ROW)
        .map(|row| {
            let n = usize::from(u16::from_le_bytes(row[32..34].try_into().unwrap()));
            let signature = if n > 4096 {
                // A typed input can declare any length. For unmaterialized
                // non-3309 lengths original checks width and does not read bytes.
                vec![0; n]
            } else {
                row[34..][..n].to_vec()
            };
            PqReleaseSignatureV1 {
                key_id: row[..32].try_into().unwrap(),
                signature,
            }
        })
        .collect();
    match verify_quorum(&role, &verifiers, &frame[48..FIXED], &signatures) {
        Ok(()) => 0,
        Err(PqReleaseErrorV1::InsufficientSignatures) => 105,
        Err(PqReleaseErrorV1::SignatureRejected) => 106,
        Err(PqReleaseErrorV1::DuplicateSigner) => 107,
        Err(PqReleaseErrorV1::UnknownSigner) => 108,
        Err(PqReleaseErrorV1::InvalidKey) => 109,
        unexpected => panic!("unexpected original result: {unexpected:?}"),
    }
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut out = io::stdout().lock();
    match std::env::args().nth(1).as_deref() {
        Some("issue") => issue(&input, &mut out),
        Some("verify") => {
            let mut rest = input.as_slice();
            while !rest.is_empty() {
                let n = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
                out.write_all(&[verify(&rest[4..4 + n])]).unwrap();
                rest = &rest[4 + n..];
            }
        }
        _ => panic!("expected qualification mode"),
    }
}

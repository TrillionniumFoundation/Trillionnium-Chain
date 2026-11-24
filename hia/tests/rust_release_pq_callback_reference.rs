// Locked Rust owner fixture. It outputs only public bytes; all signing keys
// originate in and are dropped in this one offline synthetic test process.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Write},
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use trnm_release_bundle::{
    pq_release::{
        pq_release_signature_digest_v1, PqReleaseAuthorityV1, PqReleaseErrorV1,
        PqReleaseMetadataV1, PqReleaseRoleKeysV1, PqReleaseRoleV1, PqReleaseRootV1,
        PqReleaseSignatureV1,
    },
    ArtifactEntryV0, BuildInputV0, BuilderProvenanceV0, Digest32V0, ExactSourceV0, ReleaseBundleV0,
    SbomPackageV0,
};
use zeroize::Zeroizing;

const NODE: PqReleaseRoleV1 = PqReleaseRoleV1::NodeSoftware;
const ROOT_NETWORK: [u8; 32] = [0xa1; 32];
const ROOT_EXPIRY: u64 = 100;
const NOW: u64 = 9;

fn blank() -> ReleaseBundleV0 {
    let z = Digest32V0([0; 32]);
    ReleaseBundleV0 {
        bundle_name: vec![],
        release_version: vec![],
        protocol_digest: z,
        exact_source: ExactSourceV0 {
            repository_digest: z,
            commit_digest: z,
            tree_digest: z,
            cargo_lock_digest: z,
            toolchain_digest: z,
            production_closure_digest: z,
            dirty: false,
        },
        artifacts: vec![],
        sbom_packages: vec![],
        provenance: BuilderProvenanceV0 {
            builder_identity_digest: z,
            workflow_digest: z,
            run_identity_digest: z,
            isolated_environment_digest: z,
            exact_source_digest: z,
            artifact_set_digest: z,
            sbom_digest: z,
            provenance_digest: z,
            build_inputs: vec![],
        },
        previous_bundle_digest: None,
        signer_identity_digest: z,
        signature_digest: z,
        bundle_digest: z,
    }
}

fn ephemeral(random: &mut File) -> PqNativeSigningKey {
    let mut seed = Zeroizing::new([0; 32]);
    random.read_exact(seed.as_mut()).unwrap();
    let public = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqNativeSigningKey::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&public).unwrap()).unwrap()
}
fn pins(keys: &[PqNativeSigningKey]) -> PqReleaseRoleKeysV1 {
    PqReleaseRoleKeysV1 {
        threshold: keys.len() as u16,
        keys: keys
            .iter()
            .map(|k| (k.public_key_id(), k.public_spki().to_vec()))
            .collect(),
    }
}

fn public_metadata(m: &PqReleaseMetadataV1) -> Vec<u8> {
    let mut v = vec![m.role as u8];
    v.extend(m.network_id);
    for n in [m.root_generation, m.role_version, m.expires_at] {
        v.extend(n.to_le_bytes());
    }
    v.extend(m.expected_checkpoint);
    v.push(u8::from(m.previous_content.is_some()));
    v.extend(m.previous_content.unwrap_or([0; 32]));
    v.extend(m.content);
    v.push(u8::from(m.approved_content_rollback));
    v
}

fn issue(input: &[u8], out: &mut impl Write) -> io::Result<()> {
    let (template, required, tail) = decode(input);
    let mut random = File::open("/dev/urandom")?;
    let mut node = [ephemeral(&mut random), ephemeral(&mut random)];
    node.sort_by_key(PqNativeSigningKey::public_key_id);
    let other = [
        ephemeral(&mut random),
        ephemeral(&mut random),
        ephemeral(&mut random),
        ephemeral(&mut random),
    ];
    let root = PqReleaseRootV1 {
        network_id: ROOT_NETWORK,
        generation: 1,
        expires_at: ROOT_EXPIRY,
        previous_root_digest: [0; 32],
        offline_root: pins(&other[..1]),
        roles: BTreeMap::from([
            (NODE, pins(&node)),
            (PqReleaseRoleV1::ProtocolConfiguration, pins(&other[1..2])),
            (PqReleaseRoleV1::CellManifest, pins(&other[2..3])),
            (PqReleaseRoleV1::CellActivation, pins(&other[3..4])),
        ]),
    };
    let pin = root.digest().unwrap();
    let initial = PqReleaseAuthorityV1::bootstrap_pinned(root.clone(), pin, NOW).unwrap();
    let checkpoint = initial.checkpoint();
    out.write_all(&ROOT_NETWORK)?;
    out.write_all(&checkpoint)?;
    for n in [ROOT_EXPIRY, NOW] {
        out.write_all(&n.to_le_bytes())?;
    }
    for k in &node {
        out.write_all(&k.public_key_id())?;
        out.write_all(k.public_spki())?;
    }
    for index in 0..14 {
        let mut authority = PqReleaseAuthorityV1::bootstrap_pinned(root.clone(), pin, NOW).unwrap();
        let mut bundle = template.clone();
        bundle.signer_identity_digest = Digest32V0(authority.bundle_signer_identity(NODE));
        if index == 11 {
            bundle.signer_identity_digest.0[0] ^= 1;
        }
        bundle.bundle_digest = bundle.canonical_digest();
        let mut metadata = PqReleaseMetadataV1 {
            network_id: ROOT_NETWORK,
            role: NODE,
            root_generation: 1,
            role_version: 1,
            expires_at: 90,
            expected_checkpoint: checkpoint,
            previous_content: None,
            content: bundle.bundle_digest.0,
            approved_content_rollback: false,
        };
        match index {
            1 | 3 | 10 => metadata.root_generation = 2,
            2 => metadata.network_id[0] ^= 1,
            4 | 8 | 9 | 12 => metadata.expected_checkpoint[0] ^= 1,
            6 => metadata.role = PqReleaseRoleV1::ProtocolConfiguration,
            7 => metadata.content[0] ^= 1,
            _ => {}
        }
        if index == 10 {
            metadata.expires_at = NOW;
        }
        let selected = [&node[0], if index == 13 { &other[1] } else { &node[1] }];
        let mut signatures: Vec<_> = selected
            .into_iter()
            .map(|k| PqReleaseSignatureV1 {
                key_id: k.public_key_id(),
                signature: k
                    .sign_exact_message(&metadata.signing_message())
                    .unwrap()
                    .to_vec(),
            })
            .collect();
        if matches!(index, 3 | 5 | 9) {
            signatures[0].signature[0] ^= 1;
        }
        bundle.signature_digest = Digest32V0(pq_release_signature_digest_v1(&signatures).unwrap());
        if index == 4 {
            bundle.signature_digest.0[0] ^= 1;
        }
        if index == 12 {
            signatures[1] = signatures[0].clone();
        }
        if matches!(index, 5..=7) {
            bundle.exact_source.dirty = true;
        }
        let outcome = authority.accept_bundle(&bundle, &required, &metadata, &signatures, NOW);
        let code = match outcome {
            Ok(_) => 0,
            Err(PqReleaseErrorV1::BundleBinding) => 1,
            Err(PqReleaseErrorV1::InvalidBundle) => 2,
            Err(PqReleaseErrorV1::Expired) => 203,
            Err(PqReleaseErrorV1::WrongAuthority) => 204,
            Err(PqReleaseErrorV1::CheckpointConflict) => 205,
            result => panic!("unexpected locked original bundle result: {result:?}"),
        };
        let mut frame = input.to_vec();
        frame[42..74].copy_from_slice(&bundle.signer_identity_digest.0);
        frame[74..106].copy_from_slice(&bundle.signature_digest.0);
        frame[298] = u8::from(bundle.exact_source.dirty);
        frame[tail..tail + 32].copy_from_slice(&bundle.bundle_digest.0);
        out.write_all(&[code])?;
        out.write_all(&public_metadata(&metadata))?;
        for sig in &signatures {
            out.write_all(&sig.key_id)?;
            out.write_all(&sig.signature)?;
        }
        out.write_all(&frame)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mut input = vec![];
    io::stdin().read_to_end(&mut input)?;
    issue(&input, &mut io::stdout().lock())
}

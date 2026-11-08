use std::io::{self, Cursor, Read};

use sha2::{Digest, Sha256, Sha512};
use trnm_protocol::crypto_profile::{
    BoundCryptoProfile, CryptoProfile, ProfileBinding, ProfileScope,
};

use super::*;
use crate::cell::{CellChunkV1, CellManifestV1};

const PAYLOAD: &[u8] = b"TCM2 model payload readback\n";

fn profile(kind: CryptoProfile) -> BoundCryptoProfile {
    kind.bind(ProfileBinding {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        protocol_version: 1,
        scope: ProfileScope::WholeSystemCandidate,
        activation_height: 10,
        retirement_height: Some(100),
    })
    .unwrap()
}

fn context(kind: ContentKind) -> ContentContextV1 {
    ContentContextV1::new(
        &profile(CryptoProfile::CandidateMlDsa65V1),
        kind,
        [7; 64],
        9,
    )
    .unwrap()
}

fn metadata() -> CellContextV1 {
    CellContextV1 {
        family: "test-cell".into(),
        base: [0x11; 32],
        parent: [0x22; 32],
        tokenizer: [0x33; 32],
        layout: [0x44; 32],
        runtime: [0x55; 32],
    }
}

fn budget() -> ContentReadBudget {
    ContentReadBudget::new(32, 1_048_576).unwrap()
}

fn observed_payload(bytes: &[u8]) -> ObservedContentV1 {
    observe_bytes(&context(ContentKind::ModelPayload), &mut budget(), bytes).unwrap()
}

fn fixture(bytes: &[u8]) -> (CellContentManifestV2, ContentClaimV1) {
    let manifest =
        CellContentManifestV2::from_observed_payload(metadata(), &observed_payload(bytes)).unwrap();
    let pin = manifest
        .observe_manifest(&context(ContentKind::ModelManifest), &mut budget())
        .unwrap()
        .claim()
        .clone();
    (manifest, pin)
}

#[derive(Debug)]
struct CountingReader<'a> {
    bytes: Cursor<&'a [u8]>,
    calls: usize,
}

impl<'a> CountingReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            calls: 0,
        }
    }
}

impl Read for CountingReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        self.bytes.read(output)
    }
}

#[test]
fn exact_wire_and_full_readback_match_independent_python_vectors() {
    // Generated independently with Python hashlib and explicit big-endian
    // framing. No Rust encoder was imported or executed to obtain these values.
    // CPQ1 binding: network=01*32, parameters=02*32, genesis=03*32, version=1,
    // WholeSystemCandidate, activation=10, retirement=100. CCH1 instance=07*64,
    // generation=9, payload kind=4, manifest kind=3; legacy aliases=11..55*32.
    let (manifest, pin) = fixture(PAYLOAD);
    let wire = manifest.encode();
    assert_eq!(PAYLOAD.len(), 28);
    assert_eq!(wire.len(), 387);
    assert_eq!(
        hex::encode(manifest.payload_claim().digest()),
        concat!(
            "48cec7e9775f3ce42c65e7ffff5dca1f594780bd94f120a29d0591f2968e49c6b",
            "3148bde76e82dd21d54fba861967c0d2ca517e4d5900e1cfdccfdf9d5b3212a"
        )
    );
    assert_eq!(
        hex::encode(pin.digest()),
        concat!(
            "95ae42661eadaf65b7f6b6fb1efa8052be7b688a15e0a322152a47eafa433e4fc",
            "6cb7f2b43d6f2bef401920c8ba17cdc1911936cd9afc70ebc5b2ff8612f7009"
        )
    );
    assert_eq!(
        hex::encode(Sha512::digest(&wire)),
        concat!(
            "155c559b4dbb995c6ed00f677d6f0147e84aead7da4bf618c7fc6d59b4d099074",
            "e3533df1c6668f2f84da9357366a9b6e78654e7a9a58b871c4e1c9c96cd8550"
        )
    );
    let decoded = CellContentManifestV2::decode(&wire).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.legacy_metadata(), &metadata());
    let mut reader = CountingReader::new(PAYLOAD);
    let mut read_budget = budget();
    let readback = decoded
        .verify_payload_reader(&pin, &mut read_budget, &mut reader)
        .unwrap();
    assert_eq!(readback.manifest_claim(), &pin);
    assert_eq!(readback.payload_claim(), manifest.payload_claim());
    assert_eq!(reader.bytes.position(), PAYLOAD.len() as u64);
    assert_eq!(reader.calls, 2); // full payload, then an actual EOF probe
    assert_eq!(read_budget.reads_reserved(), 2);
    assert_eq!(
        read_budget.bytes_reserved(),
        (wire.len() + PAYLOAD.len() + 2) as u64
    );
}

#[test]
fn changed_real_payload_truncation_and_tail_refuse_readback() {
    let (manifest, pin) = fixture(PAYLOAD);
    let mut changed = PAYLOAD.to_vec();
    changed[PAYLOAD.len() - 1] ^= 1;
    assert!(matches!(
        manifest.verify_payload_bytes(&pin, &mut budget(), &changed),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
    assert!(matches!(
        manifest.verify_payload_bytes(&pin, &mut budget(), &PAYLOAD[..PAYLOAD.len() - 1]),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Truncated
        ))
    ));
    let mut extra = PAYLOAD.to_vec();
    extra.push(0);
    assert!(matches!(
        manifest.verify_payload_bytes(&pin, &mut budget(), &extra),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::TrailingBytes
        ))
    ));
}

struct FailingReader<'a> {
    bytes: Cursor<&'a [u8]>,
    fail_at: u64,
    error: io::ErrorKind,
}

impl Read for FailingReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.fail_at.saturating_sub(self.bytes.position());
        if remaining == 0 {
            return Err(io::Error::new(
                self.error,
                "retained injected source failure",
            ));
        }
        let count = output.len().min(remaining as usize);
        self.bytes.read(&mut output[..count])
    }
}

#[test]
fn source_errors_and_cancellation_never_become_complete_readback() {
    let (manifest, pin) = fixture(PAYLOAD);
    for fail_at in [0, 5, PAYLOAD.len() as u64] {
        for error in [io::ErrorKind::Interrupted, io::ErrorKind::TimedOut] {
            let mut reader = FailingReader {
                bytes: Cursor::new(PAYLOAD),
                fail_at,
                error,
            };
            let mut read_budget = budget();
            let result = manifest.verify_payload_reader(&pin, &mut read_budget, &mut reader);
            assert!(matches!(result, Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::Io(actual)
            )) if actual.kind() == error));
            assert_eq!(read_budget.reads_reserved(), 2);
            assert_eq!(
                read_budget.bytes_reserved(),
                (manifest.encode().len() + PAYLOAD.len() + 2) as u64
            );
        }
    }
}

#[test]
fn legacy_digest_bytes_and_sha512_digest_wrapping_do_not_verify_real_payload() {
    // Equal lengths ensure the first refusal is about actual bytes, not merely
    // a payload-length check. Reading digest bytes is not reading model bytes.
    let payload = [0x61; 32];
    let legacy_digest: [u8; 32] = Sha256::digest(payload).into();
    let (digest_manifest, digest_pin) = fixture(&legacy_digest);
    assert!(matches!(
        digest_manifest.verify_payload_bytes(&digest_pin, &mut budget(), &payload),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));

    // Even a structurally valid CCH1 claim with a 64-byte H512(H256(payload))
    // replacement cannot pass the complete real-payload observation.
    let (real_manifest, _) = fixture(&payload);
    let mut forged_wire = real_manifest.encode();
    let digest_start = forged_wire.len() - 64;
    forged_wire[digest_start..].copy_from_slice(&Sha512::digest(legacy_digest));
    let forged_manifest = CellContentManifestV2::decode(&forged_wire).unwrap();
    let forged_pin = forged_manifest
        .observe_manifest(&context(ContentKind::ModelManifest), &mut budget())
        .unwrap();
    assert!(matches!(
        forged_manifest.verify_payload_bytes(forged_pin.claim(), &mut budget(), &payload),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
}

#[test]
fn payload_constructor_and_decoder_reject_every_other_content_role() {
    let (valid, _) = fixture(PAYLOAD);
    for kind in [
        ContentKind::StateSnapshot,
        ContentKind::ReleaseArtifact,
        ContentKind::ModelManifest,
        ContentKind::MigrationCheckpoint,
    ] {
        let wrong = observe_bytes(&context(kind), &mut budget(), PAYLOAD).unwrap();
        assert!(CellContentManifestV2::from_observed_payload(metadata(), &wrong).is_err());
        let mut wire = valid.encode();
        let start = wire.len() - CONTENT_CLAIM_BYTES;
        wire[start..].copy_from_slice(&wrong.claim().encode());
        assert!(CellContentManifestV2::decode(&wire).is_err());
    }
}

#[test]
fn wrong_manifest_role_instance_generation_or_profile_is_refused_before_payload_io() {
    let (manifest, _) = fixture(PAYLOAD);
    let fixed_profile = profile(CryptoProfile::CandidateMlDsa65V1);
    let variants = [
        context(ContentKind::ModelPayload),
        context(ContentKind::StateSnapshot),
        ContentContextV1::new(&fixed_profile, ContentKind::ModelManifest, [8; 64], 9).unwrap(),
        ContentContextV1::new(&fixed_profile, ContentKind::ModelManifest, [7; 64], 10).unwrap(),
        ContentContextV1::new(
            &profile(CryptoProfile::CandidateMlDsa87V1),
            ContentKind::ModelManifest,
            [7; 64],
            9,
        )
        .unwrap(),
    ];
    for wrong_context in variants {
        assert!(manifest
            .observe_manifest(&wrong_context, &mut budget())
            .is_err());
        let wrong_pin = observe_bytes(&wrong_context, &mut budget(), &manifest.encode()).unwrap();
        let mut reader = CountingReader::new(PAYLOAD);
        assert!(manifest
            .verify_payload_reader(wrong_pin.claim(), &mut budget(), &mut reader)
            .is_err());
        assert_eq!(reader.calls, 0);
    }
}

#[test]
fn changed_legacy_metadata_is_bound_but_does_not_select_the_expected_pin() {
    let original_payload = observed_payload(PAYLOAD);
    let (_, original_pin) = fixture(PAYLOAD);
    let mut variants = vec![];
    let mut family = metadata();
    family.family.push('x');
    variants.push(family);
    for which in 0..5 {
        let mut changed = metadata();
        let alias = match which {
            0 => &mut changed.base,
            1 => &mut changed.parent,
            2 => &mut changed.tokenizer,
            3 => &mut changed.layout,
            _ => &mut changed.runtime,
        };
        alias[0] ^= 1;
        variants.push(changed);
    }
    for changed in variants {
        let replacement =
            CellContentManifestV2::from_observed_payload(changed, &original_payload).unwrap();
        let mut reader = CountingReader::new(PAYLOAD);
        assert!(replacement
            .verify_payload_reader(&original_pin, &mut budget(), &mut reader)
            .is_err());
        assert_eq!(reader.calls, 0);
    }
}

#[test]
fn all_manifest_truncations_tails_and_legacy_formats_are_rejected() {
    let (manifest, _) = fixture(PAYLOAD);
    let wire = manifest.encode();
    for size in 0..wire.len() {
        assert!(CellContentManifestV2::decode(&wire[..size]).is_err());
    }
    let mut tail = wire.clone();
    tail.push(0);
    assert!(CellContentManifestV2::decode(&tail).is_err());
    let mut unknown = wire.clone();
    unknown[..4].copy_from_slice(b"TCM3");
    assert!(CellContentManifestV2::decode(&unknown).is_err());
    let mut bad_family = wire;
    bad_family[5] = b'/';
    assert!(CellContentManifestV2::decode(&bad_family).is_err());

    let digest = Sha256::digest(PAYLOAD).into();
    let legacy = CellManifestV1::new(
        metadata(),
        PAYLOAD.len() as u64,
        digest,
        16_384,
        vec![CellChunkV1 {
            size: PAYLOAD.len() as u32,
            sha256: digest,
        }],
    )
    .unwrap();
    assert!(CellContentManifestV2::decode(&legacy.encode()).is_err());
    assert!(CellManifestV1::decode(&manifest.encode()).is_err());
    let mut relabeled = legacy.encode();
    relabeled[..4].copy_from_slice(b"TCM2");
    assert!(CellContentManifestV2::decode(&relabeled).is_err());
    assert!(CellContentManifestV2::decode(&Sha512::digest(legacy.encode())).is_err());
}

#[test]
fn payload_size_limits_apply_to_local_creation_and_untrusted_claims() {
    assert!(
        CellContentManifestV2::from_observed_payload(metadata(), &observed_payload(&[])).is_err()
    );
    let (manifest, _) = fixture(PAYLOAD);
    for declared_len in [0, MAX_CELL_BYTES + 1, u64::MAX] {
        let mut wire = manifest.encode();
        // CCH1's exact length field immediately precedes its 64-byte digest.
        let length_start = wire.len() - 64 - 8;
        wire[length_start..length_start + 8].copy_from_slice(&declared_len.to_be_bytes());
        assert!(CellContentManifestV2::decode(&wire).is_err());
    }
}

#[test]
fn complete_readback_uses_one_cumulative_budget_with_no_failed_read_refund() {
    let (manifest, pin) = fixture(PAYLOAD);
    let total_bytes = (manifest.encode().len() + PAYLOAD.len() + 2) as u64;
    let mut exact = ContentReadBudget::new(2, total_bytes).unwrap();
    manifest
        .verify_payload_bytes(&pin, &mut exact, PAYLOAD)
        .unwrap();
    assert_eq!(exact.bytes_reserved(), total_bytes);
    assert_eq!(exact.reads_reserved(), 2);

    for mut exhausted in [
        ContentReadBudget::new(1, total_bytes).unwrap(),
        ContentReadBudget::new(2, total_bytes - 1).unwrap(),
    ] {
        let mut reader = CountingReader::new(PAYLOAD);
        assert!(matches!(
            manifest.verify_payload_reader(&pin, &mut exhausted, &mut reader),
            Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::Budget
            ))
        ));
        assert_eq!(reader.calls, 0);
        assert!(exhausted.exhausted());
    }

    let mut once = ContentReadBudget::new(2, total_bytes).unwrap();
    assert!(manifest
        .verify_payload_bytes(&pin, &mut once, &PAYLOAD[..2])
        .is_err());
    assert_eq!(once.bytes_reserved(), total_bytes);
    assert!(matches!(
        manifest.verify_payload_bytes(&pin, &mut once, PAYLOAD),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Budget
        ))
    ));
}

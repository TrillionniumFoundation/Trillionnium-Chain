use super::*;
use crate::crypto_profile::{CryptoProfile, ProfileBinding, ProfileScope};
use sha2::Sha256;

fn profile() -> BoundCryptoProfile {
    CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap()
}
fn context() -> ContentContextV1 {
    ContentContextV1::new(&profile(), ContentKind::ReleaseArtifact, [4; 64], 7).unwrap()
}
fn budget() -> ContentReadBudget {
    ContentReadBudget::new(100, 4_000_000).unwrap()
}

#[test]
fn complete_content_and_every_context_field_are_bound() {
    let c = context();
    let mut b = budget();
    let observation = observe_bytes(&c, &mut b, b"actual artifact bytes").unwrap();
    let encoded = observation.claim().encode();
    assert_eq!(encoded.len(), CONTENT_CLAIM_BYTES);
    assert_eq!(&encoded[133..141], &7u64.to_be_bytes());
    assert_eq!(&encoded[141..149], &21u64.to_be_bytes());
    ContentClaimV1::decode(&encoded)
        .unwrap()
        .verify(&observation)
        .unwrap();
    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        if let Ok(claim) = ContentClaimV1::decode(&changed) {
            assert!(claim.verify(&observation).is_err(), "unbound byte {index}");
        }
    }
    let changed = observe_bytes(&c, &mut b, b"actual artifact byteS").unwrap();
    assert!(observation.claim().verify(&changed).is_err());
    for kind in [
        ContentKind::StateSnapshot,
        ContentKind::ModelManifest,
        ContentKind::ModelPayload,
        ContentKind::MigrationCheckpoint,
    ] {
        let other = ContentContextV1::new(&profile(), kind, [4; 64], 7).unwrap();
        let observed = observe_bytes(&other, &mut b, b"actual artifact bytes").unwrap();
        assert!(observation.claim().verify(&observed).is_err());
    }
}

#[test]
fn old_digest_and_rehashed_old_digest_do_not_verify_as_actual_content() {
    let actual = [31u8; 32]; // Legitimate 32-byte content must remain supported.
    let mut b = budget();
    let expected = observe_bytes(&context(), &mut b, &actual).unwrap();
    let old = Sha256::digest(actual);
    let wrapped = Sha512::digest(old);
    for bytes in [old.as_slice(), wrapped.as_slice()] {
        let supplied = observe_bytes(&context(), &mut b, bytes).unwrap();
        assert!(expected.claim().verify(&supplied).is_err());
        assert!(ContentClaimV1::decode(bytes).is_err());
    }
}

#[test]
fn decoder_rejects_unknown_suite_short_digest_and_noncanonical_tail() {
    let observed = observe_bytes(&context(), &mut budget(), b"x").unwrap();
    let wire = observed.claim().encode();
    for len in 0..wire.len() {
        assert!(ContentClaimV1::decode(&wire[..len]).is_err());
    }
    let mut changed = wire.clone();
    changed.push(0);
    assert!(ContentClaimV1::decode(&changed).is_err());
    for unknown in [0, 6, 255] {
        let mut changed = wire.clone();
        changed[68] = unknown;
        assert!(ContentClaimV1::decode(&changed).is_err());
    }
    for range in [4..68, 69..133] {
        let mut changed = wire.clone();
        changed[range].fill(0);
        assert!(ContentClaimV1::decode(&changed).is_err());
    }
    let mut legacy = wire;
    legacy[..4].copy_from_slice(b"CPQ1");
    assert!(ContentClaimV1::decode(&legacy).is_err());
}

struct FailingReader {
    remaining: usize,
}
impl Read for FailingReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        let n = out.len().min(self.remaining);
        out[..n].fill(9);
        self.remaining -= n;
        Ok(n)
    }
}
#[test]
fn short_long_partial_and_eof_probe_failures_never_produce_an_observation() {
    let c = context();
    let mut b = budget();
    assert!(matches!(
        observe_reader(&c, &mut b, 3, &mut Cursor::new(b"ab")),
        Err(ContentCommitmentError::Truncated)
    ));
    assert!(matches!(
        observe_reader(&c, &mut b, 3, &mut Cursor::new(b"abcd")),
        Err(ContentCommitmentError::TrailingBytes)
    ));
    assert!(matches!(
        observe_reader(&c, &mut b, 3, &mut FailingReader { remaining: 2 }),
        Err(ContentCommitmentError::Io(_))
    ));
    assert!(matches!(
        observe_reader(&c, &mut b, 3, &mut FailingReader { remaining: 3 }),
        Err(ContentCommitmentError::Io(_))
    ));
    assert_eq!((b.reads_reserved(), b.bytes_reserved()), (4, 16));
}

struct NeverRead;
impl Read for NeverRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("read before reservation")
    }
}
#[test]
fn reservation_is_cumulative_sticky_and_precedes_any_reader_call() {
    let c = context();
    let mut b = ContentReadBudget::new(2, 8).unwrap();
    assert!(observe_reader(&c, &mut b, 3, &mut Cursor::new(b"ab")).is_err());
    observe_bytes(&c, &mut b, b"xyz").unwrap();
    assert_eq!((b.reads_reserved(), b.bytes_reserved()), (2, 8));
    assert!(matches!(
        observe_reader(&c, &mut b, 0, &mut NeverRead),
        Err(ContentCommitmentError::Budget)
    ));
    assert!(b.exhausted());
    assert!(observe_reader(&c, &mut b, 0, &mut NeverRead).is_err());
    let mut overflow = ContentReadBudget::new(u64::MAX, u64::MAX).unwrap();
    assert!(observe_reader(&c, &mut overflow, u64::MAX, &mut NeverRead).is_err());
    assert!(overflow.exhausted());
}

struct Fragmented<R> {
    inner: R,
    maximum: usize,
}
impl<R: Read> Read for Fragmented<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.maximum);
        self.inner.read(&mut out[..n])
    }
}
#[test]
fn actual_large_content_is_independent_of_transport_fragmentation() {
    let data: Vec<u8> = (0..70_013).map(|n| (n % 251) as u8).collect();
    let expected = observe_bytes(&context(), &mut budget(), &data).unwrap();
    for maximum in [1, 7, 4095, 8192] {
        let mut reader = Fragmented {
            inner: Cursor::new(&data),
            maximum,
        };
        let observed =
            observe_reader(&context(), &mut budget(), data.len() as u64, &mut reader).unwrap();
        expected.claim().verify(&observed).unwrap();
    }
    let empty = observe_bytes(&context(), &mut budget(), &[]).unwrap();
    assert_eq!(empty.claim().content_len(), 0);
    assert_ne!(empty.claim().digest(), expected.claim().digest());
}

#[test]
fn legacy_profile_and_unspecified_instance_cannot_construct_candidate_context() {
    let mut binding = *profile().binding();
    binding.scope = ProfileScope::NativeAccounts;
    binding.protocol_version = 6;
    let legacy = CryptoProfile::LegacyMlDsa65V1.bind(binding).unwrap();
    assert!(matches!(
        ContentContextV1::new(&legacy, ContentKind::StateSnapshot, [4; 64], 0),
        Err(ContentCommitmentError::CandidateOnly)
    ));
    assert!(ContentContextV1::new(&profile(), ContentKind::StateSnapshot, [0; 64], 0).is_err());
}

#[test]
fn independently_generated_python_framing_vectors_match_native_hashing() {
    // Synthetic IDs test byte framing only. They are not selectable profiles;
    // the real signature-boundary tests independently reject their authorization.
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/cpq1-content-v1/vectors.json"
    ))
    .unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let claim =
            ContentClaimV1::decode(&hex::decode(vector["claim_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let payload = hex::decode(vector["payload_hex"].as_str().unwrap()).unwrap();
        let observed = observe_bytes(claim.context(), &mut budget(), &payload).unwrap();
        claim.verify(&observed).unwrap();
    }
}

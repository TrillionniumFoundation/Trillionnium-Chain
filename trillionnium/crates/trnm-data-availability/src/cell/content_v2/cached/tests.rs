use std::time::Duration;

use trnm_protocol::{
    content_commitment::{observe_bytes, ContentContextV1, ContentKind},
    crypto_profile::{BoundCryptoProfile, CryptoProfile, ProfileBinding, ProfileScope},
};

use super::*;
use crate::cell::{CellCacheConfigV4, CellChunkV1, CellContextV1};

const CHUNK_BYTES: u32 = 16_384;

fn profile() -> BoundCryptoProfile {
    CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
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
    ContentContextV1::new(&profile(), kind, [7; 64], 9).unwrap()
}

fn observation_budget() -> ContentReadBudget {
    ContentReadBudget::new(32, 1_048_576).unwrap()
}

struct Fixture {
    directory: tempfile::TempDir,
    store: CellStoreV1,
    transport: CellManifestV1,
    manifest: CellContentManifestV2,
    pin: ContentClaimV1,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let bytes: Vec<u8> = (0_u32..(2 * CHUNK_BYTES + 113))
            .map(|i| (i.wrapping_mul(31) ^ (i / CHUNK_BYTES)) as u8)
            .collect();
        let metadata = CellContextV1 {
            family: "cached-full-content".into(),
            base: [0x11; 32],
            parent: [0x22; 32],
            tokenizer: [0x33; 32],
            layout: [0x44; 32],
            runtime: [0x55; 32],
        };
        let directory = tempfile::tempdir().unwrap();
        let store = CellStoreV1::open(
            &directory.path().join("cache.sqlite"),
            CellCacheConfigV4 {
                max_database_bytes: 16 * 1024 * 1024,
                max_logical_bytes: 4 * 1024 * 1024,
                max_chunk_rows: 256,
                max_manifest_rows: 16,
            },
        )
        .unwrap();
        let chunks = bytes
            .chunks(CHUNK_BYTES as usize)
            .map(|bytes| {
                let chunk = CellChunkV1 {
                    size: bytes.len() as u32,
                    sha256: Sha256::digest(bytes).into(),
                };
                store.put_chunk(&chunk, bytes).unwrap();
                chunk
            })
            .collect();
        let transport = CellManifestV1::new(
            metadata.clone(),
            bytes.len() as u64,
            Sha256::digest(&bytes).into(),
            CHUNK_BYTES,
            chunks,
        )
        .unwrap();
        store
            .put_manifest(transport.id(), &transport.encode())
            .unwrap();
        let observed = observe_bytes(
            &context(ContentKind::ModelPayload),
            &mut observation_budget(),
            &bytes,
        )
        .unwrap();
        let manifest = CellContentManifestV2::from_observed_payload(metadata, &observed).unwrap();
        let pin = manifest
            .observe_manifest(
                &context(ContentKind::ModelManifest),
                &mut observation_budget(),
            )
            .unwrap()
            .claim()
            .clone();
        Self {
            directory,
            store,
            transport,
            manifest,
            pin,
            bytes,
        }
    }

    fn required_bytes(&self) -> u64 {
        self.manifest.encode().len() as u64 + self.transport.size() + 2
    }

    fn materialize(
        &self,
        budget: &mut ContentReadBudget,
        deadline: Instant,
        output: &Path,
    ) -> CellContentReadbackV2 {
        self.manifest
            .materialize_cached_payload(
                &self.store,
                &self.pin,
                &self.transport,
                budget,
                deadline,
                output,
            )
            .unwrap()
    }

    fn check_output(&self, readback: &CellContentReadbackV2, output: &Path) {
        let actual = fs::read(output).unwrap();
        assert_eq!(actual, self.bytes);
        let observed = observe_bytes(
            &context(ContentKind::ModelPayload),
            &mut observation_budget(),
            &actual,
        )
        .unwrap();
        readback.payload_claim().verify(&observed).unwrap();
        assert_eq!(readback.manifest_claim(), &self.pin);
        assert_eq!(readback.payload_claim(), self.manifest.payload_claim());
        for entry in fs::read_dir(self.directory.path()).unwrap() {
            assert!(!entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".partial"));
        }
    }
}

#[test]
fn normal_multichunk_cache_materialization_preserves_complete_claim_and_original_budget() {
    let fixture = Fixture::new();
    let output = fixture.directory.path().join("payload");
    let mut budget = ContentReadBudget::new(2, fixture.required_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let readback = fixture.materialize(&mut budget, deadline, &output);
    fixture.check_output(&readback, &output);
    assert_eq!(budget.reads_reserved(), 2);
    assert_eq!(budget.bytes_reserved(), fixture.required_bytes());
    assert_eq!(
        fixture.store.manifest(fixture.transport.id()).unwrap(),
        Some(fixture.transport.clone())
    );
}

#[test]
fn normal_repeated_materialization_shares_one_budget_and_original_deadline() {
    let fixture = Fixture::new();
    let mut budget = ContentReadBudget::new(4, 2 * fixture.required_bytes()).unwrap();
    let original_deadline = Instant::now() + Duration::from_secs(30);
    for completed in 1..=2 {
        let output = fixture
            .directory
            .path()
            .join(format!("payload-{completed}"));
        let readback = fixture.materialize(&mut budget, original_deadline, &output);
        fixture.check_output(&readback, &output);
        assert_eq!(budget.reads_reserved(), 2 * completed);
        assert_eq!(
            budget.bytes_reserved(),
            completed * fixture.required_bytes()
        );
    }
    fixture.store.verify_complete(&fixture.transport).unwrap();
}

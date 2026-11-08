use std::{cell::Cell, rc::Rc, sync::mpsc, time::Duration};

use rusqlite::{params, Connection};
use sha2::Sha512;
use trnm_protocol::{
    content_commitment::{observe_bytes, ContentCommitmentError, ContentContextV1, ContentKind},
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

fn metadata() -> CellContextV1 {
    CellContextV1 {
        family: "cached-full-content".into(),
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

fn pinned_manifest(bytes: &[u8]) -> (CellContentManifestV2, ContentClaimV1) {
    let observed =
        observe_bytes(&context(ContentKind::ModelPayload), &mut budget(), bytes).unwrap();
    let manifest = CellContentManifestV2::from_observed_payload(metadata(), &observed).unwrap();
    let pin = manifest
        .observe_manifest(&context(ContentKind::ModelManifest), &mut budget())
        .unwrap()
        .claim()
        .clone();
    (manifest, pin)
}

fn payload() -> Vec<u8> {
    (0_u32..(2 * CHUNK_BYTES + 113))
        .map(|i| (i.wrapping_mul(31) ^ (i / CHUNK_BYTES)) as u8)
        .collect()
}

struct Fixture {
    directory: tempfile::TempDir,
    store: CellStoreV1,
    transport: CellManifestV1,
    manifest: CellContentManifestV2,
    pin: ContentClaimV1,
}

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
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
            metadata(),
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
            CHUNK_BYTES,
            chunks,
        )
        .unwrap();
        store
            .put_manifest(transport.id(), &transport.encode())
            .unwrap();
        let (manifest, pin) = pinned_manifest(bytes);
        Self {
            directory,
            store,
            transport,
            manifest,
            pin,
        }
    }

    fn exact_budget(&self) -> ContentReadBudget {
        ContentReadBudget::new(2, self.required_bytes()).unwrap()
    }

    fn required_bytes(&self) -> u64 {
        self.manifest.encode().len() as u64 + self.transport.size() + 2
    }

    fn materialize(
        &self,
        budget: &mut ContentReadBudget,
        deadline: Instant,
        output: &Path,
    ) -> Result<CellContentReadbackV2, CellContentErrorV2> {
        self.manifest.materialize_cached_payload(
            &self.store,
            &self.pin,
            &self.transport,
            budget,
            deadline,
            output,
        )
    }

    fn database(&self) -> Connection {
        Connection::open(self.directory.path().join("cache.sqlite")).unwrap()
    }

    fn corrupt_first_chunk(&self) -> Vec<u8> {
        let first = &self.transport.chunks()[0];
        let corrupt = vec![0xb9; first.size as usize];
        self.database()
            .execute(
                "UPDATE cell_chunks_v1 SET bytes=?1 WHERE hash=?2",
                params![&corrupt, first.sha256.as_slice()],
            )
            .unwrap();
        corrupt
    }

    fn raw_first_chunk(&self) -> Vec<u8> {
        self.database()
            .query_row(
                "SELECT bytes FROM cell_chunks_v1 WHERE hash=?1",
                [self.transport.chunks()[0].sha256.as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn assert_no_partials(directory: &Path) {
    for entry in fs::read_dir(directory).unwrap() {
        assert!(!entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial"));
    }
}

fn assert_refused_output(fixture: &Fixture, output: &Path) {
    assert!(!output.exists());
    assert_no_partials(fixture.directory.path());
}

#[test]
fn cached_materialization_binds_the_exact_multichunk_output_and_eof() {
    let bytes = payload();
    let fixture = Fixture::new(&bytes);
    let output = fixture.directory.path().join("payload");
    let mut consumed = fixture.exact_budget();
    let readback = fixture
        .materialize(&mut consumed, deadline(), &output)
        .unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    let actual = observe_bytes(
        &context(ContentKind::ModelPayload),
        &mut budget(),
        &fs::read(&output).unwrap(),
    )
    .unwrap();
    readback.payload_claim().verify(&actual).unwrap();
    assert_eq!(readback.manifest_claim(), &fixture.pin);
    assert_eq!(readback.payload_claim(), fixture.manifest.payload_claim());
    assert_eq!(consumed.reads_reserved(), 2);
    assert_eq!(consumed.bytes_reserved(), fixture.required_bytes());
    assert_no_partials(fixture.directory.path());
}

#[test]
fn cache_mutation_cannot_change_owned_bytes_and_a_fresh_read_refuses_corruption() {
    let bytes = payload();
    let fixture = Fixture::new(&bytes);
    let first = fixture.transport.chunks()[0].clone();
    let database = fixture.directory.path().join("cache.sqlite");
    let changed = Rc::new(Cell::new(false));
    let observed = changed.clone();
    let original = deadline();
    let output = fixture.directory.path().join("owned-bytes");
    let readback = with_checkpoint_hook(
        Stage::PayloadRead,
        Box::new(move |actual| {
            assert_eq!(actual, original);
            // Only the first half of this chunk has been returned. The remaining
            // bytes must come from the same immutable owned buffer, even though
            // the corresponding disposable cache row changes under that buffer.
            Connection::open(database)
                .unwrap()
                .execute(
                    "UPDATE cell_chunks_v1 SET bytes=?1 WHERE hash=?2",
                    params![vec![0xb9_u8; first.size as usize], first.sha256.as_slice()],
                )
                .unwrap();
            observed.set(true);
        }),
        || fixture.materialize(&mut fixture.exact_budget(), original, &output),
    )
    .unwrap();
    assert!(changed.get());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    let actual = observe_bytes(
        &context(ContentKind::ModelPayload),
        &mut budget(),
        &fs::read(&output).unwrap(),
    )
    .unwrap();
    readback.payload_claim().verify(&actual).unwrap();
    assert_eq!(
        fixture.raw_first_chunk(),
        vec![0xb9_u8; CHUNK_BYTES as usize]
    );
    let later = fixture.directory.path().join("fresh-read");
    assert!(matches!(
        fixture.materialize(&mut fixture.exact_budget(), deadline(), &later),
        Err(CellContentErrorV2::Commitment(ContentCommitmentError::Io(error)))
            if matches!(error.get_ref().and_then(|error| error.downcast_ref::<CellErrorV1>()),
                Some(CellErrorV1::Unavailable))
    ));
    assert_refused_output(&fixture, &later);
    assert_eq!(fs::read(output).unwrap(), bytes);
}

#[test]
fn self_consistent_legacy_cache_cannot_replace_the_pinned_full_payload() {
    let fixture = Fixture::new(b"different model bytes");
    let (expected, pin) = pinned_manifest(b"authentic model bytes");
    assert_eq!(
        expected.payload_claim().content_len(),
        fixture.transport.size()
    );
    // The legacy path accepts this complete, internally consistent substitute.
    fixture.store.verify_complete(&fixture.transport).unwrap();
    let legacy_output = fixture.directory.path().join("legacy-output");
    fixture
        .store
        .materialize(&fixture.transport, &legacy_output)
        .unwrap();
    assert_eq!(fs::read(legacy_output).unwrap(), b"different model bytes");
    let output = fixture.directory.path().join("full-output");
    let mut consumed = fixture.exact_budget();
    assert!(matches!(
        expected.materialize_cached_payload(
            &fixture.store,
            &pin,
            &fixture.transport,
            &mut consumed,
            deadline(),
            &output,
        ),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
    assert_eq!(consumed.reads_reserved(), 2);
    assert_eq!(consumed.bytes_reserved(), fixture.required_bytes());
    assert_refused_output(&fixture, &output);
}

#[test]
fn wrapping_a_legacy_digest_cannot_materialize_actual_payload_bytes() {
    let bytes = [0x61; 32];
    let fixture = Fixture::new(&bytes);
    let mut wire = fixture.manifest.encode();
    let digest_start = wire.len() - 64;
    wire[digest_start..].copy_from_slice(&Sha512::digest(Sha256::digest(bytes)));
    let wrapped = CellContentManifestV2::decode(&wire).unwrap();
    let pin = wrapped
        .observe_manifest(&context(ContentKind::ModelManifest), &mut budget())
        .unwrap();
    let output = fixture.directory.path().join("wrapped");
    assert!(matches!(
        wrapped.materialize_cached_payload(
            &fixture.store,
            pin.claim(),
            &fixture.transport,
            &mut fixture.exact_budget(),
            deadline(),
            &output,
        ),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
    assert_refused_output(&fixture, &output);
}

#[test]
fn wrong_complete_manifest_pin_precedes_cache_and_output_effects() {
    let fixture = Fixture::new(&payload());
    let corrupt = fixture.corrupt_first_chunk();
    let mut wire = fixture.pin.encode();
    *wire.last_mut().unwrap() ^= 1;
    let wrong_pin = ContentClaimV1::decode(&wire).unwrap();
    // A missing output parent would report I/O if staging were reached.
    let output = fixture.directory.path().join("absent-parent/payload");
    let mut consumed = fixture.exact_budget();
    assert!(matches!(
        fixture.manifest.materialize_cached_payload(
            &fixture.store,
            &wrong_pin,
            &fixture.transport,
            &mut consumed,
            deadline(),
            &output,
        ),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
    assert_eq!(consumed.reads_reserved(), 1);
    assert_eq!(
        consumed.bytes_reserved(),
        fixture.manifest.encode().len() as u64 + 1
    );
    // A cache read would evict this corrupt disposable chunk. It was not read.
    assert_eq!(fixture.raw_first_chunk(), corrupt);
    assert_refused_output(&fixture, &output);
}

#[test]
fn manifest_profile_instance_generation_and_purpose_cannot_be_substituted() {
    let fixture = Fixture::new(&payload());
    let corrupt = fixture.corrupt_first_chunk();
    for offset in [4, 69, 133, 68] {
        let mut wire = fixture.pin.encode();
        wire[offset] ^= 1;
        let wrong_pin = ContentClaimV1::decode(&wire).unwrap();
        let output = fixture.directory.path().join("absent-parent/payload");
        let mut consumed = fixture.exact_budget();
        assert!(matches!(
            fixture.manifest.materialize_cached_payload(
                &fixture.store,
                &wrong_pin,
                &fixture.transport,
                &mut consumed,
                deadline(),
                &output,
            ),
            Err(CellContentErrorV2::Invalid(_))
        ));
        assert_eq!(consumed.reads_reserved(), 0);
        assert_eq!(fixture.raw_first_chunk(), corrupt);
        assert_refused_output(&fixture, &output);
    }
}

#[test]
fn transport_family_aliases_and_size_must_match_before_staging() {
    let fixture = Fixture::new(&payload());
    let corrupt = fixture.corrupt_first_chunk();
    for variant in 0..7 {
        let mut metadata = fixture.transport.context().clone();
        let mut size = fixture.transport.size();
        let mut chunks = fixture.transport.chunks().to_vec();
        match variant {
            0 => metadata.family.push('x'),
            1 => metadata.base[0] ^= 1,
            2 => metadata.parent[0] ^= 1,
            3 => metadata.tokenizer[0] ^= 1,
            4 => metadata.layout[0] ^= 1,
            5 => metadata.runtime[0] ^= 1,
            _ => {
                size += 1;
                chunks.last_mut().unwrap().size += 1;
            }
        }
        let transport = CellManifestV1::new(
            metadata,
            size,
            fixture.transport.payload_sha256(),
            CHUNK_BYTES,
            chunks,
        )
        .unwrap();
        let output = fixture.directory.path().join("absent-parent/payload");
        let mut consumed = fixture.exact_budget();
        assert!(matches!(
            fixture.manifest.materialize_cached_payload(
                &fixture.store,
                &fixture.pin,
                &transport,
                &mut consumed,
                deadline(),
                &output,
            ),
            Err(CellContentErrorV2::Invalid("cached payload metadata"))
        ));
        assert_eq!(consumed.reads_reserved(), 1);
        assert_eq!(fixture.raw_first_chunk(), corrupt);
        assert_refused_output(&fixture, &output);
    }
}

#[test]
fn missing_or_corrupt_late_chunks_never_publish_or_refund_failed_reads() {
    for corrupt in [false, true] {
        let fixture = Fixture::new(&payload());
        let last = fixture.transport.chunks().last().unwrap();
        if corrupt {
            fixture
                .database()
                .execute(
                    "UPDATE cell_chunks_v1 SET bytes=?1 WHERE hash=?2",
                    params![vec![0_u8; last.size as usize], last.sha256.as_slice()],
                )
                .unwrap();
        } else {
            fixture
                .database()
                .execute(
                    "DELETE FROM cell_chunks_v1 WHERE hash=?1",
                    [last.sha256.as_slice()],
                )
                .unwrap();
        }
        let output = fixture.directory.path().join("incomplete");
        let mut consumed = fixture.exact_budget();
        assert!(matches!(
            fixture.materialize(&mut consumed, deadline(), &output),
            Err(CellContentErrorV2::Commitment(ContentCommitmentError::Io(error)))
                if matches!(error.get_ref().and_then(|error| error.downcast_ref::<CellErrorV1>()),
                    Some(CellErrorV1::Unavailable))
        ));
        assert_eq!(consumed.reads_reserved(), 2);
        assert_eq!(consumed.bytes_reserved(), fixture.required_bytes());
        assert_refused_output(&fixture, &output);
        assert!(matches!(
            fixture.materialize(&mut consumed, deadline(), &output),
            Err(CellContentErrorV2::Commitment(
                ContentCommitmentError::Budget
            ))
        ));
        assert!(consumed.exhausted());
        assert_refused_output(&fixture, &output);
    }
}

#[test]
fn chunk_order_substitution_and_false_legacy_whole_digest_refuse_publication() {
    let bytes = payload()[..2 * CHUNK_BYTES as usize].to_vec();
    let fixture = Fixture::new(&bytes);
    for reordered in [true, false] {
        let mut chunks = fixture.transport.chunks().to_vec();
        let digest = if reordered {
            chunks.reverse();
            let reversed: Vec<u8> = bytes[CHUNK_BYTES as usize..]
                .iter()
                .chain(&bytes[..CHUNK_BYTES as usize])
                .copied()
                .collect();
            Sha256::digest(&reversed).into()
        } else {
            [0xb9; 32]
        };
        let transport =
            CellManifestV1::new(metadata(), bytes.len() as u64, digest, CHUNK_BYTES, chunks)
                .unwrap();
        let output = fixture.directory.path().join("changed-order-or-digest");
        let result = fixture.manifest.materialize_cached_payload(
            &fixture.store,
            &fixture.pin,
            &transport,
            &mut fixture.exact_budget(),
            deadline(),
            &output,
        );
        if reordered {
            fixture.store.verify_complete(&transport).unwrap();
            assert!(matches!(
                result,
                Err(CellContentErrorV2::Commitment(
                    ContentCommitmentError::Mismatch
                ))
            ));
        } else {
            assert!(matches!(result,
                Err(CellContentErrorV2::Commitment(ContentCommitmentError::Io(error)))
                    if matches!(error.get_ref().and_then(|error| error.downcast_ref::<CellErrorV1>()),
                        Some(CellErrorV1::Invalid("complete cached payload digest")))));
        }
        assert_refused_output(&fixture, &output);
    }
}

#[test]
fn exhausted_budget_precedes_cache_reads_and_is_not_renewed() {
    let fixture = Fixture::new(&payload());
    let corrupt = fixture.corrupt_first_chunk();
    for mut consumed in [
        ContentReadBudget::new(1, fixture.required_bytes()).unwrap(),
        ContentReadBudget::new(2, fixture.required_bytes() - 1).unwrap(),
    ] {
        let output = fixture.directory.path().join("over-budget");
        for _ in 0..2 {
            assert!(matches!(
                fixture.materialize(&mut consumed, deadline(), &output),
                Err(CellContentErrorV2::Commitment(
                    ContentCommitmentError::Budget
                ))
            ));
            assert!(consumed.exhausted());
            assert_eq!(fixture.raw_first_chunk(), corrupt);
            assert_refused_output(&fixture, &output);
        }
    }
}

#[test]
fn payload_budget_refusal_precedes_even_opening_an_absent_output_parent() {
    let fixture = Fixture::new(&payload());
    let output = fixture.directory.path().join("absent-parent/over-budget");
    let corrupt = fixture.corrupt_first_chunk();
    let mut consumed = ContentReadBudget::new(1, fixture.required_bytes()).unwrap();
    assert!(matches!(
        fixture.materialize(&mut consumed, deadline(), &output),
        Err(CellContentErrorV2::Commitment(
            ContentCommitmentError::Budget
        ))
    ));
    assert!(consumed.exhausted());
    assert_eq!(fixture.raw_first_chunk(), corrupt);
    assert_refused_output(&fixture, &output);
    // A separately authorized budget reaches the actual filesystem failure,
    // proving the missing parent was not silently created or bypassed above.
    assert!(matches!(
        fixture.materialize(&mut fixture.exact_budget(), deadline(), &output),
        Err(CellContentErrorV2::Commitment(ContentCommitmentError::Io(error)))
            if error.kind() == io::ErrorKind::NotFound
    ));
    assert_eq!(fixture.raw_first_chunk(), corrupt);
    assert_refused_output(&fixture, &output);
}

#[test]
fn expired_deadline_precedes_pin_reservation_cache_or_output_effects() {
    let fixture = Fixture::new(&payload());
    let corrupt = fixture.corrupt_first_chunk();
    let output = fixture.directory.path().join("absent-parent/payload");
    let mut consumed = fixture.exact_budget();
    let expired = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        fixture.materialize(&mut consumed, expired, &output),
        Err(CellContentErrorV2::Metadata(CellErrorV1::Io(error)))
            if error.kind() == io::ErrorKind::TimedOut
    ));
    assert_eq!(consumed.reads_reserved(), 0);
    assert_eq!(fixture.raw_first_chunk(), corrupt);
    assert_refused_output(&fixture, &output);
}

// Production uses the real clock and original deadline. These one-shot,
// thread-local hooks pause at an I/O checkpoint or change the disposable cache;
// they do not replace time, expected claims, or the bytes already observed.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Stage {
    PayloadRead,
    Publication,
}

type CheckpointHook = (Stage, Box<dyn FnOnce(Instant)>);
thread_local! {
    static CHECKPOINT_HOOK: std::cell::RefCell<Option<CheckpointHook>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn checkpoint(stage: Stage, deadline: Instant) {
    let hook = CHECKPOINT_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(expected, _)| *expected == stage)
        {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, hook)) = hook {
        hook(deadline);
    }
}

fn with_checkpoint_hook<T>(
    stage: Stage,
    hook: Box<dyn FnOnce(Instant)>,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CHECKPOINT_HOOK.with(|slot| slot.borrow_mut().take());
        }
    }
    CHECKPOINT_HOOK.with(|slot| assert!(slot.borrow_mut().replace((stage, hook)).is_none()));
    let _reset = Reset;
    run()
}

fn refuse_expiry_at(stage: Stage) {
    let fixture = Fixture::new(&payload());
    let original = Instant::now() + Duration::from_secs(1);
    let reached = Rc::new(Cell::new(false));
    let observed = reached.clone();
    let output = fixture.directory.path().join("late-output");
    let mut consumed = fixture.exact_budget();
    let error = with_checkpoint_hook(
        stage,
        Box::new(move |actual| {
            assert_eq!(
                actual, original,
                "cached read or publication renewed deadline"
            );
            observed.set(true);
            let (_hold, elapsed) = mpsc::channel::<()>();
            while let Some(left) = original.checked_duration_since(Instant::now()) {
                assert!(matches!(
                    elapsed.recv_timeout(left),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
            }
        }),
        || fixture.materialize(&mut consumed, original, &output),
    )
    .unwrap_err();
    assert!(
        reached.get(),
        "selected real I/O checkpoint was not reached"
    );
    match error {
        CellContentErrorV2::Commitment(ContentCommitmentError::Io(error))
        | CellContentErrorV2::Metadata(CellErrorV1::Io(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
        other => panic!("unexpected deadline refusal: {other}"),
    }
    assert_eq!(consumed.reads_reserved(), 2);
    assert_eq!(consumed.bytes_reserved(), fixture.required_bytes());
    assert_refused_output(&fixture, &output);
    // Only an explicit new caller operation may grant a new budget/deadline.
    fixture
        .materialize(&mut fixture.exact_budget(), deadline(), &output)
        .unwrap();
    assert_eq!(fs::read(output).unwrap(), payload());
}

#[test]
fn expiry_during_cached_payload_read_keeps_the_original_deadline_and_budget() {
    refuse_expiry_at(Stage::PayloadRead);
}

#[test]
fn expiry_after_sync_and_before_publication_never_publishes() {
    refuse_expiry_at(Stage::Publication);
}

#[test]
fn no_replace_preserves_existing_output_bytes_and_consumes_the_attempt() {
    let fixture = Fixture::new(&payload());
    let output = fixture.directory.path().join("existing");
    fs::write(&output, b"retain original output bytes").unwrap();
    let mut consumed = fixture.exact_budget();
    assert!(matches!(
        fixture.materialize(&mut consumed, deadline(), &output),
        Err(CellContentErrorV2::Metadata(CellErrorV1::Io(error)))
            if error.kind() == io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(output).unwrap(), b"retain original output bytes");
    assert_eq!(consumed.reads_reserved(), 2);
    assert_eq!(consumed.bytes_reserved(), fixture.required_bytes());
    assert_no_partials(fixture.directory.path());
}

#[cfg(unix)]
#[test]
fn no_replace_preserves_existing_and_dangling_symlinks() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(&payload());
    for dangling in [false, true] {
        let target = fixture
            .directory
            .path()
            .join(if dangling { "missing" } else { "target" });
        if !dangling {
            fs::write(&target, b"retain target bytes").unwrap();
        }
        let output = fixture
            .directory
            .path()
            .join(if dangling { "dangling-link" } else { "link" });
        symlink(&target, &output).unwrap();
        assert!(matches!(
            fixture.materialize(&mut fixture.exact_budget(), deadline(), &output),
            Err(CellContentErrorV2::Metadata(CellErrorV1::Io(error)))
                if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_link(output).unwrap(), target);
        if dangling {
            assert!(!target.exists());
        } else {
            assert_eq!(fs::read(target).unwrap(), b"retain target bytes");
        }
        assert_no_partials(fixture.directory.path());
    }
}

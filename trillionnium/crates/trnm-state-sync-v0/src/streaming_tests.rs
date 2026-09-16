use super::*;
use std::{cell::Cell, rc::Rc};

struct IncrementalRoot {
    fail_at: Option<u32>,
    fail_finish: bool,
    wrong_root: bool,
}
struct RootAccumulator {
    hash: Sha256,
    fail_at: Option<u32>,
    fail_finish: bool,
    wrong_root: bool,
}
impl StreamingStateRootRecomputerV1 for IncrementalRoot {
    type Error = &'static str;
    type Accumulator = RootAccumulator;
    fn begin(&self, manifest: &SnapshotManifestV0) -> Result<RootAccumulator, Self::Error> {
        let mut hash = Sha256::new();
        hash.update(b"test.state-root");
        hash.update(manifest.schema_digest.0);
        Ok(RootAccumulator {
            hash,
            fail_at: self.fail_at,
            fail_finish: self.fail_finish,
            wrong_root: self.wrong_root,
        })
    }
}
impl StateRootAccumulatorV1 for RootAccumulator {
    type Error = &'static str;
    fn absorb(&mut self, index: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        if self.fail_at == Some(index) {
            return Err("root absorb");
        }
        self.hash.update((bytes.len() as u64).to_be_bytes());
        self.hash.update(bytes);
        Ok(())
    }
    fn finish(self) -> Result<Digest32V0, Self::Error> {
        if self.fail_finish {
            return Err("root finish");
        }
        Ok(if self.wrong_root {
            d(88)
        } else {
            Digest32V0(self.hash.finalize().into())
        })
    }
}
fn root() -> IncrementalRoot {
    IncrementalRoot {
        fail_at: None,
        fail_finish: false,
        wrong_root: false,
    }
}

#[derive(Debug)]
struct TargetError(&'static str);
impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for TargetError {}

struct Target {
    current: Digest32V0,
    begins: usize,
    writes: Rc<Cell<usize>>,
    commits: usize,
    aborts: usize,
    fail_write: Option<u32>,
    fail_abort: bool,
    commit_error: bool,
    bad_receipt: bool,
    bad_identity: bool,
}
impl Default for Target {
    fn default() -> Self {
        Self {
            current: d(20),
            begins: 0,
            writes: Rc::new(Cell::new(0)),
            commits: 0,
            aborts: 0,
            fail_write: None,
            fail_abort: false,
            commit_error: false,
            bad_receipt: false,
            bad_identity: false,
        }
    }
}
impl NonDestructiveInstallTargetV0 for Target {
    type Error = TargetError;
    fn begin_staging(&mut self, _: &SnapshotManifestV0) -> Result<StagingIdentityV0, Self::Error> {
        self.begins += 1;
        Ok(StagingIdentityV0 {
            generation: if self.bad_identity { 0 } else { 2 },
            staging_digest: d(33),
        })
    }
    fn write_chunk(
        &mut self,
        _: StagingIdentityV0,
        index: u32,
        _: &[u8],
    ) -> Result<(), Self::Error> {
        if self.fail_write == Some(index) {
            return Err(TargetError("write failed"));
        }
        self.writes.set(self.writes.get() + 1);
        Ok(())
    }
    fn commit_staging_cas(
        &mut self,
        staging: StagingIdentityV0,
        expected: Digest32V0,
        manifest: &SnapshotManifestV0,
    ) -> Result<InstallReceiptV0, Self::Error> {
        self.commits += 1;
        if self.current != expected {
            return Err(TargetError("stale root"));
        }
        self.current = manifest.state_root;
        if self.commit_error {
            return Err(TargetError("commit applied, reply lost"));
        }
        Ok(InstallReceiptV0 {
            previous_root: expected,
            installed_root: manifest.state_root,
            installed_height: manifest.height,
            generation: if self.bad_receipt {
                9
            } else {
                staging.generation
            },
            durable_receipt_digest: d(19),
        })
    }
    fn abort_staging(&mut self, _: StagingIdentityV0) -> Result<(), Self::Error> {
        self.aborts += 1;
        if self.fail_abort {
            Err(TargetError("abort failed"))
        } else {
            Ok(())
        }
    }
}
fn stream(
    chunks: Vec<SnapshotChunkV0>,
) -> impl Iterator<Item = Result<SnapshotChunkV0, &'static str>> {
    chunks.into_iter().map(Ok)
}

#[test]
fn streaming_matches_buffered_verification_and_installs_each_chunk_once() {
    let (trust, manifest, chunks) = fixture();
    let mut buffered = StateSyncSessionV0::new(trust, manifest.clone()).unwrap();
    for chunk in chunks.clone() {
        buffered.accept_chunk(chunk).unwrap();
    }
    let expected = buffered.verify_complete(&HashRoot).unwrap();
    let mut target = Target::default();
    let receipt = install_streaming_snapshot_v1(
        &buffered.trust_path,
        &manifest,
        stream(chunks),
        &root(),
        &mut target,
        d(20),
    )
    .unwrap();
    assert_eq!(receipt.installed_root, expected.state_root());
    assert_eq!(
        (
            target.begins,
            target.writes.get(),
            target.commits,
            target.aborts
        ),
        (1, 2, 1, 0)
    );
}

#[test]
fn each_chunk_is_written_before_the_next_input_is_requested() {
    let (trust, manifest, chunks) = fixture();
    let mut target = Target::default();
    let writes = target.writes.clone();
    let source = chunks.into_iter().enumerate().map(move |(index, chunk)| {
        assert_eq!(
            writes.get(),
            index,
            "transport must not pre-collect payloads"
        );
        Ok::<_, &'static str>(chunk)
    });
    install_streaming_snapshot_v1(&trust, &manifest, source, &root(), &mut target, d(20)).unwrap();
}

#[test]
fn invalid_manifest_or_expected_root_has_no_target_side_effect() {
    for invalid_root in [false, true] {
        let (trust, mut manifest, chunks) = fixture();
        if !invalid_root {
            manifest.height += 1;
        }
        let mut target = Target::default();
        assert!(install_streaming_snapshot_v1(
            &trust,
            &manifest,
            stream(chunks),
            &root(),
            &mut target,
            if invalid_root { d(0) } else { d(20) }
        )
        .is_err());
        assert_eq!(
            (
                target.begins,
                target.writes.get(),
                target.commits,
                target.aborts
            ),
            (0, 0, 0, 0)
        );
    }
}

#[test]
fn invalid_staging_identity_never_reaches_abort_or_writes() {
    let (trust, manifest, chunks) = fixture();
    let mut target = Target {
        bad_identity: true,
        ..Target::default()
    };
    assert!(install_streaming_snapshot_v1(
        &trust,
        &manifest,
        stream(chunks),
        &root(),
        &mut target,
        d(20)
    )
    .is_err());
    assert_eq!(
        (target.writes.get(), target.commits, target.aborts),
        (0, 0, 0)
    );
}

#[test]
fn missing_duplicate_reordered_and_corrupt_streams_never_commit() {
    for variant in 0..4 {
        let (trust, manifest, mut chunks) = fixture();
        match variant {
            0 => {
                chunks.pop();
            }
            1 => chunks[1] = chunks[0].clone(),
            2 => chunks.swap(0, 1),
            _ => chunks[1].bytes[0] ^= 1,
        }
        let mut target = Target::default();
        assert!(install_streaming_snapshot_v1(
            &trust,
            &manifest,
            stream(chunks),
            &root(),
            &mut target,
            d(20)
        )
        .is_err());
        assert_eq!(
            (target.current, target.commits, target.aborts),
            (d(20), 0, 1)
        );
    }
}

#[test]
fn oversized_suffix_consumes_only_one_extra_item() {
    let (trust, manifest, chunks) = fixture();
    let repeated = chunks[0].clone();
    let reads = Rc::new(Cell::new(0));
    let calls = reads.clone();
    let source = chunks
        .into_iter()
        .chain(std::iter::repeat(repeated))
        .map(move |chunk| {
            calls.set(calls.get() + 1);
            assert!(calls.get() <= 3);
            Ok::<_, &'static str>(chunk)
        });
    let mut target = Target::default();
    assert!(matches!(
        install_streaming_snapshot_v1(&trust, &manifest, source, &root(), &mut target, d(20)),
        Err(StreamingInstallErrorV1::BeforeCommit {
            failure: StreamingFailureV1::ExcessChunks,
            abort_error: None
        })
    ));
    assert_eq!(reads.get(), 3);
    assert_eq!(target.current, d(20));
}

#[test]
fn transport_error_is_not_a_successful_short_snapshot() {
    let (trust, manifest, chunks) = fixture();
    let source = vec![Ok(chunks[0].clone()), Err("network read failed")];
    let mut target = Target::default();
    assert!(matches!(
        install_streaming_snapshot_v1(&trust, &manifest, source, &root(), &mut target, d(20)),
        Err(StreamingInstallErrorV1::BeforeCommit {
            failure: StreamingFailureV1::Input("network read failed"),
            abort_error: None
        })
    ));
    assert_eq!(
        (target.current, target.commits, target.aborts),
        (d(20), 0, 1)
    );
}

#[test]
fn root_absorb_finish_and_root_mismatch_abort_only_staging() {
    for variant in 0..3 {
        let (trust, manifest, chunks) = fixture();
        let mut recomputer = root();
        match variant {
            0 => recomputer.fail_at = Some(1),
            1 => recomputer.fail_finish = true,
            _ => recomputer.wrong_root = true,
        }
        let mut target = Target::default();
        assert!(install_streaming_snapshot_v1(
            &trust,
            &manifest,
            stream(chunks),
            &recomputer,
            &mut target,
            d(20)
        )
        .is_err());
        assert_eq!(
            (target.current, target.commits, target.aborts),
            (d(20), 0, 1)
        );
    }
}

#[test]
fn write_and_abort_failures_are_both_retained() {
    let (trust, manifest, chunks) = fixture();
    let mut target = Target {
        fail_write: Some(1),
        fail_abort: true,
        ..Target::default()
    };
    assert!(matches!(
        install_streaming_snapshot_v1(
            &trust,
            &manifest,
            stream(chunks),
            &root(),
            &mut target,
            d(20)
        ),
        Err(StreamingInstallErrorV1::BeforeCommit {
            failure: StreamingFailureV1::Write(TargetError("write failed")),
            abort_error: Some(TargetError("abort failed"))
        })
    ));
    assert_eq!(target.current, d(20));
    assert_eq!(target.commits, 0);
}

#[test]
fn commit_response_loss_and_bad_receipt_never_trigger_destructive_abort() {
    for lost in [true, false] {
        let (trust, manifest, chunks) = fixture();
        let mut target = Target {
            commit_error: lost,
            bad_receipt: !lost,
            ..Target::default()
        };
        let error = install_streaming_snapshot_v1(
            &trust,
            &manifest,
            stream(chunks),
            &root(),
            &mut target,
            d(20),
        )
        .unwrap_err();
        if lost {
            assert!(matches!(error, StreamingInstallErrorV1::CommitUncertain(_)));
        } else {
            assert!(matches!(error, StreamingInstallErrorV1::ReceiptMismatch(_)));
        }
        assert_eq!(
            (target.current, target.commits, target.aborts),
            (manifest.state_root, 1, 0)
        );
    }
}

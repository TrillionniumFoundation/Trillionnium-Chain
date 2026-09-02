#!/usr/bin/env python3
"""One-shot source migration for state-sync and migration safety hardening."""

from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def replace_once(text: str, old: str, new: str, message: str) -> str:
    require(old in text, message)
    return text.replace(old, new, 1)


sync_path = Path("trillionnium/crates/trnm-state-sync-v0/src/lib.rs")
sync = sync_path.read_text()

sync = replace_once(
    sync,
    """        if self.epoch == 0 || self.height == 0 || self.checkpoint_digest == Digest32V0([0; 32]) {
            return Err(StateSyncErrorV0::InvalidTrustAnchor);
        }
""",
    """        if self.chain_id == Digest32V0([0; 32])
            || self.protocol_digest == Digest32V0([0; 32])
            || self.epoch == 0
            || self.height == 0
            || self.checkpoint_digest == Digest32V0([0; 32])
            || self.validator_set_digest == Digest32V0([0; 32])
        {
            return Err(StateSyncErrorV0::InvalidTrustAnchor);
        }
""",
    "state-sync trust anchor validation changed",
)

sync = replace_once(
    sync,
    """        if link.chain_id != anchor.chain_id
            || link.protocol_digest != anchor.protocol_digest
            || link.parent_checkpoint_digest != previous_digest
            || link.height <= previous_height
            || link.epoch < previous_epoch
            || link.epoch > previous_epoch.saturating_add(1)
            || link.validator_set_digest != expected_validator_set
            || link.checkpoint_digest != link.canonical_digest()
        {
""",
    """        if link.chain_id != anchor.chain_id
            || link.protocol_digest != anchor.protocol_digest
            || link.parent_checkpoint_digest != previous_digest
            || link.height <= previous_height
            || link.epoch < previous_epoch
            || link.epoch > previous_epoch.saturating_add(1)
            || link.state_root == Digest32V0([0; 32])
            || link.validator_set_digest != expected_validator_set
            || link.next_validator_set_digest == Digest32V0([0; 32])
            || (link.epoch == previous_epoch
                && link.next_validator_set_digest != expected_validator_set)
            || link.finality_proof_digest == Digest32V0([0; 32])
            || link.checkpoint_digest == Digest32V0([0; 32])
            || link.checkpoint_digest != link.canonical_digest()
        {
""",
    "state-sync trust path validation changed",
)

old_digest = """    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.snapshot-manifest.v0",
            &[
                &self.chain_id.0,
                &self.protocol_digest.0,
                &self.height.to_be_bytes(),
                &self.epoch.to_be_bytes(),
                &self.state_root.0,
                &self.chunk_root.0,
                &self.chunk_count.to_be_bytes(),
                &self.maximum_chunk_bytes.to_be_bytes(),
                &self.total_bytes.to_be_bytes(),
                &self.schema_digest.0,
                &self.checkpoint_digest.0,
            ],
        )
    }
"""
new_digest = """    /// Stable digest bound into every chunk. It deliberately excludes both
    /// `chunk_root` and `manifest_digest`, preventing a hash self-reference.
    #[must_use]
    pub fn chunk_binding_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.snapshot-header.v0",
            &[
                &self.chain_id.0,
                &self.protocol_digest.0,
                &self.height.to_be_bytes(),
                &self.epoch.to_be_bytes(),
                &self.state_root.0,
                &self.chunk_count.to_be_bytes(),
                &self.maximum_chunk_bytes.to_be_bytes(),
                &self.total_bytes.to_be_bytes(),
                &self.schema_digest.0,
                &self.checkpoint_digest.0,
            ],
        )
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.snapshot-manifest.v0",
            &[&self.chunk_binding_digest().0, &self.chunk_root.0],
        )
    }
"""
sync = replace_once(sync, old_digest, new_digest, "snapshot digest source changed")

sync = replace_once(
    sync,
    """        if self.chunk_count == 0
            || self.chunk_count > MAX_CHUNK_COUNT_V0
            || self.maximum_chunk_bytes == 0
            || self.maximum_chunk_bytes as usize > MAX_CHUNK_BYTES_V0
            || self.total_bytes == 0
            || self.total_bytes > MAX_SNAPSHOT_BYTES_V0
            || self.manifest_digest != self.canonical_digest()
        {
""",
    """        let declared_capacity = u64::from(self.chunk_count)
            .checked_mul(u64::from(self.maximum_chunk_bytes))
            .ok_or(StateSyncErrorV0::InvalidManifest)?;
        if self.chunk_count == 0
            || self.chunk_count > MAX_CHUNK_COUNT_V0
            || self.maximum_chunk_bytes == 0
            || self.maximum_chunk_bytes as usize > MAX_CHUNK_BYTES_V0
            || self.total_bytes == 0
            || self.total_bytes > MAX_SNAPSHOT_BYTES_V0
            || self.total_bytes > declared_capacity
            || self.state_root == Digest32V0([0; 32])
            || self.chunk_root == Digest32V0([0; 32])
            || self.schema_digest == Digest32V0([0; 32])
            || self.checkpoint_digest == Digest32V0([0; 32])
            || self.manifest_digest == Digest32V0([0; 32])
            || self.manifest_digest != self.canonical_digest()
        {
""",
    "snapshot manifest validation changed",
)

sync = replace_once(
    sync,
    "if self.manifest_digest != manifest.manifest_digest\n            || self.index >= manifest.chunk_count",
    "if self.manifest_digest != manifest.chunk_binding_digest()\n            || self.index >= manifest.chunk_count",
    "snapshot chunk binding changed",
)

sync = replace_once(
    sync,
    """        self.received_bytes = self
            .received_bytes
            .checked_add(
                u64::try_from(chunk.bytes.len()).map_err(|_| StateSyncErrorV0::SnapshotTooLarge)?,
            )
            .ok_or(StateSyncErrorV0::SnapshotTooLarge)?;
        if self.received_bytes > self.manifest.total_bytes
            || self.received_bytes > MAX_SNAPSHOT_BYTES_V0
        {
            return Err(StateSyncErrorV0::SnapshotTooLarge);
        }
        self.chunks.insert(chunk.index, chunk);
""",
    """        let next_received_bytes = self
            .received_bytes
            .checked_add(
                u64::try_from(chunk.bytes.len()).map_err(|_| StateSyncErrorV0::SnapshotTooLarge)?,
            )
            .ok_or(StateSyncErrorV0::SnapshotTooLarge)?;
        if next_received_bytes > self.manifest.total_bytes
            || next_received_bytes > MAX_SNAPSHOT_BYTES_V0
        {
            return Err(StateSyncErrorV0::SnapshotTooLarge);
        }
        self.chunks.insert(chunk.index, chunk);
        self.received_bytes = next_received_bytes;
""",
    "state-sync chunk accounting changed",
)

install_start = sync.index("    pub fn install<R, T>(")
install_end = sync.index(
    "\n}\n\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct VerifiedSnapshotV0",
    install_start,
)
new_install = """    pub fn install<R, T>(
        &self,
        recomputer: &R,
        target: &mut T,
        expected_current_root: Digest32V0,
    ) -> Result<InstallReceiptV0, StateSyncInstallErrorV0<R::Error, T::Error>>
    where
        R: StateRootRecomputerV0,
        T: NonDestructiveInstallTargetV0,
    {
        self.verify_complete(recomputer)
            .map_err(StateSyncInstallErrorV0::Verification)?;
        if expected_current_root == Digest32V0([0; 32]) {
            return Err(StateSyncInstallErrorV0::Protocol(
                StateSyncErrorV0::InvalidExpectedCurrentRoot,
            ));
        }
        let staging = target
            .begin_staging(&self.manifest)
            .map_err(StateSyncInstallErrorV0::Target)?;
        for index in 0..self.manifest.chunk_count {
            let chunk = match self.chunks.get(&index) {
                Some(chunk) => chunk,
                None => {
                    if let Err(abort_error) = target.abort_staging(staging) {
                        return Err(StateSyncInstallErrorV0::Abort(abort_error));
                    }
                    return Err(StateSyncInstallErrorV0::Protocol(
                        StateSyncErrorV0::IncompleteSnapshot,
                    ));
                }
            };
            if let Err(write_error) = target.write_chunk(staging, index, &chunk.bytes) {
                return match target.abort_staging(staging) {
                    Ok(()) => Err(StateSyncInstallErrorV0::Write(write_error)),
                    Err(abort_error) => Err(StateSyncInstallErrorV0::WriteAndAbort {
                        write_error,
                        abort_error,
                    }),
                };
            }
        }

        // Once commit starts, the caller must treat any error or receipt
        // mismatch as uncertain durable state. Never issue a destructive abort.
        let receipt = target
            .commit_staging_cas(staging, expected_current_root, &self.manifest)
            .map_err(StateSyncInstallErrorV0::CommitUncertain)?;
        if receipt.previous_root != expected_current_root
            || receipt.installed_root != self.manifest.state_root
            || receipt.installed_height != self.manifest.height
            || receipt.generation != staging.generation
            || receipt.durable_receipt_digest == Digest32V0([0; 32])
        {
            return Err(StateSyncInstallErrorV0::CommitReceiptMismatch(
                StateSyncErrorV0::InstallReceiptMismatch,
            ));
        }
        Ok(receipt)
    }
"""
sync = sync[:install_start] + new_install + sync[install_end:]

sync = replace_once(
    sync,
    """    StateRootMismatch,
    InstallReceiptMismatch,
}
""",
    """    StateRootMismatch,
    InvalidExpectedCurrentRoot,
    InstallReceiptMismatch,
}
""",
    "state-sync protocol error enum changed",
)
sync = replace_once(
    sync,
    """            Self::StateRootMismatch => "recomputed application state root mismatch",
            Self::InstallReceiptMismatch => "non-destructive install receipt mismatch",
""",
    """            Self::StateRootMismatch => "recomputed application state root mismatch",
            Self::InvalidExpectedCurrentRoot => "expected current state root is invalid",
            Self::InstallReceiptMismatch => "non-destructive install receipt mismatch",
""",
    "state-sync protocol display changed",
)

old_install_error = """pub enum StateSyncInstallErrorV0<RootError, TargetError> {
    Protocol(StateSyncErrorV0),
    Verification(StateSyncHostErrorV0<RootError>),
    Target(TargetError),
}

impl<R: fmt::Display, T: fmt::Display> fmt::Display for StateSyncInstallErrorV0<R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "state-sync installation rejected: {error}"),
            Self::Verification(error) => write!(f, "snapshot verification failed: {error}"),
            Self::Target(error) => write!(f, "staging target failed: {error}"),
        }
    }
}
"""
new_install_error = """pub enum StateSyncInstallErrorV0<RootError, TargetError> {
    Protocol(StateSyncErrorV0),
    Verification(StateSyncHostErrorV0<RootError>),
    Target(TargetError),
    Write(TargetError),
    Abort(TargetError),
    WriteAndAbort {
        write_error: TargetError,
        abort_error: TargetError,
    },
    CommitUncertain(TargetError),
    CommitReceiptMismatch(StateSyncErrorV0),
}

impl<R: fmt::Display, T: fmt::Display> fmt::Display for StateSyncInstallErrorV0<R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "state-sync installation rejected: {error}"),
            Self::Verification(error) => write!(f, "snapshot verification failed: {error}"),
            Self::Target(error) => write!(f, "staging target failed before writes: {error}"),
            Self::Write(error) => write!(f, "staging write failed and was aborted: {error}"),
            Self::Abort(error) => write!(f, "staging abort failed: {error}"),
            Self::WriteAndAbort {
                write_error,
                abort_error,
            } => write!(
                f,
                "staging write failed ({write_error}) and abort also failed ({abort_error})"
            ),
            Self::CommitUncertain(error) => {
                write!(f, "state-sync commit outcome is uncertain: {error}")
            }
            Self::CommitReceiptMismatch(error) => {
                write!(f, "state-sync commit receipt is untrusted: {error}")
            }
        }
    }
}
"""
sync = replace_once(sync, old_install_error, new_install_error, "install error contract changed")

fixture_start = sync.index("    fn fixture() -> (")
fixture_end = sync.index(
    "\n    #[test]\n    fn trust_path_rejects_network_selected_discontinuity()",
    fixture_start,
)
fixture = """    fn fixture() -> (
        VerifiedTrustPathV0,
        SnapshotManifestV0,
        Vec<SnapshotChunkV0>,
    ) {
        let schema = d(7);
        let chunk_bytes = [b"alpha".as_slice(), b"beta".as_slice()];
        let state_root = HashRoot
            .recompute_state_root(schema, chunk_bytes)
            .unwrap();
        let anchor = WeakSubjectivityAnchorV0 {
            chain_id: d(1),
            protocol_digest: d(2),
            epoch: 3,
            height: 4,
            checkpoint_digest: d(5),
            validator_set_digest: d(6),
        };
        let terminal = link(anchor, state_root);
        let trust = verify_trust_path_v0(&AcceptProof, anchor, &[terminal]).unwrap();
        let mut manifest = SnapshotManifestV0 {
            chain_id: anchor.chain_id,
            protocol_digest: anchor.protocol_digest,
            height: terminal.height,
            epoch: terminal.epoch,
            state_root,
            chunk_root: d(0),
            chunk_count: 2,
            maximum_chunk_bytes: 1024,
            total_bytes: 9,
            schema_digest: schema,
            checkpoint_digest: terminal.checkpoint_digest,
            manifest_digest: d(0),
        };
        let binding = manifest.chunk_binding_digest();
        let chunks: Vec<SnapshotChunkV0> = chunk_bytes
            .iter()
            .enumerate()
            .map(|(index, bytes)| SnapshotChunkV0 {
                manifest_digest: binding,
                index: index as u32,
                bytes: bytes.to_vec(),
                chunk_digest: SnapshotChunkV0::canonical_digest(binding, index as u32, bytes),
            })
            .collect();
        manifest.chunk_root = chunk_merkle_root_v0(
            &chunks
                .iter()
                .map(|chunk| chunk.chunk_digest)
                .collect::<Vec<_>>(),
        );
        manifest.manifest_digest = manifest.canonical_digest();
        (trust, manifest, chunks)
    }
"""
sync = sync[:fixture_start] + fixture + sync[fixture_end:]
require("for _ in 0..16" not in sync, "snapshot fixed-point loop survived")

sync_tests = """

    #[derive(Debug)]
    struct TargetFailure;

    impl fmt::Display for TargetFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("injected target failure")
        }
    }

    impl Error for TargetFailure {}

    struct TrackingTarget {
        aborts: u32,
        commit_fails: bool,
        bad_receipt: bool,
    }

    impl NonDestructiveInstallTargetV0 for TrackingTarget {
        type Error = TargetFailure;

        fn begin_staging(
            &mut self,
            _manifest: &SnapshotManifestV0,
        ) -> Result<StagingIdentityV0, Self::Error> {
            Ok(StagingIdentityV0 {
                generation: 7,
                staging_digest: d(40),
            })
        }

        fn write_chunk(
            &mut self,
            _staging: StagingIdentityV0,
            _index: u32,
            _bytes: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn commit_staging_cas(
            &mut self,
            staging: StagingIdentityV0,
            expected_current_root: Digest32V0,
            manifest: &SnapshotManifestV0,
        ) -> Result<InstallReceiptV0, Self::Error> {
            if self.commit_fails {
                return Err(TargetFailure);
            }
            Ok(InstallReceiptV0 {
                previous_root: expected_current_root,
                installed_root: if self.bad_receipt { d(99) } else { manifest.state_root },
                installed_height: manifest.height,
                generation: staging.generation,
                durable_receipt_digest: d(41),
            })
        }

        fn abort_staging(&mut self, _staging: StagingIdentityV0) -> Result<(), Self::Error> {
            self.aborts += 1;
            Ok(())
        }
    }

    fn complete_session() -> StateSyncSessionV0 {
        let (trust, manifest, chunks) = fixture();
        let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
        for chunk in chunks {
            session.accept_chunk(chunk).unwrap();
        }
        session
    }

    #[test]
    fn oversized_chunk_attempt_does_not_mutate_session_accounting() {
        let (trust, mut manifest, _) = fixture();
        manifest.total_bytes = 1;
        manifest.manifest_digest = manifest.canonical_digest();
        let binding = manifest.chunk_binding_digest();
        let bytes = b"alpha".to_vec();
        let chunk = SnapshotChunkV0 {
            manifest_digest: binding,
            index: 0,
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, 0, &bytes),
            bytes,
        };
        let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
        assert_eq!(
            session.accept_chunk(chunk).unwrap_err(),
            StateSyncErrorV0::SnapshotTooLarge
        );
        assert_eq!(session.received_bytes, 0);
        assert_eq!(session.missing_chunks(), vec![0, 1]);
    }

    #[test]
    fn commit_error_never_triggers_destructive_abort() {
        let session = complete_session();
        let mut target = TrackingTarget {
            aborts: 0,
            commit_fails: true,
            bad_receipt: false,
        };
        assert!(matches!(
            session.install(&HashRoot, &mut target, d(50)),
            Err(StateSyncInstallErrorV0::CommitUncertain(_))
        ));
        assert_eq!(target.aborts, 0);
    }

    #[test]
    fn commit_receipt_mismatch_never_triggers_destructive_abort() {
        let session = complete_session();
        let mut target = TrackingTarget {
            aborts: 0,
            commit_fails: false,
            bad_receipt: true,
        };
        assert!(matches!(
            session.install(&HashRoot, &mut target, d(50)),
            Err(StateSyncInstallErrorV0::CommitReceiptMismatch(
                StateSyncErrorV0::InstallReceiptMismatch
            ))
        ));
        assert_eq!(target.aborts, 0);
    }
"""
pos = sync.rfind("\n}")
require(pos >= 0, "state-sync test module end missing")
sync = sync[:pos] + sync_tests + sync[pos:]
sync_path.write_text(sync)


migration_path = Path("trillionnium/crates/trnm-migration-v0/src/lib.rs")
migration = migration_path.read_text()

old_forbidden = """#[must_use]
pub fn forbidden_authority_namespace(namespace: &[u8]) -> bool {
    matches!(
        namespace,
        b"validator_signing_state"
            | b"consensus_private_key"
            | b"signer_journal"
            | b"safety_store"
            | b"remote_signer_watermark"
            | b"node_commit_ledger"
            | b"operator_recovery_key"
    )
}
"""
new_forbidden = """#[must_use]
pub fn forbidden_authority_namespace(namespace: &[u8]) -> bool {
    const RESERVED: &[&[u8]] = &[
        b"validator_signing_state",
        b"consensus_private_key",
        b"signer_journal",
        b"safety_store",
        b"remote_signer_watermark",
        b"node_commit_ledger",
        b"operator_recovery_key",
    ];
    RESERVED.iter().any(|prefix| namespace.starts_with(prefix))
}
"""
migration = replace_once(migration, old_forbidden, new_forbidden, "migration namespace guard changed")

verify_start = migration.index("pub fn verify_export_v0<V>(")
verify_end = migration.index(
    "\n#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]\npub struct TargetRowV0",
    verify_start,
)
verify_block = """fn validate_verified_rows_v0(
    export: &VerifiedExportV0,
    rows: &[ExportRowV0],
) -> Result<(), MigrationErrorV0> {
    if export.header.row_count != rows.len() as u64 {
        return Err(MigrationErrorV0::VerifiedExportMismatch);
    }
    let mut previous: Option<(&[u8], &[u8])> = None;
    let mut row_digests = Vec::with_capacity(rows.len());
    let mut ordered_hasher = Sha256::new();
    ordered_hasher.update(b"trnm.migration.ordered-rows.v0");
    for row in rows {
        row.validate()?;
        if previous.is_some_and(|(namespace, key)| {
            (row.namespace.as_slice(), row.key.as_slice()) <= (namespace, key)
        }) {
            return Err(MigrationErrorV0::RowsNotStrictlyOrdered);
        }
        previous = Some((&row.namespace, &row.key));
        row_digests.push(row.row_digest);
        ordered_hasher.update(row.row_digest.0);
    }
    if merkle_root_v0(&row_digests) != export.header.export_root
        || Digest32V0(ordered_hasher.finalize().into()) != export.ordered_rows_digest
    {
        return Err(MigrationErrorV0::VerifiedExportMismatch);
    }
    Ok(())
}

pub fn verify_export_v0<V>(
    verifier: &V,
    header: FinalizedExportHeaderV0,
    rows: &[ExportRowV0],
) -> Result<VerifiedExportV0, MigrationHostErrorV0<V::Error>>
where
    V: SourceFinalityVerifierV0,
{
    if header.source_chain_id == Digest32V0([0; 32])
        || header.source_protocol_digest == Digest32V0([0; 32])
        || header.source_height == 0
        || header.source_state_root == Digest32V0([0; 32])
        || header.source_schema_digest == Digest32V0([0; 32])
        || header.source_finality_proof_digest == Digest32V0([0; 32])
        || header.row_count == 0
        || header.row_count > MAX_EXPORT_ROWS_V0
        || header.row_count != rows.len() as u64
        || header.export_root == Digest32V0([0; 32])
        || header.header_digest == Digest32V0([0; 32])
        || header.header_digest != header.canonical_digest()
    {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::InvalidExportHeader,
        ));
    }
    verifier
        .verify_finalized_export(&header)
        .map_err(MigrationHostErrorV0::SourceFinality)?;

    let mut previous: Option<(&[u8], &[u8])> = None;
    let mut row_digests = Vec::with_capacity(rows.len());
    let mut ordered_hasher = Sha256::new();
    ordered_hasher.update(b"trnm.migration.ordered-rows.v0");
    for row in rows {
        row.validate().map_err(MigrationHostErrorV0::Protocol)?;
        if previous.is_some_and(|(namespace, key)| {
            (row.namespace.as_slice(), row.key.as_slice()) <= (namespace, key)
        }) {
            return Err(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::RowsNotStrictlyOrdered,
            ));
        }
        previous = Some((&row.namespace, &row.key));
        row_digests.push(row.row_digest);
        ordered_hasher.update(row.row_digest.0);
    }
    if merkle_root_v0(&row_digests) != header.export_root {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::ExportRootMismatch,
        ));
    }
    Ok(VerifiedExportV0 {
        header,
        ordered_rows_digest: Digest32V0(ordered_hasher.finalize().into()),
    })
}
"""
migration = migration[:verify_start] + verify_block + migration[verify_end:]

migration = replace_once(
    migration,
    """        if !self.no_fallback
            || !self.downgrade_prohibited
            || self.source_chain_id != export.header.source_chain_id
""",
    """        if !self.no_fallback
            || !self.downgrade_prohibited
            || self.source_chain_id == Digest32V0([0; 32])
            || self.source_protocol_digest == Digest32V0([0; 32])
            || self.source_chain_id != export.header.source_chain_id
""",
    "migration plan validation start changed",
)
migration = replace_once(
    migration,
    """            || self.target_chain_id == self.source_chain_id
            || self.target_genesis_id == Digest32V0([0; 32])
            || self.plan_digest != self.canonical_digest()
""",
    """            || self.target_chain_id == Digest32V0([0; 32])
            || self.target_chain_id == self.source_chain_id
            || self.target_protocol_digest == Digest32V0([0; 32])
            || self.target_schema_digest == Digest32V0([0; 32])
            || self.target_genesis_id == Digest32V0([0; 32])
            || self.plan_digest == Digest32V0([0; 32])
            || self.plan_digest != self.canonical_digest()
""",
    "migration plan validation tail changed",
)

migration = replace_once(
    migration,
    """    if export.header.row_count != source_rows.len() as u64 {
        return Err(MigrationProjectionErrorV0::Protocol(
            MigrationErrorV0::InvalidExportHeader,
        ));
    }
""",
    """    validate_verified_rows_v0(export, source_rows)
        .map_err(MigrationProjectionErrorV0::Protocol)?;
""",
    "migration projection source binding changed",
)

cutover_start = migration.index("pub fn verify_cutover_agreement_v0<V>(")
cutover_end = migration.index(
    "\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum MigrationErrorV0",
    cutover_start,
)
cutover = """pub fn verify_cutover_agreement_v0<V>(
    verifier: &V,
    projection: &MigrationProjectionV0,
    required_weight: u64,
    attestations: &[CutoverAttestationV0],
) -> Result<CutoverAgreementV0, MigrationHostErrorV0<V::Error>>
where
    V: CutoverSignatureVerifierV0,
{
    if required_weight == 0
        || projection.plan_digest == Digest32V0([0; 32])
        || projection.target_state_root == Digest32V0([0; 32])
        || projection.target_genesis_id == Digest32V0([0; 32])
        || attestations.is_empty()
        || attestations.len() > MAX_CUTOVER_SIGNERS_V0
    {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::InvalidCutoverAgreement,
        ));
    }

    let mut canonical = attestations.to_vec();
    canonical.sort_by_key(|attestation| attestation.signer_id);
    let mut previous_signer = None;
    let mut weighted = Vec::with_capacity(canonical.len());
    let mut signed_weight = 0_u64;
    for attestation in canonical {
        if attestation.signer_id == Digest32V0([0; 32])
            || attestation.plan_digest != projection.plan_digest
            || attestation.target_state_root != projection.target_state_root
            || attestation.target_genesis_id != projection.target_genesis_id
            || attestation.signature_digest == Digest32V0([0; 32])
            || previous_signer == Some(attestation.signer_id)
        {
            return Err(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::InvalidCutoverAgreement,
            ));
        }
        previous_signer = Some(attestation.signer_id);
        let weight = verifier
            .verify_attestation(&attestation)
            .map_err(MigrationHostErrorV0::CutoverSignature)?;
        if weight == 0 {
            return Err(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::InvalidCutoverAgreement,
            ));
        }
        signed_weight = signed_weight
            .checked_add(weight)
            .ok_or(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::WeightOverflow,
            ))?;
        weighted.push((attestation.signer_id, weight));
    }
    if signed_weight < required_weight {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::InsufficientCutoverWeight,
        ));
    }
    let mut signer_hasher = Sha256::new();
    signer_hasher.update(b"trnm.migration.cutover-signers.v0");
    for (signer_id, weight) in weighted {
        signer_hasher.update(signer_id.0);
        signer_hasher.update(weight.to_be_bytes());
    }
    let signer_set_digest = Digest32V0(signer_hasher.finalize().into());
    let agreement_digest = Digest32V0::hash(
        b"trnm.migration.cutover-agreement.v0",
        &[
            &projection.plan_digest.0,
            &projection.target_state_root.0,
            &projection.target_genesis_id.0,
            &signed_weight.to_be_bytes(),
            &required_weight.to_be_bytes(),
            &signer_set_digest.0,
        ],
    );
    Ok(CutoverAgreementV0 {
        plan_digest: projection.plan_digest,
        target_state_root: projection.target_state_root,
        target_genesis_id: projection.target_genesis_id,
        signed_weight,
        required_weight,
        signer_set_digest,
        agreement_digest,
    })
}
"""
migration = migration[:cutover_start] + cutover + migration[cutover_end:]

migration = replace_once(
    migration,
    """    ExportRootMismatch,
    InvalidTargetRow,
""",
    """    ExportRootMismatch,
    VerifiedExportMismatch,
    InvalidTargetRow,
""",
    "migration error enum changed",
)
migration = replace_once(
    migration,
    """            Self::ExportRootMismatch => "source export root mismatch",
            Self::InvalidTargetRow => "invalid projected target row",
""",
    """            Self::ExportRootMismatch => "source export root mismatch",
            Self::VerifiedExportMismatch => {
                "projection rows do not match the independently verified export"
            }
            Self::InvalidTargetRow => "invalid projected target row",
""",
    "migration error display changed",
)

migration_tests = """

    fn verified_fixture() -> (Vec<ExportRowV0>, VerifiedExportV0, MigrationPlanV0) {
        let rows = vec![row(1), row(2)];
        let export_root =
            merkle_root_v0(&rows.iter().map(|row| row.row_digest).collect::<Vec<_>>());
        let mut header = FinalizedExportHeaderV0 {
            source_chain_id: d(1),
            source_protocol_digest: d(2),
            source_height: 100,
            source_state_root: d(3),
            source_schema_digest: d(4),
            source_finality_proof_digest: d(5),
            row_count: rows.len() as u64,
            export_root,
            header_digest: d(0),
        };
        header.header_digest = header.canonical_digest();
        let export = verify_export_v0(&AcceptFinality, header, &rows).unwrap();
        let mut plan = MigrationPlanV0 {
            source_chain_id: header.source_chain_id,
            source_protocol_digest: header.source_protocol_digest,
            source_height: header.source_height,
            source_export_header_digest: header.header_digest,
            target_chain_id: d(6),
            target_protocol_digest: d(7),
            target_schema_digest: d(8),
            target_genesis_id: d(9),
            no_fallback: true,
            downgrade_prohibited: true,
            plan_digest: d(0),
        };
        plan.plan_digest = plan.canonical_digest();
        (rows, export, plan)
    }

    #[test]
    fn projection_rejects_rows_substituted_after_export_verification() {
        let (rows, export, plan) = verified_fixture();
        let mut substituted = rows.clone();
        substituted[1].value.push(99);
        substituted[1].row_digest = ExportRowV0::canonical_digest(
            &substituted[1].namespace,
            &substituted[1].key,
            &substituted[1].value,
        );
        assert!(matches!(
            project_and_recompute_v0(
                &plan,
                &export,
                &substituted,
                &IdentityProjector,
                &HashRoot
            ),
            Err(MigrationProjectionErrorV0::Protocol(
                MigrationErrorV0::VerifiedExportMismatch
            ))
        ));
    }

    #[test]
    fn authority_namespace_prefixes_are_never_importable() {
        assert!(forbidden_authority_namespace(b"signer_journal/v2"));
        assert!(forbidden_authority_namespace(b"node_commit_ledger_archive"));
        assert!(!forbidden_authority_namespace(b"accounts"));
    }

    #[test]
    fn cutover_signer_commitment_is_permutation_invariant() {
        let (rows, export, plan) = verified_fixture();
        let projection =
            project_and_recompute_v0(&plan, &export, &rows, &IdentityProjector, &HashRoot).unwrap();
        let first = CutoverAttestationV0 {
            signer_id: d(10),
            plan_digest: plan.plan_digest,
            target_state_root: projection.target_state_root,
            target_genesis_id: plan.target_genesis_id,
            signature_digest: d(11),
        };
        let second = CutoverAttestationV0 {
            signer_id: d(12),
            plan_digest: plan.plan_digest,
            target_state_root: projection.target_state_root,
            target_genesis_id: plan.target_genesis_id,
            signature_digest: d(13),
        };
        let a = verify_cutover_agreement_v0(&WeightOne, &projection, 2, &[first, second])
            .unwrap();
        let b = verify_cutover_agreement_v0(&WeightOne, &projection, 2, &[second, first])
            .unwrap();
        assert_eq!(a.signer_set_digest, b.signer_set_digest);
        assert_eq!(a.agreement_digest, b.agreement_digest);
    }
"""
pos = migration.rfind("\n}")
require(pos >= 0, "migration test module end missing")
migration = migration[:pos] + migration_tests + migration[pos:]
migration_path.write_text(migration)

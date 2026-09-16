//! Actual native SQL + strict Ed25519 + Borsh/JMT producer/consumer seam.
//! Test keys and child proof headers remain fixtures, not a live validator set.
use super::*;
use crate::{
    verify_native_snapshot_stream_v1, NativeSnapshotExportV1, NativeSnapshotReadLimitsV1,
    NativeSnapshotStreamErrorV1,
};
use sha2::{Digest, Sha256};
use std::{cell::Cell, io};
use trnm_native_application::{
    NativeSnapshotChunkV0, NativeSnapshotManifestV0, NativeSnapshotRequestV0,
};

fn committed(directory: &TempDir) -> Prepared {
    let value = prepare(directory);
    value
        .application
        .commit_poco_finality_bytes_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &value.bytes,
            value.executed.clone(),
            PARENT_TIMESTAMP,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    value
}
fn export(value: &Prepared, size: u32) -> NativeSnapshotExportV1 {
    value
        .application
        .begin_finalized_snapshot_export_v1(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &value.bytes,
            HeightV0::new(1),
            PARENT_TIMESTAMP,
            size,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap()
}
fn limits() -> NativeSnapshotReadLimitsV1 {
    NativeSnapshotReadLimitsV1::new(64 * 1024 * 1024, 1_000_000, 1024 * 1024).unwrap()
}
fn read(value: &Prepared) -> PocoFinalizedApplicationReadV0 {
    value
        .application
        .read_poco_finalized_bytes_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &value.bytes,
            HeightV0::new(1),
            PARENT_TIMESTAMP,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap()
}
fn chunks(value: &Prepared, export: &NativeSnapshotExportV1) -> Vec<Vec<u8>> {
    (0..export.manifest().chunks().len() as u32)
        .map(|index| {
            value
                .application
                .read_snapshot_chunk_v1(export, index)
                .unwrap()
        })
        .collect()
}
fn manifest_for_bytes(
    original: &NativeSnapshotManifestV0,
    bytes: &[u8],
) -> (NativeSnapshotManifestV0, Vec<Vec<u8>>) {
    let chunks: Vec<_> = bytes
        .chunks(original.request().maximum_chunk_bytes() as usize)
        .map(<[u8]>::to_vec)
        .collect();
    let descriptors: Vec<_> = chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            NativeSnapshotChunkV0::new(
                index as u32,
                bytes.len() as u32,
                Hash32V0::new(trnm_finality_types::hash_domain(
                    "trnm.native-application.snapshot-chunk.v0",
                    &[&(index as u32).to_be_bytes(), bytes],
                )),
            )
            .unwrap()
        })
        .collect();
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let hashes: Vec<_> = descriptors
        .iter()
        .map(|chunk| chunk.digest().into_bytes())
        .collect();
    let mut parts: Vec<&[u8]> = vec![&digest];
    parts.extend(hashes.iter().map(<[u8; 32]>::as_slice));
    let manifest = NativeSnapshotManifestV0::new(
        original.request().clone(),
        descriptors,
        Hash32V0::new(trnm_finality_types::hash_domain(
            "trnm.native-application.snapshot-manifest.v0",
            &parts,
        )),
    )
    .unwrap();
    (manifest, chunks)
}

#[test]
fn exact_native_export_stream_recomputes_jmt_and_preserves_database() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let exported = export(&value, 4096);
    let original = value
        .application
        .snapshot(exported.manifest().request().clone())
        .unwrap();
    assert_eq!(
        &original,
        exported.manifest(),
        "no native wire/domain change"
    );
    let before = std::fs::read(directory.path().join("app.sqlite")).unwrap();
    let proof = read(&value);
    let source = (0..exported.manifest().chunks().len() as u32).map(|index| {
        value
            .application
            .read_snapshot_chunk_v1(&exported, index)
            .map_err(io::Error::other)
    });
    let verified = verify_native_snapshot_stream_v1(
        &config(),
        proof.finality(),
        exported.manifest(),
        source,
        limits(),
    )
    .unwrap();
    assert_eq!(verified.height(), 1);
    assert_eq!(
        verified.state_root(),
        value
            .executed
            .request()
            .expected()
            .post_state_root()
            .as_bytes()
    );
    assert_eq!(verified.snapshot_digest(), exported.snapshot_digest());
    assert_eq!(verified.finality_proof_id(), exported.finality_proof_id());
    assert_eq!(verified.total_bytes(), exported.manifest().total_bytes());
    assert_eq!(
        std::fs::read(directory.path().join("app.sqlite")).unwrap(),
        before
    );
}

#[test]
fn prepared_and_corrupt_finality_cannot_start_export() {
    let directory = TempDir::new().unwrap();
    let value = prepare(&directory);
    let before = std::fs::read(directory.path().join("app.sqlite")).unwrap();
    for class in [POCO_THREE_CHAIN_PROOF_CLASS_V0, "qc"] {
        assert!(value
            .application
            .begin_finalized_snapshot_export_v1(
                class,
                &value.bytes,
                HeightV0::new(1),
                PARENT_TIMESTAMP,
                4096,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .is_err());
    }
    assert_eq!(
        std::fs::read(directory.path().join("app.sqlite")).unwrap(),
        before
    );
}

#[test]
fn export_is_owner_bound_and_reopen_requires_fresh_proof() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let token = export(&value, 4096);
    assert!(value
        .application
        .read_snapshot_chunk_v1(&token, u32::MAX)
        .is_err());
    let bytes = value.bytes.clone();
    drop(value);
    let reopened =
        DurableNativeApplicationV0::open(directory.path().join("app.sqlite"), config()).unwrap();
    assert!(reopened.read_snapshot_chunk_v1(&token, 0).is_err());
    let fresh = reopened
        .begin_finalized_snapshot_export_v1(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &bytes,
            HeightV0::new(1),
            PARENT_TIMESTAMP,
            4096,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(fresh.snapshot_digest(), token.snapshot_digest());
    assert!(!reopened
        .read_snapshot_chunk_v1(&fresh, 0)
        .unwrap()
        .is_empty());
}

#[test]
fn transport_tampering_incomplete_and_extra_chunks_are_rejected() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let token = export(&value, 4096);
    let proof = read(&value);
    let source = chunks(&value, &token);
    let mut bad = source.clone();
    bad[0][0] ^= 1;
    assert!(matches!(
        verify_native_snapshot_stream_v1(
            &config(),
            proof.finality(),
            token.manifest(),
            bad.into_iter().map(Ok),
            limits()
        ),
        Err(NativeSnapshotStreamErrorV1::ChunkMismatch)
    ));
    let mut short = source.clone();
    short.pop();
    assert!(matches!(
        verify_native_snapshot_stream_v1(
            &config(),
            proof.finality(),
            token.manifest(),
            short.into_iter().map(Ok),
            limits()
        ),
        Err(NativeSnapshotStreamErrorV1::Incomplete)
    ));
    let mut extra = source;
    extra.push(vec![1]);
    assert!(matches!(
        verify_native_snapshot_stream_v1(
            &config(),
            proof.finality(),
            token.manifest(),
            extra.into_iter().map(Ok),
            limits()
        ),
        Err(NativeSnapshotStreamErrorV1::TrailingInput)
    ));
}

#[test]
fn valid_transport_hashes_cannot_hide_corrupt_jmt_snapshot() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let token = export(&value, 4096);
    let proof = read(&value);
    let mut bytes = chunks(&value, &token).concat();
    // The final record is a root commitment in the unchanged Borsh map.
    *bytes.last_mut().unwrap() ^= 1;
    let (manifest, parts) = manifest_for_bytes(token.manifest(), &bytes);
    assert!(matches!(
        verify_native_snapshot_stream_v1(
            &config(),
            proof.finality(),
            &manifest,
            parts.into_iter().map(Ok),
            limits()
        ),
        Err(NativeSnapshotStreamErrorV1::InvalidSnapshot(_))
    ));
}

#[test]
fn total_resource_limit_rejects_before_touching_transport() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let token = export(&value, 4096);
    let proof = read(&value);
    let calls = Cell::new(0);
    let input = std::iter::from_fn(|| -> Option<io::Result<Vec<u8>>> {
        calls.set(calls.get() + 1);
        panic!("must not consume input");
    });
    let tiny = NativeSnapshotReadLimitsV1::new(1, 1, 1).unwrap();
    assert!(matches!(
        verify_native_snapshot_stream_v1(
            &config(),
            proof.finality(),
            token.manifest(),
            input,
            tiny
        ),
        Err(NativeSnapshotStreamErrorV1::LimitExceeded)
    ));
    assert_eq!(calls.get(), 0);
}

#[test]
fn huge_map_count_is_a_local_resource_error_not_a_valid_snapshot() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let token = export(&value, 4096);
    let proof = read(&value);
    let mut bytes = Vec::from(1_u16.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    let (manifest, parts) = manifest_for_bytes(token.manifest(), &bytes);
    assert!(matches!(
        verify_native_snapshot_stream_v1(
            &config(),
            proof.finality(),
            &manifest,
            parts.into_iter().map(Ok),
            limits()
        ),
        Err(NativeSnapshotStreamErrorV1::LimitExceeded)
    ));
}

#[test]
fn transport_error_keeps_its_original_kind() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let token = export(&value, 4096);
    let proof = read(&value);
    let input = std::iter::once(Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "fixture timeout",
    )));
    match verify_native_snapshot_stream_v1(
        &config(),
        proof.finality(),
        token.manifest(),
        input,
        limits(),
    ) {
        Err(NativeSnapshotStreamErrorV1::Transport(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut)
        }
        other => panic!("expected original transport error, got {other:?}"),
    }
}

#[test]
fn manifest_root_cannot_replace_strict_finality_target() {
    let directory = TempDir::new().unwrap();
    let value = committed(&directory);
    let token = export(&value, 4096);
    let proof = read(&value);
    let head = token.manifest().request().head();
    let changed = trnm_native_application::ApplicationHeadV0::new(
        head.height(),
        head.block_id(),
        StateRootV0::new([99; 32]).unwrap(),
        head.commit_id(),
    );
    let manifest = NativeSnapshotManifestV0::new(
        NativeSnapshotRequestV0::new(changed, 4096).unwrap(),
        token.manifest().chunks().to_vec(),
        token.manifest().manifest_digest(),
    )
    .unwrap();
    let input = std::iter::from_fn(|| -> Option<io::Result<Vec<u8>>> {
        panic!("untrusted target must not consume input");
    });
    assert!(matches!(
        verify_native_snapshot_stream_v1(&config(), proof.finality(), &manifest, input, limits()),
        Err(NativeSnapshotStreamErrorV1::ContextMismatch)
    ));
}

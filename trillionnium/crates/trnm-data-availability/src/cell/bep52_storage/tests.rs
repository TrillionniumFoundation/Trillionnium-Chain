use std::{io::Cursor, time::Duration};

use super::*;
use crate::cell::{
    CellBep52BindingV1, CellBep52ChunkProofV1, CellCacheConfigV4, CellChunkV1, MAX_CHUNK_BYTES,
};

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "bep52-storage-v2-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn manifest(bytes: &[u8], chunk_bytes: u32) -> CellManifestV1 {
    CellManifestV1::new(
        context(),
        bytes.len() as u64,
        Sha256::digest(bytes).into(),
        chunk_bytes,
        bytes
            .chunks(chunk_bytes as usize)
            .map(|chunk| CellChunkV1 {
                size: chunk.len() as u32,
                sha256: Sha256::digest(chunk).into(),
            })
            .collect(),
    )
    .unwrap()
}

fn limits(manifest: &CellManifestV1) -> CellReleaseLimitsV1 {
    CellReleaseLimitsV1 {
        max_payload_bytes: manifest.size(),
        max_chunks: manifest.chunks().len() as u64,
        deadline: Instant::now() + Duration::from_secs(30),
    }
}

fn binding(bytes: &[u8], chunk_bytes: u32) -> CellBep52StorageBindingV2 {
    let manifest = manifest(bytes, chunk_bytes);
    CellBep52StorageBindingV2::from_pinned_reader(
        &manifest,
        manifest.id(),
        &context(),
        &mut Cursor::new(bytes),
        limits(&manifest),
    )
    .unwrap()
}

fn cache(path: &std::path::Path) -> CellStoreV1 {
    CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 16 * 1024 * 1024,
            max_logical_bytes: 12 * 1024 * 1024,
            max_chunk_rows: 16,
            max_manifest_rows: 8,
        },
    )
    .unwrap()
}

#[test]
fn same_bytes_have_same_bep52_root_across_storage_sizes_and_short_file_boundaries() {
    for size in [
        1, 16_383, 16_384, 16_385, 32_768, 32_769, 65_536, 65_537, 81_923,
    ] {
        let bytes: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let reference_manifest = manifest(&bytes, 16_384);
        let reference = CellBep52BindingV1::from_pinned_manifest(
            &reference_manifest,
            reference_manifest.id(),
            &context(),
        )
        .unwrap();
        for chunk_bytes in [16_384, 32_768, 65_536, MAX_CHUNK_BYTES] {
            let mapped = binding(&bytes, chunk_bytes);
            assert_eq!(mapped.pieces_root(), reference.pieces_root());
            assert_eq!(mapped.leaf_count() as usize, bytes.len().div_ceil(16_384));
            mapped.verify_info_bytes(&mapped.info_bytes()).unwrap();
            mapped
                .verify_metainfo_bytes(&mapped.metainfo_bytes())
                .unwrap();
            if size <= chunk_bytes as usize {
                assert!(mapped.metainfo_bytes().ends_with(b"12:piece layersdee"));
            }
            if chunk_bytes == 16_384 {
                assert_eq!(mapped.info_bytes(), reference.info_bytes());
                assert_eq!(mapped.metainfo_bytes(), reference.metainfo_bytes());
            }
            for index in [0, mapped.leaf_count() - 1] {
                let location = mapped.leaf_location(index).unwrap();
                let start = location.storage_index as usize * chunk_bytes as usize;
                let end = (start + chunk_bytes as usize).min(bytes.len());
                let proof = mapped.leaf_proof(index, &bytes[start..end]).unwrap();
                let leaf_start = location.payload_offset as usize;
                mapped
                    .verify_transport_leaf(
                        &proof,
                        &bytes[leaf_start..leaf_start + location.size as usize],
                    )
                    .unwrap();
            }
        }
    }
}

#[test]
fn independent_32k_piece_reference_vector_uses_subtree_roots_not_storage_sha() {
    // Python hashlib + direct four-leaf recursive tree + canonical bencoding,
    // plus independently packed big-endian TCM1/CBM2/CBL2 byte layouts.
    let bytes = [vec![b'A'; 16_384], vec![b'B'; 16_384], vec![b'C']].concat();
    let mapped = binding(&bytes, 32_768);
    assert_eq!(
        digest_hex(mapped.pieces_root()),
        "f3c9ca846350d432de56330cc6375ce0c80a3a2ad81952a20d3771d88f5f1e1f"
    );
    assert_eq!(
        digest_hex(mapped.info_hash()),
        "2b248fd93b8789314a99dc36b8d153dc40fde018f4ff589ca52da46aa5b614ce"
    );
    assert_eq!(
        digest_hex(Sha256::digest(mapped.metainfo_bytes()).into()),
        "cf91c77037651c375062ac11f62ce9bedc6801a25f762a9649b65a72d1f878a6"
    );
    assert_eq!(mapped.metainfo_bytes().len(), 278);
    assert_eq!(
        hex::encode(mapped.mapping_bytes()),
        concat!(
            "43424d32386c37da59c97bbfbe1b936dbf65022de509d70cb1aab172508dd2084a7f9b9e",
            "00000000000080010000800000000002",
            "76ae7596e8219b17ab48a331a08bdebb3bcf83c6312dc0420fa5fed5071d2e82",
            "931b84117478bd5da595b0c8d47e57c6ba1dc68b609c200008c205d2e02340bf"
        )
    );
    assert_eq!(
        digest_hex(mapped.mapping_id()),
        "50fac0c9e8b36a7c1d430fbab875abb4a173705a753cf462c0fecbc736bdcab4"
    );
    assert_ne!(mapped.piece_roots()[0], mapped.manifest.chunks()[0].sha256);
    assert_eq!(
        digest_hex(mapped.piece_roots()[1]),
        "931b84117478bd5da595b0c8d47e57c6ba1dc68b609c200008c205d2e02340bf"
    );
    let proof = mapped.leaf_proof(2, b"C").unwrap();
    assert_eq!(proof.encode().len(), 173);
    assert_eq!(
        digest_hex(Sha256::digest(proof.encode()).into()),
        "5b4d35915c96a71244f02d1822e1bf20036c4dcea43cbc688aab58e666534523"
    );
    assert_eq!(proof.siblings[0], [0; 32]);
    mapped.verify_transport_leaf(&proof, b"C").unwrap();
}

#[test]
fn absent_piece_padding_is_a_zero_subtree_at_the_storage_piece_height() {
    let bytes = [vec![17; 65_536], vec![29]].concat();
    let mapped = binding(&bytes, 32_768);
    let proof = mapped.leaf_proof(4, &[29]).unwrap();
    assert_eq!(proof.siblings.len(), 3);
    assert_eq!(proof.siblings[0], [0; 32]);
    assert_eq!(proof.siblings[1], hash_pair([0; 32], [0; 32]));
    assert_ne!(proof.siblings[1], [0; 32]);
    mapped.verify_transport_leaf(&proof, &[29]).unwrap();
}

#[test]
fn mapping_roundtrip_requires_original_manifest_context_and_independent_mapping_pin() {
    let mapped = binding(&vec![41; 65_537], 65_536);
    let bytes = mapped.mapping_bytes();
    let imported = CellBep52StorageBindingV2::from_pinned_mapping(
        &mapped.manifest,
        mapped.manifest_id,
        &context(),
        mapped.mapping_id,
        &bytes,
    )
    .unwrap();
    assert_eq!(imported, mapped);
    assert_eq!(imported.magnet().info_hash(), mapped.info_hash());
    assert!(CellBep52StorageBindingV2::from_pinned_mapping(
        &mapped.manifest,
        mapped.manifest_id,
        &context(),
        mapped.info_hash,
        &bytes,
    )
    .is_err());
    let mut other_context = context();
    other_context.runtime = [44; 32];
    assert!(CellBep52StorageBindingV2::from_pinned_mapping(
        &mapped.manifest,
        mapped.manifest_id,
        &other_context,
        mapped.mapping_id,
        &bytes,
    )
    .is_err());
    assert!(CellBep52StorageBindingV2::from_pinned_mapping(
        &mapped.manifest,
        [44; 32],
        &context(),
        mapped.mapping_id,
        &bytes,
    )
    .is_err());
    let mut missing = bytes.clone();
    missing.truncate(missing.len() - 32);
    assert!(CellBep52StorageBindingV2::from_pinned_mapping(
        &mapped.manifest,
        mapped.manifest_id,
        &context(),
        mapping_digest(&missing),
        &missing,
    )
    .is_err());
}

#[test]
fn imported_mapping_does_not_substitute_for_a_complete_original_storage_chunk_check() {
    let bytes = vec![53; 32_768];
    let mapped = binding(&bytes, 32_768);
    let mut declaration = mapped.mapping_bytes();
    // Even an independently pinned declaration must agree with actual bytes.
    declaration[MAPPING_HEADER_BYTES] ^= 1;
    let imported = CellBep52StorageBindingV2::from_pinned_mapping(
        &mapped.manifest,
        mapped.manifest_id,
        &context(),
        mapping_digest(&declaration),
        &declaration,
    )
    .unwrap();
    assert!(imported.verify_storage_chunk(0, &bytes).is_err());
    assert!(imported.verified_storage_chunk(0, &bytes).is_err());
    assert!(imported
        .verify_transport_leaf(&mapped.leaf_proof(0, &bytes).unwrap(), &bytes[..16_384])
        .is_err());
}

#[test]
fn complete_payload_digest_is_verified_beyond_individual_storage_chunk_digests() {
    let bytes = vec![67; 32_769];
    let good = manifest(&bytes, 32_768);
    let inconsistent = CellManifestV1::new(
        context(),
        good.size(),
        [99; 32],
        good.chunk_bytes(),
        good.chunks().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        CellBep52StorageBindingV2::from_pinned_reader(
            &inconsistent,
            inconsistent.id(),
            &context(),
            &mut Cursor::new(&bytes),
            limits(&inconsistent),
        ),
        Err(CellErrorV1::Invalid(
            "BEP52 storage complete payload digest"
        ))
    ));
    let mut changed = bytes.clone();
    changed[20_000] ^= 1;
    assert!(CellBep52StorageBindingV2::from_pinned_reader(
        &good,
        good.id(),
        &context(),
        &mut Cursor::new(&changed),
        limits(&good),
    )
    .is_err());
}

#[test]
fn source_stream_requires_exact_eof_and_original_reservation_before_reading() {
    let bytes = vec![71; 32_769];
    let good = manifest(&bytes, 32_768);
    for length in [bytes.len() - 1, bytes.len() + 1] {
        let mut input = bytes.clone();
        input.resize(length, 71);
        assert!(CellBep52StorageBindingV2::from_pinned_reader(
            &good,
            good.id(),
            &context(),
            &mut Cursor::new(input),
            limits(&good),
        )
        .is_err());
    }
    for kind in 0..3 {
        let mut reservation = limits(&good);
        match kind {
            0 => reservation.max_payload_bytes -= 1,
            1 => reservation.max_chunks -= 1,
            _ => reservation.deadline = Instant::now() - Duration::from_secs(1),
        }
        let mut input = Cursor::new(&bytes);
        assert!(CellBep52StorageBindingV2::from_pinned_reader(
            &good,
            good.id(),
            &context(),
            &mut input,
            reservation,
        )
        .is_err());
        assert_eq!(input.position(), 0);
    }
}

#[test]
fn actual_4mib_chunks_cross_16k_transport_leaves_and_enter_cache_only_when_complete() {
    let bytes: Vec<_> = (0..MAX_CHUNK_BYTES as usize + 17)
        .map(|i| (i % 251) as u8)
        .collect();
    let owner = binding(&bytes, MAX_CHUNK_BYTES);
    assert_eq!(owner.manifest.chunks().len(), 2);
    assert_eq!(owner.leaf_count(), 257);
    let receiver = CellBep52StorageBindingV2::from_pinned_mapping(
        &owner.manifest,
        owner.manifest_id,
        &context(),
        owner.mapping_id,
        &owner.mapping_bytes(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = cache(&dir.path().join("target.sqlite"));
    target
        .put_manifest(receiver.manifest_id, &receiver.manifest.encode())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    for (index, storage_bytes) in bytes.chunks(MAX_CHUNK_BYTES as usize).enumerate() {
        let served = owner
            .verified_storage_chunk(index as u32, storage_bytes)
            .unwrap();
        let mut acquired = receiver
            .begin_storage_chunk(index as u32, deadline)
            .unwrap();
        for leaf in served.first_leaf_index()..served.first_leaf_index() + served.leaf_count() {
            let encoded = served.leaf_proof(leaf).unwrap().encode();
            let proof = CellBep52LeafProofV2::decode(&encoded).unwrap();
            acquired
                .push(&proof, served.leaf_bytes(leaf).unwrap())
                .unwrap();
            assert!(target
                .chunk(receiver.manifest.chunks()[index].sha256)
                .unwrap()
                .is_none());
        }
        assert_eq!(acquired.received_bytes() as usize, storage_bytes.len());
        acquired.finish_into_store(&target).unwrap();
        assert_eq!(
            target
                .chunk(receiver.manifest.chunks()[index].sha256)
                .unwrap()
                .unwrap(),
            storage_bytes
        );
    }
    target.verify_complete(receiver.manifest()).unwrap();
    let readback = CellBep52StorageBindingV2::from_pinned_store(
        receiver.manifest(),
        receiver.manifest_id(),
        &context(),
        &target,
        limits(receiver.manifest()),
    )
    .unwrap();
    assert_eq!(readback, owner);
    assert_eq!(
        receiver.leaf_location(256).unwrap(),
        CellBep52LeafLocationV2 {
            leaf_index: 256,
            storage_index: 1,
            storage_offset: 0,
            payload_offset: MAX_CHUNK_BYTES as u64,
            size: 17,
        }
    );
}

#[test]
fn incomplete_duplicate_and_wrong_chunk_sequences_leave_original_cache_row_absent() {
    let bytes = vec![83; 32_769];
    let mapped = binding(&bytes, 32_768);
    let dir = tempfile::tempdir().unwrap();
    let target = cache(&dir.path().join("target.sqlite"));
    let mut receiver = mapped
        .begin_storage_chunk(0, Instant::now() + Duration::from_secs(5))
        .unwrap();
    let served = mapped.verified_storage_chunk(0, &bytes[..32_768]).unwrap();
    let first = served.leaf_proof(0).unwrap();
    let second = served.leaf_proof(1).unwrap();
    assert!(receiver
        .push(&second, served.leaf_bytes(1).unwrap())
        .is_err());
    assert_eq!(receiver.received_bytes(), 0);
    receiver
        .push(&first, served.leaf_bytes(0).unwrap())
        .unwrap();
    assert!(receiver
        .push(&first, served.leaf_bytes(0).unwrap())
        .is_err());
    let tail = mapped.leaf_proof(2, &bytes[32_768..]).unwrap();
    assert!(receiver.push(&tail, &bytes[32_768..]).is_err());
    assert_eq!(receiver.received_bytes(), 16_384);
    assert!(receiver.finish_into_store(&target).is_err());
    assert!(target
        .chunk(mapped.manifest.chunks()[0].sha256)
        .unwrap()
        .is_none());
}

#[test]
fn original_deadline_survives_leaf_assembly_and_cache_publication() {
    let bytes = vec![89; 16_385];
    let mapped = binding(&bytes, 32_768);
    let expired = Instant::now() - Duration::from_secs(1);
    assert!(mapped.begin_storage_chunk(0, expired).is_err());
    let mut receiver = mapped
        .begin_storage_chunk(0, Instant::now() + Duration::from_secs(5))
        .unwrap();
    let served = mapped.verified_storage_chunk(0, &bytes).unwrap();
    for index in 0..2 {
        receiver
            .push(
                &served.leaf_proof(index).unwrap(),
                served.leaf_bytes(index).unwrap(),
            )
            .unwrap();
    }
    receiver.deadline = expired;
    let dir = tempfile::tempdir().unwrap();
    let target = cache(&dir.path().join("target.sqlite"));
    assert!(receiver.finish_into_store(&target).is_err());
    assert!(target
        .chunk(mapped.manifest.chunks()[0].sha256)
        .unwrap()
        .is_none());
}

#[test]
fn new_mapping_and_leaf_profile_do_not_reinterpret_v1_16k_binding_or_proof() {
    let bytes = vec![97; 32_769];
    let larger = binding(&bytes, 32_768);
    assert!(CellBep52BindingV1::from_pinned_manifest(
        &larger.manifest,
        larger.manifest_id,
        &context(),
    )
    .is_err());
    let small = binding(&bytes, 16_384);
    let old =
        CellBep52BindingV1::from_pinned_manifest(&small.manifest, small.manifest_id, &context())
            .unwrap();
    assert_eq!(old.info_hash(), small.info_hash());
    assert!(CellBep52LeafProofV2::decode(&old.chunk_proof(0).unwrap().encode()).is_err());
    assert!(CellBep52ChunkProofV1::decode(
        &small.leaf_proof(0, &bytes[..16_384]).unwrap().encode()
    )
    .is_err());
}

#[test]
fn proof_parsing_bounds_and_leaf_coordinates_are_checked_before_byte_release() {
    let bytes = vec![101; 32_769];
    let mapped = binding(&bytes, 32_768);
    let encoded = mapped.leaf_proof(2, &bytes[32_768..]).unwrap().encode();
    for end in 0..encoded.len() {
        assert!(CellBep52LeafProofV2::decode(&encoded[..end]).is_err());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    assert!(CellBep52LeafProofV2::decode(&extra).is_err());
    let mut wrong_index = encoded.clone();
    wrong_index[100..104].copy_from_slice(&3_u32.to_be_bytes());
    assert!(CellBep52LeafProofV2::decode(&wrong_index).is_err());
    let mut wrong_count = encoded;
    wrong_count[104..108].copy_from_slice(&(MAX_LEAVES + 1).to_be_bytes());
    assert!(CellBep52LeafProofV2::decode(&wrong_count).is_err());
    assert!(mapped.leaf_location(mapped.leaf_count()).is_err());
    assert!(mapped.verify_storage_chunk(u32::MAX, &[]).is_err());
    let served = mapped.verified_storage_chunk(0, &bytes[..32_768]).unwrap();
    assert!(served.leaf_bytes(2).is_err());
    assert!(served.leaf_proof(2).is_err());
    let proof = served.leaf_proof(0).unwrap();
    assert!(mapped
        .verify_transport_leaf(&proof, &bytes[..16_383])
        .is_err());
    let mut metainfo = mapped.metainfo_bytes();
    let layer_byte = metainfo.len() - 3;
    metainfo[layer_byte] ^= 1;
    assert!(mapped.verify_metainfo_bytes(&metainfo).is_err());
}

#[test]
fn maximum_existing_storage_shape_has_bounded_mapping_and_twenty_two_hash_proof() {
    // Structural boundary only: one real 4 MiB chunk is reused in a declared
    // 64 GiB layout. This does not claim materialization/full-payload readback.
    let bytes = vec![107; MAX_CHUNK_BYTES as usize];
    let chunk = CellChunkV1 {
        size: MAX_CHUNK_BYTES,
        sha256: Sha256::digest(&bytes).into(),
    };
    let declared = CellManifestV1::new(
        context(),
        MAX_CELL_BYTES,
        [113; 32],
        MAX_CHUNK_BYTES,
        vec![chunk; MAX_CELL_BEP52_STORAGE_PIECES_V2],
    )
    .unwrap();
    let root = leaf_levels(&bytes, 256).last().unwrap()[0];
    let mapped = CellBep52StorageBindingV2::from_roots(
        &declared,
        declared.id(),
        vec![root; MAX_CELL_BEP52_STORAGE_PIECES_V2],
    );
    assert_eq!(
        mapped.mapping_bytes().len(),
        MAX_CELL_BEP52_STORAGE_MAPPING_BYTES_V2
    );
    assert!(mapped.metainfo_bytes().len() <= MAX_CELL_BEP52_STORAGE_METAINFO_BYTES_V2);
    assert_eq!(
        mapped.levels.iter().map(Vec::len).sum::<usize>(),
        2 * 16_384 - 1
    );
    let imported = CellBep52StorageBindingV2::from_pinned_mapping(
        &declared,
        declared.id(),
        &context(),
        mapped.mapping_id(),
        &mapped.mapping_bytes(),
    )
    .unwrap();
    let proof = imported.leaf_proof(MAX_LEAVES - 1, &bytes).unwrap();
    assert_eq!(proof.siblings.len(), 22);
    assert_eq!(proof.encode().len(), MAX_CELL_BEP52_LEAF_PROOF_BYTES_V2);
    imported
        .verify_transport_leaf(&proof, &bytes[bytes.len() - 16_384..])
        .unwrap();
    assert_eq!(
        imported
            .leaf_location(MAX_LEAVES - 1)
            .unwrap()
            .payload_offset,
        MAX_CELL_BYTES - 16_384
    );
}

#[test]
fn missing_storage_bytes_cannot_create_a_verified_mapping() {
    let bytes = vec![127; 32_769];
    let declared = manifest(&bytes, 32_768);
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    source
        .put_manifest(declared.id(), &declared.encode())
        .unwrap();
    source
        .put_chunk(&declared.chunks()[0], &bytes[..32_768])
        .unwrap();
    assert!(matches!(
        CellBep52StorageBindingV2::from_pinned_store(
            &declared,
            declared.id(),
            &context(),
            &source,
            limits(&declared),
        ),
        Err(CellErrorV1::Unavailable)
    ));
}

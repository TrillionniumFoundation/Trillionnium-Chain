use super::*;
use crate::cell::{CellChunkV1, CellErrorV1};

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "bep52-test-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn manifest(bytes: &[u8], chunk_bytes: u32, context: CellContextV1) -> CellManifestV1 {
    CellManifestV1::new(
        context,
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

fn binding(bytes: &[u8]) -> CellBep52BindingV1 {
    let manifest = manifest(bytes, CELL_BEP52_PIECE_BYTES_V1, context());
    CellBep52BindingV1::from_pinned_manifest(&manifest, manifest.id(), &context()).unwrap()
}

fn three_leaves() -> Vec<u8> {
    [vec![b'A'; 16_384], vec![b'B'; 16_384], vec![b'C']].concat()
}

// Independent reference vectors use Python hashlib, a sorted-dictionary
// bencoder and recursive tree splitting (not the production bottom-up tree).
#[test]
fn short_single_leaf_has_unpadded_sha256_root_and_exact_bencoding() {
    let binding = binding(b"abc");
    assert_eq!(
        digest_hex(binding.pieces_root()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex::encode(binding.info_bytes()),
        concat!(
            "64393a66696c65207472656564383a63656c6c2e62696e64303a64363a6c656e677468693365",
            "31313a70696563657320726f6f7433323a",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "65656531323a6d6574612076657273696f6e693265343a6e616d65383a63656c6c2e62696e",
            "31323a7069656365206c656e6774686931363338346565"
        )
    );
    assert_eq!(
        binding.magnet().encode(),
        concat!(
            "magnet:?xt=urn:btmh:1220",
            "667db46d8af4a61ad7548bd7307f347b27ed3b6e680d92477f6e563a568f5173"
        )
    );
    assert_eq!(
        hex::encode(Sha256::digest(binding.metainfo_bytes())),
        "773b5bc36cabe96e2477dce436e68435bbdd9fb7233944c84afc6b717f536190"
    );
    assert!(binding.metainfo_bytes().ends_with(b"12:piece layersdee"));
    let proof = binding.chunk_proof(0).unwrap();
    assert_eq!(proof.encode().len(), PROOF_HEADER_BYTES);
    binding.verify_chunk(&proof, b"abc").unwrap();
    assert!(binding.verify_chunk(&proof, b"abc\0").is_err());
    assert!(binding.verify_chunk(&proof, b"ab").is_err());
    assert!(binding.verify_chunk(&proof, b"abd").is_err());
}

#[test]
fn non_power_of_two_tree_uses_zero_digest_padding_and_omits_padding_in_piece_layer() {
    let bytes = three_leaves();
    let binding = binding(&bytes);
    assert_eq!(
        digest_hex(binding.pieces_root()),
        "f3c9ca846350d432de56330cc6375ce0c80a3a2ad81952a20d3771d88f5f1e1f"
    );
    assert_eq!(
        digest_hex(binding.info_hash()),
        "3c4f8aecfc1b5508e0f6cb3db936fa8488a5b1acade6f81e994f91a295e0399e"
    );
    assert_eq!(
        hex::encode(Sha256::digest(binding.metainfo_bytes())),
        "0afbfbf570b627ca6e8babe6738d6f6823edb2700f8275e5cd83347665958752"
    );
    assert_eq!(binding.metainfo_bytes().len(), 310);
    assert_eq!(binding.chunk_proof(2).unwrap().siblings[0], [0; 32]);
    for (index, chunk) in bytes.chunks(16_384).enumerate() {
        let proof = binding.chunk_proof(index as u32).unwrap();
        let decoded = CellBep52ChunkProofV1::decode(&proof.encode()).unwrap();
        assert_eq!(proof, decoded);
        binding.verify_chunk(&decoded, chunk).unwrap();
    }
}

#[test]
fn wholly_padded_upper_subtrees_are_hashes_of_zero_children_not_zero() {
    let mut bytes: Vec<u8> = (1..5).flat_map(|value| vec![value; 16_384]).collect();
    bytes.extend_from_slice(b"end");
    let binding = binding(&bytes);
    assert_eq!(
        digest_hex(binding.pieces_root()),
        "1b17fc29d810dfc74e9301d8d289ba5d17e2d6eb5b5ca40f7dafcac13838449a"
    );
    assert_eq!(
        digest_hex(binding.info_hash()),
        "90e3dc3799abcc8bd9db963ade56ba291f63dd89a6f4f747f444fc8f764854e5"
    );
    let proof = binding.chunk_proof(4).unwrap();
    assert_eq!(proof.siblings[0], [0; 32]);
    assert_eq!(
        digest_hex(proof.siblings[1]),
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
    );
    binding.verify_chunk(&proof, b"end").unwrap();
    let mut wrong = proof.encode();
    wrong[PROOF_HEADER_BYTES + 32..PROOF_HEADER_BYTES + 64].fill(0);
    assert!(matches!(
        CellBep52ChunkProofV1::decode(&wrong),
        Err(CellErrorV1::Invalid("BEP52 padding subtree"))
    ));
    let mut empty_hash_padding = proof.encode();
    empty_hash_padding[PROOF_HEADER_BYTES..PROOF_HEADER_BYTES + 32]
        .copy_from_slice(&Sha256::digest([]));
    assert!(CellBep52ChunkProofV1::decode(&empty_hash_padding).is_err());
}

#[test]
fn boundary_file_lengths_and_exact_last_piece_lengths_verify() {
    for size in [1, 16_383, 16_384, 16_385, 32_768, 32_769, 65_536, 65_537] {
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let binding = binding(&bytes);
        binding.verify_info_bytes(&binding.info_bytes()).unwrap();
        binding
            .verify_metainfo_bytes(&binding.metainfo_bytes())
            .unwrap();
        binding.verify_magnet(&binding.magnet().encode()).unwrap();
        for (index, chunk) in bytes.chunks(16_384).enumerate() {
            let proof = binding.chunk_proof(index as u32).unwrap();
            binding.verify_chunk(&proof, chunk).unwrap();
            assert!(binding
                .verify_chunk(&proof, &chunk[..chunk.len() - 1])
                .is_err());
        }
        assert!(binding
            .chunk_proof(binding.manifest.chunks().len() as u32)
            .is_err());
        assert!(binding.chunk_proof(u32::MAX).is_err());
    }
}

#[test]
fn full_piece_layers_are_checked_even_when_infohash_is_unchanged() {
    let binding = binding(&three_leaves());
    let good = binding.metainfo_bytes();
    let info = binding.info_bytes();
    binding.verify_metainfo_bytes(&good).unwrap();
    let layer_start = good.len() - 2 - 3 * 32;
    let mut corrupted = good.clone();
    corrupted[layer_start] ^= 1;
    assert_eq!(&corrupted[7..7 + info.len()], info.as_slice());
    assert!(binding.verify_metainfo_bytes(&corrupted).is_err());
    let mut reordered = good.clone();
    let first = reordered[layer_start..layer_start + 32].to_vec();
    let second = reordered[layer_start + 32..layer_start + 64].to_vec();
    reordered[layer_start..layer_start + 32].copy_from_slice(&second);
    reordered[layer_start + 32..layer_start + 64].copy_from_slice(&first);
    assert!(binding.verify_metainfo_bytes(&reordered).is_err());
    let mut missing_layers = b"d4:info".to_vec();
    missing_layers.extend(info);
    missing_layers.push(b'e');
    assert!(binding.verify_metainfo_bytes(&missing_layers).is_err());
    for end in 0..good.len() {
        assert!(binding.verify_metainfo_bytes(&good[..end]).is_err());
    }
    let mut extra = good;
    extra.push(0);
    assert!(binding.verify_metainfo_bytes(&extra).is_err());
}

#[test]
fn alternate_bencoding_path_names_codecs_and_overlarge_metadata_fail_closed() {
    let binding = binding(b"abc");
    let info = binding.info_bytes();
    for end in 0..info.len() {
        assert!(binding.verify_info_bytes(&info[..end]).is_err());
    }
    for (before, after) in [
        (b"i3e".as_slice(), b"i03e".as_slice()),
        (b"8:cell.bin".as_slice(), b"8:../x.bin".as_slice()),
        (b"versioni2e".as_slice(), b"versioni1e".as_slice()),
    ] {
        let offset = info
            .windows(before.len())
            .position(|w| w == before)
            .unwrap();
        let mut mutated = info.clone();
        mutated.splice(offset..offset + before.len(), after.iter().copied());
        assert!(binding.verify_info_bytes(&mutated).is_err());
    }
    let mut extra = info;
    extra.extend_from_slice(b"junk");
    assert!(binding.verify_info_bytes(&extra).is_err());
    assert!(binding
        .verify_info_bytes(&[0; MAX_CELL_BEP52_INFO_BYTES_V1 + 1])
        .is_err());
    assert!(binding
        .verify_metainfo_bytes(&vec![0; MAX_CELL_BEP52_METAINFO_BYTES_V1 + 1])
        .is_err());
    assert!(binding
        .verify_info_bytes(&binding.manifest.encode())
        .is_err());
}

#[test]
fn a_valid_external_hash_never_replaces_the_internal_manifest_or_context_pin() {
    let a = manifest(b"abc", 16_384, context());
    let mut other_context = context();
    other_context.parent = [7; 32];
    let b = manifest(b"abc", 16_384, other_context.clone());
    let ba = CellBep52BindingV1::from_pinned_manifest(&a, a.id(), &context()).unwrap();
    let bb = CellBep52BindingV1::from_pinned_manifest(&b, b.id(), &other_context).unwrap();
    assert_eq!(ba.info_hash(), bb.info_hash());
    assert_ne!(ba.manifest_id(), bb.manifest_id());
    assert!(CellBep52BindingV1::from_pinned_manifest(&b, a.id(), &other_context).is_err());
    assert!(CellBep52BindingV1::from_pinned_manifest(&b, b.id(), &context()).is_err());
    assert!(CellBep52BindingV1::from_pinned_manifest(&a, a.payload_sha256(), &context()).is_err());
    assert!(CellBep52BindingV1::from_pinned_manifest(&a, ba.info_hash(), &context()).is_err());
    assert!(bb
        .verify_chunk(&ba.chunk_proof(0).unwrap(), b"abc")
        .is_err());
    assert!(ba
        .verify_magnet(&binding(b"abd").magnet().encode())
        .is_err());
}

#[test]
fn magnet_profile_rejects_ambiguous_topics_and_network_parameter_injection() {
    let binding = binding(b"abc");
    let uri = binding.magnet().encode();
    assert_eq!(CellBep52MagnetV1::parse(&uri).unwrap(), binding.magnet());
    assert_eq!(
        CellBep52MagnetV1::parse(&uri).unwrap().info_hash(),
        binding.info_hash()
    );
    let malformed = [
        String::new(),
        uri.to_uppercase(),
        uri.replace("xt=", "%78t="),
        uri.replace("urn:", "urn%3a"),
        uri.replace("1220", "1320"),
        uri.replace("1220", "1221"),
        uri.replace("btmh:1220", "btih:"),
        format!("{uri}&xt=urn:btmh:1220{}", "0".repeat(64)),
        format!("{uri}&tr=http://127.0.0.1:1/"),
        format!("{uri}&x.pe=127.0.0.1:1"),
        format!("{uri}&dn=cell.bin"),
        format!("{uri}#fragment"),
        format!("{uri}\n"),
        format!("{uri}%00"),
        format!("{MAGNET_PREFIX}{}", "é".repeat(32)),
        format!("{MAGNET_PREFIX}{}", "0".repeat(65)),
        format!("{MAGNET_PREFIX}{}", "0".repeat(63)),
        format!("{MAGNET_PREFIX}{}", "f".repeat(1_000_000)),
    ];
    for value in malformed {
        assert!(CellBep52MagnetV1::parse(&value).is_err());
        assert!(binding.verify_magnet(&value).is_err());
    }
    let syntactic_only = format!("{MAGNET_PREFIX}{}", "0".repeat(64));
    assert!(CellBep52MagnetV1::parse(&syntactic_only).is_ok());
    assert!(binding.verify_magnet(&syntactic_only).is_err());
}

#[test]
fn truncated_extra_and_hostile_proof_shapes_are_rejected_before_indexing() {
    let binding = binding(&three_leaves());
    let encoded = binding.chunk_proof(2).unwrap().encode();
    for end in 0..encoded.len() {
        assert!(CellBep52ChunkProofV1::decode(&encoded[..end]).is_err());
    }
    let mut extra = encoded.clone();
    extra.extend_from_slice(&[0; 32]);
    assert!(CellBep52ChunkProofV1::decode(&extra).is_err());
    for count in [0, 16_385, u32::MAX] {
        let mut hostile = encoded.clone();
        hostile[72..76].copy_from_slice(&count.to_be_bytes());
        assert!(CellBep52ChunkProofV1::decode(&hostile).is_err());
    }
    for index in [3, u32::MAX] {
        let mut hostile = encoded.clone();
        hostile[68..72].copy_from_slice(&index.to_be_bytes());
        assert!(CellBep52ChunkProofV1::decode(&hostile).is_err());
    }
    let mut extra_depth = encoded;
    extra_depth[76] = u8::MAX;
    assert!(CellBep52ChunkProofV1::decode(&extra_depth).is_err());
    assert!(CellBep52ChunkProofV1::decode(&[0; MAX_CELL_BEP52_PROOF_BYTES_V1 + 1]).is_err());
}

#[test]
fn reordered_chunks_cross_index_replays_and_every_single_byte_proof_corruption_fail() {
    let bytes: Vec<u8> = (1..5).flat_map(|value| vec![value; 16_384]).collect();
    let binding = binding(&bytes);
    let proof = binding.chunk_proof(0).unwrap();
    let chunk = &bytes[..16_384];
    assert!(binding
        .verify_chunk(&proof, &bytes[16_384..32_768])
        .is_err());
    let mut changed = proof.encode();
    changed[68..72].copy_from_slice(&1_u32.to_be_bytes());
    let changed = CellBep52ChunkProofV1::decode(&changed).unwrap();
    assert!(binding
        .verify_chunk(&changed, &bytes[16_384..32_768])
        .is_err());
    for offset in 0..proof.encode().len() {
        let mut corrupted = proof.encode();
        corrupted[offset] ^= 1;
        if let Ok(decoded) = CellBep52ChunkProofV1::decode(&corrupted) {
            assert!(
                binding.verify_chunk(&decoded, chunk).is_err(),
                "offset {offset}"
            );
        }
    }
    let mut corrupted_chunk = chunk.to_vec();
    let middle = corrupted_chunk.len() / 2;
    corrupted_chunk[middle] ^= 1;
    assert!(binding.verify_chunk(&proof, &corrupted_chunk).is_err());
}

#[test]
fn larger_chunks_and_empty_cells_are_explicitly_outside_this_profile() {
    for chunk_bytes in [32_768, 4 * 1024 * 1024] {
        let manifest = manifest(b"abc", chunk_bytes, context());
        assert!(matches!(
            CellBep52BindingV1::from_pinned_manifest(&manifest, manifest.id(), &context()),
            Err(CellErrorV1::Invalid("BEP52 requires 16 KiB TCM1 chunks"))
        ));
    }
    assert!(CellManifestV1::new(context(), 0, Sha256::digest([]).into(), 16_384, vec![]).is_err());
    let binding = binding(b"abc");
    // Empty files are legal in BEP 52 in general, but cannot be a TCM1 Cell.
    let empty_info = b"d9:file treed8:cell.bind0:d6:lengthi0eeee12:meta versioni2e4:name8:cell.bin12:piece lengthi16384ee";
    assert!(binding.verify_info_bytes(empty_info).is_err());
}

#[test]
fn maximum_declared_tree_has_bounded_metadata_and_fourteen_sibling_proof() {
    // A structural declaration fixture; it does not claim the full payload was
    // materialized or that this arbitrary full-payload SHA-256 was verified.
    let chunk = vec![7; 16_384];
    let declared = CellManifestV1::new(
        context(),
        MAX_CELL_BEP52_LEAVES_V1 as u64 * 16_384,
        [9; 32],
        16_384,
        vec![
            CellChunkV1 {
                size: 16_384,
                sha256: Sha256::digest(&chunk).into()
            };
            MAX_CELL_BEP52_LEAVES_V1
        ],
    )
    .unwrap();
    let binding =
        CellBep52BindingV1::from_pinned_manifest(&declared, declared.id(), &context()).unwrap();
    assert!(binding.info_bytes().len() <= MAX_CELL_BEP52_INFO_BYTES_V1);
    assert!(binding.metainfo_bytes().len() <= MAX_CELL_BEP52_METAINFO_BYTES_V1);
    assert_eq!(
        binding.levels.iter().map(Vec::len).sum::<usize>(),
        2 * 16_384 - 1
    );
    let proof = binding.chunk_proof(16_383).unwrap();
    assert_eq!(proof.siblings.len(), 14);
    assert_eq!(proof.encode().len(), MAX_CELL_BEP52_PROOF_BYTES_V1);
    binding
        .verify_chunk(
            &CellBep52ChunkProofV1::decode(&proof.encode()).unwrap(),
            &chunk,
        )
        .unwrap();
}

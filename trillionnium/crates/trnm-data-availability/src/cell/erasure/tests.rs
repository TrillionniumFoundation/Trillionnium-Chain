use super::*;
use crate::cell::digest_hex;

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "rs46-test-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn manifest(bytes: &[u8], context: CellContextV1) -> CellManifestV1 {
    let hash = Sha256::digest(bytes).into();
    CellManifestV1::new(
        context,
        bytes.len() as u64,
        hash,
        MAX_CHUNK_BYTES,
        vec![CellChunkV1 {
            size: bytes.len() as u32,
            sha256: hash,
        }],
    )
    .unwrap()
}

fn binding(bytes: &[u8]) -> CellRs46ChunkBindingV1 {
    let manifest = manifest(bytes, context());
    CellRs46ChunkBindingV1::from_pinned_manifest(&manifest, manifest.id(), &context(), 0).unwrap()
}

fn select(shards: &[CellRs46ShardV1; 6], indices: &[usize]) -> Vec<CellRs46ShardV1> {
    indices.iter().map(|index| shards[*index].clone()).collect()
}

// Polynomial long division, independent of production's shift/reduce loop.
fn reference_mul(a: u8, b: u8) -> u8 {
    let mut polynomial = 0_u16;
    for bit in 0..8 {
        if (b >> bit) & 1 != 0 {
            polynomial ^= u16::from(a) << bit;
        }
    }
    for degree in (8..=14).rev() {
        if (polynomial >> degree) & 1 != 0 {
            polynomial ^= 0x11d_u16 << (degree - 8);
        }
    }
    polynomial as u8
}

#[test]
fn every_field_product_matches_independent_polynomial_division() {
    for a in 0..=u8::MAX {
        for b in 0..=u8::MAX {
            assert_eq!(gf_mul(a, b), reference_mul(a, b));
        }
        if a != 0 {
            assert_eq!(gf_mul(a, gf_pow(a, 254)), 1);
        }
    }
    assert_eq!(gf_mul(0x57, 0x83), 0x31);
}

#[test]
fn exact_systematic_and_partial_shard_vectors_and_crs1_identity() {
    // Python polynomial arithmetic + separately constructed TCM1/CRS1 bytes.
    let pin = binding(&[1, 2, 3, 4]);
    let shards = pin.encode_chunk(&[1, 2, 3, 4]).unwrap();
    assert_eq!(
        shards.each_ref().map(|s| s.payload()[0]),
        [1, 2, 3, 4, 0x45, 0x5e]
    );
    assert_eq!(
        digest_hex(pin.manifest_id()),
        "a58a797159f1411bd6b08afd69729812647137897c0ae9aaf30c7c773d5c8496"
    );
    assert_eq!(
        hex::encode(shards[4].encode()),
        concat!(
            "43525331a58a797159f1411bd6b08afd69729812647137897c0ae9aaf30c7c773d5c8496",
            "00000000000000049f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
            "040000000145"
        )
    );
    assert_eq!(
        digest_hex(shards[4].id()),
        "0524d4b2be21cb4fb0fc6b7355da7aaabca5cb55b97e66ec91c6226ed1707970"
    );
    let partial = binding(b"abcde").encode_chunk(b"abcde").unwrap();
    assert_eq!(
        partial.each_ref().map(|s| hex::encode(s.payload())),
        ["6162", "6364", "6500", "0000", "d67b", "9b69"]
    );
    for shard in shards {
        assert_eq!(CellRs46ShardV1::decode(&shard.encode()).unwrap(), shard);
    }
}

#[test]
fn all_fifteen_four_shard_subsets_restore_real_non_aligned_chunk() {
    let bytes: Vec<u8> = (0..16_401).map(|i| (i % 251) as u8).collect();
    let binding = binding(&bytes);
    let shards = binding.encode_chunk(&bytes).unwrap();
    let mut subsets = 0;
    for a in 0..3 {
        for b in a + 1..4 {
            for c in b + 1..5 {
                for d in c + 1..6 {
                    let selected = select(&shards, &[a, b, c, d]);
                    assert_eq!(binding.recover_chunk(&selected).unwrap(), bytes);
                    subsets += 1;
                }
            }
        }
    }
    assert_eq!(subsets, 15);
    for omitted in 0..6 {
        let selected = select(
            &shards,
            &(0..6).filter(|i| *i != omitted).collect::<Vec<_>>(),
        );
        assert_eq!(binding.recover_chunk(&selected).unwrap(), bytes);
    }
    assert_eq!(binding.recover_chunk(&shards).unwrap(), bytes);
}

#[test]
fn insufficient_duplicate_and_reordered_shards_are_not_silently_reinterpreted() {
    let binding = binding(b"abcde");
    let shards = binding.encode_chunk(b"abcde").unwrap();
    for count in 0..4 {
        assert!(binding.recover_chunk(&shards[..count]).is_err());
    }
    assert!(binding
        .recover_chunk(&select(&shards, &[0, 1, 2, 2]))
        .is_err());
    assert!(binding
        .recover_chunk(&select(&shards, &[3, 2, 1, 0]))
        .is_err());
    assert!(binding
        .recover_chunk(&select(&shards, &[0, 2, 1, 5]))
        .is_err());
    assert!(binding
        .recover_chunk(&select(&shards, &[0, 1, 2, 3, 4, 5, 5]))
        .is_err());
}

#[test]
fn corrupted_required_or_extra_shards_never_return_verified_source_bytes() {
    let bytes = b"a real chunk with a partial shard";
    let binding = binding(bytes);
    let shards = binding.encode_chunk(bytes).unwrap();
    for index in 0..6 {
        let mut corrupted = shards.clone();
        corrupted[index].bytes[0] ^= 1;
        assert!(binding.recover_chunk(&corrupted).is_err(), "index {index}");
        assert_ne!(corrupted[index].id(), shards[index].id());
        // Shape decoding deliberately does not authenticate shard content.
        assert!(CellRs46ShardV1::decode(&corrupted[index].encode()).is_ok());
    }
    let mut extra = shards.clone();
    extra[5].bytes[0] ^= 1;
    assert!(matches!(
        binding.recover_chunk(&extra),
        Err(CellErrorV1::Invalid("RS46 inconsistent extra shard"))
    ));
}

#[test]
fn nonzero_padding_is_rejected_even_when_original_payload_hash_would_match() {
    let binding = binding(b"x");
    let mut shards = binding.encode_chunk(b"x").unwrap();
    shards[3].bytes[0] = 1;
    let data: [&[u8]; 4] = std::array::from_fn(|index| shards[index].payload());
    let parity4 = apply_row(GENERATOR[4], data);
    let parity5 = apply_row(GENERATOR[5], data);
    shards[4].bytes = parity4;
    shards[5].bytes = parity5;
    assert!(matches!(
        binding.recover_chunk(&shards),
        Err(CellErrorV1::Invalid("RS46 zero padding"))
    ));
}

#[test]
fn internal_context_object_and_chunk_pins_cannot_be_replaced_by_shard_headers() {
    let original = manifest(b"abcde", context());
    let binding =
        CellRs46ChunkBindingV1::from_pinned_manifest(&original, original.id(), &context(), 0)
            .unwrap();
    assert!(CellRs46ChunkBindingV1::from_pinned_manifest(
        &original,
        original.payload_sha256(),
        &context(),
        0
    )
    .is_err());
    assert!(
        CellRs46ChunkBindingV1::from_pinned_manifest(&original, original.id(), &context(), 1)
            .is_err()
    );
    assert!(CellRs46ChunkBindingV1::from_pinned_manifest(
        &original,
        original.id(),
        &context(),
        u32::MAX
    )
    .is_err());
    let mut changed_context = context();
    changed_context.runtime = [8; 32];
    assert!(CellRs46ChunkBindingV1::from_pinned_manifest(
        &original,
        original.id(),
        &changed_context,
        0
    )
    .is_err());
    let other_manifest = manifest(b"abcde", changed_context.clone());
    let other = CellRs46ChunkBindingV1::from_pinned_manifest(
        &other_manifest,
        other_manifest.id(),
        &changed_context,
        0,
    )
    .unwrap();
    let foreign = other.encode_chunk(b"abcde").unwrap();
    assert!(binding.recover_chunk(&foreign).is_err());
    let mut different_index = binding.encode_chunk(b"abcde").unwrap();
    different_index[0].chunk_index = 1;
    assert!(binding.recover_chunk(&different_index).is_err());
    let mut different_hash = binding.encode_chunk(b"abcde").unwrap();
    different_hash[0].source_sha256[0] ^= 1;
    assert!(binding.recover_chunk(&different_hash).is_err());
}

#[test]
fn every_single_byte_wire_mutation_is_rejected_by_shape_or_pinned_recovery() {
    let bytes = [1, 2, 3, 4];
    let binding = binding(&bytes);
    let shards = binding.encode_chunk(&bytes).unwrap();
    let original = shards[4].encode();
    for offset in 0..original.len() {
        let mut corrupted = original.clone();
        corrupted[offset] ^= 1;
        if let Ok(decoded) = CellRs46ShardV1::decode(&corrupted) {
            let mut selected = select(&shards, &[0, 1, 2]);
            selected.push(decoded);
            assert!(binding.recover_chunk(&selected).is_err(), "offset {offset}");
        }
    }
}

#[test]
fn truncated_extra_oversized_and_hostile_headers_refuse_before_payload_copy() {
    let wire = binding(b"abcde").encode_chunk(b"abcde").unwrap()[0].encode();
    for end in 0..wire.len() {
        assert!(CellRs46ShardV1::decode(&wire[..end]).is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(CellRs46ShardV1::decode(&extra).is_err());
    assert!(CellRs46ShardV1::decode(&vec![0; MAX_CELL_RS46_SHARD_WIRE_BYTES_V1 + 1]).is_err());
    for source_size in [0, MAX_CHUNK_BYTES + 1, u32::MAX] {
        let mut bad = wire.clone();
        bad[40..44].copy_from_slice(&source_size.to_be_bytes());
        assert!(CellRs46ShardV1::decode(&bad).is_err());
    }
    for shard_size in [0, MAX_CELL_RS46_SHARD_BYTES_V1 as u32 + 1, u32::MAX] {
        let mut bad = wire.clone();
        bad[77..81].copy_from_slice(&shard_size.to_be_bytes());
        assert!(CellRs46ShardV1::decode(&bad).is_err());
    }
    for index in [6, u8::MAX] {
        let mut bad = wire.clone();
        bad[76] = index;
        assert!(CellRs46ShardV1::decode(&bad).is_err());
    }
    for index in [MAX_CHUNK_INDEX + 1, u32::MAX] {
        let mut bad = wire.clone();
        bad[36..40].copy_from_slice(&index.to_be_bytes());
        assert!(CellRs46ShardV1::decode(&bad).is_err());
    }
    for magic in [b"CRS2", b"CBP1", b"TCM1"] {
        let mut bad = wire.clone();
        bad[..4].copy_from_slice(magic);
        assert!(CellRs46ShardV1::decode(&bad).is_err());
    }
}

#[test]
fn all_padding_remainders_and_short_sources_are_reconstructed_exactly() {
    for length in 1_usize..=20 {
        let bytes: Vec<u8> = (1..=length as u8).collect();
        let binding = binding(&bytes);
        let shards = binding.encode_chunk(&bytes).unwrap();
        assert_eq!(binding.source_bytes(), length as u32);
        assert_eq!(binding.shard_bytes(), length.div_ceil(4));
        assert_eq!(
            binding
                .recover_chunk(&select(&shards, &[2, 3, 4, 5]))
                .unwrap(),
            bytes
        );
        assert!(binding.encode_chunk(&bytes[..bytes.len() - 1]).is_err());
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(binding.encode_chunk(&bad).is_err());
    }
}

#[test]
fn full_four_mebibyte_chunk_recovers_with_two_missing_systematic_shards() {
    let bytes: Vec<u8> = (0..MAX_CHUNK_BYTES as usize)
        .map(|i| ((i.wrapping_mul(17) + i / 65_536) % 251) as u8)
        .collect();
    let binding = binding(&bytes);
    let shards = binding.encode_chunk(&bytes).unwrap();
    assert!(shards
        .iter()
        .all(|s| s.payload().len() == MAX_CELL_RS46_SHARD_BYTES_V1));
    assert_eq!(shards[0].encode().len(), MAX_CELL_RS46_SHARD_WIRE_BYTES_V1);
    assert_eq!(
        binding
            .recover_chunk(&select(&shards, &[2, 3, 4, 5]))
            .unwrap(),
        bytes
    );
    let mut too_long = bytes;
    too_long.push(0);
    assert!(binding.encode_chunk(&too_long).is_err());
}

#[test]
fn singular_matrix_is_an_error_and_does_not_claim_recovery() {
    assert!(matches!(
        invert([[0; 4]; 4]),
        Err(CellErrorV1::Invalid("RS46 singular matrix"))
    ));
    let identity: [[u8; 4]; 4] =
        std::array::from_fn(|row| std::array::from_fn(|col| u8::from(row == col)));
    assert_eq!(invert(identity).unwrap(), identity);
}

// Sole selected cfg(test) child of original, copied retrieval.rs.
use super::*;
use crate::DaAuthorAuthorityV1;
use std::fs::OpenOptions;
use std::io::{self, Write};

const MARKER: &str = "TRNM_DA_BOUND_INCLUSION_COMPARATOR_V1";
const PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
fn digest(b: u8) -> Hash32V1 {
    Hash32V1::new([b; 32])
}
fn fixture(width: u32, chunk_size: u32) -> UnsignedTransactionBatchV1 {
    let author = b"1".to_vec();
    let context = ProtocolContextV1::new(digest(1), "x", digest(2)).unwrap();
    let cap = 2_097_152;
    let member = DaMemberV1::new(PUBLIC, 1, None, digest(3), digest(4)).unwrap();
    let committee = DaCommitteeDescriptorV1::new_transaction_batch(
        context, 7, vec![member], 2, cap, cap, 32, 4,
    ).unwrap();
    let authority = DaAuthorAuthorityV1::new(author.clone(), PUBLIC, 1, 4, cap, 4).unwrap();
    let policy = DaPolicyV1::new_transaction_batch(
        &committee, vec![authority], chunk_size, 512, 4, cap, 50, 20,
    ).unwrap();
    let bytes = (0..(width as usize * chunk_size as usize - 8))
        .map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let batch = UnsignedTransactionBatchV1::build(&committee, &policy, author, 1, vec![bytes]).unwrap();
    assert_eq!(batch.envelope().chunk_count(), width);
    batch
}

fn emit(
    out: &mut impl Write, coordinates: &DaChunkCoordinateV1, payload: &[u8],
    path: &DaChunkInclusionProofV1, root: Hash32V1, expect: u8,
) -> io::Result<()> {
    let original = DaChunkV1::new(coordinates.clone(), payload.to_vec());
    let status = match original {
        Ok(chunk) => {
            assert_eq!(chunk.index(), path.global_chunk_index);
            let leaf = chunk_leaf_v1(&chunk).unwrap();
            match verify_merkle_path_v1(leaf, path, root) {
                Ok(()) => 0,
                Err(e) => match (e.code(), e.message()) {
                    (DaErrorCodeV1::InvalidRange, "chunk proof coordinate is out of bounds") => 50,
                    (DaErrorCodeV1::InvalidRange, "chunk proof path is truncated") => 51,
                    (DaErrorCodeV1::InvalidRange, "chunk proof level/side is non-canonical") => 52,
                    (DaErrorCodeV1::InvalidRange, "chunk proof violates duplicate-final rule") => 53,
                    (DaErrorCodeV1::InvalidRange, "chunk proof path has trailing steps") => 54,
                    (DaErrorCodeV1::IdentifierMismatch, "chunk proof root differs from certified envelope") => 55,
                    other => panic!("unexpected private original observation: {other:?}"),
                },
            }
        }
        Err(e) => {
            assert_eq!(e.code(), DaErrorCodeV1::InvalidBounds);
            assert_eq!(e.message(), "chunk bytes/coordinate length mismatch");
            6
        }
    };
    assert_eq!(status, expect);
    let mut frame = vec![0; 32];
    frame[..4].copy_from_slice(b"HCD1");
    frame.extend(root.as_bytes());
    frame.extend(borsh::to_vec(path).unwrap());
    frame.extend(borsh::to_vec(coordinates).unwrap());
    frame.extend(borsh::to_vec(&payload.to_vec()).unwrap());
    out.write_all(&[status])?;
    out.write_all(&(frame.len() as u32).to_le_bytes())?;
    out.write_all(&frame)?;
    Ok(())
}

#[test]
fn original_bound_chunk_observe() {
    let path = std::env::var_os("TRNM_DA_PRIVATE_PATH_FIXTURE").expect("private capture path");
    let mut out = OpenOptions::new().write(true).create_new(true).open(path).unwrap();
    out.write_all(MARKER.as_bytes()).unwrap();
    for (width, size) in [(1, 32), (2, 32), (3, 32), (5, 32), (7, 32), (1, 1_048_321), (1, 1_048_322)] {
        let batch = fixture(width, size);
        let leaves = batch.chunks().iter().map(chunk_leaf_v1).collect::<DaResultV1<Vec<_>>>().unwrap();
        let root = batch.envelope().chunk_root();
        for (i, chunk) in batch.chunks().iter().enumerate() {
            let path = DaChunkInclusionProofV1 {
                global_chunk_index: i as u32,
                chunk_item_count: width,
                merkle_path: merkle_path_v1(&leaves, i as u32).unwrap(),
            };
            let coordinate = chunk.coordinate();
            let payload = chunk.bytes();
            emit(&mut out, coordinate, payload, &path, root, 0).unwrap();
            if width == 2 && i == 0 {
                let mut changed = payload.to_vec();
                changed[7] ^= 1;
                emit(&mut out, coordinate, &changed, &path, root, 55).unwrap();
                emit(&mut out, coordinate, &[], &path, root, 6).unwrap();
                emit(&mut out, coordinate, &payload[..payload.len()-1], &path, root, 6).unwrap();
                let mut bad = path.clone();
                bad.chunk_item_count = 0;
                emit(&mut out, coordinate, payload, &bad, root, 50).unwrap();
                bad = path.clone();
                bad.merkle_path.clear();
                emit(&mut out, coordinate, payload, &bad, root, 51).unwrap();
                bad = path.clone();
                bad.merkle_path[0].level = 1;
                emit(&mut out, coordinate, payload, &bad, root, 52).unwrap();
                bad = path.clone();
                bad.merkle_path.push(path.merkle_path[0]);
                emit(&mut out, coordinate, payload, &bad, digest(0), 54).unwrap();
                emit(&mut out, coordinate, payload, &path, digest(0), 55).unwrap();
            }
            if width == 3 && i == 2 {
                let mut bad = path.clone();
                bad.merkle_path[0].sibling_hash = digest(0);
                emit(&mut out, coordinate, payload, &bad, root, 53).unwrap();
            }
        }
    }
}

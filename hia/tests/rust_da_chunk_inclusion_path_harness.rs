// Test-only child of the copied original retrieval module. No proof signer,
// authority checker, DB, or exported API is present in this harness.
use super::*;
use crate::{DaAuthorAuthorityV1, DaMemberV1};
use std::fs::OpenOptions;
use std::io::{self, Write};

const MARKER: &str = "TRNM_DA_MERKLE_COMPARATOR_HARNESS_V1";
const PUBLIC: [u8;32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
fn digest(b: u8) -> Hash32V1 { Hash32V1::new([b;32]) }

fn fixture(chunks: u32) -> UnsignedTransactionBatchV1 {
    let id = b"read-only DA comparator".to_vec();
    let context = ProtocolContextV1::new(digest(1), "local-merkle-comparator", digest(2)).unwrap();
    let member = DaMemberV1::new(PUBLIC, 1, None, digest(3), digest(4)).unwrap();
    let committee = DaCommitteeDescriptorV1::new_transaction_batch(context, 7, vec![member], 2, 8192, 4096, 32, 4).unwrap();
    let authority = DaAuthorAuthorityV1::new(id.clone(), PUBLIC, 1, 4, 8192, 4).unwrap();
    let policy = DaPolicyV1::new_transaction_batch(&committee, vec![authority], 32, 256, 4, 16384, 50, 20).unwrap();
    let bytes = (0..(chunks as usize * 32 - 8)).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let batch = UnsignedTransactionBatchV1::build(&committee, &policy, id, 1, vec![bytes]).unwrap();
    assert_eq!(batch.envelope().chunk_count(), chunks);
    batch
}

fn observe(out: &mut impl Write, leaf: Hash32V1, proof: &DaChunkInclusionProofV1,
           root: Hash32V1, expect: u8) -> io::Result<()> {
    let code = match verify_merkle_path_v1(leaf, proof, root) {
        Ok(()) => 0,
        Err(e) => match (e.code(), e.message()) {
            (DaErrorCodeV1::InvalidRange, "chunk proof coordinate is out of bounds") => 50,
            (DaErrorCodeV1::InvalidRange, "chunk proof path is truncated") => 51,
            (DaErrorCodeV1::InvalidRange, "chunk proof level/side is non-canonical") => 52,
            (DaErrorCodeV1::InvalidRange, "chunk proof violates duplicate-final rule") => 53,
            (DaErrorCodeV1::InvalidRange, "chunk proof path has trailing steps") => 54,
            (DaErrorCodeV1::IdentifierMismatch, "chunk proof root differs from certified envelope") => 55,
            other => panic!("unexpected original Merkle comparison: {other:?}"),
        }
    };
    assert_eq!(code, expect);
    let encoded = borsh::to_vec(proof).unwrap();
    assert_eq!(borsh::from_slice::<DaChunkInclusionProofV1>(&encoded).unwrap(), *proof);
    out.write_all(&[code])?;
    out.write_all(&((64 + encoded.len()) as u32).to_le_bytes())?;
    out.write_all(leaf.as_bytes())?;
    out.write_all(root.as_bytes())?;
    out.write_all(&encoded)?;
    Ok(())
}

#[test]
fn original_private_path_observe() {
    let target = std::env::var_os("TRNM_DA_PRIVATE_PATH_FIXTURE").expect("private capture path");
    let mut out = OpenOptions::new().write(true).create_new(true).open(target).unwrap();
    out.write_all(MARKER.as_bytes()).unwrap();
    for width in [1, 2, 3, 4, 5, 7, 9] {
        let batch = fixture(width);
        let leaves = batch.chunks().iter().map(chunk_leaf_v1).collect::<DaResultV1<Vec<_>>>().unwrap();
        let root = batch.envelope().chunk_root();
        for index in 0..width {
            let path = merkle_path_v1(&leaves, index).unwrap();
            let proof = DaChunkInclusionProofV1 {
                global_chunk_index: index, chunk_item_count: width, merkle_path: path,
            };
            let leaf = leaves[index as usize];
            observe(&mut out, leaf, &proof, root, 0).unwrap();
            if width == 3 && index == 2 {
                let mut bad = proof.clone();
                bad.chunk_item_count = 0;
                observe(&mut out, leaf, &bad, root, 50).unwrap();
                bad.chunk_item_count = 2;
                observe(&mut out, leaf, &bad, root, 50).unwrap();
                bad.chunk_item_count = u32::MAX;
                bad.merkle_path.clear();
                observe(&mut out, leaf, &bad, root, 51).unwrap();
                bad = proof.clone();
                bad.merkle_path.pop();
                observe(&mut out, leaf, &bad, root, 51).unwrap();
                bad = proof.clone();
                bad.merkle_path[0].level = 1;
                bad.merkle_path[0].sibling_hash = digest(0);
                observe(&mut out, leaf, &bad, root, 52).unwrap();
                bad.merkle_path[0].level = 0;
                bad.merkle_path[0].sibling_side = 0;
                observe(&mut out, leaf, &bad, root, 52).unwrap();
                bad.merkle_path[0].sibling_side = 1;
                observe(&mut out, leaf, &bad, root, 53).unwrap();
                bad = proof.clone();
                bad.merkle_path.push(proof.merkle_path[0]);
                observe(&mut out, leaf, &bad, digest(0), 54).unwrap();
                observe(&mut out, leaf, &proof, digest(0), 55).unwrap();
                observe(&mut out, digest(0), &proof, root, 53).unwrap();
            }
        }
    }
}

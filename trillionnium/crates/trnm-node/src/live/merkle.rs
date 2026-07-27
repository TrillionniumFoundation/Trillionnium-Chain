use anyhow::{ensure, Result};

use super::crypto::{decode_hash32, hash_domain, Hash32};
use super::protocol::{MerkleProofStepV1, MerkleProofV1};

pub fn empty_root(tree_domain: &str) -> Hash32 {
    hash_domain("trnm.merkle.empty.v1", &[tree_domain.as_bytes()])
}

fn parent(tree_domain: &str, left: &Hash32, right: &Hash32) -> Hash32 {
    hash_domain(
        "trnm.merkle.parent.v1",
        &[tree_domain.as_bytes(), left, right],
    )
}

pub fn root_and_proofs(tree_domain: &str, leaves: &[Hash32]) -> (Hash32, Vec<MerkleProofV1>) {
    if leaves.is_empty() {
        return (empty_root(tree_domain), Vec::new());
    }

    let mut levels = vec![leaves.to_vec()];
    while levels.last().expect("non-empty levels").len() > 1 {
        let current = levels.last().expect("current level");
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(parent(tree_domain, &left, &right));
        }
        levels.push(next);
    }

    let root = levels.last().expect("root level")[0];
    let mut proofs = Vec::with_capacity(leaves.len());
    for (leaf_index, leaf) in leaves.iter().enumerate() {
        let mut index = leaf_index;
        let mut steps = Vec::new();
        for level in levels.iter().take(levels.len() - 1) {
            let sibling_index = if index % 2 == 0 {
                (index + 1).min(level.len() - 1)
            } else {
                index - 1
            };
            steps.push(MerkleProofStepV1 {
                sibling_hash_hex: hex::encode(level[sibling_index]),
                sibling_on_left: index % 2 == 1,
            });
            index /= 2;
        }
        proofs.push(MerkleProofV1 {
            tree_domain: tree_domain.to_string(),
            leaf_hash_hex: hex::encode(leaf),
            leaf_index: leaf_index as u64,
            leaf_count: leaves.len() as u64,
            steps,
        });
    }
    (root, proofs)
}

pub fn root_only<I>(tree_domain: &str, leaves: I) -> Hash32
where
    I: IntoIterator<Item = Hash32>,
{
    let mut current = leaves.into_iter().collect::<Vec<_>>();
    if current.is_empty() {
        return empty_root(tree_domain);
    }
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(parent(tree_domain, &left, &right));
        }
        current = next;
    }
    current[0]
}

pub fn verify_proof(expected_root: &Hash32, proof: &MerkleProofV1) -> Result<()> {
    ensure!(
        proof.leaf_count > 0,
        "Merkle proof leaf_count must be positive"
    );
    ensure!(
        proof.leaf_index < proof.leaf_count,
        "Merkle proof leaf_index is out of range"
    );
    let mut current = decode_hash32("leaf_hash_hex", &proof.leaf_hash_hex)?;
    for step in &proof.steps {
        let sibling = decode_hash32("sibling_hash_hex", &step.sibling_hash_hex)?;
        current = if step.sibling_on_left {
            parent(&proof.tree_domain, &sibling, &current)
        } else {
            parent(&proof.tree_domain, &current, &sibling)
        };
    }
    ensure!(
        &current == expected_root,
        "Merkle inclusion proof root mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_cover_odd_leaf_counts_and_reject_tamper() {
        let leaves = [
            hash_domain("leaf", &[b"a"]),
            hash_domain("leaf", &[b"b"]),
            hash_domain("leaf", &[b"c"]),
        ];
        let (root, proofs) = root_and_proofs("transactions", &leaves);
        for proof in &proofs {
            verify_proof(&root, proof).unwrap();
        }

        let mut tampered = proofs[1].clone();
        tampered.steps[0].sibling_hash_hex = hex::encode([0u8; 32]);
        assert!(verify_proof(&root, &tampered).is_err());
    }

    #[test]
    fn empty_root_is_domain_separated() {
        assert_ne!(empty_root("transactions"), empty_root("objects"));
    }

    #[test]
    fn root_only_matches_proof_builder_for_empty_even_and_odd_trees() {
        for count in 0..=17 {
            let leaves = (0..count)
                .map(|index| hash_domain("leaf", &[&[index as u8]]))
                .collect::<Vec<_>>();
            assert_eq!(
                root_only("equivalence", leaves.iter().copied()),
                root_and_proofs("equivalence", &leaves).0
            );
        }
    }
}

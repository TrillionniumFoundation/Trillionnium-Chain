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
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
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

pub fn verify_proof(
    expected_root: &Hash32,
    expected_tree_domain: &str,
    proof: &MerkleProofV1,
) -> Result<()> {
    ensure!(
        proof.tree_domain == expected_tree_domain,
        "Merkle proof tree domain mismatch"
    );
    ensure!(
        proof.leaf_count > 0,
        "Merkle proof leaf_count must be positive"
    );
    ensure!(
        proof.leaf_index < proof.leaf_count,
        "Merkle proof leaf_index is out of range"
    );

    let mut current = decode_hash32("leaf_hash_hex", &proof.leaf_hash_hex)?;
    let mut index = proof.leaf_index;
    let mut width = proof.leaf_count;
    let mut steps = proof.steps.iter();
    while width > 1 {
        let step = steps
            .next()
            .ok_or_else(|| anyhow::anyhow!("Merkle proof is missing a required path step"))?;
        let sibling = decode_hash32("sibling_hash_hex", &step.sibling_hash_hex)?;
        let sibling_on_left = index % 2 == 1;
        ensure!(
            step.sibling_on_left == sibling_on_left,
            "Merkle proof path direction conflicts with leaf index"
        );
        let duplicate_last_padding = !sibling_on_left && index == width - 1;
        if duplicate_last_padding {
            ensure!(
                sibling == current,
                "Merkle proof odd-width padding must duplicate the current subtree"
            );
        } else {
            ensure!(
                sibling != current,
                "Merkle proof repeats the current subtree outside canonical padding"
            );
        }
        current = if sibling_on_left {
            parent(expected_tree_domain, &sibling, &current)
        } else {
            parent(expected_tree_domain, &current, &sibling)
        };
        index /= 2;
        width = width.div_ceil(2);
    }
    ensure!(
        steps.next().is_none(),
        "Merkle proof has trailing path steps"
    );
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
            verify_proof(&root, "transactions", proof).unwrap();
        }

        let mut tampered = proofs[1].clone();
        tampered.steps[0].sibling_hash_hex = hex::encode([0u8; 32]);
        assert!(verify_proof(&root, "transactions", &tampered).is_err());
    }

    #[test]
    fn proof_shape_is_derived_from_index_and_count() {
        let leaves = [
            hash_domain("leaf", &[b"a"]),
            hash_domain("leaf", &[b"b"]),
            hash_domain("leaf", &[b"c"]),
        ];
        let (root, proofs) = root_and_proofs("transactions", &leaves);

        let mut wrong_domain = proofs[2].clone();
        wrong_domain.tree_domain = "objects".to_string();
        assert!(verify_proof(&root, "transactions", &wrong_domain).is_err());

        let mut wrong_direction = proofs[2].clone();
        wrong_direction.steps[0].sibling_on_left = true;
        assert!(verify_proof(&root, "transactions", &wrong_direction).is_err());

        let mut missing = proofs[2].clone();
        missing.steps.pop();
        assert!(verify_proof(&root, "transactions", &missing).is_err());

        let mut trailing = proofs[2].clone();
        trailing.steps.push(MerkleProofStepV1 {
            sibling_hash_hex: hex::encode([0x44; 32]),
            sibling_on_left: false,
        });
        assert!(verify_proof(&root, "transactions", &trailing).is_err());
    }

    #[test]
    fn duplicate_last_padding_cannot_be_relabelled_as_a_real_leaf() {
        let leaves = [
            hash_domain("leaf", &[b"a"]),
            hash_domain("leaf", &[b"b"]),
            hash_domain("leaf", &[b"c"]),
        ];
        let (root, proofs) = root_and_proofs("transactions", &leaves);
        let mut relabelled = proofs[2].clone();
        relabelled.leaf_index = 3;
        relabelled.leaf_count = 4;
        relabelled.steps[0].sibling_on_left = true;
        assert!(verify_proof(&root, "transactions", &relabelled).is_err());
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

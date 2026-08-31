//! Minimal, node-independent verification for TRNM finality receipts.

use anyhow::{anyhow, ensure, Result};
use trnm_finality_types::{
    decode_hash32, hash_domain, FinalityReceiptV1, Hash32, MerkleProofV1, ValidatorSetV1,
    FINALITY_RECEIPT_SCHEMA_V1,
};

const TRANSACTION_TREE_DOMAIN_V1: &str = "trnm.transactions.v1";
const STATE_OBJECT_TREE_DOMAIN_V1: &str = "trnm.state.objects.v1";

fn merkle_parent(tree_domain: &str, left: &Hash32, right: &Hash32) -> Hash32 {
    hash_domain(
        "trnm.merkle.parent.v1",
        &[tree_domain.as_bytes(), left, right],
    )
}

/// Verify the canonical duplicate-last Merkle proof used by the v1 receipt
/// format.
///
/// The expected tree domain is supplied by the receipt field being verified;
/// a proof cannot select its own semantic domain. The path direction and exact
/// number of levels are derived from `(leaf_index, leaf_count)`. At an odd
/// right edge the producer duplicates the current subtree, and that duplicate
/// is accepted only at the unique canonical padding position. Conversely, an
/// equal sibling at a non-padding position is rejected so duplicate-last
/// padding cannot be reinterpreted as an additional real leaf.
fn verify_proof(
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

    let mut current = decode_hash32("Merkle proof leaf_hash_hex", &proof.leaf_hash_hex)?;
    let mut index = proof.leaf_index;
    let mut width = proof.leaf_count;
    let mut steps = proof.steps.iter();

    while width > 1 {
        let step = steps
            .next()
            .ok_or_else(|| anyhow!("Merkle proof is missing a required path step"))?;
        let sibling = decode_hash32("Merkle proof sibling_hash_hex", &step.sibling_hash_hex)?;
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
            merkle_parent(expected_tree_domain, &sibling, &current)
        } else {
            merkle_parent(expected_tree_domain, &current, &sibling)
        };
        index /= 2;
        width = width.div_ceil(2);
    }

    ensure!(
        steps.next().is_none(),
        "Merkle proof has trailing path steps"
    );
    ensure!(current == *expected_root, "Merkle proof root mismatch");
    Ok(())
}

pub fn verify_finality_receipt(
    receipt: &FinalityReceiptV1,
    validator_set: &ValidatorSetV1,
) -> Result<()> {
    ensure!(
        receipt.schema == FINALITY_RECEIPT_SCHEMA_V1,
        "unsupported finality receipt schema"
    );
    ensure!(
        receipt.block_header.chain_id == receipt.chain_id,
        "receipt chain_id does not match block header"
    );
    if let Some(fingerprint) = &receipt.domain_command_fingerprint_hex {
        let _ = decode_hash32("domain_command_fingerprint_hex", fingerprint)?;
    }
    receipt.block_header.validate()?;
    ensure!(
        receipt.block_header.height == receipt.block_height,
        "receipt block height does not match header"
    );
    ensure!(
        receipt.block_header.state_root_hex == receipt.state_root_hex,
        "receipt state root does not match header"
    );
    ensure!(
        receipt.block_header.transaction_root_hex == receipt.transaction_root_hex,
        "receipt transaction root does not match header"
    );
    ensure!(
        receipt.block_header.validator_set_id == receipt.validator_set_id,
        "receipt validator_set_id does not match header"
    );
    ensure!(
        hex::encode(receipt.block_header.block_hash()?) == receipt.block_hash_hex,
        "receipt block hash does not match header"
    );
    ensure!(
        receipt.quorum_certificate.height == receipt.block_height
            && receipt.quorum_certificate.block_hash_hex == receipt.block_hash_hex,
        "receipt quorum certificate does not bind the block"
    );
    receipt
        .quorum_certificate
        .verify(&receipt.chain_id, validator_set)?;

    let transaction_leaf = hash_domain(
        "trnm.transaction.leaf.v1",
        &[receipt.transaction_hash_hex.as_bytes()],
    );
    ensure!(
        receipt.transaction_inclusion_proof.leaf_hash_hex == hex::encode(transaction_leaf),
        "transaction inclusion proof leaf does not bind transaction hash"
    );
    ensure!(
        receipt.transaction_inclusion_proof.leaf_index == receipt.transaction_index,
        "transaction inclusion proof index mismatch"
    );
    verify_proof(
        &decode_hash32("transaction_root_hex", &receipt.transaction_root_hex)?,
        TRANSACTION_TREE_DOMAIN_V1,
        &receipt.transaction_inclusion_proof,
    )?;

    match (&receipt.object_ref, &receipt.object_inclusion_proof) {
        (Some(object_ref), Some(proof)) => {
            let leaf = hash_domain(
                "trnm.state.object.leaf.v1",
                &[
                    object_ref.object_key_hex.as_bytes(),
                    object_ref.object_type.as_bytes(),
                    &object_ref.version.to_be_bytes(),
                    object_ref.value_hash_hex.as_bytes(),
                ],
            );
            ensure!(
                proof.leaf_hash_hex == hex::encode(leaf),
                "object inclusion proof leaf does not bind object_ref"
            );
            verify_proof(
                &decode_hash32("state_root_hex", &receipt.state_root_hex)?,
                STATE_OBJECT_TREE_DOMAIN_V1,
                proof,
            )?;
        }
        (None, None) => {}
        _ => return Err(anyhow!("object_ref and object proof presence mismatch")),
    }

    ensure!(
        receipt.receipt_hash_hex == hex::encode(receipt.compute_receipt_hash()?),
        "receipt_hash_hex mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_finality_types::{
        BlockHeaderV1, FinalityReceiptV1, MerkleProofStepV1, MerkleProofV1,
        QuorumCertificateV1, ValidatorDescriptorV1, ValidatorSetV1, ValidatorVoteV1,
        BLOCK_HEADER_SCHEMA_V1, FINALITY_RECEIPT_SCHEMA_V1, VALIDATOR_VOTE_SCHEMA_V1,
    };

    use super::*;

    fn public_key_hex(signing_key: &SigningKey) -> String {
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    fn sign_hex(signing_key: &SigningKey, message: &[u8]) -> String {
        hex::encode(signing_key.sign(message).to_bytes())
    }

    fn proof_fixture(
        tree_domain: &str,
        leaves: &[Hash32],
        leaf_index: usize,
    ) -> (Hash32, MerkleProofV1) {
        assert!(!leaves.is_empty());
        assert!(leaf_index < leaves.len());
        let mut levels = vec![leaves.to_vec()];
        while levels.last().expect("level").len() > 1 {
            let level = levels.last().expect("level");
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                next.push(merkle_parent(tree_domain, &left, &right));
            }
            levels.push(next);
        }

        let mut index = leaf_index;
        let mut steps = Vec::with_capacity(levels.len() - 1);
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

        (
            levels.last().expect("root level")[0],
            MerkleProofV1 {
                tree_domain: tree_domain.to_string(),
                leaf_hash_hex: hex::encode(leaves[leaf_index]),
                leaf_index: leaf_index as u64,
                leaf_count: leaves.len() as u64,
                steps,
            },
        )
    }

    fn fixture() -> (FinalityReceiptV1, ValidatorSetV1) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let validator_set = ValidatorSetV1 {
            validator_set_id: "validators-v1".to_string(),
            validators: vec![ValidatorDescriptorV1 {
                validator_id: "validator-1".to_string(),
                public_key_hex: public_key_hex(&signing_key),
                vote_endpoint: "http://127.0.0.1:39001/v1/vote".to_string(),
                voting_power: 1,
            }],
            quorum_power: 1,
        };
        let transaction_hash_hex = hex::encode(hash_domain("test.transaction.v1", &[b"tx"]));
        let transaction_leaf = hash_domain(
            "trnm.transaction.leaf.v1",
            &[transaction_hash_hex.as_bytes()],
        );
        let transaction_root_hex = hex::encode(transaction_leaf);
        let state_root_hex = hex::encode(hash_domain("test.state.v1", &[b"state"]));
        let header = BlockHeaderV1 {
            schema: BLOCK_HEADER_SCHEMA_V1.to_string(),
            chain_id: "trnm-test-chain".to_string(),
            height: 1,
            previous_block_hash_hex: hex::encode([0u8; 32]),
            transaction_root_hex: transaction_root_hex.clone(),
            state_root_hex: state_root_hex.clone(),
            validator_set_id: validator_set.validator_set_id.clone(),
            timestamp_unix_ms: 1,
        };
        let block_hash_hex = hex::encode(header.block_hash().unwrap());
        let vote = ValidatorVoteV1 {
            schema: VALIDATOR_VOTE_SCHEMA_V1.to_string(),
            validator_id: "validator-1".to_string(),
            validator_set_id: validator_set.validator_set_id.clone(),
            height: 1,
            block_hash_hex: block_hash_hex.clone(),
            public_key_hex: public_key_hex(&signing_key),
            signature_hex: sign_hex(
                &signing_key,
                &ValidatorVoteV1::signing_bytes(
                    &header.chain_id,
                    &validator_set.validator_set_id,
                    1,
                    &block_hash_hex,
                ),
            ),
        };
        let mut receipt = FinalityReceiptV1 {
            schema: FINALITY_RECEIPT_SCHEMA_V1.to_string(),
            chain_id: header.chain_id.clone(),
            command_id: "command-1".to_string(),
            transaction_hash_hex,
            domain_command_fingerprint_hex: None,
            block_height: 1,
            transaction_index: 0,
            block_hash_hex: block_hash_hex.clone(),
            transaction_root_hex,
            state_root_hex,
            validator_set_id: validator_set.validator_set_id.clone(),
            block_header: header,
            quorum_certificate: QuorumCertificateV1 {
                validator_set_id: validator_set.validator_set_id.clone(),
                height: 1,
                block_hash_hex,
                signatures: vec![vote],
            },
            transaction_inclusion_proof: MerkleProofV1 {
                tree_domain: TRANSACTION_TREE_DOMAIN_V1.to_string(),
                leaf_index: 0,
                leaf_count: 1,
                leaf_hash_hex: hex::encode(transaction_leaf),
                steps: Vec::new(),
            },
            object_ref: None,
            object_inclusion_proof: None,
            receipt_hash_hex: String::new(),
        };
        receipt.receipt_hash_hex = hex::encode(receipt.compute_receipt_hash().unwrap());
        (receipt, validator_set)
    }

    #[test]
    fn verifies_minimal_single_transaction_receipt() {
        let (receipt, validator_set) = fixture();
        verify_finality_receipt(&receipt, &validator_set).unwrap();
    }

    #[test]
    fn rejects_tampered_receipt_root() {
        let (mut receipt, validator_set) = fixture();
        receipt.transaction_root_hex = hex::encode([9u8; 32]);
        assert!(verify_finality_receipt(&receipt, &validator_set).is_err());
    }

    #[test]
    fn verifies_canonical_paths_for_even_and_odd_tree_widths() {
        for count in 1..=33usize {
            let leaves = (0..count)
                .map(|index| {
                    let index = index as u64;
                    hash_domain("test.merkle.leaf.v1", &[&index.to_le_bytes()])
                })
                .collect::<Vec<_>>();
            for index in 0..count {
                let (root, proof) = proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &leaves, index);
                verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &proof).unwrap();
            }
        }
    }

    #[test]
    fn rejects_proof_selected_domain_and_path_shape_mutants() {
        let leaves = (0u64..5)
            .map(|index| hash_domain("test.merkle.leaf.v1", &[&index.to_le_bytes()]))
            .collect::<Vec<_>>();
        let (root, proof) = proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &leaves, 4);

        let mut wrong_domain = proof.clone();
        wrong_domain.tree_domain = STATE_OBJECT_TREE_DOMAIN_V1.to_string();
        assert!(verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &wrong_domain).is_err());

        let mut wrong_direction = proof.clone();
        wrong_direction.steps[0].sibling_on_left = true;
        assert!(verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &wrong_direction).is_err());

        let mut wrong_padding = proof.clone();
        wrong_padding.steps[0].sibling_hash_hex = hex::encode([0x55; 32]);
        assert!(verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &wrong_padding).is_err());

        let mut missing_step = proof.clone();
        missing_step.steps.pop();
        assert!(verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &missing_step).is_err());

        let mut trailing_step = proof.clone();
        trailing_step.steps.push(MerkleProofStepV1 {
            sibling_hash_hex: hex::encode([0x77; 32]),
            sibling_on_left: false,
        });
        assert!(verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &trailing_step).is_err());
    }

    #[test]
    fn rejects_forged_index_and_duplicate_padding_reinterpretation() {
        let leaves = (0u64..4)
            .map(|index| hash_domain("test.merkle.leaf.v1", &[&index.to_le_bytes()]))
            .collect::<Vec<_>>();
        let (root, mut forged_index) = proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &leaves, 0);
        forged_index.leaf_index = 2;
        assert!(verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &forged_index).is_err());

        let odd_leaves = (0u64..3)
            .map(|index| hash_domain("test.merkle.leaf.v1", &[&index.to_le_bytes()]))
            .collect::<Vec<_>>();
        let (odd_root, mut forged_count) =
            proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &odd_leaves, 2);
        forged_count.leaf_index = 3;
        forged_count.leaf_count = 4;
        forged_count.steps[0].sibling_on_left = true;
        assert!(verify_proof(&odd_root, TRANSACTION_TREE_DOMAIN_V1, &forged_count).is_err());
    }

    #[test]
    fn public_receipt_verifier_rejects_proof_domain_injection() {
        let (mut receipt, validator_set) = fixture();
        receipt.transaction_inclusion_proof.tree_domain =
            STATE_OBJECT_TREE_DOMAIN_V1.to_string();
        receipt.receipt_hash_hex = hex::encode(receipt.compute_receipt_hash().unwrap());
        assert!(verify_finality_receipt(&receipt, &validator_set).is_err());
    }
}

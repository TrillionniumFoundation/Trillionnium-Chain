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

/// Check the duplicate-last path against its declared index and width. Equal
/// siblings remain legal outside padding: distinct leaves or subtrees can
/// have equal hashes. This format does not independently commit the leaf count
/// in the root, so path consistency does not authenticate an exact tree size.
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
        if !sibling_on_left && index == width - 1 {
            ensure!(
                sibling == current,
                "Merkle proof odd-width padding must duplicate the current subtree"
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
        BlockHeaderV1, FinalityReceiptV1, MerkleProofStepV1, MerkleProofV1, ObjectRefV1,
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
        let mut level = leaves.to_vec();
        let mut index = leaf_index;
        let mut steps = Vec::new();
        while level.len() > 1 {
            let sibling_index = if index % 2 == 1 {
                index - 1
            } else {
                (index + 1).min(level.len() - 1)
            };
            steps.push(MerkleProofStepV1 {
                sibling_hash_hex: hex::encode(level[sibling_index]),
                sibling_on_left: index % 2 == 1,
            });
            level = level
                .chunks(2)
                .map(|pair| merkle_parent(tree_domain, &pair[0], pair.get(1).unwrap_or(&pair[0])))
                .collect();
            index /= 2;
        }
        (
            level[0],
            MerkleProofV1 {
                tree_domain: tree_domain.to_owned(),
                leaf_hash_hex: hex::encode(leaves[leaf_index]),
                leaf_index: leaf_index as u64,
                leaf_count: leaves.len() as u64,
                steps,
            },
        )
    }

    fn reseal_receipt(receipt: &mut FinalityReceiptV1) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        receipt.block_header.state_root_hex = receipt.state_root_hex.clone();
        receipt.block_header.transaction_root_hex = receipt.transaction_root_hex.clone();
        receipt.block_hash_hex = hex::encode(receipt.block_header.block_hash().unwrap());
        receipt.quorum_certificate.block_hash_hex = receipt.block_hash_hex.clone();
        let vote = &mut receipt.quorum_certificate.signatures[0];
        vote.block_hash_hex = receipt.block_hash_hex.clone();
        vote.signature_hex = sign_hex(
            &signing_key,
            &ValidatorVoteV1::signing_bytes(
                &receipt.chain_id,
                &receipt.validator_set_id,
                receipt.block_height,
                &receipt.block_hash_hex,
            ),
        );
        receipt.receipt_hash_hex = hex::encode(receipt.compute_receipt_hash().unwrap());
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
                tree_domain: "trnm.transactions.v1".to_string(),
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
    fn verifies_every_position_in_even_and_odd_width_trees() {
        for tree_domain in [TRANSACTION_TREE_DOMAIN_V1, STATE_OBJECT_TREE_DOMAIN_V1] {
            for count in 1..=33usize {
                let leaves = (0..count)
                    .map(|index| [index as u8; 32])
                    .collect::<Vec<_>>();
                for index in 0..count {
                    let (root, proof) = proof_fixture(tree_domain, &leaves, index);
                    verify_proof(&root, tree_domain, &proof).unwrap();
                }
            }
        }
    }

    #[test]
    fn verifies_equal_real_leaves_and_equal_nonpadding_subtrees() {
        for leaves in [
            vec![[7; 32]; 2],
            vec![[7; 32]; 5],
            vec![[1; 32], [2; 32], [1; 32], [2; 32]],
        ] {
            for index in 0..leaves.len() {
                let (root, proof) = proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &leaves, index);
                verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &proof).unwrap();
            }
        }
    }

    #[test]
    fn rejects_proof_domain_and_path_shape_mutations() {
        let (root, proof) = proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &[[1; 32]; 5], 4);
        let mut mutations = Vec::new();
        let mut wrong_domain = proof.clone();
        wrong_domain.tree_domain = STATE_OBJECT_TREE_DOMAIN_V1.to_owned();
        mutations.push((wrong_domain, "tree domain mismatch"));
        let mut wrong_index = proof.clone();
        wrong_index.leaf_index = 3;
        mutations.push((wrong_index, "path direction conflicts"));
        let mut wrong_direction = proof.clone();
        wrong_direction.steps[0].sibling_on_left = true;
        mutations.push((wrong_direction, "path direction conflicts"));
        let mut wrong_padding = proof.clone();
        wrong_padding.steps[0].sibling_hash_hex = hex::encode([2; 32]);
        mutations.push((wrong_padding, "padding must duplicate"));
        let mut missing_step = proof.clone();
        missing_step.steps.pop();
        mutations.push((missing_step, "missing a required path step"));
        let mut extra_step = proof.clone();
        extra_step.steps.push(proof.steps[0].clone());
        mutations.push((extra_step, "trailing path steps"));
        let mut wrong_count = proof.clone();
        wrong_count.leaf_count = 9;
        mutations.push((wrong_count, "missing a required path step"));
        for (mutation, expected_error) in mutations {
            let error = verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &mutation).unwrap_err();
            assert!(error.to_string().contains(expected_error), "{error}");
        }
    }

    #[test]
    fn rejects_empty_out_of_range_and_overflow_width_path_claims() {
        let (root, proof) = proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &[[1; 32]], 0);
        for (leaf_index, leaf_count, expected_error) in [
            (0, 0, "leaf_count must be positive"),
            (1, 1, "leaf_index is out of range"),
            (0, u64::MAX, "missing a required path step"),
        ] {
            let mut mutation = proof.clone();
            mutation.leaf_index = leaf_index;
            mutation.leaf_count = leaf_count;
            let error = verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &mutation).unwrap_err();
            assert!(error.to_string().contains(expected_error), "{error}");
        }
    }

    #[test]
    fn public_receipt_verifier_checks_transaction_domain_and_index() {
        let (mut receipt, validator_set) = fixture();
        receipt.transaction_inclusion_proof.tree_domain = STATE_OBJECT_TREE_DOMAIN_V1.to_owned();
        reseal_receipt(&mut receipt);
        let error = verify_finality_receipt(&receipt, &validator_set).unwrap_err();
        assert!(error.to_string().contains("tree domain mismatch"));

        // Recompute the untrusted receipt digest so the regression specifically
        // exercises index/path binding, not the final receipt checksum.
        let leaf = decode_hash32(
            "tx leaf",
            &receipt.transaction_inclusion_proof.leaf_hash_hex,
        )
        .unwrap();
        let (root, proof) = proof_fixture(
            TRANSACTION_TREE_DOMAIN_V1,
            &[leaf, [3; 32], [4; 32], [5; 32]],
            0,
        );
        receipt.transaction_root_hex = hex::encode(root);
        receipt.transaction_inclusion_proof = proof;
        reseal_receipt(&mut receipt);
        verify_finality_receipt(&receipt, &validator_set).unwrap();
        receipt.transaction_index = 2;
        receipt.transaction_inclusion_proof.leaf_index = 2;
        reseal_receipt(&mut receipt);
        let error = verify_finality_receipt(&receipt, &validator_set).unwrap_err();
        assert!(error.to_string().contains("path direction conflicts"));
    }

    #[test]
    fn public_receipt_verifier_checks_object_tree_domain() {
        let (mut receipt, validator_set) = fixture();
        let object = ObjectRefV1 {
            object_key_hex: hex::encode([1; 32]),
            object_type: "test-object-v1".to_owned(),
            version: 1,
            value_hash_hex: hex::encode([2; 32]),
        };
        let leaf = hash_domain(
            "trnm.state.object.leaf.v1",
            &[
                object.object_key_hex.as_bytes(),
                object.object_type.as_bytes(),
                &object.version.to_be_bytes(),
                object.value_hash_hex.as_bytes(),
            ],
        );
        let (root, proof) = proof_fixture(STATE_OBJECT_TREE_DOMAIN_V1, &[leaf], 0);
        receipt.state_root_hex = hex::encode(root);
        receipt.object_ref = Some(object);
        receipt.object_inclusion_proof = Some(proof);
        reseal_receipt(&mut receipt);
        verify_finality_receipt(&receipt, &validator_set).unwrap();
        receipt.object_inclusion_proof.as_mut().unwrap().tree_domain =
            TRANSACTION_TREE_DOMAIN_V1.to_owned();
        reseal_receipt(&mut receipt);
        let error = verify_finality_receipt(&receipt, &validator_set).unwrap_err();
        assert!(error.to_string().contains("tree domain mismatch"));
    }

    #[test]
    fn duplicate_last_format_does_not_independently_authenticate_leaf_count() {
        let leaves = [[1; 32], [2; 32], [3; 32]];
        let (root, odd_proof) = proof_fixture(TRANSACTION_TREE_DOMAIN_V1, &leaves, 2);
        let (duplicate_root, even_proof) = proof_fixture(
            TRANSACTION_TREE_DOMAIN_V1,
            &[leaves[0], leaves[1], leaves[2], leaves[2]],
            3,
        );
        assert_eq!(root, duplicate_root);
        verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &odd_proof).unwrap();
        verify_proof(&root, TRANSACTION_TREE_DOMAIN_V1, &even_proof).unwrap();
    }
}

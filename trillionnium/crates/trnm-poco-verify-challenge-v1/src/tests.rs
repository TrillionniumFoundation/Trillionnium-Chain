use std::{fs, path::PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use trnm_poco_agent_market_v1::{AgentIdV1, AgentKeyIdV1, BondIdV1, Hash32V1, ProtocolContextV1};

use crate::{
    codec::{canonical_bytes, checksum, digest_value, strict_decode},
    *,
};

struct Fixture {
    directory: TempDir,
    provider_key: SigningKey,
    challenger_key: SigningKey,
    verifier_keys: Vec<SigningKey>,
    trust: VerifyChallengeFreshGenesisTrustBundleV1,
}

impl Fixture {
    fn new() -> Self {
        let provider_key = SigningKey::from_bytes(&[11; 32]);
        let challenger_key = SigningKey::from_bytes(&[12; 32]);
        let verifier_keys = vec![
            SigningKey::from_bytes(&[21; 32]),
            SigningKey::from_bytes(&[22; 32]),
            SigningKey::from_bytes(&[23; 32]),
            SigningKey::from_bytes(&[24; 32]),
        ];
        let context = ProtocolContextV1 {
            genesis_hash: hash(1),
            chain_id: "trnm-verify-challenge-candidate-test".to_owned(),
            protocol_version: 1,
            stack_profile_hash: hash(2),
        };
        let verifiers: Vec<RegisteredVerifierV1> = verifier_keys
            .iter()
            .enumerate()
            .map(|(index, key)| RegisteredVerifierV1 {
                verifier_id: [u8::try_from(31 + index).unwrap(); 32],
                key_id: [u8::try_from(41 + index).unwrap(); 32],
                public_key: key.verifying_key().to_bytes(),
                weight: 1,
            })
            .collect();
        let verifier_set_hash =
            digest_value("trnm.poco-ai.verifier-set.candidate.v1", &verifiers).unwrap();
        let profile_id = b"stake-quorum-test".to_vec();
        let challenge_policy_hash = hash(53);
        let settlement_policy_hash = hash(54);
        let challenge_bond_asset_id = hash(55);
        let required_da_policy_hash = hash(57);
        let profile_hash = digest_value(
            "trnm.poco-ai.stake-quorum-profile.candidate.v1",
            &(
                &profile_id,
                1u32,
                verifier_set_hash,
                3u128,
                3u32,
                20u64,
                required_da_policy_hash,
                challenge_policy_hash,
                settlement_policy_hash,
                challenge_bond_asset_id,
                100u128,
            ),
        )
        .unwrap();
        let trust = VerifyChallengeFreshGenesisTrustBundleV1 {
            schema_version: 1,
            context,
            initial_order_height: 100,
            initial_order_block_id: hash(3),
            task_id: hash(50),
            task_revision: 7,
            lease_id: hash(51),
            attempt: 1,
            execution_environment_hash: hash(52),
            provider: actor(1, 11, &provider_key),
            challenger: actor(2, 12, &challenger_key),
            verifiers,
            profile: StakeQuorumProfileV1 {
                profile_id,
                profile_version: 1,
                profile_hash,
                verifier_set_hash,
                threshold_weight: 3,
                minimum_unique_signers: 3,
                minimum_challenge_blocks: 20,
                required_da_policy_hash,
                challenge_policy_hash,
                settlement_policy_hash,
                challenge_bond_asset_id,
                challenge_bond_amount: 100,
            },
            challenge_bond_id: BondIdV1([56; 32]),
            challenge_bond_funding: 200,
        };
        Self {
            directory: tempfile::tempdir().unwrap(),
            provider_key,
            challenger_key,
            verifier_keys,
            trust,
        }
    }

    fn path(&self, index: usize) -> PathBuf {
        self.directory.path().join(format!("verify-{index}.sqlite"))
    }
    fn config(&self, index: usize) -> VerifyChallengeStoreConfigV1 {
        VerifyChallengeStoreConfigV1 {
            path: self.path(index),
            store_id: hash(u8::try_from(120 + index).unwrap()),
            trust_bundle: self.trust.clone(),
        }
    }
    fn store(&self, index: usize) -> VerifyChallengeStoreV1 {
        VerifyChallengeStoreV1::open(self.config(index)).unwrap()
    }

    fn receipt(&self, sequence: u64) -> SignedExecutionReceiptV1 {
        let body = ExecutionReceiptBodyV1 {
            schema_version: 1,
            context: self.trust.context.clone(),
            task_id: self.trust.task_id,
            task_revision: self.trust.task_revision,
            lease_id: self.trust.lease_id,
            attempt: self.trust.attempt,
            provider_agent_id: self.trust.provider.agent_id,
            provider_key_id: self.trust.provider.key_id,
            execution_outcome: 0,
            failure_code: None,
            execution_environment_hash: self.trust.execution_environment_hash,
            output_commitment: hash(60),
            meter_root: hash(61),
            verification_profile_id: self.trust.profile.profile_id.clone(),
            verification_profile_version: self.trust.profile.profile_version,
            verification_profile_hash: self.trust.profile.profile_hash,
            receipt_sequence: sequence,
            submitted_height_upper_bound: 110,
        };
        let receipt_id = body.receipt_id().unwrap();
        SignedExecutionReceiptV1 {
            body,
            receipt_id,
            signature: sign_typed(
                "trnm.poco-ai.execution-receipt-signature.v1",
                &receipt_id,
                &self.provider_key,
            ),
        }
    }

    fn claims(
        &self,
        result_id: ResultIdV1,
        receipt_id: ExecutionReceiptIdV1,
        round: u32,
        verdict: u8,
        count: usize,
        evidence_root: Hash32V1,
    ) -> Vec<SignedVerificationClaimV1> {
        let mut claims: Vec<_> = self
            .trust
            .verifiers
            .iter()
            .zip(&self.verifier_keys)
            .take(count)
            .map(|(verifier, key)| {
                let body = VerificationClaimBodyV1 {
                    schema_version: 1,
                    context: self.trust.context.clone(),
                    result_id,
                    execution_receipt_id: receipt_id,
                    verification_profile_id: self.trust.profile.profile_id.clone(),
                    verification_profile_version: self.trust.profile.profile_version,
                    verification_profile_hash: self.trust.profile.profile_hash,
                    decision_round: round,
                    verifier_id: verifier.verifier_id,
                    verifier_key_id: verifier.key_id,
                    verdict,
                    statement_digest: digest_value(
                        "trnm.poco-ai.verification-claim-statement.candidate.v1",
                        &(
                            result_id,
                            receipt_id,
                            self.trust.profile.profile_hash,
                            self.trust.profile.required_da_policy_hash,
                            self.trust.profile.challenge_policy_hash,
                            round,
                            verdict,
                            evidence_root,
                            u64::from(round),
                        ),
                    )
                    .unwrap(),
                    evidence_root,
                    claim_sequence: u64::from(round),
                };
                let claim_id = body.claim_id().unwrap();
                SignedVerificationClaimV1 {
                    body,
                    claim_id,
                    signature: sign_typed(
                        "trnm.poco-ai.verification-claim-signature.v1",
                        &claim_id,
                        key,
                    ),
                }
            })
            .collect();
        claims.sort_by_key(|claim| (claim.body.verifier_id, claim.body.verifier_key_id));
        claims
    }

    fn evaluation_evidence_root(&self, receipt: &SignedExecutionReceiptV1) -> Hash32V1 {
        digest_value(
            "trnm.poco-ai.evaluation-evidence-root.candidate.v1",
            &(
                receipt.receipt_id,
                receipt.body.output_commitment,
                receipt.body.meter_root,
                receipt.body.execution_environment_hash,
                receipt.body.verification_profile_hash,
            ),
        )
        .unwrap()
    }

    fn adjudication_evidence_root(&self, challenge: &ChallengeStateV1) -> Hash32V1 {
        digest_value(
            "trnm.poco-ai.adjudication-evidence-root.candidate.v1",
            &(
                challenge.challenge_id,
                challenge.result_id,
                &challenge.evidence_entries,
                &challenge.response_statements,
                challenge.last_transition_hash,
                self.trust.profile.challenge_policy_hash,
            ),
        )
        .unwrap()
    }

    fn challenge_body(&self, result: &ResultStateV1) -> ChallengeOpenBodyV1 {
        ChallengeOpenBodyV1 {
            schema_version: 1,
            context: self.trust.context.clone(),
            result_id: result.result_id,
            execution_receipt_id: result.execution_receipt_id,
            challenger_agent_id: self.trust.challenger.agent_id,
            challenger_key_id: self.trust.challenger.key_id,
            challenged_statement_digest: result.verification_statement_digest.unwrap(),
            counter_statement_digest: hash(71),
            challenge_bond_id: self.trust.challenge_bond_id,
            challenge_bond_asset_id: self.trust.profile.challenge_bond_asset_id,
            challenge_bond_amount: self.trust.profile.challenge_bond_amount,
            evidence_deadline_height: 105,
            response_deadline_height: 110,
            decision_deadline_height: 115,
            challenge_nonce: hash(73),
        }
    }

    fn open_command(&self, result: &ResultStateV1) -> VerifyCommandV1 {
        let body = self.challenge_body(result);
        let authorization = actor_authorization(
            &self.trust.challenger,
            "trnm.poco-ai.challenge-signature.v1",
            &body,
            &self.challenger_key,
        );
        VerifyCommandV1::OpenChallenge {
            expected_result_revision: result.revision,
            body,
            authorization,
        }
    }
}

fn hash(value: u8) -> Hash32V1 {
    Hash32V1([value; 32])
}
fn actor(id: u8, key_id: u8, key: &SigningKey) -> RegisteredActorV1 {
    RegisteredActorV1 {
        agent_id: AgentIdV1([id; 32]),
        key_id: AgentKeyIdV1([key_id; 32]),
        public_key: key.verifying_key().to_bytes(),
    }
}
fn sign_typed<T: borsh::BorshSerialize>(domain: &str, value: &T, key: &SigningKey) -> Vec<u8> {
    let root = digest_value(domain, value).unwrap();
    key.sign(&root.0).to_bytes().to_vec()
}
fn actor_authorization<T: borsh::BorshSerialize>(
    actor: &RegisteredActorV1,
    domain: &str,
    action: &T,
    key: &SigningKey,
) -> ActorAuthorizationV1 {
    let digest = digest_value(domain, action).unwrap();
    ActorAuthorizationV1 {
        actor_agent_id: actor.agent_id,
        actor_key_id: actor.key_id,
        action_digest: digest,
        signature: sign_typed(domain, &digest, key),
    }
}

fn refresh_profile_commitments(bundle: &mut VerifyChallengeFreshGenesisTrustBundleV1) {
    bundle.profile.verifier_set_hash =
        digest_value("trnm.poco-ai.verifier-set.candidate.v1", &bundle.verifiers).unwrap();
    bundle.profile.profile_hash = digest_value(
        "trnm.poco-ai.stake-quorum-profile.candidate.v1",
        &(
            &bundle.profile.profile_id,
            bundle.profile.profile_version,
            bundle.profile.verifier_set_hash,
            bundle.profile.threshold_weight,
            bundle.profile.minimum_unique_signers,
            bundle.profile.minimum_challenge_blocks,
            bundle.profile.required_da_policy_hash,
            bundle.profile.challenge_policy_hash,
            bundle.profile.settlement_policy_hash,
            bundle.profile.challenge_bond_asset_id,
            bundle.profile.challenge_bond_amount,
        ),
    )
    .unwrap();
}

fn admit_and_evaluate(fixture: &Fixture, store: &VerifyChallengeStoreV1) -> ResultStateV1 {
    let receipt = fixture.receipt(0);
    let evidence_root = fixture.evaluation_evidence_root(&receipt);
    store
        .execute(&VerifyCommandV1::AdmitReceipt { receipt })
        .unwrap();
    let submitted = store.state().unwrap().result.unwrap();
    let claims = fixture.claims(
        submitted.result_id,
        submitted.execution_receipt_id,
        0,
        0,
        3,
        evidence_root,
    );
    store
        .execute(&VerifyCommandV1::Evaluate {
            result_id: submitted.result_id,
            expected_result_revision: 0,
            decision_round: 0,
            accepted_claims: claims,
            decision: 0,
            decision_nonce: hash(75),
        })
        .unwrap();
    store.state().unwrap().result.unwrap()
}

fn open_and_add_evidence(
    fixture: &Fixture,
    store: &VerifyChallengeStoreV1,
) -> (ResultStateV1, ChallengeStateV1) {
    let provisional = admit_and_evaluate(fixture, store);
    store.execute(&fixture.open_command(&provisional)).unwrap();
    let opened = store.state().unwrap();
    let challenge = opened.challenge.unwrap();
    let result = opened.result.unwrap();
    let action = (
        challenge.challenge_id,
        challenge.revision,
        result.revision,
        hash(80),
        hash(81),
    );
    let authorization = actor_authorization(
        &fixture.trust.challenger,
        "trnm.poco-ai.challenge-add-evidence-signature.candidate.v1",
        &action,
        &fixture.challenger_key,
    );
    store
        .execute(&VerifyCommandV1::AddEvidence {
            challenge_id: challenge.challenge_id,
            expected_challenge_revision: challenge.revision,
            expected_result_revision: result.revision,
            evidence_artifact_id: hash(80),
            availability_certificate_id: hash(81),
            authorization,
        })
        .unwrap();
    let current = store.state().unwrap();
    (current.result.unwrap(), current.challenge.unwrap())
}

fn open_evidence_and_respond(
    fixture: &Fixture,
    store: &VerifyChallengeStoreV1,
) -> (ResultStateV1, ChallengeStateV1) {
    let (result, challenge) = open_and_add_evidence(fixture, store);
    let statement = hash(82);
    let action = (
        challenge.challenge_id,
        challenge.revision,
        result.revision,
        statement,
    );
    let authorization = actor_authorization(
        &fixture.trust.provider,
        "trnm.poco-ai.challenge-response-signature.candidate.v1",
        &action,
        &fixture.provider_key,
    );
    store
        .execute(&VerifyCommandV1::Respond {
            challenge_id: challenge.challenge_id,
            expected_challenge_revision: challenge.revision,
            expected_result_revision: result.revision,
            response_statement_digest: statement,
            authorization,
        })
        .unwrap();
    let current = store.state().unwrap();
    (current.result.unwrap(), current.challenge.unwrap())
}

#[test]
fn receipt_and_atomic_two_transition_evaluation_are_durable() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let receipt = fixture.receipt(0);
    let command = VerifyCommandV1::AdmitReceipt {
        receipt: receipt.clone(),
    };
    let first = store.execute(&command).unwrap();
    let replay = store.execute(&command).unwrap();
    assert!(!first.is_replay());
    assert!(replay.is_replay());
    assert_eq!(first.receipt(), replay.receipt());
    let submitted = store.state().unwrap().result.unwrap();
    assert_eq!(
        (
            submitted.revision,
            submitted.status,
            submitted.transition_history.len()
        ),
        (0, 0, 0)
    );
    let claims = fixture.claims(
        submitted.result_id,
        receipt.receipt_id,
        0,
        0,
        3,
        fixture.evaluation_evidence_root(&receipt),
    );
    store
        .execute(&VerifyCommandV1::Evaluate {
            result_id: submitted.result_id,
            expected_result_revision: 0,
            decision_round: 0,
            accepted_claims: claims,
            decision: 0,
            decision_nonce: hash(75),
        })
        .unwrap();
    let result = store.state().unwrap().result.unwrap();
    assert_eq!(
        (
            result.revision,
            result.status,
            result.transition_history.len(),
            result.challenge_close_height
        ),
        (2, 2, 2, Some(120))
    );
    drop(store);
    assert_eq!(
        VerifyChallengeStoreV1::open(fixture.config(0))
            .unwrap()
            .state()
            .unwrap()
            .result
            .unwrap(),
        result
    );
}

#[test]
fn pre_vote_preview_verifies_receipt_and_preserves_the_durable_head() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let command = VerifyCommandV1::AdmitReceipt {
        receipt: fixture.receipt(0),
    };
    let before = store.fresh_readback().expect("fresh parent");
    let preview = store
        .preview_before_vote_v1(&before, 101, hash(91), &[command])
        .expect("read-only Verify preview");
    let after = store.fresh_readback().expect("unchanged parent");
    assert_eq!(before, after);
    assert_eq!(preview.source_sequence(), before.sequence());
    assert_eq!(preview.source_state_root(), before.durable_state_root());
    assert_eq!(preview.source_journal_root(), before.durable_journal_root());
    assert_eq!(preview.candidate_receipts().len(), 1);
    assert_ne!(
        preview.candidate_post_state_root(),
        before.durable_state_root()
    );
}

#[test]
fn challenge_evidence_response_and_upheld_adjudication_are_atomic() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (result, challenge) = open_evidence_and_respond(&fixture, &store);
    assert_eq!((challenge.revision, challenge.status), (2, 2));
    let claims = fixture.claims(
        result.result_id,
        result.execution_receipt_id,
        1,
        1,
        3,
        fixture.adjudication_evidence_root(&challenge),
    );
    store
        .execute(&VerifyCommandV1::Adjudicate {
            challenge_id: challenge.challenge_id,
            expected_challenge_revision: 2,
            expected_result_revision: result.revision,
            decision_round: 1,
            accepted_claims: claims,
            decision: 0,
            decision_nonce: hash(83),
        })
        .unwrap();
    let state = store.state().unwrap();
    assert_eq!(
        (
            state.result.unwrap().status,
            state.challenge.unwrap().status
        ),
        (5, 3)
    );
    assert_eq!(
        (
            state.bond.available,
            state.bond.held,
            state.bond.released,
            state.bond.slashed,
            state.bond.version
        ),
        (100, 0, 100, 0, 2)
    );
}

#[test]
fn rejected_challenge_returns_to_provisional_and_slashes_bond() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (result, challenge) = open_evidence_and_respond(&fixture, &store);
    let claims = fixture.claims(
        result.result_id,
        result.execution_receipt_id,
        1,
        0,
        3,
        fixture.adjudication_evidence_root(&challenge),
    );
    store
        .execute(&VerifyCommandV1::Adjudicate {
            challenge_id: challenge.challenge_id,
            expected_challenge_revision: 2,
            expected_result_revision: result.revision,
            decision_round: 1,
            accepted_claims: claims,
            decision: 1,
            decision_nonce: hash(84),
        })
        .unwrap();
    let state = store.state().unwrap();
    assert_eq!(
        (
            state.result.unwrap().status,
            state.challenge.unwrap().status
        ),
        (2, 4)
    );
    assert_eq!((state.bond.released, state.bond.slashed), (0, 100));
}

#[test]
fn signature_quorum_revision_deadline_and_conflict_mutants_fail_closed() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let mut receipt = fixture.receipt(0);
    receipt.signature[0] ^= 1;
    assert_eq!(
        store
            .execute(&VerifyCommandV1::AdmitReceipt { receipt })
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::InvalidSignature
    );
    let receipt = fixture.receipt(0);
    store
        .execute(&VerifyCommandV1::AdmitReceipt {
            receipt: receipt.clone(),
        })
        .unwrap();
    let result = store.state().unwrap().result.unwrap();
    let claims = fixture.claims(
        result.result_id,
        result.execution_receipt_id,
        0,
        0,
        2,
        fixture.evaluation_evidence_root(&receipt),
    );
    assert_eq!(
        store
            .execute(&VerifyCommandV1::Evaluate {
                result_id: result.result_id,
                expected_result_revision: 0,
                decision_round: 0,
                accepted_claims: claims,
                decision: 0,
                decision_nonce: hash(75)
            })
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::UnderQuorum
    );
    let conflict = fixture.receipt(1);
    assert_eq!(
        store
            .execute(&VerifyCommandV1::AdmitReceipt { receipt: conflict })
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::Conflict
    );
}

#[test]
fn commit_uncertainty_schema_sidecar_and_tamper_are_fail_closed() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let command = VerifyCommandV1::AdmitReceipt {
        receipt: fixture.receipt(0),
    };
    assert_eq!(
        store
            .execute_with_fault(&command, VerifyCommitFaultV1::NotAppliedAckLost)
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::CommitUncertain
    );
    assert_eq!(
        store
            .execute_with_fault(&command, VerifyCommitFaultV1::AppliedAckLost)
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::CommitUncertain
    );
    assert!(store.execute(&command).unwrap().is_replay());
    let fenced = fixture.store(1);
    let other = VerifyCommandV1::AdmitReceipt {
        receipt: fixture.receipt(1),
    };
    assert_eq!(
        fenced
            .execute_with_fault(&other, VerifyCommitFaultV1::ThirdState)
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::ThirdStateFenced
    );
    drop(fenced);
    assert_eq!(
        VerifyChallengeStoreV1::open(fixture.config(1))
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::ThirdStateFenced
    );
    drop(store);
    fs::write(format!("{}-wal", fixture.path(0).display()), b"sentinel").unwrap();
    assert_eq!(
        VerifyChallengeStoreV1::open(fixture.config(0))
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::SidecarPresent
    );
}

#[test]
fn finalized_block_journal_covers_empty_same_block_and_tamper_boundaries() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let genesis = store.fresh_readback().expect("genesis readback");
    let first_empty = VerifyOrderFinalizedExecutionContextV1 {
        schema_version: 1,
        context: fixture.trust.context.clone(),
        expected_order_height: genesis.order_height(),
        expected_order_block_id: genesis.order_block_id(),
        order_height: genesis.order_height() + 1,
        order_block_id: hash(90),
    };
    let first = store
        .advance_empty_order_finalized_v1(&first_empty)
        .expect("first empty block");
    assert_ne!(
        first.durable_finalized_block_root(),
        genesis.durable_finalized_block_root()
    );
    let replay = store
        .advance_empty_order_finalized_v1(&first_empty)
        .expect("exact empty replay");
    assert_eq!(
        replay.durable_finalized_block_root(),
        first.durable_finalized_block_root()
    );
    let second_empty = VerifyOrderFinalizedExecutionContextV1 {
        schema_version: 1,
        context: fixture.trust.context.clone(),
        expected_order_height: first.order_height(),
        expected_order_block_id: first.order_block_id(),
        order_height: first.order_height() + 1,
        order_block_id: hash(91),
    };
    let second = store
        .advance_empty_order_finalized_v1(&second_empty)
        .expect("consecutive empty block");
    assert_ne!(
        second.durable_finalized_block_root(),
        first.durable_finalized_block_root()
    );
    let stale = VerifyOrderFinalizedExecutionContextV1 {
        expected_order_height: genesis.order_height(),
        expected_order_block_id: genesis.order_block_id(),
        order_height: genesis.order_height() + 1,
        order_block_id: hash(92),
        ..second_empty.clone()
    };
    assert_eq!(
        store
            .advance_empty_order_finalized_v1(&stale)
            .expect_err("stale source")
            .code(),
        VerifyChallengeErrorCodeV1::StaleRevision
    );
    let skipped = VerifyOrderFinalizedExecutionContextV1 {
        expected_order_height: second.order_height(),
        expected_order_block_id: second.order_block_id(),
        order_height: second.order_height() + 2,
        order_block_id: hash(93),
        ..second_empty
    };
    assert_eq!(
        store
            .advance_empty_order_finalized_v1(&skipped)
            .expect_err("skipped target")
            .code(),
        VerifyChallengeErrorCodeV1::InvalidContext
    );
    drop(store);
    rusqlite::Connection::open(fixture.path(0))
        .expect("open marker database")
        .execute(
            "UPDATE verify_challenge_finalized_blocks_v1 SET row_checksum=zeroblob(32) WHERE parent_order_height!=order_height",
            [],
        )
        .expect("tamper marker");
    assert_eq!(
        VerifyChallengeStoreV1::open(fixture.config(0))
            .expect_err("marker tamper")
            .code(),
        VerifyChallengeErrorCodeV1::TamperDetected
    );

    let partial = fixture.store(2);
    let partial_genesis = partial.fresh_readback().expect("partial genesis");
    partial
        .advance_empty_order_finalized_v1(&VerifyOrderFinalizedExecutionContextV1 {
            schema_version: 1,
            context: fixture.trust.context.clone(),
            expected_order_height: partial_genesis.order_height(),
            expected_order_block_id: partial_genesis.order_block_id(),
            order_height: partial_genesis.order_height() + 1,
            order_block_id: hash(94),
        })
        .expect("partial target");
    drop(partial);
    rusqlite::Connection::open(fixture.path(2))
        .expect("open partial database")
        .execute(
            "DELETE FROM verify_challenge_finalized_blocks_v1 WHERE parent_order_height!=order_height",
            [],
        )
        .expect("delete tail marker");
    assert_eq!(
        VerifyChallengeStoreV1::open(fixture.config(2))
            .expect_err("partial marker write")
            .code(),
        VerifyChallengeErrorCodeV1::TamperDetected
    );

    let multi = fixture.store(1);
    let receipt = fixture.receipt(0);
    let evidence_root = fixture.evaluation_evidence_root(&receipt);
    multi
        .execute(&VerifyCommandV1::AdmitReceipt { receipt })
        .expect("first same-block command");
    let first_root = multi
        .fresh_readback()
        .expect("first same-block readback")
        .durable_finalized_block_root();
    let submitted = multi.state().expect("submitted state").result.unwrap();
    multi
        .execute(&VerifyCommandV1::Evaluate {
            result_id: submitted.result_id,
            expected_result_revision: 0,
            decision_round: 0,
            accepted_claims: fixture.claims(
                submitted.result_id,
                submitted.execution_receipt_id,
                0,
                0,
                3,
                evidence_root,
            ),
            decision: 0,
            decision_nonce: hash(75),
        })
        .expect("second same-block command");
    assert_ne!(
        multi
            .fresh_readback()
            .expect("second same-block readback")
            .durable_finalized_block_root(),
        first_root
    );
    drop(multi);
    VerifyChallengeStoreV1::open(fixture.config(1)).expect("same-block reopen");
}

#[test]
fn actor_claim_and_transition_mutants_hit_exact_rejection_classes() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let provisional = admit_and_evaluate(&fixture, &store);

    let mut wrong_actor = fixture.open_command(&provisional);
    wrong_actor.mutate_actor_authorization_for_test(|authorization| {
        authorization.actor_agent_id = fixture.trust.provider.agent_id;
    });
    assert_eq!(
        store.execute(&wrong_actor).unwrap_err().code(),
        VerifyChallengeErrorCodeV1::Unauthorized
    );

    let mut wrong_bond = fixture.open_command(&provisional);
    if let VerifyCommandV1::OpenChallenge {
        body,
        authorization,
        ..
    } = &mut wrong_bond
    {
        body.challenge_bond_amount += 1;
        *authorization = actor_authorization(
            &fixture.trust.challenger,
            "trnm.poco-ai.challenge-signature.v1",
            body,
            &fixture.challenger_key,
        );
    }
    assert_eq!(
        store.execute(&wrong_bond).unwrap_err().code(),
        VerifyChallengeErrorCodeV1::InvalidState
    );

    let mut wrong_statement = fixture.open_command(&provisional);
    if let VerifyCommandV1::OpenChallenge {
        body,
        authorization,
        ..
    } = &mut wrong_statement
    {
        body.challenged_statement_digest = hash(96);
        *authorization = actor_authorization(
            &fixture.trust.challenger,
            "trnm.poco-ai.challenge-signature.v1",
            body,
            &fixture.challenger_key,
        );
    }
    assert_eq!(
        store.execute(&wrong_statement).unwrap_err().code(),
        VerifyChallengeErrorCodeV1::InvalidState
    );

    let mut late = fixture.open_command(&provisional);
    if let VerifyCommandV1::OpenChallenge {
        body,
        authorization,
        ..
    } = &mut late
    {
        body.evidence_deadline_height = 99;
        *authorization = actor_authorization(
            &fixture.trust.challenger,
            "trnm.poco-ai.challenge-signature.v1",
            body,
            &fixture.challenger_key,
        );
    }
    assert_eq!(
        store.execute(&late).unwrap_err().code(),
        VerifyChallengeErrorCodeV1::InvalidState
    );

    store.execute(&fixture.open_command(&provisional)).unwrap();
    let opened = store.state().unwrap();
    let challenge = opened.challenge.unwrap();
    let result = opened.result.unwrap();
    let action = (
        challenge.challenge_id,
        challenge.revision,
        result.revision,
        hash(80),
        hash(81),
    );
    let authorization = actor_authorization(
        &fixture.trust.challenger,
        "trnm.poco-ai.challenge-add-evidence-signature.candidate.v1",
        &action,
        &fixture.challenger_key,
    );
    let stale = VerifyCommandV1::AddEvidence {
        challenge_id: challenge.challenge_id,
        expected_challenge_revision: 1,
        expected_result_revision: result.revision,
        evidence_artifact_id: hash(80),
        availability_certificate_id: hash(81),
        authorization,
    };
    assert_eq!(
        store.execute(&stale).unwrap_err().code(),
        VerifyChallengeErrorCodeV1::Unauthorized
    );

    let other_fixture = Fixture::new();
    let other_store = other_fixture.store(0);
    let (submitted, evidence_root) = {
        let receipt = other_fixture.receipt(0);
        let evidence_root = other_fixture.evaluation_evidence_root(&receipt);
        other_store
            .execute(&VerifyCommandV1::AdmitReceipt { receipt })
            .unwrap();
        (other_store.state().unwrap().result.unwrap(), evidence_root)
    };
    let mut claims = other_fixture.claims(
        submitted.result_id,
        submitted.execution_receipt_id,
        0,
        0,
        3,
        evidence_root,
    );
    claims[0].signature[0] ^= 1;
    assert_eq!(
        other_store
            .execute(&VerifyCommandV1::Evaluate {
                result_id: submitted.result_id,
                expected_result_revision: 0,
                decision_round: 0,
                accepted_claims: claims,
                decision: 0,
                decision_nonce: hash(75),
            })
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::InvalidSignature
    );
}

#[test]
fn row_schema_and_journal_tamper_reject_without_migration() {
    for (index, kind) in ["schema", "metadata", "journal"].into_iter().enumerate() {
        let fixture = Fixture::new();
        let store = fixture.store(index);
        store
            .execute(&VerifyCommandV1::AdmitReceipt {
                receipt: fixture.receipt(0),
            })
            .unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(fixture.path(index)).unwrap();
        match kind {
            "schema" => {
                connection
                    .execute("DROP TABLE verify_challenge_operations_v1", [])
                    .unwrap();
            }
            "metadata" => {
                connection
                    .execute("UPDATE verify_challenge_metadata_v1 SET state = X'00'", [])
                    .unwrap();
            }
            "journal" => {
                connection
                    .execute("DELETE FROM verify_challenge_operations_v1", [])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        let expected = if kind == "schema" {
            VerifyChallengeErrorCodeV1::SchemaMismatch
        } else {
            VerifyChallengeErrorCodeV1::TamperDetected
        };
        assert_eq!(
            VerifyChallengeStoreV1::open(fixture.config(index))
                .unwrap_err()
                .code(),
            expected,
            "{kind}"
        );
    }
}

#[test]
fn verifier_identity_claim_binding_and_bootstrap_key_mutants_fail_closed() {
    for mutation in [
        "duplicate-key-id",
        "duplicate-public-key",
        "verifier-set-hash-mismatch",
        "profile-hash-mismatch",
    ] {
        let fixture = Fixture::new();
        let mut config = fixture.config(0);
        let refresh = match mutation {
            "duplicate-key-id" => {
                config.trust_bundle.verifiers[1].key_id = config.trust_bundle.verifiers[0].key_id;
                true
            }
            "duplicate-public-key" => {
                config.trust_bundle.verifiers[1].public_key =
                    config.trust_bundle.verifiers[0].public_key;
                true
            }
            "verifier-set-hash-mismatch" => {
                config.trust_bundle.profile.verifier_set_hash = hash(94);
                false
            }
            "profile-hash-mismatch" => {
                config.trust_bundle.profile.profile_hash = hash(95);
                false
            }
            _ => unreachable!(),
        };
        if refresh {
            refresh_profile_commitments(&mut config.trust_bundle);
        }
        assert_eq!(
            VerifyChallengeStoreV1::open(config).unwrap_err().code(),
            VerifyChallengeErrorCodeV1::NonCanonical,
            "{mutation}"
        );
    }

    let fixture = Fixture::new();
    let mut config = fixture.config(9);
    config.trust_bundle.verifiers.pop();
    refresh_profile_commitments(&mut config.trust_bundle);
    assert_eq!(
        VerifyChallengeStoreV1::open(config).unwrap_err().code(),
        VerifyChallengeErrorCodeV1::InvalidBounds,
        "wrong-verifier-count"
    );

    let fixture = Fixture::new();
    let receipt = fixture.receipt(0);
    let evidence_root = fixture.evaluation_evidence_root(&receipt);
    let store = fixture.store(0);
    store
        .execute(&VerifyCommandV1::AdmitReceipt { receipt })
        .unwrap();
    let result = store.state().unwrap().result.unwrap();
    let valid = fixture.claims(
        result.result_id,
        result.execution_receipt_id,
        0,
        0,
        3,
        evidence_root,
    );

    let mut duplicate_identity = valid.clone();
    duplicate_identity[1] = duplicate_identity[0].clone();
    assert_eq!(
        store
            .execute(&VerifyCommandV1::Evaluate {
                result_id: result.result_id,
                expected_result_revision: 0,
                decision_round: 0,
                accepted_claims: duplicate_identity,
                decision: 0,
                decision_nonce: hash(90),
            })
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::NonCanonical
    );

    for mutation in ["evidence", "statement", "sequence"] {
        let mut claims = valid.clone();
        match mutation {
            "evidence" => {
                claims[0].body.evidence_root = hash(91);
                claims[0].body.statement_digest = digest_value(
                    "trnm.poco-ai.verification-claim-statement.candidate.v1",
                    &(
                        result.result_id,
                        result.execution_receipt_id,
                        fixture.trust.profile.profile_hash,
                        fixture.trust.profile.required_da_policy_hash,
                        fixture.trust.profile.challenge_policy_hash,
                        0u32,
                        0u8,
                        hash(91),
                        0u64,
                    ),
                )
                .unwrap();
            }
            "statement" => claims[0].body.statement_digest = hash(92),
            "sequence" => {
                claims[0].body.claim_sequence = 1;
                claims[0].body.statement_digest = digest_value(
                    "trnm.poco-ai.verification-claim-statement.candidate.v1",
                    &(
                        result.result_id,
                        result.execution_receipt_id,
                        fixture.trust.profile.profile_hash,
                        fixture.trust.profile.required_da_policy_hash,
                        fixture.trust.profile.challenge_policy_hash,
                        0u32,
                        0u8,
                        evidence_root,
                        1u64,
                    ),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        claims[0].claim_id = claims[0].body.claim_id().unwrap();
        claims[0].signature = sign_typed(
            "trnm.poco-ai.verification-claim-signature.v1",
            &claims[0].claim_id,
            &fixture.verifier_keys[0],
        );
        assert_eq!(
            store
                .execute(&VerifyCommandV1::Evaluate {
                    result_id: result.result_id,
                    expected_result_revision: 0,
                    decision_round: 0,
                    accepted_claims: claims,
                    decision: 0,
                    decision_nonce: hash(93),
                })
                .unwrap_err()
                .code(),
            VerifyChallengeErrorCodeV1::InvalidClaim,
            "{mutation}"
        );
    }
}

#[test]
fn challenge_evidence_entries_are_hard_bounded() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let provisional = admit_and_evaluate(&fixture, &store);
    store.execute(&fixture.open_command(&provisional)).unwrap();

    for index in 0u8..64 {
        let current = store.state().unwrap();
        let challenge = current.challenge.unwrap();
        let result = current.result.unwrap();
        let artifact = hash(80 + index);
        let certificate = hash(160 + index);
        let action = (
            challenge.challenge_id,
            challenge.revision,
            result.revision,
            artifact,
            certificate,
        );
        let authorization = actor_authorization(
            &fixture.trust.challenger,
            "trnm.poco-ai.challenge-add-evidence-signature.candidate.v1",
            &action,
            &fixture.challenger_key,
        );
        store
            .execute(&VerifyCommandV1::AddEvidence {
                challenge_id: challenge.challenge_id,
                expected_challenge_revision: challenge.revision,
                expected_result_revision: result.revision,
                evidence_artifact_id: artifact,
                availability_certificate_id: certificate,
                authorization,
            })
            .unwrap();
    }

    let current = store.state().unwrap();
    let challenge = current.challenge.unwrap();
    let result = current.result.unwrap();
    let artifact = hash(144);
    let certificate = hash(224);
    let action = (
        challenge.challenge_id,
        challenge.revision,
        result.revision,
        artifact,
        certificate,
    );
    let authorization = actor_authorization(
        &fixture.trust.challenger,
        "trnm.poco-ai.challenge-add-evidence-signature.candidate.v1",
        &action,
        &fixture.challenger_key,
    );
    assert_eq!(
        store
            .execute(&VerifyCommandV1::AddEvidence {
                challenge_id: challenge.challenge_id,
                expected_challenge_revision: challenge.revision,
                expected_result_revision: result.revision,
                evidence_artifact_id: artifact,
                availability_certificate_id: certificate,
                authorization,
            })
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::InvalidState,
        "evidence-entry-limit-exceeded"
    );
}

#[test]
fn order_finalized_context_is_monotonic_and_deadlines_use_execution_height() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let receipt = fixture.receipt(0);
    let evidence_root = fixture.evaluation_evidence_root(&receipt);
    let admit = VerifyCommandV1::AdmitReceipt { receipt };
    let admitted = store
        .execute_at_height_for_test(101, hash(4), &admit)
        .unwrap();
    assert_eq!(
        (
            admitted.receipt().order_height,
            admitted.receipt().order_block_id
        ),
        (101, hash(4))
    );
    assert_eq!(store.state().unwrap().result.unwrap().accepted_height, 101);

    for (execution, expected) in [
        (
            VerifyOrderFinalizedExecutionContextV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                expected_order_height: 100,
                expected_order_block_id: hash(3),
                order_height: 102,
                order_block_id: hash(5),
            },
            VerifyChallengeErrorCodeV1::StaleRevision,
        ),
        (
            VerifyOrderFinalizedExecutionContextV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                expected_order_height: 101,
                expected_order_block_id: hash(4),
                order_height: 100,
                order_block_id: hash(6),
            },
            VerifyChallengeErrorCodeV1::InvalidContext,
        ),
        (
            VerifyOrderFinalizedExecutionContextV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                expected_order_height: 101,
                expected_order_block_id: hash(4),
                order_height: 101,
                order_block_id: hash(7),
            },
            VerifyChallengeErrorCodeV1::InvalidContext,
        ),
    ] {
        assert_eq!(
            store
                .execute_order_finalized(&execution, &admit)
                .unwrap_err()
                .code(),
            expected
        );
    }

    let submitted = store.state().unwrap().result.unwrap();
    let claims = fixture.claims(
        submitted.result_id,
        submitted.execution_receipt_id,
        0,
        0,
        3,
        evidence_root,
    );
    store
        .execute(&VerifyCommandV1::Evaluate {
            result_id: submitted.result_id,
            expected_result_revision: 0,
            decision_round: 0,
            accepted_claims: claims,
            decision: 0,
            decision_nonce: hash(75),
        })
        .unwrap();
    let provisional = store.state().unwrap().result.unwrap();
    store.execute(&fixture.open_command(&provisional)).unwrap();
    let opened = store.state().unwrap();
    let challenge = opened.challenge.unwrap();
    let result = opened.result.unwrap();
    let action = (
        challenge.challenge_id,
        challenge.revision,
        result.revision,
        hash(80),
        hash(81),
    );
    let authorization = actor_authorization(
        &fixture.trust.challenger,
        "trnm.poco-ai.challenge-add-evidence-signature.candidate.v1",
        &action,
        &fixture.challenger_key,
    );
    assert_eq!(
        store
            .execute_at_height_for_test(
                106,
                hash(8),
                &VerifyCommandV1::AddEvidence {
                    challenge_id: challenge.challenge_id,
                    expected_challenge_revision: challenge.revision,
                    expected_result_revision: result.revision,
                    evidence_artifact_id: hash(80),
                    availability_certificate_id: hash(81),
                    authorization,
                },
            )
            .unwrap_err()
            .code(),
        VerifyChallengeErrorCodeV1::InvalidState
    );
}

#[test]
fn self_consistent_state_and_operation_row_substitution_hit_durable_roots() {
    for (index, kind) in ["state", "operation"].into_iter().enumerate() {
        let fixture = Fixture::new();
        let store = fixture.store(index);
        store
            .execute(&VerifyCommandV1::AdmitReceipt {
                receipt: fixture.receipt(0),
            })
            .unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(fixture.path(index)).unwrap();
        if kind == "state" {
            type MetadataMutationRow = (
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                i64,
                Vec<u8>,
            );
            let row: MetadataMutationRow = connection
                .query_row(
                    "SELECT store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,state FROM verify_challenge_metadata_v1 WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)),
                )
                .unwrap();
            let mut state: VerifyKernelStateV1 = strict_decode(&row.8).unwrap();
            state.bond.version += 1;
            let state_bytes = canonical_bytes(&state).unwrap();
            let fenced = [u8::from(row.7 != 0)];
            let row_checksum = checksum(&[
                &2u16.to_be_bytes(),
                &row.0,
                &row.1,
                &row.2,
                &row.3,
                &row.4,
                &row.5,
                &row.6,
                &fenced,
                &state_bytes,
            ]);
            connection
                .execute(
                    "UPDATE verify_challenge_metadata_v1 SET state=?1,row_checksum=?2 WHERE singleton=1",
                    rusqlite::params![state_bytes, row_checksum.0.as_slice()],
                )
                .unwrap();
        } else {
            type OperationMutationRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
            let row: OperationMutationRow = connection
                .query_row(
                    "SELECT operation_id,sequence,command,receipt FROM verify_challenge_operations_v1 LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            let mut receipt: VerifyTransitionReceiptV1 = strict_decode(&row.3).unwrap();
            receipt.post_state_root = hash(99);
            let receipt_bytes = canonical_bytes(&receipt).unwrap();
            let row_checksum = checksum(&[&row.0, &row.1, &row.2, &receipt_bytes]);
            connection
                .execute(
                    "UPDATE verify_challenge_operations_v1 SET receipt=?1,row_checksum=?2 WHERE operation_id=?3",
                    rusqlite::params![receipt_bytes, row_checksum.0.as_slice(), row.0],
                )
                .unwrap();
        }
        drop(connection);
        assert_eq!(
            VerifyChallengeStoreV1::open(fixture.config(index))
                .unwrap_err()
                .code(),
            VerifyChallengeErrorCodeV1::TamperDetected,
            "{kind}"
        );
    }
}

#[test]
fn vector_inventory_matches_executable_candidate_assertions() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/protocol/poco-ai-native-v1/vectors/cev1-verify-challenge-kernel-v1.json"
    )))
    .unwrap();
    let strings = |name: &str| {
        vectors[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        strings("positive_cases"),
        vec![
            "provider-signed-receipt-admitted",
            "exact-receipt-replay",
            "three-of-four-weighted-verifier-claims",
            "atomic-two-transition-evaluation",
            "provisional-challenge-window-derived",
            "challenger-signed-open-and-bond-hold",
            "challenger-evidence-append",
            "provider-response",
            "upheld-quorum-final-invalid-and-bond-release",
            "rejected-quorum-return-provisional-and-bond-slash",
            "fresh-reopen-exact-state",
            "applied-ack-lost-exact-replay",
            "unique-verifier-identity-weighted-quorum",
            "exact-claim-statement-evidence-sequence-binding",
            "monotonic-order-finalized-height-and-block-cas",
            "durable-state-and-operation-tail-roots",
        ]
    );
    assert_eq!(
        strings("negative_cases"),
        vec![
            "bad-provider-signature",
            "conflicting-second-receipt",
            "under-quorum-evaluation",
            "bad-verifier-signature",
            "wrong-challenger-authority",
            "wrong-challenge-bond-amount",
            "challenge-deadline-before-open",
            "stale-evidence-revision",
            "evidence-entry-limit-exceeded",
            "schema-table-missing",
            "metadata-row-tamper",
            "operation-journal-deletion",
            "sqlite-sidecar-present",
            "third-state-permanent-fence",
            "duplicate-bootstrap-key-id",
            "duplicate-bootstrap-public-key",
            "wrong-verifier-count",
            "committed-verifier-set-hash-mismatch",
            "committed-profile-hash-mismatch",
            "duplicate-verifier-identity",
            "mismatched-claim-statement",
            "mismatched-claim-evidence-root",
            "mismatched-claim-sequence",
            "challenge-statement-substitution",
            "order-height-regression",
            "order-height-cas-mismatch",
            "same-height-block-substitution",
            "deadline-expired-at-advanced-order-height",
            "self-consistent-state-row-substitution",
            "self-consistent-operation-row-substitution",
        ]
    );
    assert_eq!(
        strings("crash_reopen_cases"),
        vec![
            "not-applied-ack-lost-no-state-change",
            "applied-ack-lost-exact-replay",
            "third-state-permanent-fence",
            "fresh-reopen-state-and-receipt",
            "schema-drift-no-migration",
            "sidecar-reject-before-open",
        ]
    );
}

#[test]
fn open_existing_requires_precreated_regular_nonsymlink_store() {
    let fixture = Fixture::new();
    let config = fixture.config(0);

    assert_eq!(
        VerifyChallengeStoreV1::open_existing(config.clone())
            .expect_err("missing store")
            .code(),
        VerifyChallengeErrorCodeV1::StoreFailure
    );
    assert!(!config.path.exists(), "strict open must not create a store");

    drop(VerifyChallengeStoreV1::open(config.clone()).expect("create store"));
    drop(VerifyChallengeStoreV1::open_existing(config.clone()).expect("strict reopen"));

    let directory_path = fixture.directory.path().join("not-a-store-file");
    fs::create_dir(&directory_path).expect("directory object");
    let mut directory_config = config.clone();
    directory_config.path = directory_path;
    assert_eq!(
        VerifyChallengeStoreV1::open_existing(directory_config)
            .expect_err("directory store path")
            .code(),
        VerifyChallengeErrorCodeV1::StoreFailure
    );

    #[cfg(unix)]
    {
        let symlink_path = fixture.directory.path().join("store-link.sqlite");
        std::os::unix::fs::symlink(&config.path, &symlink_path).expect("store symlink");
        let mut symlink_config = config;
        symlink_config.path = symlink_path;
        assert_eq!(
            VerifyChallengeStoreV1::open_existing(symlink_config)
                .expect_err("symlink store path")
                .code(),
            VerifyChallengeErrorCodeV1::StoreFailure
        );
    }
}

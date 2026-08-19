use std::{fs, path::PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use serde_json::Value;
use tempfile::TempDir;

use crate::{
    codec::{canonical_bytes, checksum, digest_value},
    engine::{
        canonical_command_for_test, cumulative_root_for_test, cumulative_usage_for_test,
        receipts_root_for_test, signature_digest_for_test, state_root,
    },
    *,
};

fn h(value: u64) -> Hash32V1 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    Hash32V1(bytes)
}

fn agent(value: u64) -> AgentIdV1 {
    AgentIdV1(h(value).0)
}

fn key_id(value: u64) -> AgentKeyIdV1 {
    AgentKeyIdV1(h(value).0)
}

fn account(value: u64) -> AccountIdV1 {
    AccountIdV1(h(value).0)
}

fn task(value: u64) -> TaskIdV1 {
    TaskIdV1(h(value).0)
}

fn lease(value: u64) -> LeaseIdV1 {
    LeaseIdV1(h(value).0)
}

fn result(value: u64) -> ResultIdV1 {
    ResultIdV1(h(value).0)
}

fn escrow(value: u64) -> EscrowIdV1 {
    EscrowIdV1(h(value).0)
}

fn certificate(value: u64) -> AvailabilityCertificateIdV1 {
    AvailabilityCertificateIdV1(h(value).0)
}

struct Harness {
    _temporary: TempDir,
    path: PathBuf,
    store_id: Hash32V1,
    trust: ConsumptionSettlementFreshGenesisTrustBundleV1,
    provider_key: SigningKey,
    consumer_key: SigningKey,
}

impl Harness {
    fn new() -> Self {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join("consumption-settlement.sqlite");
        let provider_key = SigningKey::from_bytes(&[7; 32]);
        let consumer_key = SigningKey::from_bytes(&[9; 32]);
        let policy = SettlementPolicyV1 {
            schema_version: SCHEMA_VERSION_V1,
            policy_revision: 3,
            minimum_rollup_challenge_blocks: 2,
            maximum_rollups: 1,
            protocol_fee_numerator: 1,
            protocol_fee_denominator: 10,
            fee_schedule_hash: h(91),
        };
        let trust = ConsumptionSettlementFreshGenesisTrustBundleV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: ProtocolContextV1 {
                genesis_hash: h(1),
                chain_id: "trnm-test".to_owned(),
                protocol_version: 1,
                stack_profile_hash: h(2),
            },
            initial_order_height: 9,
            initial_order_block_id: h(900),
            provider: RegisteredBilateralKeyV1 {
                agent_id: agent(10),
                key_id: key_id(11),
                public_key: provider_key.verifying_key().to_bytes(),
                policy_revision: 4,
                key_generation: 5,
            },
            consumer: RegisteredBilateralKeyV1 {
                agent_id: agent(20),
                key_id: key_id(21),
                public_key: consumer_key.verifying_key().to_bytes(),
                policy_revision: 6,
                key_generation: 7,
            },
            task_id: task(30),
            lease_id: lease(31),
            attempt: 1,
            result_id: result(32),
            result_revision: 8,
            result_status: RESULT_STATUS_FINAL_VALID_V1,
            escrow_id: escrow(33),
            escrow_version: 2,
            asset_id: h(34),
            escrow_funding: 1_000,
            provider_account_id: account(40),
            consumer_account_id: account(41),
            protocol_account_id: account(42),
            provider_opening_balance: 100,
            consumer_opening_balance: 200,
            protocol_opening_balance: 300,
            prices: vec![ConsumptionPriceV1 {
                resource_class: 7,
                resource_id: b"gpu".to_vec(),
                meter_id: b"meter".to_vec(),
                meter_version: 1,
                unit: 3,
                unit_price: 3,
            }],
            accepted_evidence_certificates: vec![certificate(50)],
            related_party_policy_hash: h(51),
            settlement_policy: policy,
        };
        Self {
            _temporary: temporary,
            path,
            store_id: h(60),
            trust,
            provider_key,
            consumer_key,
        }
    }

    fn config(&self) -> ConsumptionSettlementStoreConfigV1 {
        ConsumptionSettlementStoreConfigV1 {
            path: self.path.clone(),
            store_id: self.store_id,
            trust_bundle: self.trust.clone(),
        }
    }

    fn open(&self) -> ConsumptionSettlementStoreV1 {
        ConsumptionSettlementStoreV1::open(self.config()).expect("open candidate store")
    }

    fn execution(
        &self,
        expected_height: u64,
        expected_block: Hash32V1,
        order_height: u64,
    ) -> ConsumptionOrderFinalizedExecutionContextV1 {
        ConsumptionOrderFinalizedExecutionContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: self.trust.context.clone(),
            expected_order_height: expected_height,
            expected_order_block_id: expected_block,
            order_height,
            order_block_id: h(1_000 + order_height),
        }
    }

    fn sign_entry(
        &self,
        registered: &RegisteredBilateralKeyV1,
        key: &SigningKey,
        body_id: Hash32V1,
        height: u64,
        domain: &str,
    ) -> BilateralSignatureEntryV1 {
        let statement = BilateralSignatureStatementV1 {
            schema_version: SCHEMA_VERSION_V1,
            body_id,
            agent_id: registered.agent_id,
            key_id: registered.key_id,
            key_role: KEY_ROLE_BILATERAL_RECEIPT_V1,
            policy_revision: registered.policy_revision,
            key_generation: registered.key_generation,
            authority_height: height,
        };
        let digest = signature_digest_for_test(domain, &statement).expect("signature digest");
        BilateralSignatureEntryV1 {
            agent_id: registered.agent_id,
            key_id: registered.key_id,
            key_role: KEY_ROLE_BILATERAL_RECEIPT_V1,
            policy_revision: registered.policy_revision,
            key_generation: registered.key_generation,
            authority_height: height,
            signature_scheme: SIGNATURE_SCHEME_ED25519_V1,
            signature: key.sign(&digest.0).to_bytes().to_vec(),
        }
    }

    fn receipt(
        &self,
        prior: Option<&ConsumptionReceiptStateV1>,
        height: u64,
        amount: u128,
    ) -> ConsumptionReceiptV1 {
        let sequence = prior
            .map(|prior| prior.receipt.body.sequence + 1)
            .unwrap_or(1);
        let period_start_height = prior
            .map(|prior| prior.receipt.body.period_end_height + 1)
            .unwrap_or(height);
        let usage = vec![ResourceUsageV1 {
            resource_class: 7,
            resource_id: b"gpu".to_vec(),
            meter_id: b"meter".to_vec(),
            meter_version: 1,
            amount,
            unit: 3,
            measurement_commitment: h(2_000 + sequence),
        }];
        let cumulative = cumulative_usage_for_test(prior, &usage).expect("cumulative usage");
        let prior_charge = prior
            .map(|prior| prior.receipt.body.cumulative_charge)
            .unwrap_or(0);
        let body = ConsumptionReceiptBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: self.trust.context.clone(),
            provider_id: self.trust.provider.agent_id,
            consumer_id: self.trust.consumer.agent_id,
            task_id: self.trust.task_id,
            lease_id: self.trust.lease_id,
            attempt: self.trust.attempt,
            result_id: self.trust.result_id,
            meter_id: b"meter".to_vec(),
            meter_version: 1,
            sequence,
            period_start_height,
            period_end_height: height,
            usage,
            prior_receipt_id: prior.map(|prior| prior.receipt_id),
            cumulative_usage_root: cumulative_root_for_test(&cumulative).expect("cumulative root"),
            cumulative_usage: cumulative,
            cumulative_charge: prior_charge + amount * 3,
            evidence_certificate_id: certificate(50),
            related_party_policy_hash: self.trust.related_party_policy_hash,
        };
        self.sign_receipt(body)
    }

    fn sign_receipt(&self, body: ConsumptionReceiptBodyV1) -> ConsumptionReceiptV1 {
        let id = consumption_receipt_id_v1(&body).expect("receipt ID");
        ConsumptionReceiptV1 {
            provider_signature: self.sign_entry(
                &self.trust.provider,
                &self.provider_key,
                Hash32V1::from(id),
                body.period_end_height,
                "trnm.poco-ai.consumption-receipt-provider-signature.v1",
            ),
            consumer_signature: self.sign_entry(
                &self.trust.consumer,
                &self.consumer_key,
                Hash32V1::from(id),
                body.period_end_height,
                "trnm.poco-ai.consumption-receipt-consumer-signature.v1",
            ),
            body,
        }
    }

    fn rollup(
        &self,
        state: &ConsumptionSettlementKernelStateV1,
        height: u64,
    ) -> ConsumptionRollupV1 {
        let ids: Vec<_> = state
            .receipts
            .iter()
            .map(|receipt| receipt.receipt_id)
            .collect();
        let last = &state.receipts.last().expect("receipt chain").receipt.body;
        let totals = last
            .cumulative_usage
            .iter()
            .map(|entry| ResourceUsageV1 {
                resource_class: entry.resource_class,
                resource_id: entry.resource_id.clone(),
                meter_id: entry.meter_id.clone(),
                meter_version: entry.meter_version,
                amount: entry.total_amount,
                unit: entry.unit,
                measurement_commitment: entry.accumulator_commitment,
            })
            .collect();
        let body = ConsumptionRollupBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: self.trust.context.clone(),
            provider_id: self.trust.provider.agent_id,
            consumer_id: self.trust.consumer.agent_id,
            task_id: self.trust.task_id,
            lease_id: self.trust.lease_id,
            attempt: self.trust.attempt,
            result_id: self.trust.result_id,
            meter_id: b"meter".to_vec(),
            meter_version: 1,
            first_sequence: 1,
            last_sequence: u64::try_from(ids.len()).expect("bounded receipt count"),
            receipt_count: u32::try_from(ids.len()).expect("bounded receipt count"),
            receipts_root: receipts_root_for_test(&ids).expect("receipt root"),
            receipt_ids: ids,
            usage_totals: totals,
            total_charge: last.cumulative_charge,
            evidence_certificate_id: certificate(50),
            escrow_id: self.trust.escrow_id,
            settlement_policy_hash: settlement_policy_hash_v1(&self.trust.settlement_policy)
                .expect("policy hash"),
            related_party_policy_hash: self.trust.related_party_policy_hash,
        };
        self.sign_rollup(body, height)
    }

    fn sign_rollup(&self, body: ConsumptionRollupBodyV1, height: u64) -> ConsumptionRollupV1 {
        let id = consumption_rollup_id_v1(&body).expect("rollup ID");
        ConsumptionRollupV1 {
            provider_signature: self.sign_entry(
                &self.trust.provider,
                &self.provider_key,
                Hash32V1::from(id),
                height,
                "trnm.poco-ai.consumption-rollup-provider-signature.v1",
            ),
            consumer_signature: self.sign_entry(
                &self.trust.consumer,
                &self.consumer_key,
                Hash32V1::from(id),
                height,
                "trnm.poco-ai.consumption-rollup-consumer-signature.v1",
            ),
            body,
        }
    }
}

fn execute_receipt_chain(
    harness: &Harness,
    store: &ConsumptionSettlementStoreV1,
) -> (Hash32V1, ConsumptionSettlementKernelStateV1) {
    let first = harness.receipt(None, 10, 100);
    let first_execution = harness.execution(9, h(900), 10);
    store
        .execute_order_finalized(
            &first_execution,
            &ConsumptionSettlementCommandV1::AdmitReceipt { receipt: first },
        )
        .expect("first receipt");
    let after_first = store.state().expect("state after first receipt");
    let second = harness.receipt(after_first.receipts.last(), 11, 50);
    let second_execution = harness.execution(10, h(1_010), 11);
    store
        .execute_order_finalized(
            &second_execution,
            &ConsumptionSettlementCommandV1::AdmitReceipt { receipt: second },
        )
        .expect("second receipt");
    (h(1_011), store.state().expect("state after receipts"))
}

fn execute_rollup(
    harness: &Harness,
    store: &ConsumptionSettlementStoreV1,
) -> (Hash32V1, ConsumptionSettlementKernelStateV1) {
    let (parent_block, state) = execute_receipt_chain(harness, store);
    let rollup = harness.rollup(&state, 12);
    let receipts = state
        .receipts
        .iter()
        .map(|receipt| receipt.receipt.clone())
        .collect();
    store
        .execute_order_finalized(
            &harness.execution(11, parent_block, 12),
            &ConsumptionSettlementCommandV1::AdmitRollup { rollup, receipts },
        )
        .expect("rollup admission");
    (h(1_012), store.state().expect("state after rollup"))
}

fn advance_empty_blocks_through(
    harness: &Harness,
    store: &ConsumptionSettlementStoreV1,
    mut height: u64,
    mut block_id: Hash32V1,
    target_height: u64,
) -> Hash32V1 {
    while height < target_height {
        let next_height = height + 1;
        let readback = store
            .advance_empty_order_finalized_v1(&harness.execution(height, block_id, next_height))
            .expect("direct-successor empty finalized block");
        height = readback.order_height();
        block_id = readback.order_block_id();
    }
    block_id
}

fn settlement_operation(
    harness: &Harness,
    state: &ConsumptionSettlementKernelStateV1,
) -> SettlementOperationBodyV1 {
    SettlementOperationBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: harness.trust.context.clone(),
        task_id: harness.trust.task_id,
        lease_id: harness.trust.lease_id,
        attempt: harness.trust.attempt,
        result_id: harness.trust.result_id,
        expected_result_revision: state.result.revision,
        expected_escrow_version: state.escrow.version,
        expected_rollup_version: state.rollup.as_ref().expect("rollup").version,
        settlement_policy_hash: settlement_policy_hash_v1(&harness.trust.settlement_policy)
            .expect("policy hash"),
    }
}

#[test]
fn receipt_rollup_and_settlement_are_bilateral_gap_free_and_conserved() {
    let harness = Harness::new();
    let store = harness.open();
    let (parent_block, rolled_up) = execute_rollup(&harness, &store);
    let rollup = rolled_up.rollup.as_ref().expect("rollup");
    assert_eq!(rollup.accepted_height, 12);
    assert_eq!(rollup.challenge_close_height, 14);
    assert!(
        rolled_up
            .receipts
            .iter()
            .all(|receipt| receipt.status == 1
                && receipt.assigned_rollup_id == Some(rollup.rollup_id))
    );

    let command = ConsumptionSettlementCommandV1::Settle {
        operation: settlement_operation(&harness, &rolled_up),
    };
    let mature_parent = advance_empty_blocks_through(&harness, &store, 12, parent_block, 14);
    let outcome = store
        .execute_order_finalized(&harness.execution(14, mature_parent, 15), &command)
        .expect("mature settlement");
    assert!(outcome.confirmed.receipt().settlement_id.is_some());
    let final_state = store.state().expect("final state");
    let settlement = final_state.settlement.as_ref().expect("settlement state");
    assert_eq!(final_state.escrow.balance, 0);
    assert!(final_state.escrow.closed);
    assert_eq!(
        final_state.result.settlement_maturity,
        SETTLEMENT_MATURITY_FINAL_V1
    );
    assert_eq!(final_state.rollup.as_ref().expect("rollup").status, 1);
    let input_total = settlement.intent.inputs[0].amount;
    let output_total: u128 = settlement
        .intent
        .planned_deltas
        .iter()
        .map(|delta| delta.amount)
        .sum();
    assert_eq!(input_total, output_total);
    assert_eq!(input_total, 1_000);
    let balances: Vec<_> = final_state
        .accounts
        .iter()
        .map(|account| (account.account_id, account.balance))
        .collect();
    assert!(balances.contains(&(harness.trust.provider_account_id, 505)));
    assert!(balances.contains(&(harness.trust.consumer_account_id, 750)));
    assert!(balances.contains(&(harness.trust.protocol_account_id, 345)));
    assert_eq!(
        settlement.receipt.applied_deltas,
        settlement.intent.planned_deltas
    );
}

#[test]
fn pre_vote_preview_checks_bilateral_receipt_and_preserves_durable_rows() {
    let harness = Harness::new();
    let store = harness.open();
    let command = ConsumptionSettlementCommandV1::AdmitReceipt {
        receipt: harness.receipt(None, 10, 25),
    };
    let before = store.fresh_readback().expect("fresh parent");
    let preview = store
        .preview_before_vote_v1(&before, 10, h(1_010), &[command])
        .expect("read-only settlement preview");
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
fn receipt_signatures_sequence_prices_and_cumulative_roots_fail_closed() {
    let harness = Harness::new();
    let store = harness.open();
    let execution = harness.execution(9, h(900), 10);

    let mut bad_signature = harness.receipt(None, 10, 100);
    bad_signature.provider_signature.signature[0] ^= 1;
    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: bad_signature,
            },
        )
        .expect_err("bad signature");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::InvalidSignature
    );

    let mut wrong_sequence = harness.receipt(None, 10, 100);
    wrong_sequence.body.sequence = 2;
    wrong_sequence = harness.sign_receipt(wrong_sequence.body);
    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: wrong_sequence,
            },
        )
        .expect_err("sequence gap");
    assert_eq!(error.code(), ConsumptionSettlementErrorCodeV1::SequenceGap);

    let mut wrong_root = harness.receipt(None, 10, 100);
    wrong_root.body.cumulative_usage_root = h(999);
    wrong_root = harness.sign_receipt(wrong_root.body);
    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: wrong_root,
            },
        )
        .expect_err("cumulative root substitution");
    assert_eq!(error.code(), ConsumptionSettlementErrorCodeV1::RootMismatch);

    let mut wrong_charge = harness.receipt(None, 10, 100);
    wrong_charge.body.cumulative_charge += 1;
    wrong_charge = harness.sign_receipt(wrong_charge.body);
    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: wrong_charge,
            },
        )
        .expect_err("charge substitution");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::InsufficientFunds
    );

    let mut untrusted_evidence = harness.receipt(None, 10, 100);
    untrusted_evidence.body.evidence_certificate_id = certificate(999);
    untrusted_evidence = harness.sign_receipt(untrusted_evidence.body);
    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: untrusted_evidence,
            },
        )
        .expect_err("untrusted evidence certificate");
    assert_eq!(error.code(), ConsumptionSettlementErrorCodeV1::Unauthorized);
}

#[test]
fn rollup_requires_complete_exact_unassigned_receipt_interval() {
    let harness = Harness::new();
    let store = harness.open();
    let (parent_block, state) = execute_receipt_chain(&harness, &store);
    let rollup = harness.rollup(&state, 12);
    let receipts: Vec<_> = state
        .receipts
        .iter()
        .map(|receipt| receipt.receipt.clone())
        .collect();
    let execution = harness.execution(11, parent_block, 12);

    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitRollup {
                rollup: rollup.clone(),
                receipts: receipts[..1].to_vec(),
            },
        )
        .expect_err("receipt omission");
    assert_eq!(error.code(), ConsumptionSettlementErrorCodeV1::Conflict);

    let mut wrong_root = rollup.clone();
    wrong_root.body.receipts_root = h(888);
    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitRollup {
                rollup: wrong_root,
                receipts: receipts.clone(),
            },
        )
        .expect_err("receipt root substitution");
    assert_eq!(error.code(), ConsumptionSettlementErrorCodeV1::RootMismatch);

    let mut bad_signature = rollup.clone();
    bad_signature.consumer_signature.signature[0] ^= 1;
    let error = store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitRollup {
                rollup: bad_signature,
                receipts: receipts.clone(),
            },
        )
        .expect_err("rollup signature substitution");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::InvalidSignature
    );

    store
        .execute_order_finalized(
            &execution,
            &ConsumptionSettlementCommandV1::AdmitRollup {
                rollup: rollup.clone(),
                receipts: receipts.clone(),
            },
        )
        .expect("valid rollup");
    let next = harness.execution(12, h(1_012), 13);
    let error = store
        .execute_order_finalized(
            &next,
            &ConsumptionSettlementCommandV1::AdmitRollup { rollup, receipts },
        )
        .expect_err("second rollup");
    assert!(matches!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::InvalidTransition
            | ConsumptionSettlementErrorCodeV1::Conflict
    ));
}

#[test]
fn settlement_maturity_versions_replay_and_one_shot_are_exact() {
    let harness = Harness::new();
    let store = harness.open();
    let (parent_block, state) = execute_rollup(&harness, &store);
    let valid_operation = settlement_operation(&harness, &state);
    let command = ConsumptionSettlementCommandV1::Settle {
        operation: valid_operation.clone(),
    };
    let early_execution = harness.execution(12, parent_block, 14);
    let error = store
        .execute_order_finalized(&early_execution, &command)
        .expect_err("challenge close height is not mature");
    assert_eq!(error.code(), ConsumptionSettlementErrorCodeV1::NotMature);

    let mut stale_operation = valid_operation.clone();
    stale_operation.expected_escrow_version += 1;
    let error = store
        .execute_order_finalized(
            &harness.execution(12, parent_block, 15),
            &ConsumptionSettlementCommandV1::Settle {
                operation: stale_operation,
            },
        )
        .expect_err("stale escrow version");
    assert_eq!(error.code(), ConsumptionSettlementErrorCodeV1::StaleVersion);

    let mature_parent = advance_empty_blocks_through(&harness, &store, 12, parent_block, 14);
    let execution = harness.execution(14, mature_parent, 15);
    let first = store
        .execute_order_finalized(&execution, &command)
        .expect("first settlement");
    let replay = store
        .execute_order_finalized(&execution, &command)
        .expect("exact replay");
    assert!(!first.replay);
    assert!(replay.replay);
    assert_eq!(first.confirmed.receipt(), replay.confirmed.receipt());

    let error = store
        .execute_order_finalized(&harness.execution(15, h(1_015), 16), &command)
        .expect_err("settlement cannot be consumed twice");
    assert!(matches!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::AlreadyConsumed
            | ConsumptionSettlementErrorCodeV1::Conflict
    ));
}

#[test]
fn commit_uncertainty_reopens_to_exact_source_target_or_permanent_fence() {
    let source = Harness::new();
    let source_store = source.open();
    let source_command = ConsumptionSettlementCommandV1::AdmitReceipt {
        receipt: source.receipt(None, 10, 100),
    };
    let source_execution = source.execution(9, h(900), 10);
    let error = source_store
        .execute_with_fault(
            &source_execution,
            &source_command,
            ConsumptionCommitFaultV1::NotAppliedAckLost,
        )
        .expect_err("not-applied uncertainty");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::CommitUncertain
    );
    drop(source_store);
    assert!(source
        .open()
        .state()
        .expect("source state")
        .receipts
        .is_empty());

    let target = Harness::new();
    let target_store = target.open();
    let target_command = ConsumptionSettlementCommandV1::AdmitReceipt {
        receipt: target.receipt(None, 10, 100),
    };
    let target_execution = target.execution(9, h(900), 10);
    let error = target_store
        .execute_with_fault(
            &target_execution,
            &target_command,
            ConsumptionCommitFaultV1::AppliedAckLost,
        )
        .expect_err("applied uncertainty");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::CommitUncertain
    );
    let replay = target_store
        .execute_order_finalized(&target_execution, &target_command)
        .expect("applied acknowledgement-loss exact replay");
    assert!(replay.is_replay());
    drop(target_store);
    assert_eq!(
        target.open().state().expect("target state").receipts.len(),
        1
    );

    let fenced = Harness::new();
    let fenced_store = fenced.open();
    let fenced_command = ConsumptionSettlementCommandV1::AdmitReceipt {
        receipt: fenced.receipt(None, 10, 100),
    };
    let fenced_execution = fenced.execution(9, h(900), 10);
    let error = fenced_store
        .execute_with_fault(
            &fenced_execution,
            &fenced_command,
            ConsumptionCommitFaultV1::ThirdState,
        )
        .expect_err("third state");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::ThirdStateFenced
    );
    drop(fenced_store);
    let error = ConsumptionSettlementStoreV1::open(fenced.config()).expect_err("fenced reopen");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::ThirdStateFenced
    );
}

#[test]
fn finalized_block_journal_covers_empty_same_block_and_tamper_boundaries() {
    let harness = Harness::new();
    let store = harness.open();
    let genesis = store.fresh_readback().expect("genesis readback");
    let first_empty = harness.execution(genesis.order_height(), genesis.order_block_id(), 10);
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
    let second_empty = harness.execution(first.order_height(), first.order_block_id(), 11);
    let second = store
        .advance_empty_order_finalized_v1(&second_empty)
        .expect("consecutive empty block");
    assert_ne!(
        second.durable_finalized_block_root(),
        first.durable_finalized_block_root()
    );
    assert_eq!(
        store
            .advance_empty_order_finalized_v1(&harness.execution(9, h(900), 10))
            .expect_err("stale source")
            .code(),
        ConsumptionSettlementErrorCodeV1::StaleVersion
    );
    assert_eq!(
        store
            .advance_empty_order_finalized_v1(&harness.execution(
                second.order_height(),
                second.order_block_id(),
                second.order_height() + 2,
            ))
            .expect_err("skipped target")
            .code(),
        ConsumptionSettlementErrorCodeV1::InvalidContext
    );
    drop(store);
    Connection::open(&harness.path)
        .expect("open marker database")
        .execute(
            "UPDATE finalized_blocks SET checksum=zeroblob(32) WHERE marker_sequence=1",
            [],
        )
        .expect("tamper marker");
    assert_eq!(
        ConsumptionSettlementStoreV1::open(harness.config())
            .expect_err("marker tamper")
            .code(),
        ConsumptionSettlementErrorCodeV1::TamperDetected
    );

    let partial = Harness::new();
    let partial_store = partial.open();
    partial_store
        .advance_empty_order_finalized_v1(&partial.execution(9, h(900), 10))
        .expect("partial target");
    drop(partial_store);
    Connection::open(&partial.path)
        .expect("open partial database")
        .execute("DELETE FROM finalized_blocks WHERE marker_sequence=1", [])
        .expect("delete tail marker");
    assert_eq!(
        ConsumptionSettlementStoreV1::open(partial.config())
            .expect_err("partial marker write")
            .code(),
        ConsumptionSettlementErrorCodeV1::TamperDetected
    );

    let multi = Harness::new();
    let multi_store = multi.open();
    multi_store
        .execute_order_finalized(
            &multi.execution(9, h(900), 10),
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: multi.receipt(None, 10, 100),
            },
        )
        .expect("first same-block command");
    let first_root = multi_store
        .fresh_readback()
        .expect("first same-block readback")
        .durable_finalized_block_root();
    let state = multi_store.state().expect("state after first command");
    let rollup = multi.rollup(&state, 10);
    let receipts = state
        .receipts
        .iter()
        .map(|receipt| receipt.receipt.clone())
        .collect();
    multi_store
        .execute_order_finalized(
            &multi.execution(10, h(1_010), 10),
            &ConsumptionSettlementCommandV1::AdmitRollup { rollup, receipts },
        )
        .expect("second same-block command");
    assert_ne!(
        multi_store
            .fresh_readback()
            .expect("second same-block readback")
            .durable_finalized_block_root(),
        first_root
    );
    drop(multi_store);
    ConsumptionSettlementStoreV1::open(multi.config()).expect("same-block reopen");
}

#[test]
fn schema_sidecar_row_and_self_consistent_state_substitution_fail_closed() {
    let schema = Harness::new();
    drop(schema.open());
    Connection::open(&schema.path)
        .expect("open schema database")
        .execute("DROP TABLE operations", [])
        .expect("drop table");
    let error = ConsumptionSettlementStoreV1::open(schema.config()).expect_err("schema drift");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::SchemaMismatch
    );

    let sidecar = Harness::new();
    drop(sidecar.open());
    fs::write(format!("{}-wal", sidecar.path.display()), b"sentinel").expect("write sidecar");
    let error = ConsumptionSettlementStoreV1::open(sidecar.config()).expect_err("sidecar");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::SidecarPresent
    );

    let row = Harness::new();
    let row_store = row.open();
    row_store
        .execute_order_finalized(
            &row.execution(9, h(900), 10),
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: row.receipt(None, 10, 100),
            },
        )
        .expect("receipt before row tamper");
    drop(row_store);
    Connection::open(&row.path)
        .expect("open row database")
        .execute(
            "UPDATE operations SET receipt=zeroblob(7) WHERE sequence=1",
            [],
        )
        .expect("tamper row");
    let error = ConsumptionSettlementStoreV1::open(row.config()).expect_err("row tamper");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::TamperDetected
    );

    let state = Harness::new();
    let state_store = state.open();
    state_store
        .execute_order_finalized(
            &state.execution(9, h(900), 10),
            &ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: state.receipt(None, 10, 100),
            },
        )
        .expect("receipt before state tamper");
    drop(state_store);
    let connection = Connection::open(&state.path).expect("open state database");
    let row = connection
        .query_row("SELECT config,sequence,height,block_id,state,journal_root,fenced FROM metadata WHERE singleton=1", [], |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,Vec<u8>>(5)?,row.get::<_,i64>(6)?)))
        .expect("metadata row");
    let (config_bytes, sequence, height, block_id, state_bytes, journal_root, fenced) = row;
    let mut altered: ConsumptionSettlementKernelStateV1 =
        borsh::from_slice(&state_bytes).expect("decode durable state");
    altered.accounts[0].balance += 1;
    let altered_bytes = canonical_bytes(&altered).expect("altered state bytes");
    let altered_root = state_root(&altered).expect("altered state root");
    let sequence_u64 = u64::try_from(sequence).expect("sequence");
    let height_u64 = u64::try_from(height).expect("height");
    let block: [u8; 32] = block_id.clone().try_into().expect("block ID");
    let journal: [u8; 32] = journal_root.clone().try_into().expect("journal root");
    let sum = checksum(&[
        &2_u16.to_le_bytes(),
        &config_bytes,
        &sequence_u64.to_le_bytes(),
        &height_u64.to_le_bytes(),
        &block,
        &altered_bytes,
        &altered_root.0,
        &journal,
        &[u8::try_from(fenced).expect("fenced")],
    ]);
    connection
        .execute(
            "UPDATE metadata SET state=?1,state_root=?2,checksum=?3 WHERE singleton=1",
            params![altered_bytes, altered_root.0.to_vec(), sum.0.to_vec()],
        )
        .expect("self-consistent state substitution");
    drop(connection);
    let error = ConsumptionSettlementStoreV1::open(state.config())
        .expect_err("journal replay rejects state substitution");
    assert_eq!(
        error.code(),
        ConsumptionSettlementErrorCodeV1::TamperDetected
    );
}

#[test]
fn vector_inventory_matches_candidate_assertions() {
    let vectors: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/protocol/poco-ai-native-v1/vectors/cev1-consumption-settlement-kernel-v1.json"
    )))
    .expect("vector JSON");
    assert_eq!(vectors["schema_version"].as_u64(), Some(1));
    assert_eq!(
        vectors["classification"].as_str(),
        Some("candidate-non-normative")
    );
    assert_eq!(
        vectors["kernel_scope"].as_str(),
        Some("single-asset-single-result-single-rollup")
    );
    assert_eq!(
        vectors["positive_inventory"].as_array().map(Vec::len),
        Some(10)
    );
    assert_eq!(
        vectors["negative_inventory"].as_array().map(Vec::len),
        Some(56)
    );
    assert_eq!(vectors["crash_inventory"].as_array().map(Vec::len), Some(6));
}

#[test]
fn canonical_command_bytes_reject_trailing_and_truncation() {
    let harness = Harness::new();
    let command = ConsumptionSettlementCommandV1::AdmitReceipt {
        receipt: harness.receipt(None, 10, 100),
    };
    let bytes = canonical_command_for_test(&command).expect("canonical command");
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(borsh::from_slice::<ConsumptionSettlementCommandV1>(&trailing).is_err());
    assert!(
        borsh::from_slice::<ConsumptionSettlementCommandV1>(&bytes[..bytes.len() - 1]).is_err()
    );
    assert_ne!(
        digest_value("trnm.poco-ai.test-a", &command).expect("digest a"),
        digest_value("trnm.poco-ai.test-b", &command).expect("digest b")
    );
}

#[test]
fn open_existing_requires_precreated_regular_nonsymlink_store() {
    let harness = Harness::new();
    let config = harness.config();

    assert_eq!(
        ConsumptionSettlementStoreV1::open_existing(config.clone())
            .expect_err("missing store")
            .code(),
        ConsumptionSettlementErrorCodeV1::StoreFailure
    );
    assert!(!config.path.exists(), "strict open must not create a store");

    drop(ConsumptionSettlementStoreV1::open(config.clone()).expect("create store"));
    drop(ConsumptionSettlementStoreV1::open_existing(config.clone()).expect("strict reopen"));

    let directory_path = config.path.parent().unwrap().join("not-a-store-file");
    fs::create_dir(&directory_path).expect("directory object");
    let mut directory_config = config.clone();
    directory_config.path = directory_path;
    assert_eq!(
        ConsumptionSettlementStoreV1::open_existing(directory_config)
            .expect_err("directory store path")
            .code(),
        ConsumptionSettlementErrorCodeV1::StoreFailure
    );

    #[cfg(unix)]
    {
        let symlink_path = config.path.parent().unwrap().join("store-link.sqlite");
        std::os::unix::fs::symlink(&config.path, &symlink_path).expect("store symlink");
        let mut symlink_config = config;
        symlink_config.path = symlink_path;
        assert_eq!(
            ConsumptionSettlementStoreV1::open_existing(symlink_config)
                .expect_err("symlink store path")
                .code(),
            ConsumptionSettlementErrorCodeV1::StoreFailure
        );
    }
}

use std::{fs, path::PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use tempfile::TempDir;

use crate::{
    codec::{canonical_bytes, checksum, digest_value, strict_decode},
    error::AgentMarketErrorCodeV1,
    store::CommitFaultV1,
    *,
};

struct Fixture {
    directory: TempDir,
    requester_controller: SigningKey,
    requester_session: SigningKey,
    provider_controller: SigningKey,
    provider_session: SigningKey,
    trust: AgentMarketFreshGenesisTrustBundleV1,
}

impl Fixture {
    fn new() -> Self {
        let requester_controller = SigningKey::from_bytes(&[11; 32]);
        let requester_session = SigningKey::from_bytes(&[12; 32]);
        let provider_controller = SigningKey::from_bytes(&[21; 32]);
        let provider_session = SigningKey::from_bytes(&[22; 32]);
        let context = ProtocolContextV1 {
            genesis_hash: hash(1),
            chain_id: "trnm-agent-market-candidate-test".to_owned(),
            protocol_version: 1,
            stack_profile_hash: hash(2),
        };
        let requester = BootstrapAgentV1 {
            agent_id: agent(1),
            controller_key_id: key_id(11),
            controller_public_key: requester_controller.verifying_key().to_bytes(),
            session_key_id: key_id(12),
            session_public_key: requester_session.verifying_key().to_bytes(),
        };
        let provider = BootstrapAgentV1 {
            agent_id: agent(2),
            controller_key_id: key_id(21),
            controller_public_key: provider_controller.verifying_key().to_bytes(),
            session_key_id: key_id(22),
            session_public_key: provider_session.verifying_key().to_bytes(),
        };
        let requester_account_body = AccountBodyV1 {
            schema_version: 1,
            context: context.clone(),
            owner_agent_id: requester.agent_id,
            asset_id: hash(80),
            account_nonce: hash(81),
        };
        let provider_bond_body = BondBodyV1 {
            schema_version: 1,
            context: context.clone(),
            owner_agent_id: provider.agent_id,
            asset_id: hash(80),
            purpose: 1,
            source_object_kind: 0,
            source_object_id: hash(82),
            bond_nonce: hash(83),
        };
        let trust = AgentMarketFreshGenesisTrustBundleV1 {
            schema_version: 1,
            context,
            initial_order_height: 100,
            initial_order_block_id: hash(3),
            requester,
            provider,
            requester_account_id: requester_account_body.account_id().expect("account id"),
            requester_account_body,
            requester_account_funding: 1_000,
            provider_bond_id: provider_bond_body.bond_id().expect("bond id"),
            provider_bond_body,
            provider_bond_funding: 500,
            provider_bond_hold: 100,
        };
        Self {
            directory: tempfile::tempdir().expect("tempdir"),
            requester_controller,
            requester_session,
            provider_controller,
            provider_session,
            trust,
        }
    }

    fn path(&self, index: usize) -> PathBuf {
        self.directory
            .path()
            .join(format!("agent-market-{index}.sqlite"))
    }

    fn config(&self, index: usize) -> AgentMarketStoreConfigV1 {
        AgentMarketStoreConfigV1 {
            path: self.path(index),
            store_id: hash(u8::try_from(120 + index).expect("store index")),
            trust_bundle: self.trust.clone(),
        }
    }

    fn store(&self, index: usize) -> PocoAgentMarketStoreV1 {
        PocoAgentMarketStoreV1::open(self.config(index)).expect("open store")
    }

    fn capability_body(&self, provider: bool) -> CapabilityGrantBodyV1 {
        let actor = if provider {
            &self.trust.provider
        } else {
            &self.trust.requester
        };
        let operation_kinds = if provider { vec![5, 7] } else { vec![4, 6] };
        CapabilityGrantBodyV1 {
            schema_version: 1,
            genesis_hash: self.trust.context.genesis_hash,
            chain_id: self.trust.context.chain_id.clone(),
            protocol_version: 1,
            stack_profile_hash: self.trust.context.stack_profile_hash,
            issuer_agent_id: actor.agent_id,
            issuer_key_id: CONTROLLER_SENTINEL_KEY_V1,
            delegate_agent_id: actor.agent_id,
            delegate_key_id: Some(actor.session_key_id),
            parent_capability_id: None,
            grant_nonce: if provider { hash(31) } else { hash(30) },
            operation_scopes: operation_kinds
                .into_iter()
                .map(|operation_kind| OperationScopeV1 {
                    operation_kind,
                    task_id: None,
                    market_id: None,
                    model_commitment: Some(hash(51)),
                    tool_commitment: Some(hash(52)),
                    endpoint_commitment: None,
                    verification_profile: Some(VerificationProfileRefV1 {
                        profile_id: b"deterministic-reexecute".to_vec(),
                        profile_version: 1,
                        profile_hash: hash(53),
                    }),
                    privacy_lane: Some(0),
                    maximum_unit_price: if operation_kind == 5 { Some(300) } else { None },
                })
                .collect(),
            resource_scopes: vec![ResourceScopeV1 {
                resource_kind: 1,
                scope_mode: 0,
                allowed_ids: vec![hash(56)],
                allowlist_commitment: None,
            }],
            spend_limits: vec![AssetLimitV1 {
                asset_id: hash(80),
                maximum_amount: if provider { 20 } else { 700 },
            }],
            fee_limit: 100,
            gas_limit: 100_000,
            da_byte_limit: 10_000,
            artifact_retention_limit: 1_000,
            allowed_nonce_lanes: if provider { vec![3, 4] } else { vec![1, 2] },
            valid_from_height: 90,
            expires_after_height: 200,
            rate_window_blocks: 10,
            rate_max_operations: 20,
            max_total_operations: 20,
            delegation_depth_remaining: 0,
            revocation_generation: 0,
            conditions_hash: hash(41),
        }
    }

    fn session_body(
        &self,
        provider: bool,
        capability: &CapabilityGrantBodyV1,
    ) -> SessionKeyGrantBodyV1 {
        let actor = if provider {
            &self.trust.provider
        } else {
            &self.trust.requester
        };
        SessionKeyGrantBodyV1 {
            schema_version: 1,
            genesis_hash: self.trust.context.genesis_hash,
            chain_id: self.trust.context.chain_id.clone(),
            protocol_version: 1,
            stack_profile_hash: self.trust.context.stack_profile_hash,
            agent_id: actor.agent_id,
            session_key_id: actor.session_key_id,
            capability_id: capability.capability_id().expect("capability id"),
            allowed_nonce_lanes: capability.allowed_nonce_lanes.clone(),
            valid_from_height: 90,
            expires_after_height: 190,
            max_total_operations: 10,
            session_generation: 1,
            grant_nonce: if provider { hash(33) } else { hash(32) },
        }
    }

    fn controller_command(
        &self,
        provider: bool,
        nonce: u64,
        expected_lane_version: u64,
        body: ControllerBody<'_>,
    ) -> KernelCommandV1 {
        let actor = if provider {
            &self.trust.provider
        } else {
            &self.trust.requester
        };
        let unsigned = match body {
            ControllerBody::Capability(body) => KernelCommandV1::CapabilityGrant {
                body: body.clone(),
                authorization: placeholder_authorization(),
            },
            ControllerBody::Session(body) => KernelCommandV1::SessionGrant {
                body: body.clone(),
                authorization: placeholder_authorization(),
            },
        };
        let statement = KernelAuthorizationStatementV1 {
            schema_version: 1,
            context: self.trust.context.clone(),
            operation_kind: unsigned.operation_kind(),
            operation_digest: unsigned.operation_digest().expect("digest"),
            sender_agent_id: actor.agent_id,
            authorizing_key_id: CONTROLLER_SENTINEL_KEY_V1,
            capability_id: None,
            live_capability_generation: 0,
            session_key_grant_id: None,
            session_generation: 0,
            nonce_lane: 0,
            nonce,
            expected_lane_version,
            valid_after_height: 90,
            expires_after_height: 110,
        };
        let signing_key = if provider {
            &self.provider_controller
        } else {
            &self.requester_controller
        };
        with_authorization(
            unsigned,
            signed_authorization(&statement, actor.controller_key_id, signing_key),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn session_command(
        &self,
        provider: bool,
        lane: u16,
        nonce: u64,
        expected_lane_version: u64,
        capability: &CapabilityGrantBodyV1,
        session: &SessionKeyGrantBodyV1,
        body: SessionBody,
    ) -> KernelCommandV1 {
        let actor = if provider {
            &self.trust.provider
        } else {
            &self.trust.requester
        };
        let unsigned = match body {
            SessionBody::Task(body, charge) => KernelCommandV1::TaskCreate {
                body,
                charge,
                authorization: placeholder_authorization(),
            },
            SessionBody::Bid(body, charge) => KernelCommandV1::Bid {
                body,
                charge,
                authorization: placeholder_authorization(),
            },
            SessionBody::Lease(body, bid, escrow, bond, charge) => KernelCommandV1::LeaseAccept {
                body,
                expected_bid_version: bid,
                expected_escrow_version: escrow,
                expected_bond_version: bond,
                charge,
                authorization: placeholder_authorization(),
            },
            SessionBody::ProviderAccept(body, lease, charge) => KernelCommandV1::ProviderAccept {
                body,
                expected_lease_revision: lease,
                charge,
                authorization: placeholder_authorization(),
            },
        };
        let statement = KernelAuthorizationStatementV1 {
            schema_version: 1,
            context: self.trust.context.clone(),
            operation_kind: unsigned.operation_kind(),
            operation_digest: unsigned.operation_digest().expect("digest"),
            sender_agent_id: actor.agent_id,
            authorizing_key_id: actor.session_key_id,
            capability_id: Some(capability.capability_id().expect("capability id")),
            live_capability_generation: capability.revocation_generation,
            session_key_grant_id: Some(session.session_key_grant_id().expect("session id")),
            session_generation: session.session_generation,
            nonce_lane: lane,
            nonce,
            expected_lane_version,
            valid_after_height: 90,
            expires_after_height: 110,
        };
        let signing_key = if provider {
            &self.provider_session
        } else {
            &self.requester_session
        };
        with_authorization(
            unsigned,
            signed_authorization(&statement, actor.session_key_id, signing_key),
        )
    }

    fn setup_agents(
        &self,
        store: &PocoAgentMarketStoreV1,
    ) -> (
        CapabilityGrantBodyV1,
        SessionKeyGrantBodyV1,
        CapabilityGrantBodyV1,
        SessionKeyGrantBodyV1,
    ) {
        let requester_cap = self.capability_body(false);
        let requester_session = self.session_body(false, &requester_cap);
        let provider_cap = self.capability_body(true);
        let provider_session = self.session_body(true, &provider_cap);
        store
            .execute(&self.controller_command(
                false,
                0,
                0,
                ControllerBody::Capability(&requester_cap),
            ))
            .expect("requester capability");
        store
            .execute(&self.controller_command(
                false,
                1,
                1,
                ControllerBody::Session(&requester_session),
            ))
            .expect("requester session");
        store
            .execute(&self.controller_command(
                true,
                0,
                0,
                ControllerBody::Capability(&provider_cap),
            ))
            .expect("provider capability");
        store
            .execute(&self.controller_command(
                true,
                1,
                1,
                ControllerBody::Session(&provider_session),
            ))
            .expect("provider session");
        (
            requester_cap,
            requester_session,
            provider_cap,
            provider_session,
        )
    }

    fn task_operation(&self, lane: u16, nonce: u64) -> TaskCreationOperationBodyV1 {
        let terms = EscrowTermsV1 {
            schema_version: 1,
            asset_id: hash(80),
            funded_amount: 500,
            provider_payment_cap: 300,
            order_fee_reserve: 20,
            transaction_da_fee_reserve: 20,
            artifact_da_fee_reserve: 40,
            verification_fee_reserve: 40,
            challenge_reserve: 50,
            refund_beneficiary: self.trust.requester.agent_id,
            settlement_policy_hash: hash(55),
        };
        let offer = TaskOfferBodyV1 {
            schema_version: 1,
            genesis_hash: self.trust.context.genesis_hash,
            chain_id: self.trust.context.chain_id.clone(),
            protocol_version: 1,
            stack_profile_hash: self.trust.context.stack_profile_hash,
            requester_agent_id: self.trust.requester.agent_id,
            requester_key_id: self.trust.requester.session_key_id,
            requester_capability_id: None,
            requester_session_generation: 1,
            request_nonce_lane: lane,
            request_nonce: nonce,
            task_kind: b"inference".to_vec(),
            task_spec_commitment: hash(50),
            input_artifacts: Vec::new(),
            model_scope_commitment: hash(51),
            tool_scope_commitment: hash(52),
            verification_profile_id: b"deterministic-reexecute".to_vec(),
            verification_profile_version: 1,
            verification_profile_hash: hash(53),
            privacy_lane: 0,
            provider_policy_hash: hash(54),
            resource_limit_hash: hash(56),
            pricing_policy_hash: hash(57),
            escrow_terms_hash: digest_value("trnm.poco-ai.escrow-terms.v1", &terms)
                .expect("terms hash"),
            checkpoint_policy_hash: hash(58),
            migration_policy_hash: hash(59),
            challenge_policy_hash: hash(60),
            offer_expiry_height: 120,
            start_deadline_height: 130,
            result_deadline_height: 150,
            settlement_deadline_height: 170,
            requester_metadata_commitment: hash(61),
        };
        TaskCreationOperationBodyV1 {
            task_offer_body: offer,
            escrow_terms: terms,
            funding_account_id: self.trust.requester_account_id,
            expected_funding_account_version: 0,
            escrow_nonce: hash(62),
        }
    }

    fn bid_body(&self, task: &TaskCreationOperationBodyV1, lane: u16, nonce: u64) -> BidBodyV1 {
        BidBodyV1 {
            schema_version: 1,
            genesis_hash: self.trust.context.genesis_hash,
            chain_id: self.trust.context.chain_id.clone(),
            protocol_version: 1,
            stack_profile_hash: self.trust.context.stack_profile_hash,
            task_id: task.task_offer_body.task_id().expect("task id"),
            task_revision: 0,
            provider_agent_id: self.trust.provider.agent_id,
            provider_key_id: self.trust.provider.session_key_id,
            provider_capability_id: None,
            provider_session_generation: 1,
            provider_nonce_lane: lane,
            provider_nonce: nonce,
            price_asset_id: hash(80),
            maximum_price: 300,
            pricing_terms_hash: hash(57),
            resource_offer_hash: hash(63),
            execution_environment_hash: hash(64),
            provider_bond_id: self.trust.provider_bond_id,
            checkpoint_terms_hash: hash(58),
            availability_terms_hash: hash(65),
            bid_expiry_height: 115,
            provider_metadata_commitment: hash(66),
        }
    }

    fn lease_body(&self, task: &TaskCreationOperationBodyV1, bid: &BidBodyV1) -> TaskLeaseBodyV1 {
        let offer = &task.task_offer_body;
        TaskLeaseBodyV1 {
            schema_version: 1,
            genesis_hash: self.trust.context.genesis_hash,
            chain_id: self.trust.context.chain_id.clone(),
            protocol_version: 1,
            stack_profile_hash: self.trust.context.stack_profile_hash,
            task_id: offer.task_id().expect("task id"),
            base_task_revision: 0,
            attempt: 0,
            accepted_bid_id: bid.bid_id().expect("bid id"),
            requester_agent_id: self.trust.requester.agent_id,
            provider_agent_id: self.trust.provider.agent_id,
            escrow_id: EscrowBodyV1 {
                schema_version: 1,
                genesis_hash: offer.genesis_hash,
                chain_id: offer.chain_id.clone(),
                protocol_version: 1,
                stack_profile_hash: offer.stack_profile_hash,
                task_id: offer.task_id().expect("task id"),
                requester_agent_id: offer.requester_agent_id,
                asset_id: task.escrow_terms.asset_id,
                funded_amount: task.escrow_terms.funded_amount,
                provider_payment_cap: task.escrow_terms.provider_payment_cap,
                order_fee_reserve: task.escrow_terms.order_fee_reserve,
                transaction_da_fee_reserve: task.escrow_terms.transaction_da_fee_reserve,
                artifact_da_fee_reserve: task.escrow_terms.artifact_da_fee_reserve,
                verification_fee_reserve: task.escrow_terms.verification_fee_reserve,
                challenge_reserve: task.escrow_terms.challenge_reserve,
                refund_beneficiary: task.escrow_terms.refund_beneficiary,
                settlement_policy_hash: task.escrow_terms.settlement_policy_hash,
                escrow_nonce: task.escrow_nonce,
            }
            .escrow_id()
            .expect("escrow id"),
            provider_bond_id: bid.provider_bond_id,
            resume_checkpoint_id: None,
            execution_environment_hash: bid.execution_environment_hash,
            verification_profile_id: offer.verification_profile_id.clone(),
            verification_profile_version: offer.verification_profile_version,
            verification_profile_hash: offer.verification_profile_hash,
            pricing_terms_hash: bid.pricing_terms_hash,
            checkpoint_terms_hash: bid.checkpoint_terms_hash,
            availability_terms_hash: bid.availability_terms_hash,
            start_deadline_height: offer.start_deadline_height,
            checkpoint_deadline_height: 140,
            result_deadline_height: offer.result_deadline_height,
            lease_nonce: hash(67),
        }
    }
}

enum ControllerBody<'a> {
    Capability(&'a CapabilityGrantBodyV1),
    Session(&'a SessionKeyGrantBodyV1),
}

#[allow(clippy::large_enum_variant)]
enum SessionBody {
    Task(TaskCreationOperationBodyV1, KernelResourceChargeV1),
    Bid(BidBodyV1, KernelResourceChargeV1),
    Lease(TaskLeaseBodyV1, u64, u64, u64, KernelResourceChargeV1),
    ProviderAccept(LeaseProviderAcceptanceBodyV1, u64, KernelResourceChargeV1),
}

fn hash(value: u8) -> Hash32V1 {
    Hash32V1([value; 32])
}

fn agent(value: u8) -> AgentIdV1 {
    AgentIdV1([value; 32])
}

fn key_id(value: u8) -> AgentKeyIdV1 {
    AgentKeyIdV1([value; 32])
}

fn empty_charge() -> KernelResourceChargeV1 {
    KernelResourceChargeV1 {
        asset_charges: Vec::new(),
        fee: 1,
        gas: 10,
        da_bytes: 10,
        retention: 1,
        operations: 1,
    }
}

fn task_charge() -> KernelResourceChargeV1 {
    KernelResourceChargeV1 {
        asset_charges: vec![AssetChargeV1 {
            asset_id: hash(80),
            amount: 500,
        }],
        ..empty_charge()
    }
}

fn placeholder_authorization() -> KernelAuthorizationV1 {
    KernelAuthorizationV1 {
        statement: KernelAuthorizationStatementV1 {
            schema_version: 1,
            context: ProtocolContextV1 {
                genesis_hash: hash(0),
                chain_id: String::new(),
                protocol_version: 1,
                stack_profile_hash: hash(0),
            },
            operation_kind: 0,
            operation_digest: hash(0),
            sender_agent_id: agent(0),
            authorizing_key_id: key_id(0),
            capability_id: None,
            live_capability_generation: 0,
            session_key_grant_id: None,
            session_generation: 0,
            nonce_lane: 0,
            nonce: 0,
            expected_lane_version: 0,
            valid_after_height: 0,
            expires_after_height: 0,
        },
        signer_key_id: key_id(0),
        signature: vec![0; 64],
    }
}

/// Executable negative-case inventory consumed by the checked JSON vector
/// manifest. Each invocation records the exact vector case before asserting
/// its expected rejection code; the inventory test below fails if a declared
/// negative has no executing assertion or if a test invents an undeclared
/// negative.
fn reject_case<T: std::fmt::Debug>(
    executed: &mut Vec<&'static str>,
    name: &'static str,
    result: AgentMarketResultV1<T>,
    expected: AgentMarketErrorCodeV1,
) {
    executed.push(name);
    assert_eq!(result.expect_err(name).code(), expected, "{name}");
}

fn declared_negative_cases() -> Vec<String> {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/protocol/poco-ai-native-v1/vectors/cev1-agent-market-kernel-v1.json"
    )))
    .expect("parse checked vector manifest");
    manifest["negative_cases"]
        .as_array()
        .expect("negative_cases array")
        .iter()
        .map(|entry| entry.as_str().expect("negative case string").to_owned())
        .collect()
}

fn signed_authorization(
    statement: &KernelAuthorizationStatementV1,
    signer_key_id: AgentKeyIdV1,
    key: &SigningKey,
) -> KernelAuthorizationV1 {
    let domain = match statement.operation_kind {
        2 => "trnm.poco-ai.capability-grant-kernel-signature.candidate.v1",
        3 => "trnm.poco-ai.session-grant-kernel-signature.candidate.v1",
        4 => "trnm.poco-ai.task-offer-kernel-signature.candidate.v1",
        5 => "trnm.poco-ai.bid-kernel-signature.candidate.v1",
        6 => "trnm.poco-ai.lease-requester-kernel-signature.candidate.v1",
        7 => "trnm.poco-ai.lease-provider-kernel-signature.candidate.v1",
        _ => panic!("unknown domain"),
    };
    let root = digest_value(domain, statement).expect("signing root");
    KernelAuthorizationV1 {
        statement: statement.clone(),
        signer_key_id,
        signature: key.sign(&root.0).to_bytes().to_vec(),
    }
}

fn with_authorization(
    command: KernelCommandV1,
    authorization: KernelAuthorizationV1,
) -> KernelCommandV1 {
    match command {
        KernelCommandV1::CapabilityGrant { body, .. } => KernelCommandV1::CapabilityGrant {
            body,
            authorization,
        },
        KernelCommandV1::SessionGrant { body, .. } => KernelCommandV1::SessionGrant {
            body,
            authorization,
        },
        KernelCommandV1::TaskCreate { body, charge, .. } => KernelCommandV1::TaskCreate {
            body,
            charge,
            authorization,
        },
        KernelCommandV1::Bid { body, charge, .. } => KernelCommandV1::Bid {
            body,
            charge,
            authorization,
        },
        KernelCommandV1::LeaseAccept {
            body,
            expected_bid_version,
            expected_escrow_version,
            expected_bond_version,
            charge,
            ..
        } => KernelCommandV1::LeaseAccept {
            body,
            expected_bid_version,
            expected_escrow_version,
            expected_bond_version,
            charge,
            authorization,
        },
        KernelCommandV1::ProviderAccept {
            body,
            expected_lease_revision,
            charge,
            ..
        } => KernelCommandV1::ProviderAccept {
            body,
            expected_lease_revision,
            charge,
            authorization,
        },
    }
}

#[test]
fn capability_session_and_parallel_nonce_lanes_are_persistent() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, provider_cap, provider_session) =
        fixture.setup_agents(&store);

    let requester_id = requester_cap.capability_id().expect("capability id");
    let state = store.capability_state(requester_id).expect("cap state");
    assert_eq!(state.state_version, 0);
    assert_eq!(state.budget.operations_spent, 0);
    assert_eq!(
        store
            .session_state(
                requester_session
                    .session_key_grant_id()
                    .expect("session id")
            )
            .expect("session")
            .operations_spent,
        0
    );
    for (cap, session, lanes) in [
        (&requester_cap, &requester_session, vec![1, 2]),
        (&provider_cap, &provider_session, vec![3, 4]),
    ] {
        for lane in lanes {
            let lane_id = NonceLaneKeyBodyV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                agent_id: session.agent_id,
                authorizing_key_id: session.session_key_id,
                capability_id: Some(cap.capability_id().expect("cap id")),
                session_generation: 1,
                lane,
            }
            .nonce_lane_id()
            .expect("lane id");
            assert_eq!(store.nonce_lane_state(lane_id).expect("lane").next_nonce, 0);
        }
    }
    drop(store);
    PocoAgentMarketStoreV1::open(fixture.config(0)).expect("reopen");
}

#[test]
fn task_funded_escrow_bid_lease_and_provider_accept_are_atomic() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, provider_cap, provider_session) =
        fixture.setup_agents(&store);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    let task_command = fixture.session_command(
        false,
        1,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Task(task.clone(), task_charge()),
    );
    let first = store.execute(&task_command).expect("task");
    let replay = store.execute(&task_command).expect("replay");
    assert!(!first.is_replay());
    assert!(replay.is_replay());
    assert_eq!(first.receipt(), replay.receipt());
    let task_id = task.task_offer_body.task_id().expect("task id");
    let task_state = store.task_state(task_id).expect("task state");
    assert_eq!((task_state.revision, task_state.status), (0, 0));
    let escrow = store.escrow_state(task_state.escrow_id).expect("escrow");
    assert_eq!(
        (escrow.version, escrow.available, escrow.reserved),
        (0, 500, 0)
    );
    let account = store
        .account_state(fixture.trust.requester_account_id)
        .unwrap();
    assert_eq!(
        (account.version, account.available, account.spent),
        (1, 500, 500)
    );

    let mut bid = fixture.bid_body(&task, 3, 0);
    bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
    let bid_command = fixture.session_command(
        true,
        3,
        0,
        0,
        &provider_cap,
        &provider_session,
        SessionBody::Bid(bid.clone(), empty_charge()),
    );
    store.execute(&bid_command).expect("bid");
    let bid_id = bid.bid_id().expect("bid id");
    assert_eq!(store.bid_state(bid_id).unwrap().status, 0);

    let lease = fixture.lease_body(&task, &bid);
    let lease_command = fixture.session_command(
        false,
        2,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Lease(lease.clone(), 0, 0, 0, empty_charge()),
    );
    store.execute(&lease_command).expect("lease accept");
    let lease_id = lease.lease_id().expect("lease id");
    let task_state = store.task_state(task_id).unwrap();
    assert_eq!((task_state.revision, task_state.status), (1, 1));
    assert_eq!(task_state.active_lease_id, Some(lease_id));
    let bid_state = store.bid_state(bid_id).unwrap();
    assert_eq!((bid_state.state_version, bid_state.status), (1, 1));
    assert_eq!(bid_state.accepted_lease_id, Some(lease_id));
    let escrow = store.escrow_state(task_state.escrow_id).unwrap();
    assert_eq!(
        (escrow.version, escrow.available, escrow.reserved),
        (1, 200, 300)
    );
    let bond = store.bond_state(fixture.trust.provider_bond_id).unwrap();
    assert_eq!((bond.version, bond.available, bond.held), (1, 400, 100));
    assert_eq!(
        (
            store.lease_state(lease_id).unwrap().revision,
            store.lease_state(lease_id).unwrap().status
        ),
        (0, 0)
    );

    let acceptance = LeaseProviderAcceptanceBodyV1 {
        schema_version: 1,
        context: fixture.trust.context.clone(),
        lease_id,
        provider_agent_id: fixture.trust.provider.agent_id,
        expected_task_revision: 1,
        acceptance_nonce: hash(68),
    };
    let provider_accept = fixture.session_command(
        true,
        4,
        0,
        0,
        &provider_cap,
        &provider_session,
        SessionBody::ProviderAccept(acceptance, 0, empty_charge()),
    );
    store.execute(&provider_accept).expect("provider accept");
    let lease_state = store.lease_state(lease_id).unwrap();
    assert_eq!((lease_state.revision, lease_state.status), (1, 1));
    let final_task = store.task_state(task_id).unwrap();
    assert_eq!((final_task.revision, final_task.status), (1, 1));
    drop(store);
    let reopened = PocoAgentMarketStoreV1::open(fixture.config(0)).expect("reopen");
    assert_eq!(reopened.lease_state(lease_id).unwrap(), lease_state);
}

#[test]
fn pre_vote_preview_reuses_authority_and_leaves_every_logical_row_unchanged() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, _, _) = fixture.setup_agents(&store);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    let command = fixture.session_command(
        false,
        1,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Task(task, task_charge()),
    );
    let before = store.fresh_readback().expect("fresh parent");
    let preview = store
        .preview_before_vote_v1(&before, 101, hash(91), &[command])
        .expect("read-only candidate preview");
    let after = store.fresh_readback().expect("fresh unchanged parent");
    assert_eq!(before, after);
    assert_eq!(preview.source_sequence(), before.sequence());
    assert_eq!(preview.source_state_root(), before.durable_state_root());
    assert_eq!(preview.source_journal_root(), before.durable_journal_root());
    assert_eq!(preview.candidate_receipts().len(), 1);
    assert_ne!(
        preview.candidate_post_state_root(),
        before.durable_state_root()
    );
    assert_ne!(preview.unchanged_row_inventory_digest(), hash(0));
}

#[test]
fn authorization_signature_context_nonce_scope_and_budget_fail_closed() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, provider_cap, provider_session) =
        fixture.setup_agents(&store);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    let valid = fixture.session_command(
        false,
        1,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Task(task.clone(), task_charge()),
    );

    let mut bad_signature = valid.clone();
    if let KernelCommandV1::TaskCreate { authorization, .. } = &mut bad_signature {
        authorization.signature[0] ^= 1;
    }
    assert_eq!(
        store.execute(&bad_signature).unwrap_err().code(),
        AgentMarketErrorCodeV1::InvalidSignature
    );
    let mut wrong_context = valid.clone();
    if let KernelCommandV1::TaskCreate { authorization, .. } = &mut wrong_context {
        authorization.statement.context.genesis_hash = hash(9);
    }
    assert_eq!(
        store.execute(&wrong_context).unwrap_err().code(),
        AgentMarketErrorCodeV1::InvalidContext
    );
    let mut gap = valid.clone();
    if let KernelCommandV1::TaskCreate { authorization, .. } = &mut gap {
        authorization.statement.nonce = 1;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    assert_eq!(
        store.execute(&gap).unwrap_err().code(),
        AgentMarketErrorCodeV1::NonceGap
    );
    let mut over_budget = valid.clone();
    if let KernelCommandV1::TaskCreate { charge, .. } = &mut over_budget {
        charge.asset_charges[0].amount = 701;
    }
    let over_budget_digest = over_budget.operation_digest().unwrap();
    if let KernelCommandV1::TaskCreate { authorization, .. } = &mut over_budget {
        authorization.statement.operation_digest = over_budget_digest;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    assert_eq!(
        store.execute(&over_budget).unwrap_err().code(),
        AgentMarketErrorCodeV1::BudgetExceeded
    );
    store.execute(&valid).expect("valid task");
    let mut replay_nonce = valid.clone();
    if let KernelCommandV1::TaskCreate { body, .. } = &mut replay_nonce {
        body.task_offer_body.task_spec_commitment = hash(99);
    }
    let replay_nonce_digest = replay_nonce.operation_digest().unwrap();
    if let KernelCommandV1::TaskCreate { authorization, .. } = &mut replay_nonce {
        authorization.statement.operation_digest = replay_nonce_digest;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    assert_eq!(
        store.execute(&replay_nonce).unwrap_err().code(),
        AgentMarketErrorCodeV1::InvalidNonceLane
    );

    let mut high_bid = fixture.bid_body(&task, 3, 0);
    high_bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
    high_bid.maximum_price = 301;
    let high_bid = fixture.session_command(
        true,
        3,
        0,
        0,
        &provider_cap,
        &provider_session,
        SessionBody::Bid(high_bid, empty_charge()),
    );
    assert_eq!(
        store.execute(&high_bid).unwrap_err().code(),
        AgentMarketErrorCodeV1::BudgetExceeded
    );
}

#[test]
fn order_finalized_height_advances_monotonically_and_resets_rate_window() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, _, _) = fixture.setup_agents(&store);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    let command = fixture.session_command(
        false,
        1,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Task(task, task_charge()),
    );
    let mut head = store.fresh_readback().expect("rate-window source head");
    for height in head.order_height() + 1..110 {
        let next_block = hash(u8::try_from(height).expect("test height fits block byte"));
        head = store
            .advance_empty_order_finalized_v1(&OrderFinalizedExecutionContextV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                expected_order_height: head.order_height(),
                expected_order_block_id: head.order_block_id(),
                order_height: height,
                order_block_id: next_block,
            })
            .expect("direct-successor empty finalized block");
    }
    let receipt = store
        .execute_at_height_for_test(110, hash(90), &command)
        .expect("order-finalized height advance")
        .receipt()
        .clone();
    assert_eq!(
        (receipt.order_height, receipt.order_block_id),
        (110, hash(90))
    );
    let state = store
        .capability_state(requester_cap.capability_id().unwrap())
        .unwrap();
    assert_eq!(
        (
            state.budget.rate_window_start_height,
            state.budget.rate_window_operations,
        ),
        (110, 1)
    );
    drop(store);
    let reopened = PocoAgentMarketStoreV1::open(fixture.config(0)).unwrap();
    assert_eq!(
        reopened.confirm_receipt(&receipt).unwrap().receipt(),
        &receipt
    );
}

#[test]
fn stale_versions_expiry_double_consumption_and_conservation_reject() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, provider_cap, provider_session) =
        fixture.setup_agents(&store);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    store
        .execute(&fixture.session_command(
            false,
            1,
            0,
            0,
            &requester_cap,
            &requester_session,
            SessionBody::Task(task.clone(), task_charge()),
        ))
        .unwrap();
    let mut bid = fixture.bid_body(&task, 3, 0);
    bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
    store
        .execute(&fixture.session_command(
            true,
            3,
            0,
            0,
            &provider_cap,
            &provider_session,
            SessionBody::Bid(bid.clone(), empty_charge()),
        ))
        .unwrap();
    let lease = fixture.lease_body(&task, &bid);
    let stale = fixture.session_command(
        false,
        2,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Lease(lease.clone(), 1, 0, 0, empty_charge()),
    );
    assert_eq!(
        store.execute(&stale).unwrap_err().code(),
        AgentMarketErrorCodeV1::InvalidState
    );
    let valid = fixture.session_command(
        false,
        2,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Lease(lease.clone(), 0, 0, 0, empty_charge()),
    );
    store.execute(&valid).unwrap();
    let double = fixture.session_command(
        false,
        2,
        1,
        1,
        &requester_cap,
        &requester_session,
        SessionBody::Lease(lease, 1, 1, 1, empty_charge()),
    );
    assert_eq!(
        store.execute(&double).unwrap_err().code(),
        AgentMarketErrorCodeV1::InvalidState
    );

    let other = Fixture::new();
    let other_store = other.store(0);
    assert_eq!(
        other_store
            .confirm_receipt(valid_receipt(&store, &valid))
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::NotFound
    );
}

#[test]
fn crash_outcomes_are_exact_and_third_state_is_permanently_fenced() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let cap = fixture.capability_body(false);
    let command = fixture.controller_command(false, 0, 0, ControllerBody::Capability(&cap));
    assert_eq!(
        store
            .execute_with_fault(&command, CommitFaultV1::NotAppliedAckLost)
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::CommitUncertain
    );
    assert_eq!(
        store
            .capability_state(cap.capability_id().unwrap())
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::NotFound
    );
    assert_eq!(
        store
            .execute_with_fault(&command, CommitFaultV1::AppliedAckLost)
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::CommitUncertain
    );
    assert!(store.execute(&command).expect("exact replay").is_replay());
    drop(store);
    PocoAgentMarketStoreV1::open(fixture.config(0)).expect("reopen applied");

    let fenced = fixture.store(1);
    let provider_cap = fixture.capability_body(true);
    let command = fixture.controller_command(true, 0, 0, ControllerBody::Capability(&provider_cap));
    assert_eq!(
        fenced
            .execute_with_fault(&command, CommitFaultV1::ThirdState)
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::ThirdStateFenced
    );
    drop(fenced);
    assert_eq!(
        PocoAgentMarketStoreV1::open(fixture.config(1))
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::ThirdStateFenced
    );
}

#[test]
fn finalized_block_journal_covers_empty_same_block_and_tamper_boundaries() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let genesis = store.fresh_readback().expect("genesis readback");
    let first_empty = OrderFinalizedExecutionContextV1 {
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

    let second_empty = OrderFinalizedExecutionContextV1 {
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

    let stale = OrderFinalizedExecutionContextV1 {
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
        AgentMarketErrorCodeV1::StaleVersion
    );
    let skipped = OrderFinalizedExecutionContextV1 {
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
        AgentMarketErrorCodeV1::InvalidContext
    );
    drop(store);
    Connection::open(fixture.path(0))
        .expect("open marker database")
        .execute(
            "UPDATE agent_market_finalized_blocks_v1 SET row_checksum=zeroblob(32) WHERE parent_order_height!=order_height",
            [],
        )
        .expect("tamper marker");
    assert_eq!(
        PocoAgentMarketStoreV1::open(fixture.config(0))
            .expect_err("marker tamper")
            .code(),
        AgentMarketErrorCodeV1::TamperDetected
    );

    let partial = fixture.store(2);
    let partial_genesis = partial.fresh_readback().expect("partial genesis");
    partial
        .advance_empty_order_finalized_v1(&OrderFinalizedExecutionContextV1 {
            schema_version: 1,
            context: fixture.trust.context.clone(),
            expected_order_height: partial_genesis.order_height(),
            expected_order_block_id: partial_genesis.order_block_id(),
            order_height: partial_genesis.order_height() + 1,
            order_block_id: hash(94),
        })
        .expect("partial target");
    drop(partial);
    Connection::open(fixture.path(2))
        .expect("open partial database")
        .execute(
            "DELETE FROM agent_market_finalized_blocks_v1 WHERE parent_order_height!=order_height",
            [],
        )
        .expect("delete tail marker");
    assert_eq!(
        PocoAgentMarketStoreV1::open(fixture.config(2))
            .expect_err("partial marker write")
            .code(),
        AgentMarketErrorCodeV1::TamperDetected
    );

    let multi = fixture.store(1);
    let requester_cap = fixture.capability_body(false);
    let provider_cap = fixture.capability_body(true);
    multi
        .execute(&fixture.controller_command(
            false,
            0,
            0,
            ControllerBody::Capability(&requester_cap),
        ))
        .expect("first same-block command");
    let first_root = multi
        .fresh_readback()
        .expect("first same-block readback")
        .durable_finalized_block_root();
    multi
        .execute(&fixture.controller_command(true, 0, 0, ControllerBody::Capability(&provider_cap)))
        .expect("second same-block command");
    assert_ne!(
        multi
            .fresh_readback()
            .expect("second same-block readback")
            .durable_finalized_block_root(),
        first_root
    );
    drop(multi);
    PocoAgentMarketStoreV1::open(fixture.config(1)).expect("same-block reopen");
}

#[test]
fn schema_sidecar_row_and_journal_tamper_fail_closed_without_migration() {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let cap = fixture.capability_body(false);
    let command = fixture.controller_command(false, 0, 0, ControllerBody::Capability(&cap));
    store.execute(&command).unwrap();
    drop(store);
    let path = fixture.path(0);
    let before = fs::read(&path).expect("before bytes");
    {
        let connection = Connection::open(&path).expect("open raw");
        connection
            .execute("DELETE FROM agent_market_operations_v1", [])
            .expect("delete journal");
    }
    assert_eq!(
        PocoAgentMarketStoreV1::open(fixture.config(0))
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::TamperDetected
    );

    let second = fixture.store(1);
    drop(second);
    let second_path = fixture.path(1);
    let sidecar = PathBuf::from(format!("{}-wal", second_path.display()));
    fs::write(&sidecar, b"sentinel").expect("sidecar");
    assert_eq!(
        PocoAgentMarketStoreV1::open(fixture.config(1))
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::SidecarPresent
    );
    fs::remove_file(sidecar).unwrap();
    let pristine = fs::read(&second_path).unwrap();
    {
        let connection = Connection::open(&second_path).unwrap();
        connection
            .execute("DROP TABLE agent_market_objects_v1", [])
            .unwrap();
    }
    let drifted = fs::read(&second_path).unwrap();
    assert_ne!(pristine, drifted);
    assert_eq!(
        PocoAgentMarketStoreV1::open(fixture.config(1))
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::SchemaMismatch
    );
    assert_eq!(fs::read(&second_path).unwrap(), drifted);
    assert_ne!(fs::read(&path).unwrap(), before);
}

fn valid_receipt<'a>(
    store: &'a PocoAgentMarketStoreV1,
    command: &KernelCommandV1,
) -> &'a KernelTransitionReceiptV1 {
    // This helper is only used after command application; exact replay returns
    // the same durable receipt without advancing any state.
    Box::leak(Box::new(
        store
            .execute(command)
            .expect("replay receipt")
            .receipt()
            .clone(),
    ))
}

#[test]
fn vector_inventory_matches_executable_negative_assertions() {
    let declared = declared_negative_cases();
    assert_eq!(declared.len(), 58, "checked vector inventory changed");
    let mut unique = declared.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), declared.len(), "duplicate declared negative");

    // This test intentionally builds every bounded mutant from a new store or
    // from a deterministic common prefix. That prevents a prior rejection from
    // becoming the hidden reason a later mutant fails.
    let mut executed = Vec::new();
    execute_authorization_negative_vectors(&mut executed);
    execute_scope_height_identity_negative_vectors(&mut executed);
    execute_market_negative_vectors(&mut executed);
    execute_storage_negative_vectors(&mut executed);

    let mut actual: Vec<String> = executed.into_iter().map(str::to_owned).collect();
    actual.sort();
    let mut expected = declared;
    expected.sort();
    assert_eq!(
        actual, expected,
        "every declared negative must execute once"
    );
}

fn execute_authorization_negative_vectors(executed: &mut Vec<&'static str>) {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let requester_cap = fixture.capability_body(false);
    let valid_cap =
        fixture.controller_command(false, 0, 0, ControllerBody::Capability(&requester_cap));

    let mut wrong_context = valid_cap.clone();
    if let KernelCommandV1::CapabilityGrant { authorization, .. } = &mut wrong_context {
        authorization.statement.context.genesis_hash = hash(9);
    }
    reject_case(
        executed,
        "wrong-context",
        store.execute(&wrong_context),
        AgentMarketErrorCodeV1::InvalidContext,
    );

    let mut wrong_signature = valid_cap.clone();
    wrong_signature.authorization_mut_for_test().signature[0] ^= 1;
    reject_case(
        executed,
        "wrong-signature",
        store.execute(&wrong_signature),
        AgentMarketErrorCodeV1::InvalidSignature,
    );

    let mut wrong_role = valid_cap.clone();
    wrong_role.authorization_mut_for_test().signer_key_id = fixture.trust.requester.session_key_id;
    reject_case(
        executed,
        "wrong-key-role",
        store.execute(&wrong_role),
        AgentMarketErrorCodeV1::Unauthorized,
    );

    let mut wrong_domain = valid_cap.clone();
    {
        let authorization = wrong_domain.authorization_mut_for_test();
        let root = digest_value(
            "trnm.poco-ai.session-grant-kernel-signature.candidate.v1",
            &authorization.statement,
        )
        .unwrap();
        authorization.signature = fixture
            .requester_controller
            .sign(&root.0)
            .to_bytes()
            .to_vec();
    }
    reject_case(
        executed,
        "wrong-signature-domain",
        store.execute(&wrong_domain),
        AgentMarketErrorCodeV1::InvalidSignature,
    );

    let mut expired = valid_cap.clone();
    {
        let authorization = expired.authorization_mut_for_test();
        authorization.statement.expires_after_height = 99;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.controller_key_id,
            &fixture.requester_controller,
        );
    }
    reject_case(
        executed,
        "expired-authorization",
        store.execute(&expired),
        AgentMarketErrorCodeV1::Expired,
    );

    store.execute(&valid_cap).unwrap();
    let session = fixture.session_body(false, &requester_cap);
    let valid_session = fixture.controller_command(false, 1, 1, ControllerBody::Session(&session));

    let mut lane_zero_session = session.clone();
    lane_zero_session.allowed_nonce_lanes = vec![0, 1];
    let lane_zero =
        fixture.controller_command(false, 1, 1, ControllerBody::Session(&lane_zero_session));
    assert_eq!(
        store.execute(&lane_zero).unwrap_err().code(),
        AgentMarketErrorCodeV1::InvalidSession
    );

    let mut unsorted_session = session.clone();
    unsorted_session.allowed_nonce_lanes = vec![2, 1];
    let unsorted =
        fixture.controller_command(false, 1, 1, ControllerBody::Session(&unsorted_session));
    reject_case(
        executed,
        "duplicate-or-unsorted-lane",
        store.execute(&unsorted),
        AgentMarketErrorCodeV1::NonCanonical,
    );

    store.execute(&valid_session).unwrap();
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    let valid = fixture.session_command(
        false,
        1,
        0,
        0,
        &requester_cap,
        &session,
        SessionBody::Task(task.clone(), task_charge()),
    );

    let mut cap_generation = valid.clone();
    {
        let authorization = cap_generation.authorization_mut_for_test();
        authorization.statement.live_capability_generation = 1;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    reject_case(
        executed,
        "capability-generation-mismatch",
        store.execute(&cap_generation),
        AgentMarketErrorCodeV1::InvalidCapability,
    );
    let mut session_generation = valid.clone();
    {
        let authorization = session_generation.authorization_mut_for_test();
        authorization.statement.session_generation = 2;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    reject_case(
        executed,
        "session-generation-mismatch",
        store.execute(&session_generation),
        AgentMarketErrorCodeV1::NotFound,
    );

    let mut lane_zero = valid.clone();
    {
        let authorization = lane_zero.authorization_mut_for_test();
        authorization.statement.nonce_lane = 0;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    reject_case(
        executed,
        "session-lane-zero",
        store.execute(&lane_zero),
        AgentMarketErrorCodeV1::Unauthorized,
    );

    let mut absent_lane = valid.clone();
    {
        let authorization = absent_lane.authorization_mut_for_test();
        authorization.statement.nonce_lane = 3;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    reject_case(
        executed,
        "lane-not-in-grant",
        store.execute(&absent_lane),
        AgentMarketErrorCodeV1::NotFound,
    );

    let mut gap = valid.clone();
    {
        let authorization = gap.authorization_mut_for_test();
        authorization.statement.nonce = 1;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    reject_case(
        executed,
        "nonce-gap",
        store.execute(&gap),
        AgentMarketErrorCodeV1::NonceGap,
    );

    let mut stale_lane = valid.clone();
    {
        let authorization = stale_lane.authorization_mut_for_test();
        authorization.statement.expected_lane_version = 1;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    reject_case(
        executed,
        "stale-lane-version",
        store.execute(&stale_lane),
        AgentMarketErrorCodeV1::InvalidNonceLane,
    );

    let mut operation_scope_cap = requester_cap.clone();
    operation_scope_cap
        .operation_scopes
        .retain(|scope| scope.operation_kind == 6);
    let other = fixture.store(1);
    other
        .execute(&fixture.controller_command(
            false,
            0,
            0,
            ControllerBody::Capability(&operation_scope_cap),
        ))
        .unwrap();
    let other_session = fixture.session_body(false, &operation_scope_cap);
    other
        .execute(&fixture.controller_command(false, 1, 1, ControllerBody::Session(&other_session)))
        .unwrap();
    let mut other_task = fixture.task_operation(1, 0);
    other_task.task_offer_body.requester_capability_id =
        Some(operation_scope_cap.capability_id().unwrap());
    let outside = fixture.session_command(
        false,
        1,
        0,
        0,
        &operation_scope_cap,
        &other_session,
        SessionBody::Task(other_task, task_charge()),
    );
    reject_case(
        executed,
        "operation-outside-scope",
        other.execute(&outside),
        AgentMarketErrorCodeV1::InvalidCapability,
    );

    let budget_mutants = [
        (
            "asset-budget-exceeded",
            KernelResourceChargeV1 {
                asset_charges: vec![AssetChargeV1 {
                    asset_id: hash(80),
                    amount: 701,
                }],
                ..empty_charge()
            },
        ),
        (
            "fee-budget-exceeded",
            KernelResourceChargeV1 {
                asset_charges: vec![AssetChargeV1 {
                    asset_id: hash(80),
                    amount: 500,
                }],
                fee: 101,
                ..empty_charge()
            },
        ),
        (
            "gas-budget-exceeded",
            KernelResourceChargeV1 {
                asset_charges: vec![AssetChargeV1 {
                    asset_id: hash(80),
                    amount: 500,
                }],
                gas: 100_001,
                ..empty_charge()
            },
        ),
    ];
    for (index, (name, charge)) in budget_mutants.into_iter().enumerate() {
        let fresh = Fixture::new();
        let fresh_store = fresh.store(index);
        let (cap, grant, _, _) = fresh.setup_agents(&fresh_store);
        let mut body = fresh.task_operation(1, 0);
        body.task_offer_body.requester_capability_id = Some(cap.capability_id().unwrap());
        let command = fresh.session_command(
            false,
            1,
            0,
            0,
            &cap,
            &grant,
            SessionBody::Task(body, charge),
        );
        reject_case(
            executed,
            name,
            fresh_store.execute(&command),
            AgentMarketErrorCodeV1::BudgetExceeded,
        );
    }

    let fresh = Fixture::new();
    let fresh_store = fresh.store(10);
    let (cap, grant, _, _) = fresh.setup_agents(&fresh_store);
    let mut body = fresh.task_operation(1, 0);
    body.task_offer_body.requester_capability_id = Some(cap.capability_id().unwrap());
    let retention_over = KernelResourceChargeV1 {
        asset_charges: vec![AssetChargeV1 {
            asset_id: hash(80),
            amount: 500,
        }],
        retention: 1_001,
        ..empty_charge()
    };
    let command = fresh.session_command(
        false,
        1,
        0,
        0,
        &cap,
        &grant,
        SessionBody::Task(body, retention_over),
    );
    reject_case(
        executed,
        "retention-budget-exceeded",
        fresh_store.execute(&command),
        AgentMarketErrorCodeV1::BudgetExceeded,
    );

    let fresh = Fixture::new();
    let fresh_store = fresh.store(11);
    let (cap, grant, _, _) = fresh.setup_agents(&fresh_store);
    let mut body = fresh.task_operation(1, 0);
    body.task_offer_body.requester_capability_id = Some(cap.capability_id().unwrap());
    let da_over = KernelResourceChargeV1 {
        asset_charges: vec![AssetChargeV1 {
            asset_id: hash(80),
            amount: 500,
        }],
        da_bytes: 10_001,
        ..empty_charge()
    };
    let command = fresh.session_command(
        false,
        1,
        0,
        0,
        &cap,
        &grant,
        SessionBody::Task(body, da_over),
    );
    reject_case(
        executed,
        "da-byte-budget-exceeded",
        fresh_store.execute(&command),
        AgentMarketErrorCodeV1::BudgetExceeded,
    );

    store.execute(&valid).unwrap();
    let mut replay = valid.clone();
    if let KernelCommandV1::TaskCreate { body, .. } = &mut replay {
        body.task_offer_body.task_spec_commitment = hash(99);
    }
    let digest = replay.operation_digest().unwrap();
    {
        let authorization = replay.authorization_mut_for_test();
        authorization.statement.operation_digest = digest;
        authorization.statement.expected_lane_version = 1;
        *authorization = signed_authorization(
            &authorization.statement,
            fixture.trust.requester.session_key_id,
            &fixture.requester_session,
        );
    }
    reject_case(
        executed,
        "nonce-replay",
        store.execute(&replay),
        AgentMarketErrorCodeV1::NonceReplay,
    );
}

fn setup_requester_with_capability(
    fixture: &Fixture,
    store: &PocoAgentMarketStoreV1,
    capability: &CapabilityGrantBodyV1,
) -> SessionKeyGrantBodyV1 {
    store
        .execute(&fixture.controller_command(false, 0, 0, ControllerBody::Capability(capability)))
        .unwrap();
    let session = fixture.session_body(false, capability);
    store
        .execute(&fixture.controller_command(false, 1, 1, ControllerBody::Session(&session)))
        .unwrap();
    session
}

fn execute_scope_height_identity_negative_vectors(executed: &mut Vec<&'static str>) {
    for name in [
        "duplicate-operation-scope-kind",
        "duplicate-resource-scope-kind",
        "duplicate-spend-limit-asset",
    ] {
        let fixture = Fixture::new();
        let store = fixture.store(0);
        let mut capability = fixture.capability_body(false);
        match name {
            "duplicate-operation-scope-kind" => {
                let mut duplicate = capability.operation_scopes[0].clone();
                duplicate.task_id = Some(TaskIdV1(hash(90).0));
                capability.operation_scopes.push(duplicate);
                capability.operation_scopes.sort();
            }
            "duplicate-resource-scope-kind" => {
                let mut duplicate = capability.resource_scopes[0].clone();
                duplicate.allowed_ids = vec![hash(57)];
                capability.resource_scopes.push(duplicate);
                capability.resource_scopes.sort();
            }
            "duplicate-spend-limit-asset" => {
                let mut duplicate = capability.spend_limits[0].clone();
                duplicate.maximum_amount -= 1;
                capability.spend_limits.push(duplicate);
                capability.spend_limits.sort();
            }
            _ => unreachable!(),
        }
        let command =
            fixture.controller_command(false, 0, 0, ControllerBody::Capability(&capability));
        reject_case(
            executed,
            name,
            store.execute(&command),
            AgentMarketErrorCodeV1::NonCanonical,
        );
    }

    for name in [
        "model-outside-scope",
        "tool-outside-scope",
        "verification-profile-outside-scope",
        "privacy-lane-outside-scope",
        "resource-outside-exact-scope",
    ] {
        let fixture = Fixture::new();
        let store = fixture.store(0);
        let capability = fixture.capability_body(false);
        let session = setup_requester_with_capability(&fixture, &store, &capability);
        let mut task = fixture.task_operation(1, 0);
        task.task_offer_body.requester_capability_id = Some(capability.capability_id().unwrap());
        match name {
            "model-outside-scope" => task.task_offer_body.model_scope_commitment = hash(91),
            "tool-outside-scope" => task.task_offer_body.tool_scope_commitment = hash(91),
            "verification-profile-outside-scope" => {
                task.task_offer_body.verification_profile_hash = hash(91);
            }
            "privacy-lane-outside-scope" => task.task_offer_body.privacy_lane = 1,
            "resource-outside-exact-scope" => task.task_offer_body.resource_limit_hash = hash(91),
            _ => unreachable!(),
        }
        let command = fixture.session_command(
            false,
            1,
            0,
            0,
            &capability,
            &session,
            SessionBody::Task(task, task_charge()),
        );
        reject_case(
            executed,
            name,
            store.execute(&command),
            AgentMarketErrorCodeV1::InvalidCapability,
        );
    }

    let fixture = Fixture::new();
    let store = fixture.store(0);
    let mut committed = fixture.capability_body(false);
    committed.resource_scopes[0].scope_mode = 1;
    committed.resource_scopes[0].allowlist_commitment = Some(hash(90));
    committed.resource_scopes[0].allowed_ids.clear();
    let command = fixture.controller_command(false, 0, 0, ControllerBody::Capability(&committed));
    reject_case(
        executed,
        "committed-resource-scope-without-verifier",
        store.execute(&command),
        AgentMarketErrorCodeV1::InvalidCapability,
    );

    let fixture = Fixture::new();
    let store = fixture.store(0);
    let mut unavailable = fixture.capability_body(false);
    let task_scope = unavailable
        .operation_scopes
        .iter_mut()
        .find(|scope| scope.operation_kind == 4)
        .unwrap();
    task_scope.market_id = Some(hash(92));
    task_scope.endpoint_commitment = Some(hash(93));
    let session = setup_requester_with_capability(&fixture, &store, &unavailable);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(unavailable.capability_id().unwrap());
    let command = fixture.session_command(
        false,
        1,
        0,
        0,
        &unavailable,
        &session,
        SessionBody::Task(task, task_charge()),
    );
    reject_case(
        executed,
        "unverifiable-market-or-endpoint-scope",
        store.execute(&command),
        AgentMarketErrorCodeV1::InvalidCapability,
    );

    let fixture = Fixture::new();
    let store = fixture.store(0);
    let requester_cap = fixture.capability_body(false);
    let requester_session = setup_requester_with_capability(&fixture, &store, &requester_cap);
    let mut provider_cap = fixture.capability_body(true);
    provider_cap
        .operation_scopes
        .iter_mut()
        .find(|scope| scope.operation_kind == 7)
        .unwrap()
        .task_id = Some(TaskIdV1(hash(94).0));
    store
        .execute(&fixture.controller_command(true, 0, 0, ControllerBody::Capability(&provider_cap)))
        .unwrap();
    let provider_session = fixture.session_body(true, &provider_cap);
    store
        .execute(&fixture.controller_command(
            true,
            1,
            1,
            ControllerBody::Session(&provider_session),
        ))
        .unwrap();
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    store
        .execute(&fixture.session_command(
            false,
            1,
            0,
            0,
            &requester_cap,
            &requester_session,
            SessionBody::Task(task.clone(), task_charge()),
        ))
        .unwrap();
    let mut bid = fixture.bid_body(&task, 3, 0);
    bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
    store
        .execute(&fixture.session_command(
            true,
            3,
            0,
            0,
            &provider_cap,
            &provider_session,
            SessionBody::Bid(bid.clone(), empty_charge()),
        ))
        .unwrap();
    let lease = fixture.lease_body(&task, &bid);
    store
        .execute(&fixture.session_command(
            false,
            2,
            0,
            0,
            &requester_cap,
            &requester_session,
            SessionBody::Lease(lease.clone(), 0, 0, 0, empty_charge()),
        ))
        .unwrap();
    let acceptance = LeaseProviderAcceptanceBodyV1 {
        schema_version: 1,
        context: fixture.trust.context.clone(),
        lease_id: lease.lease_id().unwrap(),
        provider_agent_id: fixture.trust.provider.agent_id,
        expected_task_revision: 1,
        acceptance_nonce: hash(95),
    };
    let command = fixture.session_command(
        true,
        4,
        0,
        0,
        &provider_cap,
        &provider_session,
        SessionBody::ProviderAccept(acceptance, 0, empty_charge()),
    );
    reject_case(
        executed,
        "provider-acceptance-task-scope-mismatch",
        store.execute(&command),
        AgentMarketErrorCodeV1::InvalidCapability,
    );

    for name in [
        "duplicate-bootstrap-key-id",
        "duplicate-bootstrap-public-key",
    ] {
        let mut fixture = Fixture::new();
        match name {
            "duplicate-bootstrap-key-id" => {
                fixture.trust.provider.session_key_id = fixture.trust.requester.controller_key_id;
            }
            "duplicate-bootstrap-public-key" => {
                fixture.trust.provider.session_public_key =
                    fixture.trust.requester.controller_public_key;
            }
            _ => unreachable!(),
        }
        reject_case(
            executed,
            name,
            PocoAgentMarketStoreV1::open(fixture.config(0)),
            AgentMarketErrorCodeV1::InvalidBounds,
        );
    }

    for name in [
        "order-height-regression",
        "order-height-cas-mismatch",
        "same-height-block-substitution",
    ] {
        let fixture = Fixture::new();
        let store = fixture.store(0);
        let capability = fixture.capability_body(false);
        let command =
            fixture.controller_command(false, 0, 0, ControllerBody::Capability(&capability));
        let execution = match name {
            "order-height-regression" => OrderFinalizedExecutionContextV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                expected_order_height: 100,
                expected_order_block_id: hash(3),
                order_height: 99,
                order_block_id: hash(90),
            },
            "order-height-cas-mismatch" => OrderFinalizedExecutionContextV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                expected_order_height: 101,
                expected_order_block_id: hash(90),
                order_height: 101,
                order_block_id: hash(90),
            },
            "same-height-block-substitution" => OrderFinalizedExecutionContextV1 {
                schema_version: 1,
                context: fixture.trust.context.clone(),
                expected_order_height: 100,
                expected_order_block_id: hash(3),
                order_height: 100,
                order_block_id: hash(90),
            },
            _ => unreachable!(),
        };
        let expected = if name == "order-height-cas-mismatch" {
            AgentMarketErrorCodeV1::StaleVersion
        } else {
            AgentMarketErrorCodeV1::InvalidContext
        };
        reject_case(
            executed,
            name,
            store.execute_order_finalized(&execution, &command),
            expected,
        );
    }

    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, _, _) = fixture.setup_agents(&store);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    task.task_offer_body.offer_expiry_height = 109;
    let command = fixture.session_command(
        false,
        1,
        0,
        0,
        &requester_cap,
        &requester_session,
        SessionBody::Task(task, task_charge()),
    );
    let execution = OrderFinalizedExecutionContextV1 {
        schema_version: 1,
        context: fixture.trust.context.clone(),
        expected_order_height: 100,
        expected_order_block_id: hash(3),
        order_height: 110,
        order_block_id: hash(90),
    };
    reject_case(
        executed,
        "order-finalized-deadline-expired",
        store.execute_order_finalized(&execution, &command),
        AgentMarketErrorCodeV1::InvalidState,
    );
}

fn prepared_market() -> (
    Fixture,
    PocoAgentMarketStoreV1,
    CapabilityGrantBodyV1,
    SessionKeyGrantBodyV1,
    CapabilityGrantBodyV1,
    SessionKeyGrantBodyV1,
    TaskCreationOperationBodyV1,
) {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let (requester_cap, requester_session, provider_cap, provider_session) =
        fixture.setup_agents(&store);
    let mut task = fixture.task_operation(1, 0);
    task.task_offer_body.requester_capability_id = Some(requester_cap.capability_id().unwrap());
    store
        .execute(&fixture.session_command(
            false,
            1,
            0,
            0,
            &requester_cap,
            &requester_session,
            SessionBody::Task(task.clone(), task_charge()),
        ))
        .unwrap();
    (
        fixture,
        store,
        requester_cap,
        requester_session,
        provider_cap,
        provider_session,
        task,
    )
}

fn execute_market_negative_vectors(executed: &mut Vec<&'static str>) {
    {
        let (fixture, store, _, _, provider_cap, provider_session, task) = prepared_market();
        let mut bid = fixture.bid_body(&task, 3, 0);
        bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
        let charge = KernelResourceChargeV1 {
            asset_charges: vec![
                AssetChargeV1 {
                    asset_id: hash(80),
                    amount: 1,
                },
                AssetChargeV1 {
                    asset_id: hash(80),
                    amount: 2,
                },
            ],
            ..empty_charge()
        };
        let command = fixture.session_command(
            true,
            3,
            0,
            0,
            &provider_cap,
            &provider_session,
            SessionBody::Bid(bid, charge),
        );
        reject_case(
            executed,
            "duplicate-asset-charge-asset",
            store.execute(&command),
            AgentMarketErrorCodeV1::NonCanonical,
        );
    }

    for (index, name) in [
        "bid-price-outside-scope",
        "bid-expired",
        "bid-task-revision-mismatch",
    ]
    .into_iter()
    .enumerate()
    {
        let (fixture, store, _, _, provider_cap, provider_session, task) = prepared_market();
        let mut bid = fixture.bid_body(&task, 3, 0);
        bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
        match index {
            0 => bid.maximum_price = 301,
            1 => bid.bid_expiry_height = 99,
            2 => bid.task_revision = 1,
            _ => unreachable!(),
        }
        let command = fixture.session_command(
            true,
            3,
            0,
            0,
            &provider_cap,
            &provider_session,
            SessionBody::Bid(bid, empty_charge()),
        );
        let expected = if index == 0 {
            AgentMarketErrorCodeV1::BudgetExceeded
        } else {
            AgentMarketErrorCodeV1::InvalidState
        };
        reject_case(executed, name, store.execute(&command), expected);
    }

    for name in [
        "underfunded-account",
        "escrow-allocation-exceeds-funding",
        "wrong-account-version",
    ] {
        let fixture = Fixture::new();
        let store = fixture.store(0);
        let (cap, grant, _, _) = fixture.setup_agents(&store);
        let mut task = fixture.task_operation(1, 0);
        task.task_offer_body.requester_capability_id = Some(cap.capability_id().unwrap());
        match name {
            "underfunded-account" => task.escrow_terms.funded_amount = 1_001,
            "escrow-allocation-exceeds-funding" => task.escrow_terms.provider_payment_cap = 400,
            "wrong-account-version" => task.expected_funding_account_version = 1,
            _ => unreachable!(),
        }
        task.task_offer_body.escrow_terms_hash =
            digest_value("trnm.poco-ai.escrow-terms.v1", &task.escrow_terms).unwrap();
        let charge = KernelResourceChargeV1 {
            asset_charges: vec![AssetChargeV1 {
                asset_id: hash(80),
                amount: task.escrow_terms.funded_amount,
            }],
            ..empty_charge()
        };
        let command = fixture.session_command(
            false,
            1,
            0,
            0,
            &cap,
            &grant,
            SessionBody::Task(task, charge),
        );
        let expected = if name == "escrow-allocation-exceeds-funding" {
            AgentMarketErrorCodeV1::ConservationViolation
        } else {
            AgentMarketErrorCodeV1::InsufficientFunds
        };
        reject_case(executed, name, store.execute(&command), expected);
    }

    // Each lease mutant receives the same committed Task+Bid prefix, so each
    // rejection is attributable to exactly the mutated precondition.
    for name in [
        "stale-bid-version",
        "stale-escrow-version",
        "stale-bond-version",
        "lease-environment-or-profile-substitution",
    ] {
        let (
            fixture,
            store,
            requester_cap,
            requester_session,
            provider_cap,
            provider_session,
            task,
        ) = prepared_market();
        let mut bid = fixture.bid_body(&task, 3, 0);
        bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
        store
            .execute(&fixture.session_command(
                true,
                3,
                0,
                0,
                &provider_cap,
                &provider_session,
                SessionBody::Bid(bid.clone(), empty_charge()),
            ))
            .unwrap();
        let mut lease = fixture.lease_body(&task, &bid);
        let (bid_version, escrow_version, bond_version) = match name {
            "stale-bid-version" => (1, 0, 0),
            "stale-escrow-version" => (0, 1, 0),
            "stale-bond-version" => (0, 0, 1),
            "lease-environment-or-profile-substitution" => {
                lease.execution_environment_hash = hash(99);
                (0, 0, 0)
            }
            _ => unreachable!(),
        };
        let command = fixture.session_command(
            false,
            2,
            0,
            0,
            &requester_cap,
            &requester_session,
            SessionBody::Lease(
                lease,
                bid_version,
                escrow_version,
                bond_version,
                empty_charge(),
            ),
        );
        reject_case(
            executed,
            name,
            store.execute(&command),
            AgentMarketErrorCodeV1::InvalidState,
        );
    }

    for name in ["bid-double-consume", "second-lease-for-attempt"] {
        let (
            fixture,
            store,
            requester_cap,
            requester_session,
            provider_cap,
            provider_session,
            task,
        ) = prepared_market();
        let mut bid = fixture.bid_body(&task, 3, 0);
        bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
        store
            .execute(&fixture.session_command(
                true,
                3,
                0,
                0,
                &provider_cap,
                &provider_session,
                SessionBody::Bid(bid.clone(), empty_charge()),
            ))
            .unwrap();
        let lease = fixture.lease_body(&task, &bid);
        store
            .execute(&fixture.session_command(
                false,
                2,
                0,
                0,
                &requester_cap,
                &requester_session,
                SessionBody::Lease(lease.clone(), 0, 0, 0, empty_charge()),
            ))
            .unwrap();
        let command = fixture.session_command(
            false,
            2,
            1,
            1,
            &requester_cap,
            &requester_session,
            SessionBody::Lease(lease, 1, 1, 1, empty_charge()),
        );
        reject_case(
            executed,
            name,
            store.execute(&command),
            AgentMarketErrorCodeV1::InvalidState,
        );
    }

    let (fixture, store, requester_cap, requester_session, provider_cap, provider_session, task) =
        prepared_market();
    let mut bid = fixture.bid_body(&task, 3, 0);
    bid.provider_capability_id = Some(provider_cap.capability_id().unwrap());
    store
        .execute(&fixture.session_command(
            true,
            3,
            0,
            0,
            &provider_cap,
            &provider_session,
            SessionBody::Bid(bid.clone(), empty_charge()),
        ))
        .unwrap();
    let lease = fixture.lease_body(&task, &bid);
    store
        .execute(&fixture.session_command(
            false,
            2,
            0,
            0,
            &requester_cap,
            &requester_session,
            SessionBody::Lease(lease.clone(), 0, 0, 0, empty_charge()),
        ))
        .unwrap();
    let acceptance = LeaseProviderAcceptanceBodyV1 {
        schema_version: 1,
        context: fixture.trust.context.clone(),
        lease_id: lease.lease_id().unwrap(),
        provider_agent_id: fixture.trust.provider.agent_id,
        expected_task_revision: 1,
        acceptance_nonce: hash(68),
    };
    let command = fixture.session_command(
        true,
        4,
        0,
        0,
        &provider_cap,
        &provider_session,
        SessionBody::ProviderAccept(acceptance, 1, empty_charge()),
    );
    reject_case(
        executed,
        "provider-acceptance-stale-lease",
        store.execute(&command),
        AgentMarketErrorCodeV1::InvalidState,
    );
}

fn execute_storage_negative_vectors(executed: &mut Vec<&'static str>) {
    let fixture = Fixture::new();
    let store = fixture.store(0);
    let cap = fixture.capability_body(false);
    let command = fixture.controller_command(false, 0, 0, ControllerBody::Capability(&cap));
    let receipt = store.execute(&command).unwrap().receipt().clone();
    let mut foreign_config = fixture.config(1);
    foreign_config.store_id = hash(121);
    let foreign = PocoAgentMarketStoreV1::open(foreign_config).unwrap();
    reject_case(
        executed,
        "cross-store-receipt",
        foreign.confirm_receipt(&receipt),
        AgentMarketErrorCodeV1::Unauthorized,
    );

    let sidecar_fixture = Fixture::new();
    drop(sidecar_fixture.store(0));
    fs::write(
        format!("{}-wal", sidecar_fixture.path(0).display()),
        b"sentinel",
    )
    .unwrap();
    executed.push("sqlite-sidecar-present");
    assert_eq!(
        PocoAgentMarketStoreV1::open(sidecar_fixture.config(0))
            .unwrap_err()
            .code(),
        AgentMarketErrorCodeV1::SidecarPresent
    );

    for (index, name) in [
        "schema-missing-table",
        "object-row-tamper",
        "operation-journal-deletion",
        "metadata-high-watermark-tamper",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let store = fixture.store(index);
        let cap = fixture.capability_body(false);
        store
            .execute(&fixture.controller_command(false, 0, 0, ControllerBody::Capability(&cap)))
            .unwrap();
        drop(store);
        let connection = Connection::open(fixture.path(index)).unwrap();
        match name {
            "schema-missing-table" => {
                connection
                    .execute("DROP TABLE agent_market_objects_v1", [])
                    .unwrap();
            }
            "object-row-tamper" => {
                connection.execute("UPDATE agent_market_objects_v1 SET mutable_state = X'00' WHERE object_id = (SELECT MIN(object_id) FROM agent_market_objects_v1)", []).unwrap();
            }
            "operation-journal-deletion" => {
                connection
                    .execute("DELETE FROM agent_market_operations_v1", [])
                    .unwrap();
            }
            "metadata-high-watermark-tamper" => {
                connection
                    .execute(
                        "UPDATE agent_market_metadata_v1 SET sequence = X'0000000000000002'",
                        [],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        executed.push(name);
        let expected = if name == "schema-missing-table" {
            AgentMarketErrorCodeV1::SchemaMismatch
        } else {
            AgentMarketErrorCodeV1::TamperDetected
        };
        assert_eq!(
            PocoAgentMarketStoreV1::open(fixture.config(index))
                .unwrap_err()
                .code(),
            expected,
            "{name}"
        );
    }

    let fixture = Fixture::new();
    let store = fixture.store(20);
    let cap = fixture.capability_body(false);
    store
        .execute(&fixture.controller_command(false, 0, 0, ControllerBody::Capability(&cap)))
        .unwrap();
    drop(store);
    let connection = Connection::open(fixture.path(20)).unwrap();
    let (kind, id, version, body, state): (u16, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT object_kind,object_id,object_version,immutable_body,mutable_state FROM agent_market_objects_v1 WHERE object_kind=2 LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap();
    let mut decoded: CapabilityStateV1 = strict_decode(&state).unwrap();
    decoded.status = 1;
    let replacement_state = canonical_bytes(&decoded).unwrap();
    let replacement_checksum = checksum(&[
        &kind.to_le_bytes(),
        &id,
        &version,
        &body,
        &replacement_state,
    ]);
    connection
        .execute(
            "UPDATE agent_market_objects_v1 SET mutable_state=?1,row_checksum=?2 WHERE object_kind=?3 AND object_id=?4",
            params![replacement_state, &replacement_checksum.0[..], kind, id],
        )
        .unwrap();
    drop(connection);
    reject_case(
        executed,
        "self-consistent-object-row-substitution",
        PocoAgentMarketStoreV1::open(fixture.config(20)),
        AgentMarketErrorCodeV1::TamperDetected,
    );

    let fixture = Fixture::new();
    let store = fixture.store(21);
    let cap = fixture.capability_body(false);
    store
        .execute(&fixture.controller_command(false, 0, 0, ControllerBody::Capability(&cap)))
        .unwrap();
    drop(store);
    let connection = Connection::open(fixture.path(21)).unwrap();
    let (operation_id, sequence, kind, command, receipt): (
        Vec<u8>,
        Vec<u8>,
        u16,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT operation_id,sequence,operation_kind,command,receipt FROM agent_market_operations_v1 ORDER BY sequence LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap();
    let mut decoded: KernelTransitionReceiptV1 = strict_decode(&receipt).unwrap();
    decoded.post_state_root = hash(99);
    let replacement_receipt = canonical_bytes(&decoded).unwrap();
    let replacement_checksum = checksum(&[
        &operation_id,
        &sequence,
        &kind.to_le_bytes(),
        &command,
        &replacement_receipt,
    ]);
    connection
        .execute(
            "UPDATE agent_market_operations_v1 SET receipt=?1,row_checksum=?2 WHERE operation_id=?3",
            params![replacement_receipt, &replacement_checksum.0[..], operation_id],
        )
        .unwrap();
    drop(connection);
    reject_case(
        executed,
        "self-consistent-operation-row-substitution",
        PocoAgentMarketStoreV1::open(fixture.config(21)),
        AgentMarketErrorCodeV1::TamperDetected,
    );
}

#[test]
fn open_existing_requires_precreated_regular_nonsymlink_store() {
    let fixture = Fixture::new();
    let config = fixture.config(0);

    assert_eq!(
        PocoAgentMarketStoreV1::open_existing(config.clone())
            .expect_err("missing store")
            .code(),
        AgentMarketErrorCodeV1::StoreFailure
    );
    assert!(!config.path.exists(), "strict open must not create a store");

    drop(PocoAgentMarketStoreV1::open(config.clone()).expect("create store"));
    drop(PocoAgentMarketStoreV1::open_existing(config.clone()).expect("strict reopen"));

    let directory_path = fixture.directory.path().join("not-a-store-file");
    fs::create_dir(&directory_path).expect("directory object");
    let mut directory_config = config.clone();
    directory_config.path = directory_path;
    assert_eq!(
        PocoAgentMarketStoreV1::open_existing(directory_config)
            .expect_err("directory store path")
            .code(),
        AgentMarketErrorCodeV1::StoreFailure
    );

    #[cfg(unix)]
    {
        let symlink_path = fixture.directory.path().join("store-link.sqlite");
        std::os::unix::fs::symlink(&config.path, &symlink_path).expect("store symlink");
        let mut symlink_config = config;
        symlink_config.path = symlink_path;
        assert_eq!(
            PocoAgentMarketStoreV1::open_existing(symlink_config)
                .expect_err("symlink store path")
                .code(),
            AgentMarketErrorCodeV1::StoreFailure
        );
    }
}

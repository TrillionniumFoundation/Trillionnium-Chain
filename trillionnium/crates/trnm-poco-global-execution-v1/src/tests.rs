use borsh::BorshSerialize;
use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use trnm_poco_agent_market_v1 as agent;
use trnm_poco_consumption_settlement_v1 as settlement;
use trnm_poco_da_v1 as da;
use trnm_poco_mvcc_fee_v1 as mvcc;
use trnm_poco_order_application_v1 as order_application;
use trnm_poco_order_finality_verifier_v1 as order;
use trnm_poco_order_types_v1 as order_types;
use trnm_poco_verify_challenge_v1 as verify;

use crate::{
    codec::digest_value,
    error::GlobalExecutionErrorCodeV1,
    store::{
        decode_complete_retrieval_v1, derive_inert_order_binding_create_material_v1,
        sample_source_cut, GlobalExecutionSourcesV1, WholeNodeFinalizationFaultV1,
    },
    types::CandidateCompositeCommitmentBodyV1,
    CandidateCompositeCommitmentV1, CandidateExecutionContextV1, GlobalExecutionBatchV1, Hash32V1,
    ManifestBoundGlobalExecutionBatchV2, ManifestBoundGlobalExecutionInputV2,
    PocoGlobalExecutionStoreV1, PreVoteProposalV1,
};

fn bytes(value: u8) -> [u8; 32] {
    [value; 32]
}

fn gh(value: u8) -> Hash32V1 {
    Hash32V1(bytes(value))
}

fn ah(value: u8) -> agent::Hash32V1 {
    agent::Hash32V1(bytes(value))
}

fn candidate_context() -> CandidateExecutionContextV1 {
    CandidateExecutionContextV1 {
        schema_version: 1,
        chain_id: "trnm-global-pre-vote-test".to_owned(),
        genesis_hash: gh(1),
        protocol_version: 1,
        stack_profile_hash: gh(2),
    }
}

fn agent_context() -> agent::ProtocolContextV1 {
    let context = candidate_context();
    agent::ProtocolContextV1 {
        genesis_hash: ah(1),
        chain_id: context.chain_id,
        protocol_version: 1,
        stack_profile_hash: ah(2),
    }
}

fn digest_agent<T: BorshSerialize>(domain: &str, value: &T) -> agent::Hash32V1 {
    agent::Hash32V1(digest_value(domain, value).expect("candidate digest").0)
}

fn placeholder_agent_authorization() -> agent::KernelAuthorizationV1 {
    agent::KernelAuthorizationV1 {
        statement: agent::KernelAuthorizationStatementV1 {
            schema_version: 1,
            context: agent::ProtocolContextV1 {
                genesis_hash: ah(0),
                chain_id: String::new(),
                protocol_version: 1,
                stack_profile_hash: ah(0),
            },
            operation_kind: 0,
            operation_digest: ah(0),
            sender_agent_id: agent::AgentIdV1(bytes(0)),
            authorizing_key_id: agent::AgentKeyIdV1(bytes(0)),
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
        signer_key_id: agent::AgentKeyIdV1(bytes(0)),
        signature: vec![0; 64],
    }
}

fn requester_capability_body() -> agent::CapabilityGrantBodyV1 {
    agent::CapabilityGrantBodyV1 {
        schema_version: 1,
        genesis_hash: ah(1),
        chain_id: candidate_context().chain_id,
        protocol_version: 1,
        stack_profile_hash: ah(2),
        issuer_agent_id: agent::AgentIdV1(bytes(1)),
        issuer_key_id: agent::CONTROLLER_SENTINEL_KEY_V1,
        delegate_agent_id: agent::AgentIdV1(bytes(1)),
        delegate_key_id: Some(agent::AgentKeyIdV1(bytes(12))),
        parent_capability_id: None,
        grant_nonce: ah(30),
        operation_scopes: vec![agent::OperationScopeV1 {
            operation_kind: 4,
            task_id: None,
            market_id: None,
            model_commitment: Some(ah(51)),
            tool_commitment: Some(ah(52)),
            endpoint_commitment: None,
            verification_profile: Some(agent::VerificationProfileRefV1 {
                profile_id: b"deterministic-reexecute".to_vec(),
                profile_version: 1,
                profile_hash: ah(53),
            }),
            privacy_lane: Some(0),
            maximum_unit_price: None,
        }],
        resource_scopes: vec![agent::ResourceScopeV1 {
            resource_kind: 1,
            scope_mode: 0,
            allowed_ids: vec![ah(56)],
            allowlist_commitment: None,
        }],
        spend_limits: vec![agent::AssetLimitV1 {
            asset_id: ah(80),
            maximum_amount: 700,
        }],
        fee_limit: 100,
        gas_limit: 100_000,
        da_byte_limit: 10_000,
        artifact_retention_limit: 1_000,
        allowed_nonce_lanes: vec![1, 2],
        valid_from_height: 1,
        expires_after_height: 50,
        rate_window_blocks: 10,
        rate_max_operations: 20,
        max_total_operations: 20,
        delegation_depth_remaining: 0,
        revocation_generation: 0,
        conditions_hash: ah(41),
    }
}

fn requester_session_body(
    capability: &agent::CapabilityGrantBodyV1,
) -> agent::SessionKeyGrantBodyV1 {
    agent::SessionKeyGrantBodyV1 {
        schema_version: 1,
        genesis_hash: ah(1),
        chain_id: candidate_context().chain_id,
        protocol_version: 1,
        stack_profile_hash: ah(2),
        agent_id: agent::AgentIdV1(bytes(1)),
        session_key_id: agent::AgentKeyIdV1(bytes(12)),
        capability_id: capability.capability_id().expect("capability ID"),
        allowed_nonce_lanes: capability.allowed_nonce_lanes.clone(),
        valid_from_height: 1,
        expires_after_height: 49,
        max_total_operations: 10,
        session_generation: 1,
        grant_nonce: ah(32),
    }
}

fn with_agent_authorization(
    command: agent::KernelCommandV1,
    authorization: agent::KernelAuthorizationV1,
) -> agent::KernelCommandV1 {
    match command {
        agent::KernelCommandV1::CapabilityGrant { body, .. } => {
            agent::KernelCommandV1::CapabilityGrant {
                body,
                authorization,
            }
        }
        agent::KernelCommandV1::SessionGrant { body, .. } => agent::KernelCommandV1::SessionGrant {
            body,
            authorization,
        },
        agent::KernelCommandV1::TaskCreate { body, charge, .. } => {
            agent::KernelCommandV1::TaskCreate {
                body,
                charge,
                authorization,
            }
        }
        _ => panic!("test helper supports requester setup/task commands only"),
    }
}

fn sign_agent_authorization(
    statement: &agent::KernelAuthorizationStatementV1,
    signer_key_id: agent::AgentKeyIdV1,
    signing_key: &SigningKey,
) -> agent::KernelAuthorizationV1 {
    let domain = match statement.operation_kind {
        2 => "trnm.poco-ai.capability-grant-kernel-signature.candidate.v1",
        3 => "trnm.poco-ai.session-grant-kernel-signature.candidate.v1",
        4 => "trnm.poco-ai.task-offer-kernel-signature.candidate.v1",
        _ => panic!("unsupported Agent command domain"),
    };
    let signing_root = digest_agent(domain, statement);
    agent::KernelAuthorizationV1 {
        statement: statement.clone(),
        signer_key_id,
        signature: signing_key.sign(&signing_root.0).to_bytes().to_vec(),
    }
}

fn controller_command(
    unsigned: agent::KernelCommandV1,
    nonce: u64,
    expected_lane_version: u64,
) -> agent::KernelCommandV1 {
    let statement = agent::KernelAuthorizationStatementV1 {
        schema_version: 1,
        context: agent_context(),
        operation_kind: unsigned.operation_kind(),
        operation_digest: unsigned.operation_digest().expect("operation digest"),
        sender_agent_id: agent::AgentIdV1(bytes(1)),
        authorizing_key_id: agent::CONTROLLER_SENTINEL_KEY_V1,
        capability_id: None,
        live_capability_generation: 0,
        session_key_grant_id: None,
        session_generation: 0,
        nonce_lane: 0,
        nonce,
        expected_lane_version,
        valid_after_height: 1,
        expires_after_height: 20,
    };
    with_agent_authorization(
        unsigned,
        sign_agent_authorization(
            &statement,
            agent::AgentKeyIdV1(bytes(11)),
            &SigningKey::from_bytes(&bytes(11)),
        ),
    )
}

fn capability_command(nonce: u64, expected_lane_version: u64) -> agent::KernelCommandV1 {
    controller_command(
        agent::KernelCommandV1::CapabilityGrant {
            body: requester_capability_body(),
            authorization: placeholder_agent_authorization(),
        },
        nonce,
        expected_lane_version,
    )
}

fn session_grant_command(
    capability: &agent::CapabilityGrantBodyV1,
    nonce: u64,
    expected_lane_version: u64,
) -> agent::KernelCommandV1 {
    controller_command(
        agent::KernelCommandV1::SessionGrant {
            body: requester_session_body(capability),
            authorization: placeholder_agent_authorization(),
        },
        nonce,
        expected_lane_version,
    )
}

fn task_operation(
    capability: &agent::CapabilityGrantBodyV1,
    funded_amount: u128,
) -> agent::TaskCreationOperationBodyV1 {
    let terms = agent::EscrowTermsV1 {
        schema_version: 1,
        asset_id: ah(80),
        funded_amount,
        provider_payment_cap: 300,
        order_fee_reserve: 20,
        transaction_da_fee_reserve: 20,
        artifact_da_fee_reserve: 40,
        verification_fee_reserve: 40,
        challenge_reserve: 50,
        refund_beneficiary: agent::AgentIdV1(bytes(1)),
        settlement_policy_hash: ah(55),
    };
    let offer = agent::TaskOfferBodyV1 {
        schema_version: 1,
        genesis_hash: ah(1),
        chain_id: candidate_context().chain_id,
        protocol_version: 1,
        stack_profile_hash: ah(2),
        requester_agent_id: agent::AgentIdV1(bytes(1)),
        requester_key_id: agent::AgentKeyIdV1(bytes(12)),
        requester_capability_id: Some(capability.capability_id().expect("capability ID")),
        requester_session_generation: 1,
        request_nonce_lane: 1,
        request_nonce: 0,
        task_kind: b"inference".to_vec(),
        task_spec_commitment: ah(50),
        input_artifacts: Vec::new(),
        model_scope_commitment: ah(51),
        tool_scope_commitment: ah(52),
        verification_profile_id: b"deterministic-reexecute".to_vec(),
        verification_profile_version: 1,
        verification_profile_hash: ah(53),
        privacy_lane: 0,
        provider_policy_hash: ah(54),
        resource_limit_hash: ah(56),
        pricing_policy_hash: ah(57),
        escrow_terms_hash: digest_agent("trnm.poco-ai.escrow-terms.v1", &terms),
        checkpoint_policy_hash: ah(58),
        migration_policy_hash: ah(59),
        challenge_policy_hash: ah(60),
        offer_expiry_height: 20,
        start_deadline_height: 30,
        result_deadline_height: 40,
        settlement_deadline_height: 45,
        requester_metadata_commitment: ah(61),
    };
    agent::TaskCreationOperationBodyV1 {
        task_offer_body: offer,
        escrow_terms: terms,
        funding_account_id: agent::AccountBodyV1 {
            schema_version: 1,
            context: agent_context(),
            owner_agent_id: agent::AgentIdV1(bytes(1)),
            asset_id: ah(80),
            account_nonce: ah(81),
        }
        .account_id()
        .expect("account ID"),
        expected_funding_account_version: 0,
        escrow_nonce: ah(62),
    }
}

fn task_command(funded_amount: u128, fee: u128) -> agent::KernelCommandV1 {
    let capability = requester_capability_body();
    let session = requester_session_body(&capability);
    let unsigned = agent::KernelCommandV1::TaskCreate {
        body: task_operation(&capability, funded_amount),
        charge: agent::KernelResourceChargeV1 {
            asset_charges: vec![agent::AssetChargeV1 {
                asset_id: ah(80),
                amount: funded_amount,
            }],
            fee,
            gas: 10,
            da_bytes: 10,
            retention: 1,
            operations: 1,
        },
        authorization: placeholder_agent_authorization(),
    };
    let statement = agent::KernelAuthorizationStatementV1 {
        schema_version: 1,
        context: agent_context(),
        operation_kind: unsigned.operation_kind(),
        operation_digest: unsigned.operation_digest().expect("operation digest"),
        sender_agent_id: agent::AgentIdV1(bytes(1)),
        authorizing_key_id: agent::AgentKeyIdV1(bytes(12)),
        capability_id: Some(capability.capability_id().expect("capability ID")),
        live_capability_generation: 0,
        session_key_grant_id: Some(session.session_key_grant_id().expect("session ID")),
        session_generation: 1,
        nonce_lane: 1,
        nonce: 0,
        expected_lane_version: 0,
        valid_after_height: 1,
        expires_after_height: 20,
    };
    with_agent_authorization(
        unsigned,
        sign_agent_authorization(
            &statement,
            agent::AgentKeyIdV1(bytes(12)),
            &SigningKey::from_bytes(&bytes(12)),
        ),
    )
}

fn install_requester_session(store: &agent::PocoAgentMarketStoreV1) {
    let capability = requester_capability_body();
    let execution = agent::OrderFinalizedExecutionContextV1 {
        schema_version: 1,
        context: agent_context(),
        expected_order_height: 10,
        expected_order_block_id: ah(202),
        order_height: 10,
        order_block_id: ah(202),
    };
    store
        .execute_order_finalized(&execution, &capability_command(0, 0))
        .expect("install requester capability");
    store
        .execute_order_finalized(&execution, &session_grant_command(&capability, 1, 1))
        .expect("install requester session");
}

fn agent_store(path: &std::path::Path) -> agent::PocoAgentMarketStoreV1 {
    let requester_controller = SigningKey::from_bytes(&bytes(11));
    let requester_session = SigningKey::from_bytes(&bytes(12));
    let provider_controller = SigningKey::from_bytes(&bytes(21));
    let provider_session = SigningKey::from_bytes(&bytes(22));
    let context = agent_context();
    let requester = agent::BootstrapAgentV1 {
        agent_id: agent::AgentIdV1(bytes(1)),
        controller_key_id: agent::AgentKeyIdV1(bytes(11)),
        controller_public_key: requester_controller.verifying_key().to_bytes(),
        session_key_id: agent::AgentKeyIdV1(bytes(12)),
        session_public_key: requester_session.verifying_key().to_bytes(),
    };
    let provider = agent::BootstrapAgentV1 {
        agent_id: agent::AgentIdV1(bytes(2)),
        controller_key_id: agent::AgentKeyIdV1(bytes(21)),
        controller_public_key: provider_controller.verifying_key().to_bytes(),
        session_key_id: agent::AgentKeyIdV1(bytes(22)),
        session_public_key: provider_session.verifying_key().to_bytes(),
    };
    let account_body = agent::AccountBodyV1 {
        schema_version: 1,
        context: context.clone(),
        owner_agent_id: requester.agent_id,
        asset_id: ah(80),
        account_nonce: ah(81),
    };
    let bond_body = agent::BondBodyV1 {
        schema_version: 1,
        context: context.clone(),
        owner_agent_id: provider.agent_id,
        asset_id: ah(80),
        purpose: 1,
        source_object_kind: 0,
        source_object_id: ah(82),
        bond_nonce: ah(83),
    };
    let trust = agent::AgentMarketFreshGenesisTrustBundleV1 {
        schema_version: 1,
        context,
        initial_order_height: 10,
        initial_order_block_id: ah(202),
        requester,
        provider,
        requester_account_id: account_body.account_id().expect("account ID"),
        requester_account_body: account_body,
        requester_account_funding: 1_000,
        provider_bond_id: bond_body.bond_id().expect("bond ID"),
        provider_bond_body: bond_body,
        provider_bond_funding: 500,
        provider_bond_hold: 100,
    };
    agent::PocoAgentMarketStoreV1::open(agent::AgentMarketStoreConfigV1 {
        path: path.to_path_buf(),
        store_id: ah(110),
        trust_bundle: trust,
    })
    .expect("Agent store")
}

fn verify_store(path: &std::path::Path) -> verify::VerifyChallengeStoreV1 {
    let provider_key = SigningKey::from_bytes(&bytes(31));
    let challenger_key = SigningKey::from_bytes(&bytes(32));
    let verifier_keys = [
        SigningKey::from_bytes(&bytes(41)),
        SigningKey::from_bytes(&bytes(42)),
        SigningKey::from_bytes(&bytes(43)),
        SigningKey::from_bytes(&bytes(44)),
    ];
    let context = agent_context();
    let verifiers = verifier_keys
        .iter()
        .enumerate()
        .map(|(index, key)| verify::RegisteredVerifierV1 {
            verifier_id: bytes(u8::try_from(51 + index).unwrap()),
            key_id: bytes(u8::try_from(61 + index).unwrap()),
            public_key: key.verifying_key().to_bytes(),
            weight: 1,
        })
        .collect::<Vec<_>>();
    let verifier_set_hash = digest_agent("trnm.poco-ai.verifier-set.candidate.v1", &verifiers);
    let profile_id = b"stake-quorum-test".to_vec();
    let required_da_policy_hash = ah(70);
    let challenge_policy_hash = ah(71);
    let settlement_policy_hash = ah(72);
    let challenge_bond_asset_id = ah(73);
    let profile_hash = digest_agent(
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
    );
    let trust = verify::VerifyChallengeFreshGenesisTrustBundleV1 {
        schema_version: 1,
        context,
        initial_order_height: 10,
        initial_order_block_id: ah(202),
        task_id: ah(74),
        task_revision: 7,
        lease_id: ah(75),
        attempt: 1,
        execution_environment_hash: ah(76),
        provider: verify::RegisteredActorV1 {
            agent_id: agent::AgentIdV1(bytes(31)),
            key_id: agent::AgentKeyIdV1(bytes(31)),
            public_key: provider_key.verifying_key().to_bytes(),
        },
        challenger: verify::RegisteredActorV1 {
            agent_id: agent::AgentIdV1(bytes(32)),
            key_id: agent::AgentKeyIdV1(bytes(32)),
            public_key: challenger_key.verifying_key().to_bytes(),
        },
        verifiers,
        profile: verify::StakeQuorumProfileV1 {
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
        challenge_bond_id: agent::BondIdV1(bytes(77)),
        challenge_bond_funding: 200,
    };
    verify::VerifyChallengeStoreV1::open(verify::VerifyChallengeStoreConfigV1 {
        path: path.to_path_buf(),
        store_id: ah(111),
        trust_bundle: trust,
    })
    .expect("Verify store")
}

fn settlement_store(path: &std::path::Path) -> settlement::ConsumptionSettlementStoreV1 {
    let provider_key = SigningKey::from_bytes(&bytes(81));
    let consumer_key = SigningKey::from_bytes(&bytes(82));
    let policy = settlement::SettlementPolicyV1 {
        schema_version: 1,
        policy_revision: 1,
        minimum_rollup_challenge_blocks: 2,
        maximum_rollups: 1,
        protocol_fee_numerator: 1,
        protocol_fee_denominator: 10,
        fee_schedule_hash: ah(83),
    };
    let trust = settlement::ConsumptionSettlementFreshGenesisTrustBundleV1 {
        schema_version: 1,
        context: agent_context(),
        initial_order_height: 10,
        initial_order_block_id: ah(202),
        provider: settlement::RegisteredBilateralKeyV1 {
            agent_id: agent::AgentIdV1(bytes(81)),
            key_id: agent::AgentKeyIdV1(bytes(81)),
            public_key: provider_key.verifying_key().to_bytes(),
            policy_revision: 1,
            key_generation: 1,
        },
        consumer: settlement::RegisteredBilateralKeyV1 {
            agent_id: agent::AgentIdV1(bytes(82)),
            key_id: agent::AgentKeyIdV1(bytes(82)),
            public_key: consumer_key.verifying_key().to_bytes(),
            policy_revision: 1,
            key_generation: 1,
        },
        task_id: agent::TaskIdV1(bytes(84)),
        lease_id: agent::LeaseIdV1(bytes(85)),
        attempt: 1,
        result_id: settlement::ResultIdV1(bytes(86)),
        result_revision: 1,
        result_status: settlement::RESULT_STATUS_FINAL_VALID_V1,
        escrow_id: agent::EscrowIdV1(bytes(87)),
        escrow_version: 1,
        asset_id: ah(88),
        escrow_funding: 1_000,
        provider_account_id: agent::AccountIdV1(bytes(89)),
        consumer_account_id: agent::AccountIdV1(bytes(90)),
        protocol_account_id: agent::AccountIdV1(bytes(91)),
        provider_opening_balance: 10,
        consumer_opening_balance: 20,
        protocol_opening_balance: 30,
        prices: vec![settlement::ConsumptionPriceV1 {
            resource_class: 7,
            resource_id: b"gpu".to_vec(),
            meter_id: b"meter".to_vec(),
            meter_version: 1,
            unit: 3,
            unit_price: 3,
        }],
        accepted_evidence_certificates: vec![settlement::AvailabilityCertificateIdV1(bytes(92))],
        related_party_policy_hash: ah(93),
        settlement_policy: policy,
    };
    settlement::ConsumptionSettlementStoreV1::open(settlement::ConsumptionSettlementStoreConfigV1 {
        path: path.to_path_buf(),
        store_id: ah(113),
        trust_bundle: trust,
    })
    .expect("Settlement store")
}

fn oid(kind: u16, byte: u8) -> mvcc::TypedObjectIdV1 {
    mvcc::TypedObjectIdV1 {
        object_kind: kind,
        object_id: bytes(byte),
    }
}

fn mvcc_genesis() -> mvcc::MvccFeeGenesisV1 {
    let mut initial_objects = vec![
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: oid(45, 1),
            version: 0,
            value: 10_000,
            closed: false,
        },
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: oid(45, 2),
            version: 0,
            value: 100,
            closed: false,
        },
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: oid(46, 10),
            version: 0,
            value: 0,
            closed: false,
        },
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: oid(46, 11),
            version: 0,
            value: 0,
            closed: false,
        },
    ];
    initial_objects.sort_by_key(|object| object.object_id);
    mvcc::MvccFeeGenesisV1 {
        schema_version: 1,
        context: mvcc::ProtocolContextV1 {
            chain_id: candidate_context().chain_id.into_bytes(),
            genesis_hash: mvcc::Hash32V1(bytes(1)),
            protocol_id: b"trnm-poco-ai-native-v1".to_vec(),
            protocol_version: 1,
            profile_hash: mvcc::Hash32V1(bytes(2)),
        },
        store_id: mvcc::Hash32V1(bytes(112)),
        initial_height: 10,
        initial_block_id: mvcc::Hash32V1(bytes(202)),
        initial_objects,
        resource_prices: vec![
            mvcc::ResourcePriceV1 {
                resource_class: 0,
                resource_id: vec![],
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            mvcc::ResourcePriceV1 {
                resource_class: 2,
                resource_id: vec![],
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            mvcc::ResourcePriceV1 {
                resource_class: 3,
                resource_id: vec![],
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            mvcc::ResourcePriceV1 {
                resource_class: 7,
                resource_id: vec![],
                unit: 3,
                price_numerator: 1,
                price_denominator: 10,
                minimum_charge: 1,
                maximum_charge: 100,
            },
        ],
        destination_splits: vec![
            mvcc::FeeDestinationSplitV1 {
                destination: oid(46, 10),
                numerator: 3,
                denominator: 4,
            },
            mvcc::FeeDestinationSplitV1 {
                destination: oid(46, 11),
                numerator: 1,
                denominator: 4,
            },
        ],
        remainder_destination: oid(46, 11),
    }
}

fn mvcc_candidate(genesis: &mvcc::MvccFeeGenesisV1) -> mvcc::MvccBlockV1 {
    let mut access = vec![oid(45, 1), oid(45, 2)];
    access.sort_unstable();
    let mut transaction = mvcc::MvccTransactionV1 {
        schema_version: 1,
        transaction_id: mvcc::Hash32V1([0; 32]),
        transaction_index: 0,
        fee_payer: oid(45, 1),
        declared_reads: access.clone(),
        declared_writes: access,
        compute_unit_limit: 100,
        max_fee: 1_000,
        program: mvcc::ObjectProgramV1::Add {
            target: oid(45, 2),
            amount: 10,
        },
    };
    transaction.transaction_id = mvcc::derive_transaction_id_v1(&transaction).unwrap();
    let parent_root = mvcc::derive_state_root_v1(&genesis.initial_objects).unwrap();
    let mut block = mvcc::MvccBlockV1 {
        schema_version: 1,
        context: genesis.context.clone(),
        block_id: mvcc::Hash32V1([0; 32]),
        height: 11,
        expected_parent_height: 10,
        expected_parent_block_id: genesis.initial_block_id,
        expected_parent_state_root: parent_root,
        transactions: vec![transaction],
    };
    block.block_id = mvcc::derive_block_id_v1(&block).unwrap();
    block
}

struct DaFixture {
    committee: da::DaCommitteeDescriptorV1,
    policy: da::DaPolicyV1,
    author_key: SigningKey,
    author_id: Vec<u8>,
    attestors: Vec<(da::Hash32V1, SigningKey)>,
}

impl DaFixture {
    fn new() -> Self {
        let context = da::ProtocolContextV1::new(
            da::Hash32V1::new(bytes(1)),
            candidate_context().chain_id,
            da::Hash32V1::new(bytes(2)),
        )
        .unwrap();
        let mut members_and_keys = (10u8..14)
            .map(|seed| {
                let key = SigningKey::from_bytes(&bytes(seed));
                let member = da::DaMemberV1::new(
                    key.verifying_key().to_bytes(),
                    1,
                    Some(vec![seed]),
                    da::Hash32V1::new(bytes(seed + 20)),
                    da::Hash32V1::new(bytes(seed + 40)),
                )
                .unwrap();
                (member, key)
            })
            .collect::<Vec<_>>();
        members_and_keys.sort_by_key(|(member, _)| member.definition_hash());
        let members = members_and_keys
            .iter()
            .map(|(member, _)| member.clone())
            .collect::<Vec<_>>();
        let attestors = members_and_keys
            .into_iter()
            .map(|(member, key)| (member.definition_hash(), key))
            .collect::<Vec<_>>();
        let committee = da::DaCommitteeDescriptorV1::new_transaction_batch(
            context, 7, members, 2, 8_192, 4_096, 32, 4,
        )
        .unwrap();
        let author_key = SigningKey::from_bytes(&bytes(77));
        let author_id = b"agent:global/session:1".to_vec();
        let authority = da::DaAuthorAuthorityV1::new(
            author_id.clone(),
            author_key.verifying_key().to_bytes(),
            1,
            16,
            8_192,
            4,
        )
        .unwrap();
        let policy = da::DaPolicyV1::new_transaction_batch(
            &committee,
            vec![authority],
            32,
            256,
            8,
            32_768,
            50,
            20,
        )
        .unwrap();
        Self {
            committee,
            policy,
            author_key,
            author_id,
            attestors,
        }
    }

    fn store(&self, path: &std::path::Path, index: usize, store_byte: u8) -> da::PocoDaStoreV1 {
        da::PocoDaStoreV1::open(
            da::DaStoreConfigV1::new(
                path,
                da::Hash32V1::new(bytes(90)),
                da::Hash32V1::new(bytes(store_byte)),
                self.committee.clone(),
                self.policy.clone(),
                self.attestors[index].0,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn admit_and_attest(
        &self,
        store: &da::PocoDaStoreV1,
        index: usize,
        attestation_sequence: u64,
        batch: &da::UnsignedTransactionBatchV1,
        author: &da::DaBatchAuthorV1,
    ) -> da::DaAttestationV1 {
        store.admit_batch(batch, author).unwrap();
        let intent = match store
            .prepare_attestation(batch.batch_id(), attestation_sequence)
            .unwrap()
        {
            da::AttestationPreparationOutcomeV1::Prepared(intent) => intent,
            da::AttestationPreparationOutcomeV1::Existing(_) => panic!("unexpected attestation"),
        };
        let signature = self.attestors[index]
            .1
            .sign(intent.signing_root().unwrap().as_bytes())
            .to_bytes()
            .to_vec();
        store.complete_attestation(intent, signature).unwrap()
    }
}

pub(crate) struct Rig {
    _temporary: TempDir,
    global_path: std::path::PathBuf,
    pub(crate) context: CandidateExecutionContextV1,
    da_fixture: DaFixture,
    da: da::PocoDaStoreV1,
    da_second: da::PocoDaStoreV1,
    da_third: da::PocoDaStoreV1,
    agent: agent::PocoAgentMarketStoreV1,
    verify: verify::VerifyChallengeStoreV1,
    mvcc: mvcc::MvccFeeStoreV1,
    settlement: settlement::ConsumptionSettlementStoreV1,
    global: PocoGlobalExecutionStoreV1,
    pub(crate) batch: GlobalExecutionBatchV1,
    pub(crate) batch_id: da::BatchIdV1,
    missing_batch_id: da::BatchIdV1,
    pub(crate) certificate_id: da::AvailabilityCertificateIdV1,
}

#[derive(Clone, Copy)]
enum DaPayloadShape {
    Canonical,
    TrailingByte,
    MultipleGlobalItems,
}

impl Rig {
    pub(crate) fn new() -> Self {
        Self::new_with_options(Vec::new(), false, DaPayloadShape::Canonical)
    }

    fn new_with_agent_commands(
        commands: Vec<agent::KernelCommandV1>,
        install_session: bool,
    ) -> Self {
        Self::new_with_options(commands, install_session, DaPayloadShape::Canonical)
    }

    fn new_with_payload_shape(shape: DaPayloadShape) -> Self {
        Self::new_with_options(Vec::new(), false, shape)
    }

    fn new_with_options(
        agent_market_commands: Vec<agent::KernelCommandV1>,
        install_session: bool,
        payload_shape: DaPayloadShape,
    ) -> Self {
        let temporary = TempDir::new().unwrap();
        let context = candidate_context();
        let agent = agent_store(&temporary.path().join("agent.sqlite"));
        if install_session {
            install_requester_session(&agent);
        }
        let verify = verify_store(&temporary.path().join("verify.sqlite"));
        let settlement = settlement_store(&temporary.path().join("settlement.sqlite"));
        let genesis = mvcc_genesis();
        let mvcc =
            mvcc::MvccFeeStoreV1::open(temporary.path().join("mvcc.sqlite"), genesis.clone())
                .unwrap();
        let mvcc_block = mvcc_candidate(&genesis);
        let batch = GlobalExecutionBatchV1 {
            schema_version: 1,
            context: context.clone(),
            candidate_height: 11,
            candidate_block_id: gh(203),
            agent_market_commands,
            verify_challenge_commands: Vec::new(),
            mvcc_fee_block: mvcc_block,
            consumption_settlement_commands: Vec::new(),
        };

        let da_fixture = DaFixture::new();
        let canonical_item = borsh::to_vec(&batch).unwrap();
        let transaction_items = match payload_shape {
            DaPayloadShape::Canonical => vec![canonical_item],
            DaPayloadShape::TrailingByte => {
                let mut noncanonical = canonical_item;
                noncanonical.push(0);
                vec![noncanonical]
            }
            DaPayloadShape::MultipleGlobalItems => {
                let mut second = batch.clone();
                second.schema_version = 2;
                vec![canonical_item, borsh::to_vec(&second).unwrap()]
            }
        };
        let da_batch = da::UnsignedTransactionBatchV1::build(
            &da_fixture.committee,
            &da_fixture.policy,
            da_fixture.author_id.clone(),
            1,
            transaction_items,
        )
        .unwrap();
        let missing_batch_id = da::UnsignedTransactionBatchV1::build(
            &da_fixture.committee,
            &da_fixture.policy,
            da_fixture.author_id.clone(),
            2,
            vec![b"missing-certified-global-item".to_vec()],
        )
        .unwrap()
        .batch_id();
        let author_root = da::DaBatchAuthorV1::signing_root(da_batch.envelope()).unwrap();
        let author = da::DaBatchAuthorV1::from_signature(
            da_batch.envelope(),
            da_fixture.author_key.verifying_key().to_bytes(),
            da_fixture
                .author_key
                .sign(author_root.as_bytes())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let da = da_fixture.store(&temporary.path().join("da-primary.sqlite"), 0, 100);
        let second = da_fixture.store(&temporary.path().join("da-second.sqlite"), 1, 101);
        let third = da_fixture.store(&temporary.path().join("da-third.sqlite"), 2, 102);
        let mut attestations = vec![
            da_fixture.admit_and_attest(&da, 0, 1, &da_batch, &author),
            da_fixture.admit_and_attest(&second, 1, 1, &da_batch, &author),
            da_fixture.admit_and_attest(&third, 2, 1, &da_batch, &author),
        ];
        attestations.sort_by_key(|attestation| attestation.body().attestor_id());
        let certificate = da::AvailabilityCertificateV1::build(
            &da_fixture.committee,
            da_batch.envelope().clone(),
            author,
            attestations,
        )
        .unwrap();
        da.admit_certificate(&certificate).unwrap();
        let batch_id = da_batch.batch_id();
        let certificate_id = certificate.certificate_id();
        let mut da = da;
        let mut agent = agent;
        let mut verify = verify;
        let mut mvcc = mvcc;
        let mut settlement = settlement;
        let global_path = temporary.path().join("global.sqlite");
        let global = {
            let mut sources = GlobalExecutionSourcesV1 {
                da: &mut da,
                agent_market: &mut agent,
                verify_challenge: &mut verify,
                mvcc_fee: &mut mvcc,
                consumption_settlement: &mut settlement,
            };
            PocoGlobalExecutionStoreV1::initialize_new(
                global_path.clone(),
                gh(99),
                context.clone(),
                &mut sources,
            )
            .unwrap()
        };
        Self {
            _temporary: temporary,
            global_path,
            context,
            da_fixture,
            da,
            da_second: second,
            da_third: third,
            agent,
            verify,
            mvcc,
            settlement,
            global,
            batch,
            batch_id,
            missing_batch_id,
            certificate_id,
        }
    }

    fn proposal(&self) -> PreVoteProposalV1 {
        let checkpoint = self.global.fresh_checkpoint_facts_v1().unwrap();
        PreVoteProposalV1 {
            schema_version: 1,
            context: self.context.clone(),
            scope: gh(99),
            expected_checkpoint_generation: checkpoint.generation(),
            expected_checkpoint_checksum: checkpoint.checksum(),
            candidate_height: self.batch.candidate_height,
            candidate_block_id: self.batch.candidate_block_id,
            batch_id: self.batch_id,
            availability_certificate_id: self.certificate_id,
            expected_candidate_composite_root: gh(254),
        }
    }

    fn sources(&mut self) -> GlobalExecutionSourcesV1<'_> {
        GlobalExecutionSourcesV1 {
            da: &mut self.da,
            agent_market: &mut self.agent,
            verify_challenge: &mut self.verify,
            mvcc_fee: &mut self.mvcc,
            consumption_settlement: &mut self.settlement,
        }
    }

    fn certify_manifest_batch_v2(
        &mut self,
        batch: &ManifestBoundGlobalExecutionBatchV2,
    ) -> (da::BatchIdV1, da::AvailabilityCertificateIdV1) {
        let da_batch = da::UnsignedTransactionBatchV1::build(
            &self.da_fixture.committee,
            &self.da_fixture.policy,
            self.da_fixture.author_id.clone(),
            2,
            vec![borsh::to_vec(batch).expect("encode manifest-bound v2 batch")],
        )
        .expect("build manifest-bound v2 DA batch");
        let author_root = da::DaBatchAuthorV1::signing_root(da_batch.envelope())
            .expect("derive v2 batch author root");
        let author = da::DaBatchAuthorV1::from_signature(
            da_batch.envelope(),
            self.da_fixture.author_key.verifying_key().to_bytes(),
            self.da_fixture
                .author_key
                .sign(author_root.as_bytes())
                .to_bytes()
                .to_vec(),
        )
        .expect("sign manifest-bound v2 batch");
        let mut attestations = vec![
            self.da_fixture
                .admit_and_attest(&self.da, 0, 2, &da_batch, &author),
            self.da_fixture
                .admit_and_attest(&self.da_second, 1, 2, &da_batch, &author),
            self.da_fixture
                .admit_and_attest(&self.da_third, 2, 2, &da_batch, &author),
        ];
        attestations.sort_by_key(|attestation| attestation.body().attestor_id());
        let certificate = da::AvailabilityCertificateV1::build(
            &self.da_fixture.committee,
            da_batch.envelope().clone(),
            author,
            attestations,
        )
        .expect("build manifest-bound v2 availability certificate");
        self.da
            .admit_certificate(&certificate)
            .expect("admit manifest-bound v2 certificate");
        (da_batch.batch_id(), certificate.certificate_id())
    }
}

fn manifest_bound_batch_v2(rig: &Rig) -> ManifestBoundGlobalExecutionBatchV2 {
    ManifestBoundGlobalExecutionBatchV2::new(
        rig.context.clone(),
        gh(121),
        gh(122),
        gh(123),
        gh(124),
        10,
        order_types::BlockIdV1::new(bytes(202)),
        Hash32V1(order_application::empty_order_state_root_v1()),
        11,
        rig.batch.agent_market_commands.clone(),
        rig.batch.verify_challenge_commands.clone(),
        rig.batch.mvcc_fee_block.clone(),
        rig.batch.consumption_settlement_commands.clone(),
    )
    .expect("construct candidate-ID-free manifest batch")
}

fn manifest_order_template_v2() -> order_application::OrderHeaderTemplateV1 {
    order_application::OrderHeaderTemplateV1 {
        schema_version: 1,
        context: order_types::ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: bytes(1),
            chain_id: candidate_context().chain_id,
            protocol_version: 1,
            stack_profile_hash: bytes(2),
        },
        epoch: 1,
        view: 11,
        height: 11,
        block_kind: order_types::BlockKindV1::Ordinary,
        parent: order_types::ParentBlockRefV1::V1Block(order_types::BlockIdV1::new(bytes(202))),
        proposer_id: b"validator-manifest-v2".to_vec(),
        epoch_descriptor_id: order_types::EpochDescriptorIdV1::new(bytes(125)),
        justify_qc_id: Some(order_types::QuorumCertificateIdV1::new(bytes(126))),
        timeout_certificate_id: None,
        next_epoch_descriptor_id: None,
        upgrade_plan_id: None,
        epoch_handoff_id: None,
    }
}

fn manifest_bound_input_v2(
    rig: &mut Rig,
    batch: ManifestBoundGlobalExecutionBatchV2,
) -> ManifestBoundGlobalExecutionInputV2 {
    let (batch_id, certificate_id) = rig.certify_manifest_batch_v2(&batch);
    let context = rig.context.clone();
    let source_cut = {
        let mut sources = rig.sources();
        sample_source_cut(&mut sources, &context).expect("sample post-certification source cut")
    };
    ManifestBoundGlobalExecutionInputV2::from_certified_batch_v2(
        batch,
        batch_id,
        certificate_id,
        source_cut.digest,
    )
    .expect("bind certified batch to exact source cut")
}

#[test]
fn manifest_bound_v2_five_plane_preview_exactly_joins_order_roots() {
    let mut rig = Rig::new();
    let batch = manifest_bound_batch_v2(&rig);
    let manifest = manifest_bound_input_v2(&mut rig, batch);
    let before = {
        let context = rig.context.clone();
        let mut sources = rig.sources();
        sample_source_cut(&mut sources, &context).expect("source cut before v2 preview")
    };
    let preview = {
        let mut sources = rig.sources();
        manifest
            .preview_five_plane_inert_v2(&mut sources)
            .expect("fresh candidate-ID-free five-plane preview")
    };
    assert!(preview.plan().state_creates().is_empty());
    assert_eq!(preview.receipts().len(), 1);
    assert_ne!(preview.preview_digest(), Hash32V1([0; 32]));
    let candidate_local_id = preview.plane_roots().candidate_local_id();
    let expected_roots = preview.ordered_roots();
    let (input, plan, binding) = preview.into_order_material_v2();
    let anchor = order_application::EmptyOrderStateAnchorV1::new(
        10,
        order_types::BlockIdV1::new(bytes(202)),
    )
    .expect("empty Order state parent");
    let sealed = order_application::seal_manifest_bound_g2_order_block_v2(
        order_application::OrderApplicationParentV1::EmptyAnchor(&anchor),
        manifest_order_template_v2(),
        input,
        plan,
    )
    .expect("seal exact candidate-local roots into containing Order header");
    let request = sealed
        .into_finalize_binding_request_v2()
        .expect("derive exact later finalize request");
    let joined = binding
        .join_finalize_request_v2(request)
        .expect("join all eight exact roots");
    assert_eq!(joined.ordered_roots(), expected_roots);
    assert_eq!(joined.ordered_roots()[2], anchor.state_root());
    assert_eq!(joined.receipts().len(), 1);
    assert_ne!(
        joined.candidate_block_id().to_bytes(),
        candidate_local_id.to_bytes()
    );
    assert_ne!(joined.join_digest(), Hash32V1([0; 32]));
    let after = {
        let context = rig.context.clone();
        let mut sources = rig.sources();
        sample_source_cut(&mut sources, &context).expect("source cut after v2 preview")
    };
    assert_eq!(after, before);
}

#[test]
fn manifest_bound_v2_source_and_plan_substitution_fail_closed() {
    let mut rig = Rig::new();
    let batch = manifest_bound_batch_v2(&rig);
    let manifest = manifest_bound_input_v2(&mut rig, batch.clone());
    let wrong_source = ManifestBoundGlobalExecutionInputV2::from_certified_batch_v2(
        batch,
        manifest.da_batch_id(),
        manifest.da_certificate_id(),
        gh(250),
    )
    .expect("wrong source remains inert data");
    let source_error = {
        let mut sources = rig.sources();
        wrong_source
            .preview_five_plane_inert_v2(&mut sources)
            .expect_err("foreign source cut must fail closed")
    };
    assert_eq!(
        source_error.code(),
        GlobalExecutionErrorCodeV1::SourceCutMismatch
    );

    let preview = {
        let mut sources = rig.sources();
        manifest
            .preview_five_plane_inert_v2(&mut sources)
            .expect("canonical preview")
    };
    let (_, _, binding) = preview.into_order_material_v2();
    let (narrow_input, narrow_plan) = manifest
        .project_inert_order_plan_v2()
        .expect("same input with T0-A narrow plan");
    let anchor = order_application::EmptyOrderStateAnchorV1::new(
        10,
        order_types::BlockIdV1::new(bytes(202)),
    )
    .expect("empty Order state parent");
    let narrow_request = order_application::seal_manifest_bound_g2_order_block_v2(
        order_application::OrderApplicationParentV1::EmptyAnchor(&anchor),
        manifest_order_template_v2(),
        narrow_input,
        narrow_plan,
    )
    .expect("narrow plan remains a valid but foreign seal")
    .into_finalize_binding_request_v2()
    .expect("derive foreign narrow request");
    let join_error = binding
        .join_finalize_request_v2(narrow_request)
        .expect_err("plan/root substitution must fail closed");
    assert_eq!(
        join_error.code(),
        GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch
    );
}

fn derive_expected_commitment(
    rig: &mut Rig,
    proposal: &PreVoteProposalV1,
) -> CandidateCompositeCommitmentV1 {
    let source_cut_digest = rig
        .global
        .fresh_checkpoint_facts_v1()
        .unwrap()
        .source_cut_digest();
    let certified = rig.da.certified_batch(proposal.batch_id).unwrap();
    let facts = certified.facts();
    let retrieval = rig
        .da
        .retrieve(
            proposal.batch_id,
            0,
            certified.certificate().envelope().uncompressed_bytes(),
        )
        .unwrap();
    let transaction_items: Vec<Vec<u8>> = borsh::from_slice(retrieval.bytes()).unwrap();
    let agent_parent = rig.agent.fresh_readback().unwrap();
    let verify_parent = rig.verify.fresh_readback().unwrap();
    let mvcc_parent = rig.mvcc.fresh_readback().unwrap();
    let settlement_parent = rig.settlement.fresh_readback().unwrap();
    let candidate_id = agent::Hash32V1(proposal.candidate_block_id.0);
    let agent = rig
        .agent
        .preview_before_vote_v1(&agent_parent, proposal.candidate_height, candidate_id, &[])
        .unwrap();
    let verify = rig
        .verify
        .preview_before_vote_v1(&verify_parent, proposal.candidate_height, candidate_id, &[])
        .unwrap();
    let mvcc = rig
        .mvcc
        .preview_before_vote_v1(&mvcc_parent, &rig.batch.mvcc_fee_block)
        .unwrap();
    let settlement = rig
        .settlement
        .preview_before_vote_v1(
            &settlement_parent,
            proposal.candidate_height,
            candidate_id,
            &[],
        )
        .unwrap();
    let body = CandidateCompositeCommitmentBodyV1 {
        schema_version: 1,
        context: proposal.context.clone(),
        candidate_height: proposal.candidate_height,
        candidate_block_id: proposal.candidate_block_id,
        source_cut_digest,
        da_batch_id: proposal.batch_id,
        da_certificate_id: proposal.availability_certificate_id,
        da_obligation_id: facts.obligation_id(),
        da_obligation_version: facts.obligation_version(),
        retrieved_batch_digest: digest_value(
            "trnm.poco-ai.global-execution-retrieved-batch.candidate.v1",
            &transaction_items,
        )
        .unwrap(),
        agent_market_candidate_root: Hash32V1(agent.candidate_post_state_root().0),
        agent_market_receipts_root: digest_value(
            "trnm.poco-ai.global-execution-agent-receipts.candidate.v1",
            &agent.candidate_receipts(),
        )
        .unwrap(),
        verify_challenge_candidate_root: Hash32V1(verify.candidate_post_state_root().0),
        verify_challenge_receipts_root: digest_value(
            "trnm.poco-ai.global-execution-verify-receipts.candidate.v1",
            &verify.candidate_receipts(),
        )
        .unwrap(),
        mvcc_fee_candidate_root: Hash32V1(mvcc.candidate_post_state_root().0),
        mvcc_receipts_root: Hash32V1(mvcc.candidate_receipt().receipts_root.0),
        mvcc_resource_totals_root: Hash32V1(mvcc.candidate_receipt().resource_totals_root.0),
        mvcc_fee_deltas_root: Hash32V1(mvcc.candidate_receipt().fee_deltas_root.0),
        mvcc_resolution_root: Hash32V1(mvcc.candidate_receipt().mvcc_resolution_root.0),
        consumption_settlement_candidate_root: Hash32V1(settlement.candidate_post_state_root().0),
        consumption_settlement_receipts_root: digest_value(
            "trnm.poco-ai.global-execution-settlement-receipts.candidate.v1",
            &settlement.candidate_receipts(),
        )
        .unwrap(),
    };
    CandidateCompositeCommitmentV1 {
        candidate_composite_root: digest_value(
            "trnm.poco-ai.global-execution-composite-root.candidate.v1",
            &body,
        )
        .unwrap(),
        body,
    }
}

fn prepare_ready(rig: &mut Rig) -> crate::PreVoteExecutionReadyV1 {
    let mut proposal = rig.proposal();
    let global = rig.global.clone();
    proposal.expected_candidate_composite_root = {
        let mut sources = rig.sources();
        global
            .preview_candidate_commitment_v1(&proposal, &mut sources)
            .expect("read-only candidate preview")
            .candidate_composite_root()
    };
    let global = rig.global.clone();
    let mut sources = rig.sources();
    global
        .prepare_before_vote_v1(&proposal, &mut sources)
        .expect("prepare exact terminal candidate")
}

fn finalized_order_for(rig: &Rig) -> order::VerifiedOrderFinalityV1 {
    order::issue_test_order_finality_with_ancestor_v1(
        &rig.context.chain_id,
        rig.context.genesis_hash.0,
        rig.context.protocol_version,
        rig.context.stack_profile_hash.0,
        1,
        rig.batch.candidate_height,
        rig.batch.candidate_block_id.0,
        bytes(240),
        10,
        bytes(202),
    )
    .expect("explicit test feature issues one exact Order-finality carrier")
}

#[test]
fn verified_order_finality_drives_recoverable_source_apply_and_terminal_owner() {
    let mut rig = Rig::new();
    let ready = prepare_ready(&mut rig);
    let order = finalized_order_for(&rig);
    let global = rig.global.clone();
    let owner = {
        let mut sources = rig.sources();
        global
            .apply_finalized_candidate_and_issue_owner_v1(&ready, &order, &mut sources)
            .expect("verified Order finality applies every source plane")
    };
    assert_eq!(owner.candidate_height(), rig.batch.candidate_height);
    assert_eq!(owner.candidate_block_id(), rig.batch.candidate_block_id);
    assert_ne!(owner.final_execution_root(), Hash32V1([0; 32]));

    let agent = rig.agent.fresh_readback().unwrap();
    let verify = rig.verify.fresh_readback().unwrap();
    let mvcc = rig.mvcc.fresh_readback().unwrap();
    let settlement = rig.settlement.fresh_readback().unwrap();
    for (height, block_id) in [
        (agent.order_height(), agent.order_block_id().0),
        (verify.order_height(), verify.order_block_id().0),
        (settlement.order_height(), settlement.order_block_id().0),
    ] {
        assert_eq!(height, rig.batch.candidate_height);
        assert_eq!(block_id, rig.batch.candidate_block_id.0);
    }
    assert_eq!(mvcc.height(), rig.batch.candidate_height);
    assert_eq!(mvcc.block_id().0, rig.batch.mvcc_execution_block_id().0);
    assert_ne!(mvcc.block_id().0, rig.batch.candidate_block_id.0);

    let replay_owner = {
        let mut sources = rig.sources();
        global
            .apply_finalized_candidate_and_issue_owner_v1(&ready, &order, &mut sources)
            .expect("source/target acknowledgement loss resolves by exact replay")
    };
    assert_eq!(
        replay_owner.final_execution_root(),
        owner.final_execution_root()
    );
    let finalized = global
        .finalize_terminal_facts_v1(&owner)
        .expect("terminal owner advances the global checkpoint");
    assert!(!finalized.is_replay());
    let replayed = global
        .finalize_terminal_facts_v1(&replay_owner)
        .expect("independent exact owner resolves final checkpoint replay");
    assert!(replayed.is_replay());
    assert_eq!(
        replayed.final_execution_root(),
        finalized.final_execution_root()
    );
}

#[test]
fn prepared_and_finalized_terminal_owners_recover_only_from_exact_durable_facts() {
    let mut rig = Rig::new();
    let ready = prepare_ready(&mut rig);
    let reopened = PocoGlobalExecutionStoreV1::open_existing(
        rig.global_path.clone(),
        gh(99),
        rig.context.clone(),
    )
    .expect("reopen prepared global checkpoint");
    let recovered_ready = reopened
        .recover_prepared_ready_v1(
            ready.checkpoint_generation(),
            ready.checkpoint_checksum(),
            ready.candidate_block_id(),
        )
        .expect("authenticated prepared history reissues exact ready carrier");
    assert_eq!(
        recovered_ready.candidate_composite_root(),
        ready.candidate_composite_root()
    );
    assert_eq!(
        reopened
            .recover_prepared_ready_v1(
                ready.checkpoint_generation(),
                ready.checkpoint_checksum(),
                gh(238),
            )
            .expect_err("foreign recovery selector rejects")
            .code(),
        GlobalExecutionErrorCodeV1::RecoveryMismatch
    );

    let order = finalized_order_for(&rig);
    let owner = {
        let mut sources = rig.sources();
        reopened
            .recover_finalization_owner_v1(&order, &mut sources)
            .expect("prepared recovery drives exact source-plane replay/apply")
    };
    assert_eq!(
        owner.candidate_composite_root(),
        ready.candidate_composite_root()
    );
    let finalized = reopened
        .finalize_terminal_facts_v1(&owner)
        .expect("recovered owner finalizes exact terminal facts");
    let after_finalize = PocoGlobalExecutionStoreV1::open_existing(
        rig.global_path.clone(),
        gh(99),
        rig.context.clone(),
    )
    .expect("reopen finalized global checkpoint");
    let recovered_owner = {
        let mut sources = rig.sources();
        after_finalize
            .recover_finalization_owner_v1(&order, &mut sources)
            .expect("fresh five-plane terminal readback reissues finalized owner")
    };
    assert_eq!(
        recovered_owner.final_execution_root(),
        finalized.final_execution_root()
    );
    assert_eq!(
        recovered_owner.candidate_composite_root(),
        ready.candidate_composite_root()
    );
    let foreign_order = order::issue_test_order_finality_v1(
        &rig.context.chain_id,
        rig.context.genesis_hash.0,
        rig.context.protocol_version,
        rig.context.stack_profile_hash.0,
        1,
        rig.batch.candidate_height,
        bytes(237),
        bytes(240),
    )
    .expect("test-only foreign finalized target");
    assert_eq!(
        {
            let mut sources = rig.sources();
            after_finalize.recover_finalization_owner_v1(&foreign_order, &mut sources)
        }
        .expect_err("foreign finality cannot recover owner")
        .code(),
        GlobalExecutionErrorCodeV1::RecoveryMismatch
    );
}

#[test]
fn foreign_verified_order_target_cannot_start_source_apply() {
    let mut rig = Rig::new();
    let ready = prepare_ready(&mut rig);
    let before_agent = rig.agent.fresh_readback().unwrap();
    let order = order::issue_test_order_finality_v1(
        &rig.context.chain_id,
        rig.context.genesis_hash.0,
        rig.context.protocol_version,
        rig.context.stack_profile_hash.0,
        1,
        rig.batch.candidate_height,
        bytes(239),
        bytes(240),
    )
    .unwrap();
    let global = rig.global.clone();
    let error = {
        let mut sources = rig.sources();
        global.apply_finalized_candidate_and_issue_owner_v1(&ready, &order, &mut sources)
    }
    .expect_err("verified finality for a foreign block must reject before source apply");
    assert_eq!(
        error.code(),
        GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch
    );
    assert_eq!(rig.agent.fresh_readback().unwrap(), before_agent);
}

#[test]
fn pre_vote_missing_da_and_partial_retrieval_fail_closed() {
    let mut rig = Rig::new();
    let mut missing = rig.proposal();
    missing.batch_id = rig.missing_batch_id;
    let global = rig.global.clone();
    let error = {
        let mut sources = rig.sources();
        global.prepare_before_vote_v1(&missing, &mut sources)
    }
    .expect_err("missing certified DA batch must reject");
    assert_eq!(error.code(), GlobalExecutionErrorCodeV1::DaRejected);

    let proposal = rig.proposal();
    let certified = rig.da.certified_batch(proposal.batch_id).unwrap();
    let expected_total = certified.certificate().envelope().uncompressed_bytes();
    let retrieval = rig
        .da
        .retrieve(proposal.batch_id, 0, expected_total)
        .unwrap();
    let partial = &retrieval.bytes()[..retrieval.bytes().len() - 1];
    let error = decode_complete_retrieval_v1(
        proposal.availability_certificate_id,
        retrieval.certificate().certificate_id(),
        certified.certificate().envelope().item_count(),
        expected_total,
        retrieval.offset(),
        retrieval.total_length(),
        partial,
    )
    .expect_err("partial local retrieval must never reach candidate decode");
    assert_eq!(error.code(), GlobalExecutionErrorCodeV1::DaRejected);
}

#[test]
fn pre_vote_trailing_and_multiple_global_item_codecs_fail_closed() {
    for shape in [
        DaPayloadShape::TrailingByte,
        DaPayloadShape::MultipleGlobalItems,
    ] {
        let mut rig = Rig::new_with_payload_shape(shape);
        let proposal = rig.proposal();
        let global = rig.global.clone();
        let error = {
            let mut sources = rig.sources();
            global.prepare_before_vote_v1(&proposal, &mut sources)
        }
        .expect_err("non-canonical or multiple global item must reject");
        assert_eq!(error.code(), GlobalExecutionErrorCodeV1::NonCanonicalBatch);
    }
}

#[test]
fn pre_vote_agent_signature_nonce_and_version_fail_closed() {
    let mut bad_signature = capability_command(0, 0);
    match &mut bad_signature {
        agent::KernelCommandV1::CapabilityGrant { authorization, .. } => {
            authorization.signature[0] ^= 1;
        }
        _ => unreachable!(),
    }
    for command in [
        bad_signature,
        capability_command(1, 0),
        capability_command(0, 1),
    ] {
        let mut rig = Rig::new_with_agent_commands(vec![command], false);
        let proposal = rig.proposal();
        let global = rig.global.clone();
        let error = {
            let mut sources = rig.sources();
            global.prepare_before_vote_v1(&proposal, &mut sources)
        }
        .expect_err("Agent signature/nonce/version mutant must reject");
        assert_eq!(
            error.code(),
            GlobalExecutionErrorCodeV1::AgentMarketRejected
        );
    }
}

#[test]
fn pre_vote_fee_and_conservation_fail_closed() {
    for command in [task_command(500, 101), task_command(400, 1)] {
        let mut rig = Rig::new_with_agent_commands(vec![command], true);
        let proposal = rig.proposal();
        let global = rig.global.clone();
        let error = {
            let mut sources = rig.sources();
            global.prepare_before_vote_v1(&proposal, &mut sources)
        }
        .expect_err("fee or escrow-conservation mutant must reject");
        assert_eq!(
            error.code(),
            GlobalExecutionErrorCodeV1::AgentMarketRejected
        );
    }
}

#[test]
fn pre_vote_certified_retrieve_preview_composite_root_and_whole_node_cas_are_linear() {
    let mut rig = Rig::new();
    let mut proposal = rig.proposal();
    let expected = derive_expected_commitment(&mut rig, &proposal);
    let initial_checkpoint = rig.global.fresh_checkpoint_facts_v1().unwrap();

    let global = rig.global.clone();
    let preview = {
        let mut sources = rig.sources();
        global.preview_candidate_commitment_v1(&proposal, &mut sources)
    }
    .expect("public read-only preview derives the canonical commitment");
    assert_eq!(preview, expected);
    let checkpoint_after_preview = rig.global.fresh_checkpoint_facts_v1().unwrap();
    assert_eq!(
        checkpoint_after_preview.generation(),
        initial_checkpoint.generation(),
    );
    assert_eq!(
        checkpoint_after_preview.checksum(),
        initial_checkpoint.checksum(),
    );
    assert_eq!(
        checkpoint_after_preview.source_cut_digest(),
        initial_checkpoint.source_cut_digest(),
    );
    assert_eq!(
        checkpoint_after_preview.final_execution_root(),
        initial_checkpoint.final_execution_root(),
        "preview cannot advance or rewrite the whole-node checkpoint",
    );

    proposal.expected_candidate_composite_root = gh(253);
    let global = rig.global.clone();
    let mismatch = {
        let mut sources = rig.sources();
        global.prepare_before_vote_v1(&proposal, &mut sources)
    }
    .expect_err("candidate root mismatch must not mint a carrier");
    assert_eq!(
        mismatch.code(),
        GlobalExecutionErrorCodeV1::CandidateCompositeRootMismatch
    );
    assert_eq!(
        rig.global.fresh_checkpoint_facts_v1().unwrap().generation(),
        initial_checkpoint.generation()
    );

    proposal.expected_candidate_composite_root = expected.candidate_composite_root();
    let stale = proposal.clone();
    let global = rig.global.clone();
    let ready = {
        let mut sources = rig.sources();
        global.prepare_before_vote_v1(&proposal, &mut sources)
    }
    .expect("successful full pre-vote owner path");
    assert_eq!(
        ready.candidate_composite_root(),
        expected.candidate_composite_root()
    );
    assert_eq!(ready.candidate_height(), 11);
    assert_eq!(ready.candidate_block_id(), rig.batch.candidate_block_id);
    assert_eq!(
        ready.checkpoint_generation(),
        initial_checkpoint.generation() + 1
    );
    let reopened = PocoGlobalExecutionStoreV1::open_existing(
        rig.global_path.clone(),
        gh(99),
        rig.context.clone(),
    )
    .expect("reopen exact prepared target");
    let reopened_facts = reopened
        .fresh_checkpoint_facts_v1()
        .expect("fresh reopened target readback");
    assert_eq!(reopened_facts.generation(), ready.checkpoint_generation());
    assert_eq!(reopened_facts.checksum(), ready.checkpoint_checksum());

    let global = rig.global.clone();
    let stale_error = {
        let mut sources = rig.sources();
        global.prepare_before_vote_v1(&stale, &mut sources)
    }
    .expect_err("stale whole-node CAS source must fail closed");
    assert_eq!(
        stale_error.code(),
        GlobalExecutionErrorCodeV1::CheckpointStale
    );
}

#[test]
fn pre_vote_source_change_after_anchor_prevents_whole_node_cas() {
    let mut rig = Rig::new();
    let proposal = rig.proposal();
    rig.mvcc
        .execute_block(&rig.batch.mvcc_fee_block)
        .expect("advance one source outside global owner");
    let global = rig.global.clone();
    let error = {
        let mut sources = rig.sources();
        global.prepare_before_vote_v1(&proposal, &mut sources)
    }
    .expect_err("changed source cut must reject");
    assert_eq!(error.code(), GlobalExecutionErrorCodeV1::SourceCutMismatch);
}

#[test]
fn whole_node_terminal_facts_cas_is_atomic_reopenable_and_exact_retry() {
    let mut rig = Rig::new();
    let da_before = rig.da.fresh_readback().unwrap();
    let agent_before = rig.agent.fresh_readback().unwrap();
    let verify_before = rig.verify.fresh_readback().unwrap();
    let mvcc_before = rig.mvcc.fresh_readback().unwrap();
    let settlement_before = rig.settlement.fresh_readback().unwrap();
    let ready = prepare_ready(&mut rig);
    let owner = rig
        .global
        .issue_test_finalization_owner_v1(&ready)
        .expect("test issuer mints exact terminal owner");
    let replay_owner = rig
        .global
        .issue_test_finalization_owner_v1(&ready)
        .expect("independent exact retry owner");
    let prepared_generation = ready.checkpoint_generation();

    let material = derive_inert_order_binding_create_material_v1(&owner, 12)
        .expect("terminal owner derives inert later-height tag-50 bytes");
    assert_eq!(material.materialized_at_height(), 12);
    assert_eq!(material.object_kind(), 50);
    assert_eq!(material.object_version(), 0);
    assert_ne!(material.object_id(), [0; 32]);
    assert_ne!(material.state_key(), [0; 32]);
    assert!(!material.value_bytes().is_empty());
    assert_eq!(
        derive_inert_order_binding_create_material_v1(&owner, 11)
            .expect_err("same-height tag-50 material is self-referential")
            .code(),
        GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
    );

    let finalized = rig
        .global
        .finalize_terminal_facts_v1(&owner)
        .expect("single terminal-facts transaction applies");
    assert!(!finalized.is_replay());
    assert_eq!(finalized.checkpoint_generation(), prepared_generation + 1);
    assert_eq!(finalized.candidate_height(), 11);
    assert_eq!(finalized.candidate_block_id(), rig.batch.candidate_block_id);
    assert_eq!(
        finalized.final_execution_root(),
        owner.final_execution_root()
    );

    let reopened = PocoGlobalExecutionStoreV1::open_existing(
        rig.global_path.clone(),
        gh(99),
        rig.context.clone(),
    )
    .expect("terminal checkpoint reopens through complete history audit");
    let reopened_facts = reopened.fresh_checkpoint_facts_v1().unwrap();
    assert_eq!(
        reopened_facts.final_execution_root(),
        Some(finalized.final_execution_root())
    );
    assert_eq!(reopened_facts.checksum(), finalized.checkpoint_checksum());

    let replay = reopened
        .finalize_terminal_facts_v1(&replay_owner)
        .expect("exact terminal retry is idempotent");
    assert!(replay.is_replay());
    assert_eq!(
        replay.checkpoint_checksum(),
        finalized.checkpoint_checksum()
    );
    assert_eq!(
        replay.final_execution_root(),
        finalized.final_execution_root()
    );

    assert_eq!(rig.da.fresh_readback().unwrap(), da_before);
    assert_eq!(rig.agent.fresh_readback().unwrap(), agent_before);
    assert_eq!(rig.verify.fresh_readback().unwrap(), verify_before);
    assert_eq!(rig.mvcc.fresh_readback().unwrap(), mvcc_before);
    assert_eq!(rig.settlement.fresh_readback().unwrap(), settlement_before);
}

#[test]
fn whole_node_terminal_owner_stale_fork_and_plane_root_mutants_fail_closed() {
    enum Mutant {
        Stale,
        Fork,
        PlaneRoot,
    }
    for mutant in [Mutant::Stale, Mutant::Fork, Mutant::PlaneRoot] {
        let mut rig = Rig::new();
        let ready = prepare_ready(&mut rig);
        let prepared = rig.global.fresh_checkpoint_facts_v1().unwrap();
        let mut owner = rig.global.issue_test_finalization_owner_v1(&ready).unwrap();
        let expected_code = match mutant {
            Mutant::Stale => {
                owner.test_mutate_prepared_checksum_v1();
                GlobalExecutionErrorCodeV1::FinalizationStale
            }
            Mutant::Fork => {
                owner.test_mutate_candidate_fork_v1();
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch
            }
            Mutant::PlaneRoot => {
                owner.test_mutate_terminal_root_v1();
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch
            }
        };
        let error = rig
            .global
            .finalize_terminal_facts_v1(&owner)
            .expect_err("stale/fork/plane terminal mutant must reject");
        assert_eq!(error.code(), expected_code);
        let after = rig.global.fresh_checkpoint_facts_v1().unwrap();
        assert_eq!(after.generation(), prepared.generation());
        assert_eq!(after.checksum(), prepared.checksum());
        assert_eq!(after.final_execution_root(), None);
    }
}

#[test]
fn whole_node_terminal_commit_faults_resolve_source_or_exact_target() {
    let mut before_commit = Rig::new();
    let ready = prepare_ready(&mut before_commit);
    let owner = before_commit
        .global
        .issue_test_finalization_owner_v1(&ready)
        .unwrap();
    let error = before_commit
        .global
        .finalize_terminal_facts_with_fault_v1(&owner, WholeNodeFinalizationFaultV1::BeforeCommit)
        .expect_err("pre-commit interruption must roll back");
    assert_eq!(error.code(), GlobalExecutionErrorCodeV1::CheckpointRace);
    let rolled_back = PocoGlobalExecutionStoreV1::open_existing(
        before_commit.global_path.clone(),
        gh(99),
        before_commit.context.clone(),
    )
    .expect("rolled-back source remains exact");
    assert_eq!(
        rolled_back
            .fresh_checkpoint_facts_v1()
            .unwrap()
            .generation(),
        ready.checkpoint_generation()
    );
    let applied = rolled_back
        .finalize_terminal_facts_v1(&owner)
        .expect("same owner applies after exact source readback");
    assert!(!applied.is_replay());

    let mut after_commit = Rig::new();
    let ready = prepare_ready(&mut after_commit);
    let owner = after_commit
        .global
        .issue_test_finalization_owner_v1(&ready)
        .unwrap();
    let resolved = after_commit
        .global
        .finalize_terminal_facts_with_fault_v1(
            &owner,
            WholeNodeFinalizationFaultV1::AfterCommitBeforeReturn,
        )
        .expect("post-commit acknowledgement loss resolves by exact target readback");
    assert!(!resolved.is_replay());
    let reopened = PocoGlobalExecutionStoreV1::open_existing(
        after_commit.global_path.clone(),
        gh(99),
        after_commit.context.clone(),
    )
    .expect("resolved target reopens");
    assert_eq!(
        reopened
            .fresh_checkpoint_facts_v1()
            .unwrap()
            .final_execution_root(),
        Some(resolved.final_execution_root())
    );
}

#[test]
fn whole_node_terminal_partial_torn_tamper_and_logical_rollback_fail_closed() {
    enum Mutant {
        MissingFinalizedRow,
        MissingHistoryTail,
        TamperedFinalizedBytes,
        MetadataRollbackWithFutureRows,
    }
    for mutant in [
        Mutant::MissingFinalizedRow,
        Mutant::MissingHistoryTail,
        Mutant::TamperedFinalizedBytes,
        Mutant::MetadataRollbackWithFutureRows,
    ] {
        let mut rig = Rig::new();
        let ready = prepare_ready(&mut rig);
        let owner = rig.global.issue_test_finalization_owner_v1(&ready).unwrap();
        rig.global
            .finalize_terminal_facts_v1(&owner)
            .expect("terminal target before corruption");
        let connection = rusqlite::Connection::open(&rig.global_path).unwrap();
        match mutant {
            Mutant::MissingFinalizedRow => {
                connection
                    .execute("DELETE FROM global_execution_finalized_v1", [])
                    .unwrap();
            }
            Mutant::MissingHistoryTail => {
                connection
                    .execute(
                        "DELETE FROM global_execution_checkpoints_v1 WHERE generation=?1",
                        rusqlite::params![&(ready.checkpoint_generation() + 1).to_be_bytes()[..]],
                    )
                    .unwrap();
            }
            Mutant::TamperedFinalizedBytes => {
                let mut raw: Vec<u8> = connection
                    .query_row(
                        "SELECT commitment FROM global_execution_finalized_v1",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let final_byte = raw.len() - 1;
                raw[final_byte] ^= 1;
                connection
                    .execute(
                        "UPDATE global_execution_finalized_v1 SET commitment=?1",
                        rusqlite::params![raw],
                    )
                    .unwrap();
            }
            Mutant::MetadataRollbackWithFutureRows => {
                let (checksum, record): (Vec<u8>, Vec<u8>) = connection
                    .query_row(
                        "SELECT checkpoint_checksum,record FROM global_execution_checkpoints_v1 WHERE generation=?1",
                        rusqlite::params![&ready.checkpoint_generation().to_be_bytes()[..]],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                connection
                    .execute(
                        "UPDATE global_execution_metadata_v1 SET generation=?1,checkpoint_checksum=?2,record=?3 WHERE singleton=1",
                        rusqlite::params![
                            &ready.checkpoint_generation().to_be_bytes()[..],
                            checksum,
                            record,
                        ],
                    )
                    .unwrap();
            }
        }
        drop(connection);
        let error = PocoGlobalExecutionStoreV1::open_existing(
            rig.global_path.clone(),
            gh(99),
            rig.context.clone(),
        )
        .expect_err("partial/torn/tampered/logically rolled-back store must reject");
        assert!(matches!(
            error.code(),
            GlobalExecutionErrorCodeV1::CheckpointTamper
                | GlobalExecutionErrorCodeV1::FinalizationTamper
                | GlobalExecutionErrorCodeV1::NonCanonicalBatch
        ));
    }
}

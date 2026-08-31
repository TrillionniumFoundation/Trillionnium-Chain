use std::{fs, path::Path};

use borsh::BorshSerialize;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "g2-process-test-support"))]
use tempfile::TempDir;
use trnm_poco_agent_market_v1 as agent;
use trnm_poco_consumption_settlement_v1 as settlement;
use trnm_poco_da_v1 as da;
use trnm_poco_global_execution_v1::{
    CandidateExecutionContextV1, GlobalExecutionBatchV1, GlobalExecutionSourcesV1,
    Hash32V1 as GlobalHash32V1, ManifestBoundGlobalExecutionBatchV2, PocoGlobalExecutionStoreV1,
    PreVoteProposalV1,
};
use trnm_poco_mvcc_fee_v1 as mvcc;
use trnm_poco_order_finality_verifier_v1::{
    verify_pinned_direct_order_finality_v1, VerifiedOrderFinalityV1,
};
use trnm_poco_order_state_v1::PocoCanonicalOrderStateStoreV1;
use trnm_poco_order_types_v1::{
    derive_block_id_v1, derive_quorum_certificate_id_v1, derive_vote_signature_root_v1,
    domain_separated_digest_v1, empty_ordered_root_v1, BlockHeaderV1, BlockIdV1, BlockKindV1,
    Cev1EncodeV1, ConsensusContextV1, EpochDescriptorIdV1, ParentBlockRefV1, ProtocolContextV1,
    QuorumCertificateBodyV1, QuorumCertificateV1, VoteSignatureEntryV1, VoteStatementBodyV1,
};
use trnm_poco_verify_challenge_v1 as verify;

use super::*;

#[cfg(feature = "g2-process-test-support")]
use crate::g2_manifest_bound_process_v2::PocoNodeG2CandidateProcessManifestV2;

const REAL_JOURNAL_ID_V1: [u8; 32] = [0xa1; 32];
const REAL_SCOPE_V1: [u8; 32] = [0xa2; 32];
const REAL_CANONICAL_STORE_ID_V1: [u8; 32] = [0xa3; 32];
const VALIDATOR_DEFINITION_DOMAIN_V1: &str = "trnm.poco-ai.validator-set-definition.v1";
const VALIDATOR_SET_DOMAIN_V1: &str = "trnm.poco-ai.validator-set.v1";
const CONSENSUS_PARAMETERS_DOMAIN_V1: &str = "trnm.poco-ai.consensus-parameters.v1";
const EPOCH_DESCRIPTOR_DOMAIN_V1: &str = "trnm.poco-ai.epoch-descriptor.v1";

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn put_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u128(output: &mut Vec<u8>, value: u128) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(output: &mut Vec<u8>, value: [u8; 32]) {
    output.extend_from_slice(&value);
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_u32(
        output,
        u32::try_from(value.len()).expect("bounded test CEV1 bytes fit u32"),
    );
    output.extend_from_slice(value);
}

fn sha256(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}

fn consensus_parameters_cev1_v1() -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, 1);
    put_u16(&mut out, 2);
    put_u16(&mut out, 3);
    put_u8(&mut out, 3);
    put_u8(&mut out, 1);
    put_u32(&mut out, 1);
    put_u32(&mut out, 128);
    put_u16(&mut out, 64);
    put_u64(&mut out, 16 * 1024 * 1024);
    put_u32(&mut out, 64);
    put_u32(&mut out, 1);
    put_u64(&mut out, u64::MAX - 1);
    put_u64(&mut out, u64::MAX - 1);
    put_u64(&mut out, u64::MAX - 1);
    put_u32(&mut out, 4096);
    put_u64(&mut out, 1000);
    put_u64(&mut out, 997);
    put_u64(&mut out, 998);
    put_u64(&mut out, 999);
    put_u64(&mut out, 4 * 1024 * 1024);
    put_u32(&mut out, 4096);
    put_u32(&mut out, 4096);
    put_u32(&mut out, 10_000);
    put_u64(&mut out, 1024 * 1024);
    put_u128(&mut out, 1_000_000_000_000_000_000);
    put_u64(&mut out, 500);
    put_u64(&mut out, 30_000);
    put_u32(&mut out, 3);
    put_u32(&mut out, 2);
    put_u32(&mut out, 1024);
    put_u64(&mut out, 4 * 1024 * 1024);
    out
}

#[derive(Clone)]
struct CertifiedHeaderFixtureV1 {
    header: BlockHeaderV1,
    block_id: BlockIdV1,
    qc: QuorumCertificateV1,
}

struct RealOrderChainFixtureV1 {
    context: ProtocolContextV1,
    signing_key: SigningKey,
    validator_id: Vec<u8>,
    runtime_profile_hash: [u8; 32],
    validator_set_hash: [u8; 32],
    consensus_parameters_hash: [u8; 32],
    descriptor_id: EpochDescriptorIdV1,
    derived_state_hash: [u8; 32],
    trust_raw: Vec<u8>,
    certified: Vec<CertifiedHeaderFixtureV1>,
}

impl RealOrderChainFixtureV1 {
    fn new(canonical_h4_root: [u8; 32]) -> Self {
        let context = ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: hash(0x31),
            chain_id: "trnm-g2-real-recovery-e2e".to_owned(),
            protocol_version: 1,
            stack_profile_hash: hash(0x32),
        };
        let signing_key = SigningKey::from_bytes(&hash(0x33));
        let validator_id = b"validator-a".to_vec();

        let mut definition_raw = Vec::new();
        put_u16(&mut definition_raw, 1);
        put_u32(&mut definition_raw, 1);
        put_bytes(&mut definition_raw, &validator_id);
        put_u16(&mut definition_raw, 0);
        put_bytes(&mut definition_raw, &signing_key.verifying_key().to_bytes());
        put_u128(&mut definition_raw, 1);
        put_hash(&mut definition_raw, hash(0x34));
        put_hash(&mut definition_raw, hash(0x35));
        put_hash(&mut definition_raw, hash(0x36));
        put_u128(&mut definition_raw, 1);
        put_u128(&mut definition_raw, 1);
        let definition_hash =
            domain_separated_digest_v1(VALIDATOR_DEFINITION_DOMAIN_V1, &definition_raw);

        let mut validator_set_raw = Vec::new();
        put_u16(&mut validator_set_raw, 1);
        context.encode_cev1_into(&mut validator_set_raw);
        put_u64(&mut validator_set_raw, 0);
        validator_set_raw.extend_from_slice(&definition_raw);
        let validator_set_hash =
            domain_separated_digest_v1(VALIDATOR_SET_DOMAIN_V1, &validator_set_raw);

        let parameters_raw = consensus_parameters_cev1_v1();
        let consensus_parameters_hash =
            domain_separated_digest_v1(CONSENSUS_PARAMETERS_DOMAIN_V1, &parameters_raw);
        let runtime_profile_hash = hash(0x37);
        let mut epoch_body_raw = Vec::new();
        put_u16(&mut epoch_body_raw, 1);
        context.encode_cev1_into(&mut epoch_body_raw);
        put_u64(&mut epoch_body_raw, 0);
        for value in [
            validator_set_hash,
            consensus_parameters_hash,
            runtime_profile_hash,
            hash(0x38),
            hash(0x39),
            hash(0x3a),
            hash(0x3b),
            hash(0x3c),
            hash(0x3d),
            hash(0x3e),
            hash(0x3f),
        ] {
            put_hash(&mut epoch_body_raw, value);
        }
        let descriptor_id = EpochDescriptorIdV1::new(domain_separated_digest_v1(
            EPOCH_DESCRIPTOR_DOMAIN_V1,
            &epoch_body_raw,
        ));
        let derived_state_hash = hash(0x40);
        let genesis_application_root = hash(0x41);
        let genesis = BlockHeaderV1 {
            schema_version: 1,
            context: context.clone(),
            epoch: 0,
            view: 1,
            height: 1,
            block_kind: BlockKindV1::FreshGenesis,
            parent: ParentBlockRefV1::Genesis {
                derived_state_hash,
                application_state_root: genesis_application_root,
            },
            proposer_id: validator_id.clone(),
            epoch_descriptor_id: descriptor_id,
            justify_qc_id: None,
            timeout_certificate_id: None,
            batch_refs_root: empty_ordered_root_v1(0),
            protocol_objects_root: empty_ordered_root_v1(1),
            post_state_root: genesis_application_root,
            transaction_execution_receipts_root: empty_ordered_root_v1(2),
            evidence_root: empty_ordered_root_v1(3),
            consumption_rollups_root: empty_ordered_root_v1(4),
            settlement_root: empty_ordered_root_v1(5),
            resource_usage_root: empty_ordered_root_v1(6),
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        };

        let mut fixture = Self {
            context,
            signing_key,
            validator_id,
            runtime_profile_hash,
            validator_set_hash,
            consensus_parameters_hash,
            descriptor_id,
            derived_state_hash,
            trust_raw: Vec::new(),
            certified: Vec::new(),
        };
        fixture.certified.push(fixture.certify(genesis));
        fixture.push_ordinary(hash(0x42));
        fixture.push_ordinary(hash(0x43));
        fixture.push_ordinary(canonical_h4_root);

        let mut trust_raw = Vec::new();
        put_u16(&mut trust_raw, 1);
        fixture.context.encode_cev1_into(&mut trust_raw);
        put_hash(&mut trust_raw, fixture.derived_state_hash);
        put_hash(&mut trust_raw, definition_hash);
        fixture.certified[0].header.encode_cev1_into(&mut trust_raw);
        trust_raw.extend_from_slice(&epoch_body_raw);
        put_hash(&mut trust_raw, fixture.descriptor_id.to_bytes());
        trust_raw.extend_from_slice(&validator_set_raw);
        trust_raw.extend_from_slice(&parameters_raw);
        fixture.trust_raw = trust_raw;
        fixture
    }

    fn certify(&self, header: BlockHeaderV1) -> CertifiedHeaderFixtureV1 {
        let block_id = derive_block_id_v1(&header);
        let statement = VoteStatementBodyV1 {
            schema_version: 1,
            consensus_context: ConsensusContextV1 {
                schema_version: 1,
                context: self.context.clone(),
                runtime_profile_hash: self.runtime_profile_hash,
                epoch: 0,
                validator_set_hash: self.validator_set_hash,
                consensus_parameters_hash: self.consensus_parameters_hash,
                view: header.view,
                message_kind: 1,
            },
            block_id,
            height: header.height,
            epoch_descriptor_id: self.descriptor_id,
            post_state_root: header.post_state_root,
            batch_refs_root: header.batch_refs_root,
            transaction_execution_receipts_root: header.transaction_execution_receipts_root,
        };
        let signature = self
            .signing_key
            .sign(&derive_vote_signature_root_v1(&statement))
            .to_bytes()
            .to_vec();
        let body = QuorumCertificateBodyV1 {
            schema_version: 1,
            statement,
            signatures: vec![VoteSignatureEntryV1 {
                voter_id: self.validator_id.clone(),
                signature_scheme: 0,
                signature,
            }],
        };
        CertifiedHeaderFixtureV1 {
            header,
            block_id,
            qc: QuorumCertificateV1 {
                quorum_certificate_id: derive_quorum_certificate_id_v1(&body),
                body,
            },
        }
    }

    fn ordinary_header(
        &self,
        parent: &CertifiedHeaderFixtureV1,
        post_state_root: [u8; 32],
    ) -> BlockHeaderV1 {
        let height = parent.header.height + 1;
        BlockHeaderV1 {
            schema_version: 1,
            context: self.context.clone(),
            epoch: 0,
            view: parent.header.view + 1,
            height,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(parent.block_id),
            proposer_id: self.validator_id.clone(),
            epoch_descriptor_id: self.descriptor_id,
            justify_qc_id: Some(parent.qc.quorum_certificate_id),
            timeout_certificate_id: None,
            batch_refs_root: empty_ordered_root_v1(0),
            protocol_objects_root: empty_ordered_root_v1(1),
            post_state_root,
            transaction_execution_receipts_root: empty_ordered_root_v1(2),
            evidence_root: empty_ordered_root_v1(3),
            consumption_rollups_root: empty_ordered_root_v1(4),
            settlement_root: empty_ordered_root_v1(5),
            resource_usage_root: empty_ordered_root_v1(6),
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }

    fn push_ordinary(&mut self, post_state_root: [u8; 32]) {
        let header = self.ordinary_header(
            self.certified.last().expect("certified parent"),
            post_state_root,
        );
        let certified = self.certify(header);
        self.certified.push(certified);
    }

    fn candidate_block_id(&self) -> BlockIdV1 {
        self.certified[1].block_id
    }

    fn source_parent_block_id(&self) -> BlockIdV1 {
        self.certified[0].block_id
    }

    fn canonical_parent_block_id(&self) -> BlockIdV1 {
        self.certified[3].block_id
    }

    fn materialization_template(&self) -> OrderHeaderTemplateV1 {
        let parent = &self.certified[3];
        OrderHeaderTemplateV1 {
            schema_version: 1,
            context: self.context.clone(),
            epoch: 0,
            view: 5,
            height: 5,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(parent.block_id),
            proposer_id: self.validator_id.clone(),
            epoch_descriptor_id: self.descriptor_id,
            justify_qc_id: Some(parent.qc.quorum_certificate_id),
            timeout_certificate_id: None,
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }

    fn append_materialization_and_tail(&mut self, materialization: BlockHeaderV1) {
        assert_eq!(materialization.height, 5);
        assert_eq!(
            materialization.parent,
            ParentBlockRefV1::V1Block(self.canonical_parent_block_id())
        );
        let certified = self.certify(materialization);
        self.certified.push(certified);
        self.push_ordinary(hash(0x46));
        self.push_ordinary(hash(0x47));
    }

    fn verified_prefix(&self, length: usize) -> VerifiedOrderFinalityV1 {
        assert!((3..=self.certified.len()).contains(&length));
        let target_index = length - 3;
        let target = &self.certified[target_index];
        let mut proof = Vec::new();
        put_u16(&mut proof, 1);
        self.context.encode_cev1_into(&mut proof);
        put_u8(&mut proof, 0);
        put_hash(&mut proof, self.derived_state_hash);
        self.certified[0].header.encode_cev1_into(&mut proof);
        put_hash(&mut proof, target.block_id.to_bytes());
        put_u64(&mut proof, target.header.height);
        target.header.encode_cev1_into(&mut proof);
        put_u32(
            &mut proof,
            u32::try_from(length).expect("bounded proof prefix length"),
        );
        for certified in self.certified.iter().take(length) {
            certified.header.encode_cev1_into(&mut proof);
            put_hash(&mut proof, certified.block_id.to_bytes());
            certified.qc.encode_cev1_into(&mut proof);
            put_u8(&mut proof, 0);
        }
        put_u32(&mut proof, 0);
        verify_pinned_direct_order_finality_v1(sha256(&self.trust_raw), &self.trust_raw, &proof)
            .expect("real raw CEV1 trust/QC/direct finality verifies")
    }
}

fn global_context_v1(context: &ProtocolContextV1) -> CandidateExecutionContextV1 {
    CandidateExecutionContextV1 {
        schema_version: 1,
        chain_id: context.chain_id.clone(),
        genesis_hash: GlobalHash32V1(context.genesis_hash),
        protocol_version: context.protocol_version,
        stack_profile_hash: GlobalHash32V1(context.stack_profile_hash),
    }
}

fn agent_context_v1(context: &ProtocolContextV1) -> agent::ProtocolContextV1 {
    agent::ProtocolContextV1 {
        genesis_hash: agent::Hash32V1(context.genesis_hash),
        chain_id: context.chain_id.clone(),
        protocol_version: context.protocol_version,
        stack_profile_hash: agent::Hash32V1(context.stack_profile_hash),
    }
}

fn borsh_digest_v1<T: BorshSerialize>(domain: &str, value: &T) -> [u8; 32] {
    let encoded = borsh::to_vec(value).expect("test fixture Borsh encodes");
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("static test domain fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain.as_bytes());
    hasher.update(encoded);
    hasher.finalize().into()
}

fn agent_store_config_v1(
    path: &Path,
    context: &ProtocolContextV1,
    initial_order_block_id: BlockIdV1,
) -> agent::AgentMarketStoreConfigV1 {
    let requester_controller = SigningKey::from_bytes(&hash(0x51));
    let requester_session = SigningKey::from_bytes(&hash(0x52));
    let provider_controller = SigningKey::from_bytes(&hash(0x53));
    let provider_session = SigningKey::from_bytes(&hash(0x54));
    let agent_context = agent_context_v1(context);
    let requester = agent::BootstrapAgentV1 {
        agent_id: agent::AgentIdV1(hash(0x55)),
        controller_key_id: agent::AgentKeyIdV1(hash(0x56)),
        controller_public_key: requester_controller.verifying_key().to_bytes(),
        session_key_id: agent::AgentKeyIdV1(hash(0x57)),
        session_public_key: requester_session.verifying_key().to_bytes(),
    };
    let provider = agent::BootstrapAgentV1 {
        agent_id: agent::AgentIdV1(hash(0x58)),
        controller_key_id: agent::AgentKeyIdV1(hash(0x59)),
        controller_public_key: provider_controller.verifying_key().to_bytes(),
        session_key_id: agent::AgentKeyIdV1(hash(0x5a)),
        session_public_key: provider_session.verifying_key().to_bytes(),
    };
    let account_body = agent::AccountBodyV1 {
        schema_version: 1,
        context: agent_context.clone(),
        owner_agent_id: requester.agent_id,
        asset_id: agent::Hash32V1(hash(0x5b)),
        account_nonce: agent::Hash32V1(hash(0x5c)),
    };
    let bond_body = agent::BondBodyV1 {
        schema_version: 1,
        context: agent_context.clone(),
        owner_agent_id: provider.agent_id,
        asset_id: agent::Hash32V1(hash(0x5b)),
        purpose: 1,
        source_object_kind: 0,
        source_object_id: agent::Hash32V1(hash(0x5d)),
        bond_nonce: agent::Hash32V1(hash(0x5e)),
    };
    let trust = agent::AgentMarketFreshGenesisTrustBundleV1 {
        schema_version: 1,
        context: agent_context,
        initial_order_height: 1,
        initial_order_block_id: agent::Hash32V1(initial_order_block_id.to_bytes()),
        requester,
        provider,
        requester_account_id: account_body.account_id().expect("requester account ID"),
        requester_account_body: account_body,
        requester_account_funding: 1_000,
        provider_bond_id: bond_body.bond_id().expect("provider bond ID"),
        provider_bond_body: bond_body,
        provider_bond_funding: 500,
        provider_bond_hold: 100,
    };
    agent::AgentMarketStoreConfigV1 {
        path: path.to_path_buf(),
        store_id: agent::Hash32V1(hash(0x60)),
        trust_bundle: trust,
    }
}

fn agent_store_v1(
    path: &Path,
    context: &ProtocolContextV1,
    initial_order_block_id: BlockIdV1,
) -> (
    agent::PocoAgentMarketStoreV1,
    agent::AgentMarketStoreConfigV1,
) {
    let config = agent_store_config_v1(path, context, initial_order_block_id);
    let store =
        agent::PocoAgentMarketStoreV1::open(config.clone()).expect("real G2 Agent/Market source");
    (store, config)
}

fn verify_store_config_v1(
    path: &Path,
    context: &ProtocolContextV1,
    initial_order_block_id: BlockIdV1,
) -> verify::VerifyChallengeStoreConfigV1 {
    let provider_key = SigningKey::from_bytes(&hash(0x61));
    let challenger_key = SigningKey::from_bytes(&hash(0x62));
    let verifier_keys = [
        SigningKey::from_bytes(&hash(0x63)),
        SigningKey::from_bytes(&hash(0x64)),
        SigningKey::from_bytes(&hash(0x65)),
        SigningKey::from_bytes(&hash(0x66)),
    ];
    let agent_context = agent_context_v1(context);
    let verifiers = verifier_keys
        .iter()
        .enumerate()
        .map(|(index, key)| verify::RegisteredVerifierV1 {
            verifier_id: hash(u8::try_from(0x67 + index).expect("bounded verifier index")),
            key_id: hash(u8::try_from(0x6b + index).expect("bounded verifier key index")),
            public_key: key.verifying_key().to_bytes(),
            weight: 1,
        })
        .collect::<Vec<_>>();
    let verifier_set_hash = agent::Hash32V1(borsh_digest_v1(
        "trnm.poco-ai.verifier-set.candidate.v1",
        &verifiers,
    ));
    let profile_id = b"g2-real-stake-quorum".to_vec();
    let required_da_policy_hash = agent::Hash32V1(hash(0x70));
    let challenge_policy_hash = agent::Hash32V1(hash(0x71));
    let settlement_policy_hash = agent::Hash32V1(hash(0x72));
    let challenge_bond_asset_id = agent::Hash32V1(hash(0x73));
    let profile_hash = agent::Hash32V1(borsh_digest_v1(
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
    ));
    let trust = verify::VerifyChallengeFreshGenesisTrustBundleV1 {
        schema_version: 1,
        context: agent_context,
        initial_order_height: 1,
        initial_order_block_id: agent::Hash32V1(initial_order_block_id.to_bytes()),
        task_id: agent::Hash32V1(hash(0x74)),
        task_revision: 1,
        lease_id: agent::Hash32V1(hash(0x75)),
        attempt: 1,
        execution_environment_hash: agent::Hash32V1(hash(0x76)),
        provider: verify::RegisteredActorV1 {
            agent_id: agent::AgentIdV1(hash(0x61)),
            key_id: agent::AgentKeyIdV1(hash(0x61)),
            public_key: provider_key.verifying_key().to_bytes(),
        },
        challenger: verify::RegisteredActorV1 {
            agent_id: agent::AgentIdV1(hash(0x62)),
            key_id: agent::AgentKeyIdV1(hash(0x62)),
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
        challenge_bond_id: agent::BondIdV1(hash(0x77)),
        challenge_bond_funding: 200,
    };
    verify::VerifyChallengeStoreConfigV1 {
        path: path.to_path_buf(),
        store_id: agent::Hash32V1(hash(0x78)),
        trust_bundle: trust,
    }
}

fn verify_store_v1(
    path: &Path,
    context: &ProtocolContextV1,
    initial_order_block_id: BlockIdV1,
) -> (
    verify::VerifyChallengeStoreV1,
    verify::VerifyChallengeStoreConfigV1,
) {
    let config = verify_store_config_v1(path, context, initial_order_block_id);
    let store = verify::VerifyChallengeStoreV1::open(config.clone())
        .expect("real G2 Verify/Challenge source");
    (store, config)
}

fn settlement_store_config_v1(
    path: &Path,
    context: &ProtocolContextV1,
    initial_order_block_id: BlockIdV1,
) -> settlement::ConsumptionSettlementStoreConfigV1 {
    let provider_key = SigningKey::from_bytes(&hash(0x79));
    let consumer_key = SigningKey::from_bytes(&hash(0x7a));
    let policy = settlement::SettlementPolicyV1 {
        schema_version: 1,
        policy_revision: 1,
        minimum_rollup_challenge_blocks: 2,
        maximum_rollups: 1,
        protocol_fee_numerator: 1,
        protocol_fee_denominator: 10,
        fee_schedule_hash: agent::Hash32V1(hash(0x7b)),
    };
    let trust = settlement::ConsumptionSettlementFreshGenesisTrustBundleV1 {
        schema_version: 1,
        context: agent_context_v1(context),
        initial_order_height: 1,
        initial_order_block_id: agent::Hash32V1(initial_order_block_id.to_bytes()),
        provider: settlement::RegisteredBilateralKeyV1 {
            agent_id: agent::AgentIdV1(hash(0x79)),
            key_id: agent::AgentKeyIdV1(hash(0x79)),
            public_key: provider_key.verifying_key().to_bytes(),
            policy_revision: 1,
            key_generation: 1,
        },
        consumer: settlement::RegisteredBilateralKeyV1 {
            agent_id: agent::AgentIdV1(hash(0x7a)),
            key_id: agent::AgentKeyIdV1(hash(0x7a)),
            public_key: consumer_key.verifying_key().to_bytes(),
            policy_revision: 1,
            key_generation: 1,
        },
        task_id: agent::TaskIdV1(hash(0x7c)),
        lease_id: agent::LeaseIdV1(hash(0x7d)),
        attempt: 1,
        result_id: settlement::ResultIdV1(hash(0x7e)),
        result_revision: 1,
        result_status: settlement::RESULT_STATUS_FINAL_VALID_V1,
        escrow_id: agent::EscrowIdV1(hash(0x7f)),
        escrow_version: 1,
        asset_id: agent::Hash32V1(hash(0x80)),
        escrow_funding: 1_000,
        provider_account_id: agent::AccountIdV1(hash(0x81)),
        consumer_account_id: agent::AccountIdV1(hash(0x82)),
        protocol_account_id: agent::AccountIdV1(hash(0x83)),
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
        accepted_evidence_certificates: vec![settlement::AvailabilityCertificateIdV1(hash(0x84))],
        related_party_policy_hash: agent::Hash32V1(hash(0x85)),
        settlement_policy: policy,
    };
    settlement::ConsumptionSettlementStoreConfigV1 {
        path: path.to_path_buf(),
        store_id: agent::Hash32V1(hash(0x86)),
        trust_bundle: trust,
    }
}

fn settlement_store_v1(
    path: &Path,
    context: &ProtocolContextV1,
    initial_order_block_id: BlockIdV1,
) -> (
    settlement::ConsumptionSettlementStoreV1,
    settlement::ConsumptionSettlementStoreConfigV1,
) {
    let config = settlement_store_config_v1(path, context, initial_order_block_id);
    let store = settlement::ConsumptionSettlementStoreV1::open(config.clone())
        .expect("real G2 Consumption/Settlement source");
    (store, config)
}

fn mvcc_object_v1(kind: u16, byte: u8) -> mvcc::TypedObjectIdV1 {
    mvcc::TypedObjectIdV1 {
        object_kind: kind,
        object_id: hash(byte),
    }
}

fn mvcc_genesis_v1(
    context: &ProtocolContextV1,
    initial_order_block_id: BlockIdV1,
) -> mvcc::MvccFeeGenesisV1 {
    let mut initial_objects = vec![
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: mvcc_object_v1(45, 1),
            version: 0,
            value: 10_000,
            closed: false,
        },
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: mvcc_object_v1(45, 2),
            version: 0,
            value: 100,
            closed: false,
        },
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: mvcc_object_v1(46, 10),
            version: 0,
            value: 0,
            closed: false,
        },
        mvcc::ObjectStateV1 {
            schema_version: 1,
            object_id: mvcc_object_v1(46, 11),
            version: 0,
            value: 0,
            closed: false,
        },
    ];
    initial_objects.sort_by_key(|object| object.object_id);
    mvcc::MvccFeeGenesisV1 {
        schema_version: 1,
        context: mvcc::ProtocolContextV1 {
            chain_id: context.chain_id.as_bytes().to_vec(),
            genesis_hash: mvcc::Hash32V1(context.genesis_hash),
            protocol_id: b"trnm-poco-ai-native-v1".to_vec(),
            protocol_version: context.protocol_version,
            profile_hash: mvcc::Hash32V1(context.stack_profile_hash),
        },
        store_id: mvcc::Hash32V1(hash(0x87)),
        initial_height: 1,
        initial_block_id: mvcc::Hash32V1(initial_order_block_id.to_bytes()),
        initial_objects,
        resource_prices: vec![
            mvcc::ResourcePriceV1 {
                resource_class: 0,
                resource_id: Vec::new(),
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            mvcc::ResourcePriceV1 {
                resource_class: 2,
                resource_id: Vec::new(),
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            mvcc::ResourcePriceV1 {
                resource_class: 3,
                resource_id: Vec::new(),
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            mvcc::ResourcePriceV1 {
                resource_class: 7,
                resource_id: Vec::new(),
                unit: 3,
                price_numerator: 1,
                price_denominator: 10,
                minimum_charge: 1,
                maximum_charge: 100,
            },
        ],
        destination_splits: vec![
            mvcc::FeeDestinationSplitV1 {
                destination: mvcc_object_v1(46, 10),
                numerator: 3,
                denominator: 4,
            },
            mvcc::FeeDestinationSplitV1 {
                destination: mvcc_object_v1(46, 11),
                numerator: 1,
                denominator: 4,
            },
        ],
        remainder_destination: mvcc_object_v1(46, 11),
    }
}

fn mvcc_candidate_v1(genesis: &mvcc::MvccFeeGenesisV1) -> mvcc::MvccBlockV1 {
    let mut access = vec![mvcc_object_v1(45, 1), mvcc_object_v1(45, 2)];
    access.sort_unstable();
    let mut transaction = mvcc::MvccTransactionV1 {
        schema_version: 1,
        transaction_id: mvcc::Hash32V1([0; 32]),
        transaction_index: 0,
        fee_payer: mvcc_object_v1(45, 1),
        declared_reads: access.clone(),
        declared_writes: access,
        compute_unit_limit: 100,
        max_fee: 1_000,
        program: mvcc::ObjectProgramV1::Add {
            target: mvcc_object_v1(45, 2),
            amount: 10,
        },
    };
    transaction.transaction_id =
        mvcc::derive_transaction_id_v1(&transaction).expect("derive MVCC transaction ID");
    let parent_root =
        mvcc::derive_state_root_v1(&genesis.initial_objects).expect("derive MVCC genesis root");
    let mut block = mvcc::MvccBlockV1 {
        schema_version: 1,
        context: genesis.context.clone(),
        block_id: mvcc::Hash32V1([0; 32]),
        height: 2,
        expected_parent_height: 1,
        expected_parent_block_id: genesis.initial_block_id,
        expected_parent_state_root: parent_root,
        transactions: vec![transaction],
    };
    block.block_id = mvcc::derive_block_id_v1(&block).expect("derive MVCC execution BlockId");
    block
}

struct DaFixtureV1 {
    committee: da::DaCommitteeDescriptorV1,
    policy: da::DaPolicyV1,
    author_key: SigningKey,
    author_id: Vec<u8>,
    attestors: Vec<(da::Hash32V1, SigningKey)>,
}

impl DaFixtureV1 {
    fn new(context: &ProtocolContextV1) -> Self {
        let da_context = da::ProtocolContextV1::new(
            da::Hash32V1::new(context.genesis_hash),
            context.chain_id.clone(),
            da::Hash32V1::new(context.stack_profile_hash),
        )
        .expect("real G2 DA context");
        let mut members_and_keys = (0x90u8..0x94)
            .map(|seed| {
                let key = SigningKey::from_bytes(&hash(seed));
                let member = da::DaMemberV1::new(
                    key.verifying_key().to_bytes(),
                    1,
                    Some(vec![seed]),
                    da::Hash32V1::new(hash(seed.wrapping_add(10))),
                    da::Hash32V1::new(hash(seed.wrapping_add(20))),
                )
                .expect("DA committee member");
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
            da_context, 7, members, 2, 8_192, 4_096, 32, 4,
        )
        .expect("DA committee");
        let author_key = SigningKey::from_bytes(&hash(0x94));
        let author_id = b"agent:g2-real/session:1".to_vec();
        let authority = da::DaAuthorAuthorityV1::new(
            author_id.clone(),
            author_key.verifying_key().to_bytes(),
            1,
            16,
            8_192,
            4,
        )
        .expect("DA author authority");
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
        .expect("DA policy");
        Self {
            committee,
            policy,
            author_key,
            author_id,
            attestors,
        }
    }

    fn store(&self, path: &Path, index: usize, store_byte: u8) -> da::PocoDaStoreV1 {
        da::PocoDaStoreV1::open(
            da::DaStoreConfigV1::new(
                path,
                da::Hash32V1::new(hash(0x95)),
                da::Hash32V1::new(hash(store_byte)),
                self.committee.clone(),
                self.policy.clone(),
                self.attestors[index].0,
            )
            .expect("DA store config"),
        )
        .expect("DA store")
    }

    fn admit_and_attest(
        &self,
        store: &da::PocoDaStoreV1,
        index: usize,
        attestation_sequence: u64,
        batch: &da::UnsignedTransactionBatchV1,
        author: &da::DaBatchAuthorV1,
    ) -> da::DaAttestationV1 {
        store
            .admit_batch(batch, author)
            .expect("admit exact global batch");
        let intent = match store
            .prepare_attestation(batch.batch_id(), attestation_sequence)
            .expect("prepare durable DA attestation")
        {
            da::AttestationPreparationOutcomeV1::Prepared(intent) => intent,
            da::AttestationPreparationOutcomeV1::Existing(_) => {
                panic!("fresh DA fixture unexpectedly retained an attestation")
            }
        };
        let signature = self.attestors[index]
            .1
            .sign(
                intent
                    .signing_root()
                    .expect("DA attestation signing root")
                    .as_bytes(),
            )
            .to_bytes()
            .to_vec();
        store
            .complete_attestation(intent, signature)
            .expect("complete durable DA attestation")
    }
}

pub(crate) struct RealG2RigV1 {
    _temporary: TempDir,
    namespaces: PocoNodeG2OrderCommitNamespacesV1,
    order: RealOrderChainFixtureV1,
    canonical_path: std::path::PathBuf,
    da_fixture: DaFixtureV1,
    da: da::PocoDaStoreV1,
    da_second: da::PocoDaStoreV1,
    da_third: da::PocoDaStoreV1,
    agent: agent::PocoAgentMarketStoreV1,
    #[cfg_attr(not(feature = "g2-process-test-support"), allow(dead_code))]
    agent_config: agent::AgentMarketStoreConfigV1,
    verify: verify::VerifyChallengeStoreV1,
    #[cfg_attr(not(feature = "g2-process-test-support"), allow(dead_code))]
    verify_config: verify::VerifyChallengeStoreConfigV1,
    mvcc: mvcc::MvccFeeStoreV1,
    #[cfg_attr(not(feature = "g2-process-test-support"), allow(dead_code))]
    mvcc_genesis: mvcc::MvccFeeGenesisV1,
    settlement: settlement::ConsumptionSettlementStoreV1,
    #[cfg_attr(not(feature = "g2-process-test-support"), allow(dead_code))]
    settlement_config: settlement::ConsumptionSettlementStoreConfigV1,
    global: PocoGlobalExecutionStoreV1,
    canonical: PocoCanonicalOrderStateStoreV1,
    batch: GlobalExecutionBatchV1,
    batch_id: da::BatchIdV1,
    certificate_id: da::AvailabilityCertificateIdV1,
}

impl RealG2RigV1 {
    pub(crate) fn new() -> Self {
        let temporary = tempfile::tempdir().expect("real G2 E2E tempdir");
        let journal_directory = temporary.path().join("journal");
        let global_directory = temporary.path().join("global");
        let canonical_directory = temporary.path().join("canonical");
        let sources_directory = temporary.path().join("sources");
        for directory in [
            &journal_directory,
            &global_directory,
            &canonical_directory,
            &sources_directory,
        ] {
            fs::create_dir(directory).expect("create private G2 E2E directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .expect("set private G2 E2E directory mode");
            }
        }
        let namespaces = PocoNodeG2OrderCommitNamespacesV1::new(
            &journal_directory,
            &global_directory,
            &canonical_directory,
        )
        .expect("real G2 E2E namespaces are disjoint and private");

        let disposable = PocoCanonicalOrderStateStoreV1::initialize_new(
            temporary.path().join("empty-root-oracle.sqlite"),
            hash(0xa4),
            4,
            BlockIdV1::new(hash(0xa5)),
        )
        .expect("derive canonical empty-state root through the real store");
        let empty_root = disposable
            .fresh_head_pin_v1()
            .expect("fresh disposable canonical pin")
            .state_root();
        drop(disposable);

        let order = RealOrderChainFixtureV1::new(empty_root);
        let canonical_path = canonical_directory.join("canonical-order-state.sqlite");
        let canonical = PocoCanonicalOrderStateStoreV1::initialize_new(
            &canonical_path,
            REAL_CANONICAL_STORE_ID_V1,
            4,
            order.canonical_parent_block_id(),
        )
        .expect("initialize canonical Order state at certified h4");
        assert_eq!(
            canonical
                .fresh_head_pin_v1()
                .expect("fresh canonical h4 pin")
                .state_root(),
            empty_root,
        );

        let source_parent = order.source_parent_block_id();
        let (agent, agent_config) = agent_store_v1(
            &sources_directory.join("agent.sqlite"),
            &order.context,
            source_parent,
        );
        let (verify, verify_config) = verify_store_v1(
            &sources_directory.join("verify.sqlite"),
            &order.context,
            source_parent,
        );
        let (settlement, settlement_config) = settlement_store_v1(
            &sources_directory.join("settlement.sqlite"),
            &order.context,
            source_parent,
        );
        let mvcc_genesis = mvcc_genesis_v1(&order.context, source_parent);
        let mvcc =
            mvcc::MvccFeeStoreV1::open(sources_directory.join("mvcc.sqlite"), mvcc_genesis.clone())
                .expect("real G2 MVCC/Fee source");
        let mvcc_fee_block = mvcc_candidate_v1(&mvcc_genesis);
        let context = global_context_v1(&order.context);
        let batch = GlobalExecutionBatchV1 {
            schema_version: 1,
            context: context.clone(),
            candidate_height: 2,
            candidate_block_id: GlobalHash32V1(order.candidate_block_id().to_bytes()),
            agent_market_commands: Vec::new(),
            verify_challenge_commands: Vec::new(),
            mvcc_fee_block,
            consumption_settlement_commands: Vec::new(),
        };
        assert_ne!(
            batch.candidate_block_id,
            batch.mvcc_execution_block_id(),
            "Order and plane-local MVCC identities are domain-separated",
        );

        let da_fixture = DaFixtureV1::new(&order.context);
        let da_batch = da::UnsignedTransactionBatchV1::build(
            &da_fixture.committee,
            &da_fixture.policy,
            da_fixture.author_id.clone(),
            1,
            vec![borsh::to_vec(&batch).expect("encode exact global execution batch")],
        )
        .expect("build exact DA TransactionBatch");
        let author_root =
            da::DaBatchAuthorV1::signing_root(da_batch.envelope()).expect("DA author signing root");
        let author = da::DaBatchAuthorV1::from_signature(
            da_batch.envelope(),
            da_fixture.author_key.verifying_key().to_bytes(),
            da_fixture
                .author_key
                .sign(author_root.as_bytes())
                .to_bytes()
                .to_vec(),
        )
        .expect("signed DA batch author");
        let da = da_fixture.store(&sources_directory.join("da-primary.sqlite"), 0, 0x96);
        let second = da_fixture.store(&sources_directory.join("da-second.sqlite"), 1, 0x97);
        let third = da_fixture.store(&sources_directory.join("da-third.sqlite"), 2, 0x98);
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
        .expect("build DA availability certificate");
        da.admit_certificate(&certificate)
            .expect("admit exact DA certificate");
        let batch_id = da_batch.batch_id();
        let certificate_id = certificate.certificate_id();

        let mut da = da;
        let mut agent = agent;
        let mut verify = verify;
        let mut mvcc = mvcc;
        let mut settlement = settlement;
        let global = {
            let mut sources = GlobalExecutionSourcesV1 {
                da: &mut da,
                agent_market: &mut agent,
                verify_challenge: &mut verify,
                mvcc_fee: &mut mvcc,
                consumption_settlement: &mut settlement,
            };
            PocoGlobalExecutionStoreV1::initialize_new(
                global_directory.join("global-execution.sqlite"),
                GlobalHash32V1(REAL_SCOPE_V1),
                context,
                &mut sources,
            )
            .expect("initialize real global-execution checkpoint")
        };

        Self {
            _temporary: temporary,
            namespaces,
            order,
            canonical_path,
            da_fixture,
            da,
            da_second: second,
            da_third: third,
            agent,
            agent_config,
            verify,
            verify_config,
            mvcc,
            mvcc_genesis,
            settlement,
            settlement_config,
            global,
            canonical,
            batch,
            batch_id,
            certificate_id,
        }
    }

    /// Pure typed data for the manifest-bound public path. This fixture helper
    /// creates no preview, finalize join, Node owner, or durable authority.
    pub(crate) fn manifest_bound_batch_v2(&self, seed: u8) -> ManifestBoundGlobalExecutionBatchV2 {
        ManifestBoundGlobalExecutionBatchV2::new(
            self.batch.context.clone(),
            GlobalHash32V1(hash(seed)),
            GlobalHash32V1(hash(seed.wrapping_add(1))),
            GlobalHash32V1(hash(seed.wrapping_add(2))),
            GlobalHash32V1(hash(seed.wrapping_add(3))),
            1,
            self.order.source_parent_block_id(),
            GlobalHash32V1(trnm_poco_order_application_v1::empty_order_state_root_v1()),
            2,
            Vec::new(),
            Vec::new(),
            self.batch.mvcc_fee_block.clone(),
            Vec::new(),
        )
        .expect("construct typed manifest-bound v2 test batch")
    }

    /// Certify typed manifest data through the normal DA stores. The return is
    /// data-only batch/certificate identity, never a preview or join issuer.
    pub(crate) fn certify_manifest_bound_batch_v2(
        &mut self,
        batch: &ManifestBoundGlobalExecutionBatchV2,
        sequence: u64,
    ) -> (da::BatchIdV1, da::AvailabilityCertificateIdV1) {
        let da_batch = da::UnsignedTransactionBatchV1::build(
            &self.da_fixture.committee,
            &self.da_fixture.policy,
            self.da_fixture.author_id.clone(),
            sequence,
            vec![borsh::to_vec(batch).expect("encode typed manifest-bound v2 batch")],
        )
        .expect("build typed manifest-bound v2 DA batch");
        let author_root =
            da::DaBatchAuthorV1::signing_root(da_batch.envelope()).expect("DA author root");
        let author = da::DaBatchAuthorV1::from_signature(
            da_batch.envelope(),
            self.da_fixture.author_key.verifying_key().to_bytes(),
            self.da_fixture
                .author_key
                .sign(author_root.as_bytes())
                .to_bytes()
                .to_vec(),
        )
        .expect("sign typed manifest-bound v2 DA batch");
        let mut attestations = vec![
            self.da_fixture
                .admit_and_attest(&self.da, 0, sequence, &da_batch, &author),
            self.da_fixture
                .admit_and_attest(&self.da_second, 1, sequence, &da_batch, &author),
            self.da_fixture
                .admit_and_attest(&self.da_third, 2, sequence, &da_batch, &author),
        ];
        attestations.sort_by_key(|attestation| attestation.body().attestor_id());
        let certificate = da::AvailabilityCertificateV1::build(
            &self.da_fixture.committee,
            da_batch.envelope().clone(),
            author,
            attestations,
        )
        .expect("build typed manifest-bound v2 availability certificate");
        self.da
            .admit_certificate(&certificate)
            .expect("admit typed manifest-bound v2 certificate");
        (da_batch.batch_id(), certificate.certificate_id())
    }

    pub(crate) fn manifest_bound_sources_v2(&mut self) -> GlobalExecutionSourcesV1<'_> {
        GlobalExecutionSourcesV1 {
            da: &mut self.da,
            agent_market: &mut self.agent,
            verify_challenge: &mut self.verify,
            mvcc_fee: &mut self.mvcc,
            consumption_settlement: &mut self.settlement,
        }
    }

    pub(crate) fn manifest_bound_parent_block_id_v2(&self) -> BlockIdV1 {
        self.order.source_parent_block_id()
    }

    pub(crate) fn manifest_bound_order_template_v2(&self) -> OrderHeaderTemplateV1 {
        let parent = &self.order.certified[0];
        OrderHeaderTemplateV1 {
            schema_version: 1,
            context: self.order.context.clone(),
            epoch: 0,
            view: 2,
            height: 2,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(parent.block_id),
            proposer_id: self.order.validator_id.clone(),
            epoch_descriptor_id: self.order.descriptor_id,
            justify_qc_id: Some(parent.qc.quorum_certificate_id),
            timeout_certificate_id: None,
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }

    fn proposal_v1(&self) -> PreVoteProposalV1 {
        let checkpoint = self
            .global
            .fresh_checkpoint_facts_v1()
            .expect("fresh global checkpoint before proposal");
        PreVoteProposalV1 {
            schema_version: 1,
            context: self.batch.context.clone(),
            scope: GlobalHash32V1(REAL_SCOPE_V1),
            expected_checkpoint_generation: checkpoint.generation(),
            expected_checkpoint_checksum: checkpoint.checksum(),
            candidate_height: self.batch.candidate_height,
            candidate_block_id: self.batch.candidate_block_id,
            batch_id: self.batch_id,
            availability_certificate_id: self.certificate_id,
            expected_candidate_composite_root: GlobalHash32V1([0; 32]),
        }
    }

    fn prepare_ready_v1(&mut self) -> trnm_poco_global_execution_v1::PreVoteExecutionReadyV1 {
        let mut proposal = self.proposal_v1();
        let global = self.global.clone();
        proposal.expected_candidate_composite_root = {
            let mut sources = GlobalExecutionSourcesV1 {
                da: &mut self.da,
                agent_market: &mut self.agent,
                verify_challenge: &mut self.verify,
                mvcc_fee: &mut self.mvcc,
                consumption_settlement: &mut self.settlement,
            };
            global
                .preview_candidate_commitment_v1(&proposal, &mut sources)
                .expect("normal read-only global candidate preview")
                .candidate_composite_root()
        };
        let mut sources = GlobalExecutionSourcesV1 {
            da: &mut self.da,
            agent_market: &mut self.agent,
            verify_challenge: &mut self.verify,
            mvcc_fee: &mut self.mvcc,
            consumption_settlement: &mut self.settlement,
        };
        global
            .prepare_before_vote_v1(&proposal, &mut sources)
            .expect("normal preview-to-prepare global path")
    }
}

/// Feature-gated, data-only filesystem fixture for the normal
/// `trnm-poco-node` candidate process integration test. It creates real DA,
/// Agent/Market, Verify/Challenge, MVCC/Fee, Consumption/Settlement and
/// canonical Order stores plus one canonical Borsh manifest. It never creates
/// or exposes a typed finalize join, T0-D owner, process owner, or authority
/// root; those can only be issued inside the normal node process.
#[cfg(feature = "g2-process-test-support")]
#[derive(Debug)]
pub struct PocoNodeG2ProcessFixtureV2 {
    _temporary: TempDir,
    run_root: std::path::PathBuf,
    manifest_path: std::path::PathBuf,
    manifest_sha256: String,
    da_path: std::path::PathBuf,
    canonical_order_path: std::path::PathBuf,
    t0d_journal_path: std::path::PathBuf,
}

#[cfg(feature = "g2-process-test-support")]
impl PocoNodeG2ProcessFixtureV2 {
    pub fn build_v2() -> Self {
        let mut rig = RealG2RigV1::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(rig._temporary.path(), fs::Permissions::from_mode(0o700))
                .expect("set G2 process fixture root mode");
        }

        let batch = rig.manifest_bound_batch_v2(0xb1);
        let (da_batch_id, da_certificate_id) = rig.certify_manifest_bound_batch_v2(&batch, 2);
        let order_template = rig.manifest_bound_order_template_v2();

        let process_canonical_directory = rig._temporary.path().join("process-canonical");
        let t0d_namespace = rig._temporary.path().join("process-t0d");
        for directory in [&process_canonical_directory, &t0d_namespace] {
            fs::create_dir(directory).expect("create G2 process fixture directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .expect("set G2 process fixture directory mode");
            }
        }
        let canonical_order_path = process_canonical_directory.join("canonical-order-state.sqlite");
        let canonical_order = PocoCanonicalOrderStateStoreV1::initialize_new(
            &canonical_order_path,
            hash(0xe1),
            batch.parent_height(),
            batch.parent_block_id(),
        )
        .expect("initialize process fixture canonical Order store");
        let canonical_pin = canonical_order
            .fresh_head_pin_v1()
            .expect("read process fixture canonical Order pin");
        assert_eq!(canonical_pin.height(), batch.parent_height());
        assert_eq!(canonical_pin.block_id(), batch.parent_block_id());
        assert_eq!(canonical_pin.state_root(), batch.parent_state_root().0);

        let sources_directory = rig
            .agent_config
            .path
            .parent()
            .expect("Agent/Market fixture path has a parent")
            .to_path_buf();
        let da_path = sources_directory.join("da-primary.sqlite");
        let mvcc_path = sources_directory.join("mvcc.sqlite");
        let process_scope = hash(0xe2);
        let manifest = PocoNodeG2CandidateProcessManifestV2 {
            schema_version: 2,
            process_scope,
            da_path: fixture_canonical_utf8_path_v2(&da_path),
            da_scope_id: da::Hash32V1::new(hash(0x95)),
            da_store_id: da::Hash32V1::new(hash(0x96)),
            da_committee: rig.da_fixture.committee.clone(),
            da_policy: rig.da_fixture.policy.clone(),
            da_local_attestor_id: rig.da_fixture.attestors[0].0,
            agent_market_path: fixture_canonical_utf8_path_v2(&rig.agent_config.path),
            agent_market_store_id: rig.agent_config.store_id,
            agent_market_trust_bundle: rig.agent_config.trust_bundle.clone(),
            verify_challenge_path: fixture_canonical_utf8_path_v2(&rig.verify_config.path),
            verify_challenge_store_id: rig.verify_config.store_id,
            verify_challenge_trust_bundle: rig.verify_config.trust_bundle.clone(),
            mvcc_fee_path: fixture_canonical_utf8_path_v2(&mvcc_path),
            mvcc_fee_genesis: rig.mvcc_genesis.clone(),
            consumption_settlement_path: fixture_canonical_utf8_path_v2(
                &rig.settlement_config.path,
            ),
            consumption_settlement_store_id: rig.settlement_config.store_id,
            consumption_settlement_trust_bundle: rig.settlement_config.trust_bundle.clone(),
            canonical_order_state_path: fixture_canonical_utf8_path_v2(&canonical_order_path),
            canonical_order_state_store_id: canonical_pin.store_id(),
            canonical_order_state_height: canonical_pin.height(),
            canonical_order_state_block_id: canonical_pin.block_id().to_bytes(),
            canonical_order_state_root: canonical_pin.state_root(),
            canonical_order_state_history_checksum: canonical_pin.history_checksum(),
            t0d_namespace_path: fixture_canonical_utf8_path_v2(&t0d_namespace),
            t0d_journal_id: hash(0xe3),
            t0d_scope: process_scope,
            certified_batch: batch,
            da_batch_id,
            da_certificate_id,
            order_header_schema_version: order_template.schema_version,
            order_epoch: order_template.epoch,
            order_view: order_template.view,
            order_proposer_id: order_template.proposer_id,
            order_epoch_descriptor_id: order_template.epoch_descriptor_id.to_bytes(),
            order_justify_qc_id: order_template
                .justify_qc_id
                .expect("ordinary fixture template has a justify QC")
                .to_bytes(),
        };
        let manifest_raw = borsh::to_vec(&manifest).expect("encode exact G2 process manifest");
        let manifest_sha256 = fixture_hex_v2(sha256(&manifest_raw));
        let manifest_path = rig._temporary.path().join("g2-process-manifest-v2.bin");
        fs::write(&manifest_path, &manifest_raw).expect("write exact G2 process manifest");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
                .expect("set G2 process manifest mode");
        }
        fs::File::open(&manifest_path)
            .and_then(|file| file.sync_all())
            .expect("fsync G2 process manifest");
        fs::File::open(rig._temporary.path())
            .and_then(|directory| directory.sync_all())
            .expect("fsync G2 process fixture root");

        let run_root =
            fs::canonicalize(rig._temporary.path()).expect("canonicalize G2 process fixture root");
        let manifest_path =
            fs::canonicalize(manifest_path).expect("canonicalize G2 process manifest");
        let t0d_journal_path = t0d_namespace.join("g2-manifest-bound-v2.sqlite");
        drop(canonical_order);
        let temporary = rig._temporary;
        Self {
            _temporary: temporary,
            run_root,
            manifest_path,
            manifest_sha256,
            da_path,
            canonical_order_path,
            t0d_journal_path,
        }
    }

    pub fn run_root_v2(&self) -> &Path {
        &self.run_root
    }

    pub fn manifest_path_v2(&self) -> &Path {
        &self.manifest_path
    }

    pub fn manifest_sha256_v2(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn da_path_v2(&self) -> &Path {
        &self.da_path
    }

    pub fn canonical_order_path_v2(&self) -> &Path {
        &self.canonical_order_path
    }

    pub fn t0d_journal_path_v2(&self) -> &Path {
        &self.t0d_journal_path
    }

    pub fn process_pin_path_v2(&self) -> std::path::PathBuf {
        self.run_root.join("g2-manifest-bound-process-pin-v2.bin")
    }

    pub fn process_pin_temp_path_v2(&self) -> std::path::PathBuf {
        self.run_root.join(".g2-manifest-bound-process-pin-v2.tmp")
    }
}

#[cfg(feature = "g2-process-test-support")]
fn fixture_canonical_utf8_path_v2(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|cause| panic!("canonicalize fixture path {}: {cause}", path.display()))
        .to_str()
        .unwrap_or_else(|| panic!("fixture path is not UTF-8: {}", path.display()))
        .to_owned()
}

#[cfg(feature = "g2-process-test-support")]
fn fixture_hex_v2(value: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(unix)]
fn canonical_file_identity_v1(path: &Path) -> (u64, u64, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path).expect("canonical file metadata");
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[test]
fn real_verified_g2_materialization_reissues_applied_owner_without_canonical_write() {
    let mut rig = RealG2RigV1::new();
    let candidate_finality = rig.order.verified_prefix(4);
    assert_eq!(candidate_finality.finalized_height(), 2);
    assert_eq!(
        candidate_finality.finalized_block_id(),
        rig.order.candidate_block_id().to_bytes(),
    );
    assert!(candidate_finality
        .proves_strict_ancestor_v1(1, rig.order.source_parent_block_id().to_bytes(),));

    let ready = rig.prepare_ready_v1();
    let canonical_parent = rig
        .canonical
        .fresh_head_pin_v1()
        .expect("fresh certified canonical h4 parent");
    let template = rig.order.materialization_template();
    let mut host = PocoNodeG2OrderCommitHostV1::commission_v1(
        &rig.namespaces,
        REAL_JOURNAL_ID_V1,
        REAL_SCOPE_V1,
        &rig.global,
        &rig.canonical,
        ready,
        &candidate_finality,
        canonical_parent.clone(),
    )
    .expect("commission real G2 F_c owner");
    let mut sources = GlobalExecutionSourcesV1 {
        da: &mut rig.da,
        agent_market: &mut rig.agent,
        verify_challenge: &mut rig.verify,
        mvcc_fee: &mut rig.mvcc,
        consumption_settlement: &mut rig.settlement,
    };
    assert!(!host
        .apply_sources_v1(&candidate_finality, &mut sources)
        .expect("real verified F_c applies exact five-plane sources"));
    assert!(!host
        .checkpoint_candidate_owner_v1(&candidate_finality, &mut sources)
        .expect("checkpoint exact real global terminal owner"));
    assert!(!host
        .prepare_materialization_v1(&candidate_finality, &mut sources, template.clone())
        .expect("prepare exact canonical h5 materialization"));
    let materialization_header = decode_block_header_v1(
        &host
            .current
            .materialization_plan
            .as_ref()
            .expect("durable P_m exists")
            .header_cev1,
    )
    .expect("decode exact P_m header");
    rig.order
        .append_materialization_and_tail(materialization_header);
    let materialization_finality = rig.order.verified_prefix(7);
    assert_eq!(materialization_finality.finalized_height(), 5);
    assert!(!host
        .bind_materialization_v1(
            &candidate_finality,
            &mut sources,
            template.clone(),
            materialization_finality,
        )
        .expect("bind real later Order finality to exact terminal owner and plan"));
    assert!(!host
        .apply_materialization_v1()
        .expect("apply exact finalized h5 canonical materialization"));
    assert_eq!(
        host.phase_v1(),
        PocoNodeG2OrderCommitPhaseV1::MaterializationApplied,
    );

    let applied_pin = host.journal_pin_v1();
    let canonical_target = rig
        .canonical
        .fresh_head_pin_v1()
        .expect("fresh exact canonical h5 target");
    assert_eq!(canonical_target.height(), 5);
    let canonical_bytes_before =
        fs::read(&rig.canonical_path).expect("canonical bytes before process-loss recovery");
    #[cfg(unix)]
    let canonical_identity_before = canonical_file_identity_v1(&rig.canonical_path);
    drop(host);

    let mut recovered = PocoNodeG2OrderCommitHostV1::reopen_v1(
        &rig.namespaces,
        &rig.global,
        &rig.canonical,
        &applied_pin,
    )
    .expect("reopen exact A_m journal/global/canonical cut");
    let mut sources = GlobalExecutionSourcesV1 {
        da: &mut rig.da,
        agent_market: &mut rig.agent,
        verify_challenge: &mut rig.verify,
        mvcc_fee: &mut rig.mvcc,
        consumption_settlement: &mut rig.settlement,
    };

    let wrong_candidate = rig.order.verified_prefix(3);
    assert_eq!(
        recovered
            .recover_applied_materialization_v1(
                &wrong_candidate,
                &mut sources,
                template.clone(),
                rig.order.verified_prefix(7),
            )
            .expect_err("real but foreign candidate-finality owner selector rejects")
            .code_v1(),
        PocoNodeG2OrderCommitErrorCodeV1::CandidateFinalityMismatch,
    );
    let wrong_later_finality = rig.order.verified_prefix(6);
    assert_eq!(
        recovered
            .recover_applied_materialization_v1(
                &candidate_finality,
                &mut sources,
                template.clone(),
                wrong_later_finality,
            )
            .expect_err("real finality for another exact target rejects")
            .code_v1(),
        PocoNodeG2OrderCommitErrorCodeV1::MaterializationFinalityMismatch,
    );
    let mut wrong_template = template.clone();
    wrong_template.view += 1;
    assert_eq!(
        recovered
            .recover_applied_materialization_v1(
                &candidate_finality,
                &mut sources,
                wrong_template,
                rig.order.verified_prefix(7),
            )
            .expect_err("header-template target substitution rejects")
            .code_v1(),
        PocoNodeG2OrderCommitErrorCodeV1::PlanMismatch,
    );

    assert!(recovered
        .recover_applied_materialization_v1(
            &candidate_finality,
            &mut sources,
            template,
            rig.order.verified_prefix(7),
        )
        .expect("fresh authorities reissue exact applied owner at durable A_m"));
    assert_eq!(
        recovered.phase_v1(),
        PocoNodeG2OrderCommitPhaseV1::MaterializationApplied,
    );
    assert_eq!(
        rig.canonical
            .fresh_head_pin_v1()
            .expect("fresh canonical pin after no-write recovery"),
        canonical_target,
    );
    assert_eq!(
        fs::read(&rig.canonical_path).expect("canonical bytes after no-write recovery"),
        canonical_bytes_before,
    );
    #[cfg(unix)]
    assert_eq!(
        canonical_file_identity_v1(&rig.canonical_path),
        canonical_identity_before,
        "A_m recovery cannot replace, truncate, or write the canonical SQLite file",
    );

    let completed = recovered
        .complete_v1()
        .expect("recovered applied owner advances only the private Node journal to G");
    let (applied, completed_pin) = completed.into_parts_v1();
    assert_eq!(
        completed_pin.phase_v1(),
        PocoNodeG2OrderCommitPhaseV1::Complete,
    );
    assert_eq!(applied.receipt().pin(), &canonical_target);
    assert_eq!(
        fs::read(&rig.canonical_path).expect("canonical bytes after Node completion"),
        canonical_bytes_before,
        "Node completion writes only its own journal",
    );
}

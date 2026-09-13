use borsh::BorshSerialize;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use trnm_poco_agent_market_v1::{
    AgentIdV1, AgentKeyIdV1, AgentTransactionV1, AssetLimitV1, CapabilityGrantBodyV1, Hash32V1,
    KernelAuthorizationStatementV1, KernelAuthorizationV1, KernelCommandV1, OperationScopeV1,
    ProtocolContextV1, ResourceScopeV1, CONTROLLER_SENTINEL_KEY_V1, PROTOCOL_VERSION_V1,
    SCHEMA_VERSION_V1,
};

fn hash(value: u8) -> Hash32V1 {
    Hash32V1([value; 32])
}

fn agent(value: u8) -> AgentIdV1 {
    AgentIdV1([value; 32])
}

fn key(value: u8) -> AgentKeyIdV1 {
    AgentKeyIdV1([value; 32])
}

fn digest_value<T: BorshSerialize>(domain: &str, value: &T) -> [u8; 32] {
    let encoded = borsh::to_vec(value).expect("canonical Borsh");
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("domain length")
            .to_le_bytes(),
    );
    hasher.update(domain.as_bytes());
    hasher.update(encoded);
    hasher.finalize().into()
}

fn hex(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        let byte = *byte;
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}

fn fixture_command() -> KernelCommandV1 {
    let signing_key = SigningKey::from_bytes(&[11; 32]);
    let context = ProtocolContextV1 {
        genesis_hash: hash(1),
        chain_id: "trnm-agent-transaction-wire-test".to_owned(),
        protocol_version: PROTOCOL_VERSION_V1,
        stack_profile_hash: hash(2),
    };
    let body = CapabilityGrantBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        genesis_hash: context.genesis_hash,
        chain_id: context.chain_id.clone(),
        protocol_version: context.protocol_version,
        stack_profile_hash: context.stack_profile_hash,
        issuer_agent_id: agent(1),
        issuer_key_id: CONTROLLER_SENTINEL_KEY_V1,
        delegate_agent_id: agent(1),
        delegate_key_id: Some(key(12)),
        parent_capability_id: None,
        grant_nonce: hash(3),
        operation_scopes: vec![OperationScopeV1 {
            operation_kind: 4,
            task_id: None,
            market_id: None,
            model_commitment: Some(hash(4)),
            tool_commitment: Some(hash(5)),
            endpoint_commitment: None,
            verification_profile: None,
            privacy_lane: Some(0),
            maximum_unit_price: None,
        }],
        resource_scopes: vec![ResourceScopeV1 {
            resource_kind: 1,
            scope_mode: 0,
            allowed_ids: vec![hash(6)],
            allowlist_commitment: None,
        }],
        spend_limits: vec![AssetLimitV1 {
            asset_id: hash(7),
            maximum_amount: 1_000,
        }],
        fee_limit: 100,
        gas_limit: 10_000,
        da_byte_limit: 4_096,
        artifact_retention_limit: 100,
        allowed_nonce_lanes: vec![1],
        valid_from_height: 90,
        expires_after_height: 200,
        rate_window_blocks: 10,
        rate_max_operations: 20,
        max_total_operations: 20,
        delegation_depth_remaining: 0,
        revocation_generation: 0,
        conditions_hash: hash(8),
    };
    let placeholder_statement = KernelAuthorizationStatementV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: context.clone(),
        operation_kind: 2,
        operation_digest: Hash32V1::default(),
        sender_agent_id: agent(1),
        authorizing_key_id: CONTROLLER_SENTINEL_KEY_V1,
        capability_id: None,
        live_capability_generation: 0,
        session_key_grant_id: None,
        session_generation: 0,
        nonce_lane: 0,
        nonce: 0,
        expected_lane_version: 0,
        valid_after_height: 90,
        expires_after_height: 110,
    };
    let unsigned = KernelCommandV1::CapabilityGrant {
        body: body.clone(),
        authorization: KernelAuthorizationV1 {
            statement: placeholder_statement,
            signer_key_id: key(11),
            signature: vec![0; 64],
        },
    };
    let statement = KernelAuthorizationStatementV1 {
        operation_digest: unsigned.operation_digest().expect("operation digest"),
        ..unsigned.authorization().statement.clone()
    };
    let signature_digest = digest_value(
        "trnm.poco-ai.capability-grant-kernel-signature.candidate.v1",
        &statement,
    );
    KernelCommandV1::CapabilityGrant {
        body,
        authorization: KernelAuthorizationV1 {
            statement,
            signer_key_id: key(11),
            signature: signing_key.sign(&signature_digest).to_bytes().to_vec(),
        },
    }
}

fn main() {
    let transaction =
        AgentTransactionV1::from_kernel_command(fixture_command()).expect("fixture transaction");
    println!(
        "{{\"schema\":\"trnm-agent-transaction-wire-fixture-v1\",\"wire_hex\":\"{}\",\"transaction_id\":\"{}\",\"operation_kind\":{},\"nonce\":{},\"nonce_lane\":{},\"candidate_only\":true,\"wire_accepted\":false,\"global_state_authority\":false,\"production_activation\":false}}",
        hex(transaction.encoded()),
        hex(&transaction.transaction_id().0),
        transaction.command().operation_kind(),
        transaction.command().authorization().statement.nonce,
        transaction.command().authorization().statement.nonce_lane,
    );
}

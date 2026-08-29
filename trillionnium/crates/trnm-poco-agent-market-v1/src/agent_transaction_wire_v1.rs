//! Candidate-only outer wire for Agent/Market kernel commands.
//!
//! The wire has a fixed, independently parseable header, a canonical Borsh
//! `KernelCommandV1` payload, and two domain-separated SHA-256 commitments.
//! It is not an accepted protocol object, an Order proof, a global-state
//! authority, or a production key-lifecycle implementation.

use crate::{
    codec::{canonical_bytes, digest_encoded, digest_value, strict_decode},
    error::{error, AgentMarketErrorCodeV1, AgentMarketResultV1},
    AgentIdV1, AgentKeyIdV1, CapabilityIdV1, Hash32V1, KernelCommandV1,
    SessionKeyGrantIdV1, PROTOCOL_VERSION_V1, SCHEMA_VERSION_V1,
};

pub const AGENT_TRANSACTION_MAGIC_V1: [u8; 8] = *b"TRNMATX1";
pub const AGENT_TRANSACTION_WIRE_VERSION_V1: u16 = 1;
pub const MAX_AGENT_TRANSACTION_COMMAND_BYTES_V1: usize = 1_048_576;
pub const AGENT_TRANSACTION_WIRE_ACCEPTED_V1: bool = false;
pub const AGENT_TRANSACTION_GLOBAL_STATE_AUTHORITY_V1: bool = false;
pub const AGENT_TRANSACTION_PRODUCTION_ACTIVATION_V1: bool = false;

const HEADER_BYTES_V1: usize = 294;
const TRAILER_BYTES_V1: usize = 32;
const CONTEXT_DOMAIN_V1: &str = "trnm.poco-ai.agent-transaction-context.v1";
const PAYLOAD_DOMAIN_V1: &str = "trnm.poco-ai.agent-transaction-payload.v1";
const WIRE_DOMAIN_V1: &str = "trnm.poco-ai.agent-transaction-wire.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTransactionV1 {
    command: KernelCommandV1,
    encoded: Vec<u8>,
    transaction_id: Hash32V1,
}

impl AgentTransactionV1 {
    pub fn from_kernel_command(command: KernelCommandV1) -> AgentMarketResultV1<Self> {
        validate_command_shape(&command)?;
        let encoded = encode_command(&command)?;
        let transaction_id = Hash32V1(
            encoded[encoded.len() - TRAILER_BYTES_V1..]
                .try_into()
                .map_err(|_| {
                    error(
                        AgentMarketErrorCodeV1::NonCanonical,
                        "agent transaction trailer has the wrong width",
                    )
                })?,
        );
        Ok(Self {
            command,
            encoded,
            transaction_id,
        })
    }

    pub fn decode(bytes: &[u8]) -> AgentMarketResultV1<Self> {
        let parsed = ParsedWireV1::decode(bytes)?;
        let command: KernelCommandV1 = strict_decode(parsed.command_bytes)?;
        let canonical = Self::from_kernel_command(command)?;
        if canonical.encoded != bytes {
            return Err(error(
                AgentMarketErrorCodeV1::NonCanonical,
                "agent transaction header does not match its canonical command payload",
            ));
        }
        Ok(canonical)
    }

    pub const fn command(&self) -> &KernelCommandV1 {
        &self.command
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub const fn transaction_id(&self) -> Hash32V1 {
        self.transaction_id
    }
}

fn validate_command_shape(command: &KernelCommandV1) -> AgentMarketResultV1<()> {
    let authorization = command.authorization();
    let statement = &authorization.statement;
    if statement.schema_version != SCHEMA_VERSION_V1
        || statement.context.protocol_version != PROTOCOL_VERSION_V1
        || statement.context.chain_id.is_empty()
        || statement.context.chain_id.len() > 128
        || statement.operation_kind != command.operation_kind()
        || statement.operation_digest != command.operation_digest()?
        || statement.valid_after_height > statement.expires_after_height
        || authorization.signature.len() != 64
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidContext,
            "agent transaction command or authorization envelope is malformed",
        ));
    }
    Ok(())
}

fn encode_command(command: &KernelCommandV1) -> AgentMarketResultV1<Vec<u8>> {
    let command_bytes = canonical_bytes(command)?;
    if command_bytes.len() > MAX_AGENT_TRANSACTION_COMMAND_BYTES_V1 {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "agent transaction command exceeds the wire bound",
        ));
    }
    let command_len = u32::try_from(command_bytes.len()).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "agent transaction command length exceeds u32",
        )
    })?;
    let authorization = command.authorization();
    let statement = &authorization.statement;
    let context_digest = digest_value(CONTEXT_DOMAIN_V1, &statement.context)?;
    let payload_digest = digest_encoded(PAYLOAD_DOMAIN_V1, &command_bytes)?;

    let mut encoded =
        Vec::with_capacity(HEADER_BYTES_V1 + command_bytes.len() + TRAILER_BYTES_V1);
    encoded.extend_from_slice(&AGENT_TRANSACTION_MAGIC_V1);
    encoded.extend_from_slice(&AGENT_TRANSACTION_WIRE_VERSION_V1.to_le_bytes());
    encoded.extend_from_slice(&0_u16.to_le_bytes());
    encoded.extend_from_slice(&context_digest.0);
    encoded.extend_from_slice(&statement.sender_agent_id.0);
    encoded.extend_from_slice(&statement.authorizing_key_id.0);
    encoded.extend_from_slice(&authorization.signer_key_id.0);
    encode_optional_id(
        &mut encoded,
        statement.capability_id.map(|value| value.0),
    );
    encode_optional_id(
        &mut encoded,
        statement.session_key_grant_id.map(|value| value.0),
    );
    encoded.extend_from_slice(&statement.live_capability_generation.to_le_bytes());
    encoded.extend_from_slice(&statement.session_generation.to_le_bytes());
    encoded.extend_from_slice(&statement.nonce_lane.to_le_bytes());
    encoded.extend_from_slice(&statement.operation_kind.to_le_bytes());
    encoded.extend_from_slice(&statement.nonce.to_le_bytes());
    encoded.extend_from_slice(&statement.expected_lane_version.to_le_bytes());
    encoded.extend_from_slice(&statement.valid_after_height.to_le_bytes());
    encoded.extend_from_slice(&statement.expires_after_height.to_le_bytes());
    encoded.extend_from_slice(&command_len.to_le_bytes());
    encoded.extend_from_slice(&payload_digest.0);
    encoded.extend_from_slice(&command_bytes);

    if encoded.len() != HEADER_BYTES_V1 + command_bytes.len() {
        return Err(error(
            AgentMarketErrorCodeV1::NonCanonical,
            "agent transaction encoder produced an unexpected header width",
        ));
    }
    let wire_digest = digest_encoded(WIRE_DOMAIN_V1, &encoded)?;
    encoded.extend_from_slice(&wire_digest.0);
    Ok(encoded)
}

fn encode_optional_id(target: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            target.push(1);
            target.extend_from_slice(&value);
        }
        None => {
            target.push(0);
            target.extend_from_slice(&[0; 32]);
        }
    }
}

struct ParsedWireV1<'a> {
    command_bytes: &'a [u8],
}

impl<'a> ParsedWireV1<'a> {
    fn decode(bytes: &'a [u8]) -> AgentMarketResultV1<Self> {
        if bytes.len() < HEADER_BYTES_V1 + TRAILER_BYTES_V1 {
            return Err(error(
                AgentMarketErrorCodeV1::NonCanonical,
                "agent transaction is shorter than the fixed envelope",
            ));
        }

        let mut reader = WireReaderV1::new(bytes);
        if reader.take_array::<8>()? != AGENT_TRANSACTION_MAGIC_V1 {
            return Err(error(
                AgentMarketErrorCodeV1::NonCanonical,
                "agent transaction magic differs",
            ));
        }
        if reader.take_u16()? != AGENT_TRANSACTION_WIRE_VERSION_V1 {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "agent transaction wire version differs",
            ));
        }
        if reader.take_u16()? != 0 {
            return Err(error(
                AgentMarketErrorCodeV1::NonCanonical,
                "agent transaction flags are nonzero",
            ));
        }

        let _context_digest = Hash32V1(reader.take_array::<32>()?);
        let _sender_agent_id = AgentIdV1(reader.take_array::<32>()?);
        let _authorizing_key_id = AgentKeyIdV1(reader.take_array::<32>()?);
        let _signer_key_id = AgentKeyIdV1(reader.take_array::<32>()?);
        let _capability_id = decode_optional_capability(&mut reader)?;
        let _session_key_grant_id = decode_optional_session(&mut reader)?;
        let _live_capability_generation = reader.take_u64()?;
        let _session_generation = reader.take_u64()?;
        let _nonce_lane = reader.take_u16()?;
        let operation_kind = reader.take_u16()?;
        if !(2..=7).contains(&operation_kind) {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "agent transaction operation kind is outside the candidate registry",
            ));
        }
        let _nonce = reader.take_u64()?;
        let _expected_lane_version = reader.take_u64()?;
        let valid_after_height = reader.take_u64()?;
        let expires_after_height = reader.take_u64()?;
        if valid_after_height > expires_after_height {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "agent transaction validity interval is inverted",
            ));
        }
        let command_len = reader.take_u32()? as usize;
        if command_len > MAX_AGENT_TRANSACTION_COMMAND_BYTES_V1
            || reader.remaining() != command_len + TRAILER_BYTES_V1
        {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "agent transaction command length or trailing data differs",
            ));
        }
        let payload_digest = Hash32V1(reader.take_array::<32>()?);
        let command_bytes = reader.take_slice(command_len)?;
        let trailer = Hash32V1(reader.take_array::<32>()?);
        reader.finish()?;

        if digest_encoded(PAYLOAD_DOMAIN_V1, command_bytes)? != payload_digest {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "agent transaction payload commitment differs",
            ));
        }
        let unsigned_len = bytes.len() - TRAILER_BYTES_V1;
        if digest_encoded(WIRE_DOMAIN_V1, &bytes[..unsigned_len])? != trailer {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "agent transaction wire commitment differs",
            ));
        }
        Ok(Self { command_bytes })
    }
}

fn decode_optional_capability(
    reader: &mut WireReaderV1<'_>,
) -> AgentMarketResultV1<Option<CapabilityIdV1>> {
    decode_optional_id(reader).map(|value| value.map(CapabilityIdV1))
}

fn decode_optional_session(
    reader: &mut WireReaderV1<'_>,
) -> AgentMarketResultV1<Option<SessionKeyGrantIdV1>> {
    decode_optional_id(reader).map(|value| value.map(SessionKeyGrantIdV1))
}

fn decode_optional_id(
    reader: &mut WireReaderV1<'_>,
) -> AgentMarketResultV1<Option<[u8; 32]>> {
    let tag = reader.take_u8()?;
    let value = reader.take_array::<32>()?;
    match tag {
        0 if value == [0; 32] => Ok(None),
        0 => Err(error(
            AgentMarketErrorCodeV1::NonCanonical,
            "absent agent transaction identifier is nonzero",
        )),
        1 if value != [0; 32] => Ok(Some(value)),
        1 => Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "present agent transaction identifier is zero",
        )),
        _ => Err(error(
            AgentMarketErrorCodeV1::NonCanonical,
            "agent transaction optional identifier tag differs",
        )),
    }
}

struct WireReaderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReaderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take_u8(&mut self) -> AgentMarketResultV1<u8> {
        Ok(self.take_array::<1>()?[0])
    }

    fn take_u16(&mut self) -> AgentMarketResultV1<u16> {
        Ok(u16::from_le_bytes(self.take_array::<2>()?))
    }

    fn take_u32(&mut self) -> AgentMarketResultV1<u32> {
        Ok(u32::from_le_bytes(self.take_array::<4>()?))
    }

    fn take_u64(&mut self) -> AgentMarketResultV1<u64> {
        Ok(u64::from_le_bytes(self.take_array::<8>()?))
    }

    fn take_array<const N: usize>(&mut self) -> AgentMarketResultV1<[u8; N]> {
        self.take_slice(N)?.try_into().map_err(|_| {
            error(
                AgentMarketErrorCodeV1::NonCanonical,
                "agent transaction field has the wrong width",
            )
        })
    }

    fn take_slice(&mut self, length: usize) -> AgentMarketResultV1<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "agent transaction cursor overflowed",
            )
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::NonCanonical,
                "agent transaction ended inside a field",
            )
        })?;
        self.offset = end;
        Ok(value)
    }

    fn finish(&self) -> AgentMarketResultV1<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(error(
                AgentMarketErrorCodeV1::NonCanonical,
                "agent transaction has trailing data",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::{
        AssetLimitV1, CapabilityGrantBodyV1, KernelAuthorizationStatementV1,
        KernelAuthorizationV1, OperationScopeV1, ProtocolContextV1, ResourceScopeV1,
        CONTROLLER_SENTINEL_KEY_V1,
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

    fn command() -> KernelCommandV1 {
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
        let placeholder = KernelAuthorizationV1 {
            statement: KernelAuthorizationStatementV1 {
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
            },
            signer_key_id: key(11),
            signature: vec![0; 64],
        };
        let unsigned = KernelCommandV1::CapabilityGrant {
            body: body.clone(),
            authorization: placeholder,
        };
        let statement = KernelAuthorizationStatementV1 {
            operation_digest: unsigned.operation_digest().expect("operation digest"),
            ..unsigned.authorization().statement.clone()
        };
        let signature_digest = digest_value(
            "trnm.poco-ai.capability-grant-kernel-signature.candidate.v1",
            &statement,
        )
        .expect("signature digest");
        let authorization = KernelAuthorizationV1 {
            statement,
            signer_key_id: key(11),
            signature: signing_key.sign(&signature_digest.0).to_bytes().to_vec(),
        };
        KernelCommandV1::CapabilityGrant {
            body,
            authorization,
        }
    }

    #[test]
    fn exact_round_trip_and_transaction_id_are_stable() {
        let transaction =
            AgentTransactionV1::from_kernel_command(command()).expect("encode transaction");
        let decoded = AgentTransactionV1::decode(transaction.encoded()).expect("decode transaction");
        assert_eq!(decoded, transaction);
        assert_ne!(transaction.transaction_id(), Hash32V1::default());
        assert_eq!(
            transaction.encoded().len(),
            HEADER_BYTES_V1
                + canonical_bytes(transaction.command())
                    .expect("canonical command")
                    .len()
                + TRAILER_BYTES_V1
        );
        assert!(!AGENT_TRANSACTION_WIRE_ACCEPTED_V1);
        assert!(!AGENT_TRANSACTION_GLOBAL_STATE_AUTHORITY_V1);
        assert!(!AGENT_TRANSACTION_PRODUCTION_ACTIVATION_V1);
    }

    #[test]
    fn retained_wire_mutants_fail_closed() {
        let transaction =
            AgentTransactionV1::from_kernel_command(command()).expect("encode transaction");
        let original = transaction.encoded();

        let mut mutants = Vec::new();
        for offset in [0, 8, 10, 12, 44, 140, 173, 206, 224, 258] {
            let mut value = original.to_vec();
            value[offset] ^= 1;
            mutants.push(value);
        }
        let mut payload = original.to_vec();
        payload[HEADER_BYTES_V1] ^= 1;
        mutants.push(payload);
        let mut trailer = original.to_vec();
        let last = trailer.len() - 1;
        trailer[last] ^= 1;
        mutants.push(trailer);
        let mut trailing = original.to_vec();
        trailing.push(0);
        mutants.push(trailing);
        mutants.push(original[..original.len() - 1].to_vec());

        for mutant in mutants {
            assert!(AgentTransactionV1::decode(&mutant).is_err());
        }
    }

    #[test]
    fn noncanonical_or_mismatched_commands_are_rejected_before_encoding() {
        let mut command = command();
        command.authorization_mut_for_test().signature.pop();
        assert_eq!(
            AgentTransactionV1::from_kernel_command(command)
                .expect_err("short signature")
                .code(),
            AgentMarketErrorCodeV1::InvalidContext
        );

        let mut command = command();
        command.authorization_mut_for_test().statement.operation_kind = 7;
        assert_eq!(
            AgentTransactionV1::from_kernel_command(command)
                .expect_err("operation kind mismatch")
                .code(),
            AgentMarketErrorCodeV1::InvalidContext
        );
    }
}

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CANONICAL_TX_SCHEMA_V1: &str = "trnm_canonical_tx_v1";
pub const CANONICAL_TX_PAYLOAD_TYPE_V1: &str = "trnm.canonical.tx.v1";
pub const ACCOUNT_OBJECT_TYPE_V1: &str = "trnm.account.v1";
pub const TASK_OBJECT_TYPE_V1: &str = "trnm.poco.task.v1";
pub const FEE_POLICY_OBJECT_TYPE_V1: &str = "trnm.fee-policy.v1";
pub const MONETARY_STATE_OBJECT_TYPE_V1: &str = "trnm.monetary-state.v1";
pub const FEE_COLLECTOR_ACCOUNT_V1: &str = "trnm:fee:collector";

const MAX_ID_BYTES: usize = 160;
const MAX_HASH_HEX_BYTES: usize = 64;
const MAX_CHALLENGE_WINDOW_BLOCKS: u64 = 1_000_000;
const MAX_GAS_PRICE: u128 = 1_000_000_000_000;
const MAX_BASE_GAS: u64 = 10_000_000_000;
const MAX_BYTE_GAS: u64 = 1_000_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported canonical transaction schema")]
    UnsupportedSchema,
    #[error("{0} is not canonical")]
    NonCanonical(&'static str),
    #[error("{0} must be positive")]
    NonPositive(&'static str),
    #[error("invalid task deadline")]
    InvalidDeadline,
    #[error("{0} is outside the supported range")]
    OutOfRange(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTxV1 {
    pub schema: String,
    pub sender: String,
    pub nonce: u64,
    pub max_gas: u64,
    #[serde(with = "u128_decimal")]
    pub fee_limit: u128,
    pub command: CanonicalCommandV1,
}

impl CanonicalTxV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != CANONICAL_TX_SCHEMA_V1 {
            return Err(ProtocolError::UnsupportedSchema);
        }
        validate_id("sender", &self.sender)?;
        if self.nonce == 0 {
            return Err(ProtocolError::NonPositive("nonce"));
        }
        if self.max_gas == 0 {
            return Err(ProtocolError::NonPositive("max_gas"));
        }
        self.command.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalCommandV1 {
    CreditAccount {
        account: String,
        #[serde(with = "u128_decimal")]
        amount: u128,
    },
    Transfer {
        to: String,
        #[serde(with = "u128_decimal")]
        amount: u128,
    },
    CreateTask {
        task_id: String,
        #[serde(with = "u128_decimal")]
        reward: u128,
        #[serde(with = "u128_decimal")]
        worker_stake: u128,
        result_deadline_height: u64,
        challenge_window_blocks: u64,
    },
    AssignTask {
        task_id: String,
        worker: String,
    },
    CommitResult {
        task_id: String,
        commitment_hex: String,
    },
    RevealResult {
        task_id: String,
        result_hash_hex: String,
        reveal_salt_hex: String,
    },
    RecordConsumption {
        task_id: String,
        units: u64,
        #[serde(with = "u128_decimal")]
        payment: u128,
        receipt_hash_hex: String,
    },
    OpenChallenge {
        task_id: String,
        #[serde(with = "u128_decimal")]
        bond: u128,
        evidence_hash_hex: String,
    },
    ResolveChallenge {
        task_id: String,
        accept_challenge: bool,
    },
    SettleTask {
        task_id: String,
    },
    ExpireTask {
        task_id: String,
    },
    SetFeePolicy {
        #[serde(with = "u128_decimal")]
        gas_price: u128,
        base_gas: u64,
        byte_gas: u64,
    },
    DistributeFees {
        to: String,
        #[serde(with = "u128_decimal")]
        amount: u128,
    },
}

impl CanonicalCommandV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::CreditAccount { account, amount } => {
                validate_id("account", account)?;
                positive("amount", *amount)
            }
            Self::Transfer { to, amount } => {
                validate_id("to", to)?;
                positive("amount", *amount)
            }
            Self::CreateTask {
                task_id,
                reward,
                worker_stake,
                result_deadline_height,
                challenge_window_blocks,
            } => {
                validate_id("task_id", task_id)?;
                positive("reward", *reward)?;
                positive("worker_stake", *worker_stake)?;
                if *result_deadline_height == 0 {
                    return Err(ProtocolError::InvalidDeadline);
                }
                if *challenge_window_blocks == 0
                    || *challenge_window_blocks > MAX_CHALLENGE_WINDOW_BLOCKS
                {
                    return Err(ProtocolError::OutOfRange("challenge_window_blocks"));
                }
                Ok(())
            }
            Self::AssignTask { task_id, worker } => {
                validate_id("task_id", task_id)?;
                validate_id("worker", worker)
            }
            Self::CommitResult {
                task_id,
                commitment_hex,
            } => {
                validate_id("task_id", task_id)?;
                validate_hash("commitment_hex", commitment_hex)
            }
            Self::RevealResult {
                task_id,
                result_hash_hex,
                reveal_salt_hex,
            } => {
                validate_id("task_id", task_id)?;
                validate_hash("result_hash_hex", result_hash_hex)?;
                validate_hash("reveal_salt_hex", reveal_salt_hex)
            }
            Self::RecordConsumption {
                task_id,
                units,
                payment,
                receipt_hash_hex,
            } => {
                validate_id("task_id", task_id)?;
                if *units == 0 {
                    return Err(ProtocolError::NonPositive("units"));
                }
                positive("payment", *payment)?;
                validate_hash("receipt_hash_hex", receipt_hash_hex)
            }
            Self::OpenChallenge {
                task_id,
                bond,
                evidence_hash_hex,
            } => {
                validate_id("task_id", task_id)?;
                positive("bond", *bond)?;
                validate_hash("evidence_hash_hex", evidence_hash_hex)
            }
            Self::ResolveChallenge { task_id, .. }
            | Self::SettleTask { task_id }
            | Self::ExpireTask { task_id } => validate_id("task_id", task_id),
            Self::SetFeePolicy {
                gas_price,
                base_gas,
                byte_gas,
            } => {
                positive("gas_price", *gas_price)?;
                if *base_gas == 0 {
                    return Err(ProtocolError::NonPositive("base_gas"));
                }
                if *byte_gas == 0 {
                    return Err(ProtocolError::NonPositive("byte_gas"));
                }
                if *gas_price > MAX_GAS_PRICE {
                    return Err(ProtocolError::OutOfRange("gas_price"));
                }
                if *base_gas > MAX_BASE_GAS {
                    return Err(ProtocolError::OutOfRange("base_gas"));
                }
                if *byte_gas > MAX_BYTE_GAS {
                    return Err(ProtocolError::OutOfRange("byte_gas"));
                }
                Ok(())
            }
            Self::DistributeFees { to, amount } => {
                validate_id("to", to)?;
                positive("amount", *amount)
            }
        }
    }

    pub fn operation_gas(&self) -> u64 {
        match self {
            Self::CreditAccount { .. } | Self::Transfer { .. } | Self::DistributeFees { .. } => 500,
            Self::CreateTask { .. } => 2_000,
            Self::AssignTask { .. } => 1_000,
            Self::CommitResult { .. } | Self::RevealResult { .. } => 1_200,
            Self::RecordConsumption { .. } => 1_800,
            Self::OpenChallenge { .. } | Self::ResolveChallenge { .. } => 2_000,
            Self::SettleTask { .. } | Self::ExpireTask { .. } => 1_500,
            Self::SetFeePolicy { .. } => 500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountV1 {
    pub account: String,
    #[serde(with = "u128_decimal")]
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatusV1 {
    Open,
    Assigned,
    Committed,
    Revealed,
    Consumed,
    Challenged,
    Settled,
    ResolvedForWorker,
    ResolvedForChallenger,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskV1 {
    pub task_id: String,
    pub client: String,
    pub worker: Option<String>,
    #[serde(with = "u128_decimal")]
    pub reward: u128,
    #[serde(with = "u128_decimal")]
    pub worker_stake: u128,
    pub result_deadline_height: u64,
    pub challenge_window_blocks: u64,
    pub status: TaskStatusV1,
    pub commitment_hex: Option<String>,
    pub result_hash_hex: Option<String>,
    pub reveal_salt_hex: Option<String>,
    pub challenge_deadline_height: Option<u64>,
    pub consumer: Option<String>,
    pub consumed_units: u64,
    #[serde(with = "u128_decimal")]
    pub consumption_payment: u128,
    pub receipt_hash_hex: Option<String>,
    pub challenger: Option<String>,
    #[serde(with = "u128_decimal")]
    pub challenge_bond: u128,
    pub evidence_hash_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeePolicyV1 {
    #[serde(with = "u128_decimal")]
    pub gas_price: u128,
    pub base_gas: u64,
    pub byte_gas: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MonetaryStateV1 {
    #[serde(with = "u128_decimal")]
    pub total_issued: u128,
}

impl Default for FeePolicyV1 {
    fn default() -> Self {
        Self {
            gas_price: 1,
            base_gas: 1_000,
            byte_gas: 2,
        }
    }
}

pub fn account_key(account: &str) -> String {
    object_key("trnm.account.object-key.v1", account)
}

pub fn task_key(task_id: &str) -> String {
    object_key("trnm.poco.task.object-key.v1", task_id)
}

pub fn fee_policy_key() -> String {
    object_key("trnm.fee-policy.object-key.v1", "singleton")
}

pub fn monetary_state_key() -> String {
    object_key("trnm.monetary-state.object-key.v1", "singleton")
}

pub fn result_commitment_hex(
    task_id: &str,
    worker: &str,
    result_hash_hex: &str,
    reveal_salt_hex: &str,
) -> Result<String, ProtocolError> {
    validate_id("task_id", task_id)?;
    validate_id("worker", worker)?;
    validate_hash("result_hash_hex", result_hash_hex)?;
    validate_hash("reveal_salt_hex", reveal_salt_hex)?;
    let result_hash =
        hex::decode(result_hash_hex).map_err(|_| ProtocolError::NonCanonical("result_hash_hex"))?;
    let reveal_salt =
        hex::decode(reveal_salt_hex).map_err(|_| ProtocolError::NonCanonical("reveal_salt_hex"))?;
    let mut hasher = Sha256::new();
    for field in [
        b"trnm.result-commitment.v1".as_slice(),
        task_id.as_bytes(),
        worker.as_bytes(),
        result_hash.as_slice(),
        reveal_salt.as_slice(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn object_key(domain: &str, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((id.len() as u64).to_be_bytes());
    hasher.update(id.as_bytes());
    hex::encode(hasher.finalize())
}

fn positive(label: &'static str, value: u128) -> Result<(), ProtocolError> {
    if value == 0 {
        return Err(ProtocolError::NonPositive(label));
    }
    Ok(())
}

fn validate_id(label: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value != value.trim()
        || !value.is_ascii()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
    {
        return Err(ProtocolError::NonCanonical(label));
    }
    Ok(())
}

fn validate_hash(label: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.len() != MAX_HASH_HEX_BYTES {
        return Err(ProtocolError::NonCanonical(label));
    }
    let bytes = hex::decode(value).map_err(|_| ProtocolError::NonCanonical(label))?;
    if bytes.len() != 32 || hex::encode(bytes) != value {
        return Err(ProtocolError::NonCanonical(label));
    }
    Ok(())
}

mod u128_decimal {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        if raw.is_empty()
            || (raw.len() > 1 && raw.starts_with('0'))
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(D::Error::custom("u128 decimal is not canonical"));
        }
        raw.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_namespaces_do_not_collide() {
        assert_ne!(account_key("same"), task_key("same"));
        assert_ne!(account_key("singleton"), fee_policy_key());
        assert_ne!(fee_policy_key(), monetary_state_key());
    }

    #[test]
    fn result_commitment_binds_every_field() {
        let hash = "11".repeat(32);
        let salt = "22".repeat(32);
        let baseline = result_commitment_hex("task-1", "worker-1", &hash, &salt).unwrap();
        assert_ne!(
            baseline,
            result_commitment_hex("task-2", "worker-1", &hash, &salt).unwrap()
        );
        assert_ne!(
            baseline,
            result_commitment_hex("task-1", "worker-2", &hash, &salt).unwrap()
        );
        assert_ne!(
            baseline,
            result_commitment_hex("task-1", "worker-1", &"33".repeat(32), &salt).unwrap()
        );
        assert_ne!(
            baseline,
            result_commitment_hex("task-1", "worker-1", &hash, &"44".repeat(32)).unwrap()
        );
    }

    #[test]
    fn identifiers_and_decimal_values_are_canonical() {
        assert!(validate_id("id", "did:worker:1").is_ok());
        for invalid in ["", " worker", "worker ", "work er", "工人", "worker#1"] {
            assert!(validate_id("id", invalid).is_err(), "{invalid:?}");
        }
        let leading_zero = br#"{
            "schema":"trnm_canonical_tx_v1",
            "sender":"alice",
            "nonce":1,
            "max_gas":1000,
            "fee_limit":"01",
            "command":{"type":"transfer","to":"bob","amount":"1"}
        }"#;
        assert!(serde_json::from_slice::<CanonicalTxV1>(leading_zero).is_err());
    }
}

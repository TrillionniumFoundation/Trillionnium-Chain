//! Mode5 exact Pool purpose. This does not turn a Search/receiver grant into Pool authority.
//! Whole pending prefix and the new bundle remain distinct, original M06 is mandatory.
use crate::operator_continuous_recipient::{declared_binding_digest, VerifiedAllocation};
use crate::operator_task_policy::PolicyError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, PolicyError>;
const DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-POOL-SELECTION1";
fn check(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(PolicyError::NativeBinding)
    }
}
fn id(v: &str) -> Result<()> {
    check(
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}
fn sha(v: &[u8]) -> String {
    hex::encode(Sha256::digest(v))
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Purpose {
    Enable,
    Reconcile,
    SubmitBundle,
    Status,
    MiningBatch,
    ValidateBatch,
    Prune,
}
impl Purpose {
    pub(crate) fn claim_purpose(&self) -> &'static str {
        match self {
            Self::Enable => "pool-enable",
            Self::Reconcile => "pool-reconcile",
            Self::SubmitBundle => "pool-submit-bundle",
            Self::Status => "pool-status",
            Self::MiningBatch => "pool-mining-batch",
            Self::ValidateBatch => "pool-validate-batch",
            Self::Prune => "pool-prune",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedGroup {
    pub group: String,
    pub original_admission_operation: String,
    pub exact_transactions_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub schema: String,
    pub operation: String,
    pub purpose: Purpose,
    pub parent: String,
    pub generation: u64,
    pub native_task: String,
    pub task_binding: String,
    pub pool_context: String,
    pub limits_sha256: String,
    pub exact_new_transactions_sha256: String,
    pub retained_groups: Vec<RetainedGroup>,
    pub exact_selected_transactions_sha256: Option<String>,
    pub exact_prune_group: Option<String>,
    pub max_records: Option<u16>,
    pub max_bytes: Option<u32>,
}
impl Selection {
    pub(crate) fn payload_sha256(&self) -> Result<String> {
        check(
            self.schema == "restricted-continuous-pool-selection-v1"
                && self.retained_groups.len() <= 256,
        )?;
        for h in [
            &self.operation,
            &self.parent,
            &self.native_task,
            &self.task_binding,
            &self.pool_context,
            &self.limits_sha256,
            &self.exact_new_transactions_sha256,
        ] {
            id(h)?;
        }
        for (n, row) in self.retained_groups.iter().enumerate() {
            for h in [
                &row.group,
                &row.original_admission_operation,
                &row.exact_transactions_sha256,
            ] {
                id(h)?;
            }
            check(
                !self.retained_groups[..n]
                    .iter()
                    .any(|old| old.group == row.group),
            )?;
        }
        if let Some(h) = &self.exact_selected_transactions_sha256 {
            id(h)?;
        }
        if let Some(h) = &self.exact_prune_group {
            id(h)?;
        }
        check(
            matches!(self.purpose, Purpose::ValidateBatch)
                == self.exact_selected_transactions_sha256.is_some()
                && matches!(self.purpose, Purpose::Prune) == self.exact_prune_group.is_some()
                && matches!(self.purpose, Purpose::MiningBatch) == self.max_records.is_some()
                && matches!(self.purpose, Purpose::MiningBatch) == self.max_bytes.is_some(),
        )?;
        if let (Some(records), Some(bytes)) = (self.max_records, self.max_bytes) {
            check((1..=256).contains(&records) && (1..=524288).contains(&bytes))?;
        }
        // Operation is excluded from the hash: it is derived from this payload,
        // independently signed global ID and nonce. No self-referential digest.
        #[derive(Serialize)]
        struct Payload<'a> {
            schema: &'a str,
            purpose: &'a Purpose,
            parent: &'a str,
            generation: u64,
            native_task: &'a str,
            task_binding: &'a str,
            pool_context: &'a str,
            limits_sha256: &'a str,
            exact_new_transactions_sha256: &'a str,
            retained_groups: &'a [RetainedGroup],
            exact_selected_transactions_sha256: &'a Option<String>,
            exact_prune_group: &'a Option<String>,
            max_records: Option<u16>,
            max_bytes: Option<u32>,
        }
        let raw = serde_json::to_vec(&Payload {
            schema: &self.schema,
            purpose: &self.purpose,
            parent: &self.parent,
            generation: self.generation,
            native_task: &self.native_task,
            task_binding: &self.task_binding,
            pool_context: &self.pool_context,
            limits_sha256: &self.limits_sha256,
            exact_new_transactions_sha256: &self.exact_new_transactions_sha256,
            retained_groups: &self.retained_groups,
            exact_selected_transactions_sha256: &self.exact_selected_transactions_sha256,
            exact_prune_group: &self.exact_prune_group,
            max_records: self.max_records,
            max_bytes: self.max_bytes,
        })
        .map_err(|_| PolicyError::Input)?;
        check(raw.len() <= 65536)?;
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        message.extend_from_slice(&raw);
        Ok(sha(&message))
    }
}
#[derive(Clone)]
pub(crate) struct VerifiedSelection {
    body: Selection,
    groups: BTreeMap<String, (String, String)>,
    allowed_raws: BTreeSet<String>,
}
impl VerifiedSelection {
    pub(crate) fn authenticate(body: &Selection, permission: &VerifiedAllocation) -> Result<Self> {
        let c = permission.claim();
        check(
            c.operation == body.operation
                && c.purpose == body.purpose.claim_purpose()
                && c.payload == body.payload_sha256()?
                && c.parent == body.parent
                && c.generation == body.generation
                && c.native_task == body.native_task
                && c.task_binding == body.task_binding
                && c.task_binding == declared_binding_digest(&permission.body().declared_binding)?,
        )?;
        Ok(Self {
            body: body.clone(),
            groups: BTreeMap::new(),
            allowed_raws: BTreeSet::new(),
        })
    }
    pub(crate) fn body(&self) -> &Selection {
        &self.body
    }
    pub(crate) fn bind_new(&mut self, raws: &[Vec<u8>]) -> Result<()> {
        self.check_new_bundle(raws)?;
        for raw in raws {
            self.allowed_raws.insert(sha(raw));
        }
        Ok(())
    }
    pub(crate) fn bind_retained(
        &mut self,
        group: crate::Hash,
        original_operation: &str,
        raws: &[Vec<u8>],
    ) -> Result<()> {
        self.check_retained(group, original_operation, raws)?;
        let digest = crate::operator_mining_policy::transactions_sha256(raws)?;
        check(
            self.groups
                .insert(hex::encode(group), (original_operation.to_owned(), digest))
                .is_none(),
        )?;
        for raw in raws {
            self.allowed_raws.insert(sha(raw));
        }
        Ok(())
    }
    pub(crate) fn all_retained_bound(&self) -> Result<()> {
        check(self.groups.len() == self.body.retained_groups.len())
    }
    pub(crate) fn check_prefix(&self, raws: &[Vec<u8>]) -> Result<()> {
        crate::operator_mining_policy::transactions_sha256(raws)?;
        check(raws.iter().all(|raw| self.allowed_raws.contains(&sha(raw))))
    }
    pub(crate) fn check_bound_group(&self, raws: &[Vec<u8>]) -> Result<()> {
        let actual = crate::operator_mining_policy::transactions_sha256(raws)?;
        check(self.groups.values().any(|(_, digest)| digest == &actual))
    }
    pub(crate) fn check_internal_command(&self, command: &str, raws: &[Vec<u8>]) -> Result<()> {
        check(self.permits_internal_command(command))?;
        match command {
            "enable-pool" => check(raws.len() == 1 && sha(&raws[0]) == self.body.limits_sha256),
            "submit-bundle" => self.check_new_bundle(raws),
            "reconcile" => check(raws.is_empty()),
            _ => Err(PolicyError::NativeBinding),
        }
    }
    pub(crate) fn permits_internal_command(&self, command: &str) -> bool {
        match command {
            "enable-pool" => self.body.purpose == Purpose::Enable,
            "submit-bundle" => self.body.purpose == Purpose::SubmitBundle,
            "reconcile" => true,
            _ => false,
        }
    }

    pub(crate) fn check_actual_parent(
        &self,
        parent: crate::Hash,
        generation: u64,
        context: crate::Hash,
    ) -> Result<()> {
        check(
            self.body.parent == hex::encode(parent)
                && self.body.generation == generation
                && self.body.pool_context == hex::encode(context),
        )
    }
    pub(crate) fn check_new_bundle(&self, raws: &[Vec<u8>]) -> Result<()> {
        check(self.body.purpose != Purpose::SubmitBundle || !raws.is_empty())?;
        check(
            self.body.exact_new_transactions_sha256
                == crate::operator_mining_policy::transactions_sha256(raws)?,
        )
    }
    pub(crate) fn check_retained(
        &self,
        group: crate::Hash,
        original_operation: &str,
        raws: &[Vec<u8>],
    ) -> Result<()> {
        let row = self
            .body
            .retained_groups
            .iter()
            .find(|row| row.group == hex::encode(group))
            .ok_or(PolicyError::NativeBinding)?;
        check(
            row.original_admission_operation == original_operation
                && row.exact_transactions_sha256
                    == crate::operator_mining_policy::transactions_sha256(raws)?,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchInput {
    pub parent: String,
    pub generation: u64,
    pub context: String,
    pub preview_miner: String,
    pub transactions: Vec<String>,
    pub groups: Vec<String>,
    pub typed_gate_admissions: usize,
}
fn raws(values: &[String], limit: usize) -> crate::Result<Vec<Vec<u8>>> {
    crate::ensure(values.len() <= limit, "OWNER_CONTINUOUS_POOL_COUNT")?;
    values
        .iter()
        .map(|value| {
            crate::ensure(
                (318..=4096).contains(&value.len()),
                "OWNER_CONTINUOUS_POOL_RAW",
            )?;
            let raw = hex::decode(value).map_err(|_| "OWNER_CONTINUOUS_POOL_HEX")?;
            crate::ensure(hex::encode(&raw) == *value, "OWNER_CONTINUOUS_POOL_HEX")?;
            Ok(raw)
        })
        .collect()
}
impl BatchInput {
    pub(crate) fn actual(&self) -> crate::Result<crate::PoolBatch> {
        crate::ensure(self.groups.len() <= 256, "OWNER_CONTINUOUS_POOL_GROUPS")?;
        Ok(crate::PoolBatch {
            parent: crate::digest(&self.parent)?,
            generation: self.generation,
            context: crate::digest(&self.context)?,
            preview_miner: crate::digest(&self.preview_miner)?,
            transactions: raws(&self.transactions, 256)?,
            groups: self
                .groups
                .iter()
                .map(|h| crate::digest(h))
                .collect::<crate::Result<_>>()?,
            typed_gate_admissions: self.typed_gate_admissions,
        })
    }
    pub(crate) fn from_actual(value: crate::PoolBatch) -> Self {
        Self {
            parent: hex::encode(value.parent),
            generation: value.generation,
            context: hex::encode(value.context),
            preview_miner: hex::encode(value.preview_miner),
            transactions: value.transactions.iter().map(hex::encode).collect(),
            groups: value.groups.iter().map(hex::encode).collect(),
            typed_gate_admissions: value.typed_gate_admissions,
        }
    }
}
/// One explicit paid operation. Internal reconcile is part of that exact
/// operation, never a new external permission or reusable State capability.
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Enable { limits: Box<crate::PoolLimits> },
    Reconcile {},
    SubmitBundle { transactions: Vec<String> },
    Status {},
    MiningBatch { max_records: u16, max_bytes: u32 },
    ValidateBatch { batch: Box<BatchInput> },
    Prune { group: String },
}
impl Command {
    pub(crate) fn purpose(&self) -> Purpose {
        match self {
            Self::Enable { .. } => Purpose::Enable,
            Self::Reconcile {} => Purpose::Reconcile,
            Self::SubmitBundle { .. } => Purpose::SubmitBundle,
            Self::Status {} => Purpose::Status,
            Self::MiningBatch { .. } => Purpose::MiningBatch,
            Self::ValidateBatch { .. } => Purpose::ValidateBatch,
            Self::Prune { .. } => Purpose::Prune,
        }
    }
    pub(crate) fn new_bundle(&self) -> crate::Result<Vec<Vec<u8>>> {
        match self {
            Self::SubmitBundle { transactions } => {
                crate::ensure(
                    !transactions.is_empty(),
                    "OWNER_CONTINUOUS_POOL_EMPTY_BUNDLE",
                )?;
                raws(transactions, 16)
            }
            _ => Ok(Vec::new()),
        }
    }
    pub(crate) fn check_selection(&self, s: &Selection) -> crate::Result<()> {
        crate::ensure(self.purpose() == s.purpose, "OWNER_CONTINUOUS_POOL_PURPOSE")?;
        crate::ensure(
            crate::operator_mining_policy::transactions_sha256(&self.new_bundle()?)
                .map_err(|_| "OWNER_CONTINUOUS_POOL_RAW")?
                == s.exact_new_transactions_sha256,
            "OWNER_CONTINUOUS_POOL_NEW_BUNDLE",
        )?;
        match self {
            Self::Enable { limits } => crate::ensure(
                sha(&serde_json::to_vec(limits)?) == s.limits_sha256,
                "OWNER_CONTINUOUS_POOL_LIMITS",
            ),
            Self::MiningBatch {
                max_records,
                max_bytes,
            } => crate::ensure(
                s.max_records == Some(*max_records) && s.max_bytes == Some(*max_bytes),
                "OWNER_CONTINUOUS_POOL_BATCH_LIMITS",
            ),
            Self::ValidateBatch { batch } => crate::ensure(
                Some(
                    crate::operator_mining_policy::transactions_sha256(
                        &batch.actual()?.transactions,
                    )
                    .map_err(|_| "OWNER_CONTINUOUS_POOL_BATCH")?,
                ) == s.exact_selected_transactions_sha256,
                "OWNER_CONTINUOUS_POOL_SELECTED",
            ),
            Self::Prune { group } => crate::ensure(
                s.exact_prune_group.as_ref() == Some(group),
                "OWNER_CONTINUOUS_POOL_PRUNE",
            ),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "operator_continuous_pool_tests.rs"]
mod tests;

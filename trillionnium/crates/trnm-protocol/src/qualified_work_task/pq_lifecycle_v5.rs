//! Fresh NPQ5 demand records. Codecs confer no signature or State authority.
//! The fixed matrix relation is unchanged; old lease/Ed25519 encodings are refused.
use super::{QualifiedWorkTask, TaskError, TaskPurpose, MANIFEST_BYTES, MAX_VALIDITY_BLOCKS};
use crate::pon_wire::{hash, Hash};

pub const PROFILE: &str = "native-pq-task-lifecycle-dev-v5";
pub const DEMAND_SLOTS: u8 = 32;
pub const RETENTION_BLOCKS: u64 = 100;
pub const DEMAND_LEASE_BYTES: usize = 344;
pub const DEMAND_REVOCATION_BYTES: usize = 4 + DEMAND_LEASE_BYTES;
pub const DEMAND_RENEWAL_BYTES: usize = 4 + 64 + DEMAND_LEASE_BYTES;
pub const ATOMIC_RENEW_TASK_BYTES: usize = 4 + 32 + DEMAND_LEASE_BYTES + TASK_REGISTRATION_BYTES;
pub const TASK_REGISTRATION_BYTES: usize = 4 + 64 + MANIFEST_BYTES;
pub const OPEN_TAG: u8 = 18;
pub const RENEW_TAG: u8 = 19;
pub const ATOMIC_RENEW_TAG: u8 = 22;
pub const REVOKE_TAG: u8 = 20;
pub const REGISTER_TAG: u8 = 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    Length,
    Version,
    Reserved,
    Identity,
    Slot,
    Sequence,
    Validity,
    CostClass,
    Manifest(TaskError),
}

/// The main ledger envelope authenticates requester; source must separately sign
/// the current lease-bound task. Different keys alone do not prove independence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandLeaseV5 {
    pub slot: u8,
    pub purpose: TaskPurpose,
    pub network: Hash,
    pub parameters: Hash,
    pub demand_id: Hash,
    pub requester: Hash,
    pub source: Hash,
    pub source_record: Hash,
    pub authorization_scope: Hash,
    pub availability_manifest: Hash,
    pub availability_root: Hash,
    pub generation: u64,
    pub revision: u64,
    pub not_before: u64,
    pub expires: u64,
    pub available_until: u64,
    pub cost_class: u8,
}
impl DemandLeaseV5 {
    pub fn derived_demand_id(&self) -> Hash {
        hash(
            b"qualified-pq-demand-id-v5",
            &[
                &self.network,
                &self.parameters,
                &self.requester,
                &self.generation.to_le_bytes(),
            ],
        )
    }
    fn hashes(&self) -> [&Hash; 9] {
        [
            &self.network,
            &self.parameters,
            &self.demand_id,
            &self.requester,
            &self.source,
            &self.source_record,
            &self.authorization_scope,
            &self.availability_manifest,
            &self.availability_root,
        ]
    }
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.slot >= DEMAND_SLOTS {
            return Err(LifecycleError::Slot);
        }
        if self.generation == 0 || self.revision == 0 {
            return Err(LifecycleError::Sequence);
        }
        if self.hashes().iter().any(|value| **value == [0; 32])
            || self.requester == self.source
            || self.demand_id != self.derived_demand_id()
        {
            return Err(LifecycleError::Identity);
        }
        if self.cost_class != 1 {
            return Err(LifecycleError::CostClass);
        }
        if self.expires <= self.not_before
            || self.expires - self.not_before > MAX_VALIDITY_BLOCKS
            || self.expires.checked_add(RETENTION_BLOCKS) != Some(self.available_until)
        {
            return Err(LifecycleError::Validity);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(DEMAND_LEASE_BYTES);
        bytes.extend_from_slice(b"PQL5");
        bytes.extend_from_slice(&5_u16.to_le_bytes());
        bytes.extend_from_slice(&[self.slot, self.purpose as u8]);
        for value in self.hashes() {
            bytes.extend_from_slice(value);
        }
        for value in [
            self.generation,
            self.revision,
            self.not_before,
            self.expires,
            self.available_until,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.push(self.cost_class);
        bytes.extend_from_slice(&[0; 7]);
        debug_assert_eq!(bytes.len(), DEMAND_LEASE_BYTES);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleError> {
        if bytes.len() != DEMAND_LEASE_BYTES {
            return Err(LifecycleError::Length);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take::<4>()? != *b"PQL5" || reader.take::<2>()? != 5_u16.to_le_bytes() {
            return Err(LifecycleError::Version);
        }
        let slot = reader.take::<1>()?[0];
        let purpose =
            TaskPurpose::decode(reader.take::<1>()?[0]).map_err(LifecycleError::Manifest)?;
        let lease = Self {
            slot,
            purpose,
            network: reader.take()?,
            parameters: reader.take()?,
            demand_id: reader.take()?,
            requester: reader.take()?,
            source: reader.take()?,
            source_record: reader.take()?,
            authorization_scope: reader.take()?,
            availability_manifest: reader.take()?,
            availability_root: reader.take()?,
            generation: u64::from_le_bytes(reader.take()?),
            revision: u64::from_le_bytes(reader.take()?),
            not_before: u64::from_le_bytes(reader.take()?),
            expires: u64::from_le_bytes(reader.take()?),
            available_until: u64::from_le_bytes(reader.take()?),
            cost_class: reader.take::<1>()?[0],
        };
        if reader.take::<7>()? != [0; 7] {
            return Err(LifecycleError::Reserved);
        }
        lease.validate()?;
        Ok(lease)
    }
    pub fn id(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(b"qualified-pq-demand-lease-v5", &[&self.encode()?]))
    }
    pub fn bound_source_record(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(
            b"qualified-pq-demand-source-record-v5",
            &[&self.id()?, &self.source_record],
        ))
    }
    pub fn withdrawal_frontier(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(b"qualified-pq-demand-frontier-v5", &[&self.id()?]))
    }
}

impl DemandLeaseV5 {
    /// Renewal keeps every permission and material field except its revision and
    /// height window. This comparison carries no signature authority.
    pub fn same_scope(&self, previous: &Self) -> bool {
        self.slot == previous.slot
            && self.purpose == previous.purpose
            && self.hashes() == previous.hashes()
            && self.generation == previous.generation
            && self.cost_class == previous.cost_class
    }
    pub fn validate_successor(&self, previous: &Self, height: u64) -> Result<(), LifecycleError> {
        self.validate()?;
        previous.validate()?;
        if !self.same_scope(previous) {
            return Err(LifecycleError::Identity);
        }
        if previous.revision.checked_add(1) != Some(self.revision) {
            return Err(LifecycleError::Sequence);
        }
        if height < previous.not_before
            || height > previous.expires
            || self.not_before < previous.not_before
            || self.not_before > height
            || self.expires <= previous.expires
        {
            return Err(LifecycleError::Validity);
        }
        Ok(())
    }
    /// Stable local denial scope across renewal and fork revision changes. The
    /// caller must first match this complete lease against actual M06 State.
    /// Signed lease IDs remain separately bound for every consensus transition.
    pub fn lineage_id(&self, genesis: Hash) -> Result<Hash, LifecycleError> {
        self.validate()?;
        if genesis == [0; 32] {
            return Err(LifecycleError::Identity);
        }
        Ok(hash(
            b"qualified-pq-demand-lineage-v5",
            &[
                &self.network,
                &self.parameters,
                &genesis,
                &self.demand_id,
                &self.generation.to_le_bytes(),
                &self.requester,
                &self.source,
            ],
        ))
    }
}

/// The full lease is an optimistic concurrency assertion. Only exact equality
/// with the actual State owner can authorize a revoke or its local lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandRevocationV5 {
    pub lease: DemandLeaseV5,
}
impl DemandRevocationV5 {
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        let mut raw = b"PQR5".to_vec();
        raw.extend(self.lease.encode()?);
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, LifecycleError> {
        if raw.len() != DEMAND_REVOCATION_BYTES {
            return Err(LifecycleError::Length);
        }
        if &raw[..4] != b"PQR5" {
            return Err(LifecycleError::Version);
        }
        Ok(Self {
            lease: DemandLeaseV5::decode(&raw[4..])?,
        })
    }
}

/// Requester-only extension intentionally suspends future task eligibility until
/// a new independent source proof binds this successor lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandRenewalV5 {
    pub expected_lease_id: Hash,
    pub prior_statement_id: Hash,
    pub successor: DemandLeaseV5,
}
impl DemandRenewalV5 {
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        if self.expected_lease_id == [0; 32] {
            return Err(LifecycleError::Identity);
        }
        let mut raw = b"PQE5".to_vec();
        raw.extend(self.expected_lease_id);
        raw.extend(self.prior_statement_id);
        raw.extend(self.successor.encode()?);
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, LifecycleError> {
        if raw.len() != DEMAND_RENEWAL_BYTES {
            return Err(LifecycleError::Length);
        }
        if &raw[..4] != b"PQE5" {
            return Err(LifecycleError::Version);
        }
        let value = Self {
            expected_lease_id: raw[4..36].try_into().map_err(|_| LifecycleError::Length)?,
            prior_statement_id: raw[36..68].try_into().map_err(|_| LifecycleError::Length)?,
            successor: DemandLeaseV5::decode(&raw[68..])?,
        };
        value.encode()?;
        Ok(value)
    }
}
/// Both requester and source sign the complete NPQ5 core in distinct TPQ1 owner
/// contexts. This payload itself has no signature and cannot authorize a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRegistrationV5 {
    pub lease_id: Hash,
    /// Exact previously committed statement, or zero for the first registration.
    pub prior_statement_id: Hash,
    pub manifest: QualifiedWorkTask,
}
impl TaskRegistrationV5 {
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        if self.lease_id == [0; 32] {
            return Err(LifecycleError::Identity);
        }
        let mut raw = Vec::with_capacity(TASK_REGISTRATION_BYTES);
        raw.extend(b"PQT5");
        raw.extend(self.lease_id);
        raw.extend(self.prior_statement_id);
        raw.extend(self.manifest.encode().map_err(LifecycleError::Manifest)?);
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, LifecycleError> {
        if raw.len() != TASK_REGISTRATION_BYTES {
            return Err(LifecycleError::Length);
        }
        let mut reader = Reader {
            bytes: raw,
            position: 0,
        };
        if reader.take::<4>()? != *b"PQT5" {
            return Err(LifecycleError::Version);
        }
        let value = Self {
            lease_id: reader.take()?,
            prior_statement_id: reader.take()?,
            manifest: QualifiedWorkTask::decode(&reader.take::<MANIFEST_BYTES>()?)
                .map_err(LifecycleError::Manifest)?,
        };
        value.encode()?;
        Ok(value)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], LifecycleError> {
        let end = self.position.checked_add(N).ok_or(LifecycleError::Length)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(LifecycleError::Length)?
            .try_into()
            .map_err(|_| LifecycleError::Length)?;
        self.position = end;
        Ok(value)
    }
}

/// Both current State owners sign the exact old lease ID, successor and task in
/// the 22 core. A verifier never extracts and reuses its proof as a 21 command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicRenewTaskV5 {
    pub expected_lease_id: Hash,
    pub successor: DemandLeaseV5,
    pub registration: TaskRegistrationV5,
}
impl AtomicRenewTaskV5 {
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        if self.expected_lease_id == [0; 32] || self.registration.lease_id != self.successor.id()? {
            return Err(LifecycleError::Identity);
        }
        let mut raw = b"PQA5".to_vec();
        raw.extend(self.expected_lease_id);
        raw.extend(self.successor.encode()?);
        raw.extend(self.registration.encode()?);
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, LifecycleError> {
        if raw.len() != ATOMIC_RENEW_TASK_BYTES {
            return Err(LifecycleError::Length);
        }
        if &raw[..4] != b"PQA5" {
            return Err(LifecycleError::Version);
        }
        let end = 36 + DEMAND_LEASE_BYTES;
        let value = Self {
            expected_lease_id: raw[4..36].try_into().map_err(|_| LifecycleError::Length)?,
            successor: DemandLeaseV5::decode(&raw[36..end])?,
            registration: TaskRegistrationV5::decode(&raw[end..])?,
        };
        value.encode()?;
        Ok(value)
    }
}

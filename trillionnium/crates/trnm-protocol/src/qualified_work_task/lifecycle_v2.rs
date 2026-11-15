//! Exact bounded lifecycle statements. A decoded request is not verified demand,
//! authorization, data retention, useful learning or a computational lower bound.
use super::{QualifiedWorkTask, TaskError, TaskPurpose, MANIFEST_BYTES, MAX_VALIDITY_BLOCKS};
use crate::pon_wire::{hash, Hash};

pub const PROFILE: &str = "signed-task-lifecycle-dev-v2";
pub const DEMAND_SLOTS: u8 = 32;
pub const RETENTION_BLOCKS: u64 = 100;
pub const DEMAND_LEASE_BYTES: usize = 344;
pub const DEMAND_REVOCATION_BYTES: usize = 144;
pub const LIFECYCLE_TASK_BYTES: usize = 4 + 32 + MANIFEST_BYTES + 64;
pub const OPEN_TAG: u8 = 18;
pub const RENEW_TAG: u8 = 19;
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
pub struct DemandLeaseV2 {
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
impl DemandLeaseV2 {
    pub fn derived_demand_id(&self) -> Hash {
        hash(
            b"qualified-demand-id-v2",
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
        bytes.extend_from_slice(b"QDL2");
        bytes.extend_from_slice(&2_u16.to_le_bytes());
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
        if reader.take::<4>()? != *b"QDL2" || reader.take::<2>()? != 2_u16.to_le_bytes() {
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
        Ok(hash(b"qualified-demand-lease-v2", &[&self.encode()?]))
    }
    pub fn bound_source_record(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(
            b"qualified-demand-source-record-v2",
            &[&self.id()?, &self.source_record],
        ))
    }
    pub fn withdrawal_frontier(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(b"qualified-demand-frontier-v2", &[&self.id()?]))
    }
}

/// expected_revision is optimistic concurrency control, not a cryptographic nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandRevocationV2 {
    pub slot: u8,
    pub network: Hash,
    pub parameters: Hash,
    pub demand_id: Hash,
    pub requester: Hash,
    pub expected_revision: u64,
}
impl DemandRevocationV2 {
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        if self.slot >= DEMAND_SLOTS {
            return Err(LifecycleError::Slot);
        }
        if self.expected_revision == 0 {
            return Err(LifecycleError::Sequence);
        }
        if [
            self.network,
            self.parameters,
            self.demand_id,
            self.requester,
        ]
        .contains(&[0; 32])
        {
            return Err(LifecycleError::Identity);
        }
        let mut bytes = Vec::with_capacity(DEMAND_REVOCATION_BYTES);
        bytes.extend_from_slice(b"QDR2");
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&[self.slot, 0]);
        for value in [
            self.network,
            self.parameters,
            self.demand_id,
            self.requester,
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&self.expected_revision.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleError> {
        if bytes.len() != DEMAND_REVOCATION_BYTES {
            return Err(LifecycleError::Length);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take::<4>()? != *b"QDR2" || reader.take::<2>()? != 2_u16.to_le_bytes() {
            return Err(LifecycleError::Version);
        }
        let slot = reader.take::<1>()?[0];
        if reader.take::<1>()? != [0] {
            return Err(LifecycleError::Reserved);
        }
        let value = Self {
            slot,
            network: reader.take()?,
            parameters: reader.take()?,
            demand_id: reader.take()?,
            requester: reader.take()?,
            expected_revision: u64::from_le_bytes(reader.take()?),
        };
        value.encode()?;
        Ok(value)
    }
}

/// The fixed matrix relation is unchanged. This fresh wrapper binds the consumer's
/// current lease and uses an independent source-signature and statement-ID domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedLifecycleTaskV2 {
    pub lease_id: Hash,
    pub manifest: QualifiedWorkTask,
    pub signature: [u8; 64],
}
impl SignedLifecycleTaskV2 {
    fn unsigned_bytes(&self) -> Result<Vec<u8>, LifecycleError> {
        if self.lease_id == [0; 32] {
            return Err(LifecycleError::Identity);
        }
        let mut bytes = Vec::with_capacity(LIFECYCLE_TASK_BYTES - 64);
        bytes.extend_from_slice(b"QWA2");
        bytes.extend_from_slice(&self.lease_id);
        bytes.extend_from_slice(&self.manifest.encode().map_err(LifecycleError::Manifest)?);
        Ok(bytes)
    }
    pub fn signing_message(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(
            b"qualified-task-source-sign-v2",
            &[&self.unsigned_bytes()?],
        ))
    }
    pub fn id(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(
            b"qualified-task-manifest-v2",
            &[&self.unsigned_bytes()?],
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleError> {
        if bytes.len() != LIFECYCLE_TASK_BYTES {
            return Err(LifecycleError::Length);
        }
        if bytes[..4] != *b"QWA2" {
            return Err(LifecycleError::Version);
        }
        let value = Self {
            lease_id: bytes[4..36]
                .try_into()
                .map_err(|_| LifecycleError::Length)?,
            manifest: QualifiedWorkTask::decode(&bytes[36..36 + MANIFEST_BYTES])
                .map_err(LifecycleError::Manifest)?,
            signature: bytes[36 + MANIFEST_BYTES..]
                .try_into()
                .map_err(|_| LifecycleError::Length)?,
        };
        value.unsigned_bytes()?;
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

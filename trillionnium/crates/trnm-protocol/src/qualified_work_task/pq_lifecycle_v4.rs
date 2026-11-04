//! Fresh NPQ4 demand records. Codecs confer no signature or State authority.
//! The fixed matrix relation is unchanged; old lease/Ed25519 encodings are refused.
use super::{QualifiedWorkTask, TaskError, TaskPurpose, MANIFEST_BYTES, MAX_VALIDITY_BLOCKS};
use crate::pon_wire::{hash, Hash};

pub const PROFILE: &str = "native-pq-task-lifecycle-dev-v4";
pub const DEMAND_SLOTS: u8 = 32;
pub const RETENTION_BLOCKS: u64 = 100;
pub const DEMAND_LEASE_BYTES: usize = 344;
pub const DEMAND_REVOCATION_BYTES: usize = 176;
pub const TASK_REGISTRATION_BYTES: usize = 4 + 64 + MANIFEST_BYTES;
pub const OPEN_TAG: u8 = 18;
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
pub struct DemandLeaseV4 {
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
impl DemandLeaseV4 {
    pub fn derived_demand_id(&self) -> Hash {
        hash(
            b"qualified-pq-demand-id-v4",
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
        bytes.extend_from_slice(b"PQL4");
        bytes.extend_from_slice(&4_u16.to_le_bytes());
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
        if reader.take::<4>()? != *b"PQL4" || reader.take::<2>()? != 4_u16.to_le_bytes() {
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
        Ok(hash(b"qualified-pq-demand-lease-v4", &[&self.encode()?]))
    }
    pub fn bound_source_record(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(
            b"qualified-pq-demand-source-record-v4",
            &[&self.id()?, &self.source_record],
        ))
    }
    pub fn withdrawal_frontier(&self) -> Result<Hash, LifecycleError> {
        Ok(hash(b"qualified-pq-demand-frontier-v4", &[&self.id()?]))
    }
}

/// expected_revision is optimistic concurrency control, not a cryptographic nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandRevocationV4 {
    pub slot: u8,
    pub network: Hash,
    pub parameters: Hash,
    pub demand_id: Hash,
    pub requester: Hash,
    pub lease_id: Hash,
    pub expected_revision: u64,
}
impl DemandRevocationV4 {
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
            self.lease_id,
        ]
        .contains(&[0; 32])
        {
            return Err(LifecycleError::Identity);
        }
        let mut bytes = Vec::with_capacity(DEMAND_REVOCATION_BYTES);
        bytes.extend_from_slice(b"PQR4");
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&[self.slot, 0]);
        for value in [
            self.network,
            self.parameters,
            self.demand_id,
            self.requester,
            self.lease_id,
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
        if reader.take::<4>()? != *b"PQR4" || reader.take::<2>()? != 4_u16.to_le_bytes() {
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
            lease_id: reader.take()?,
            expected_revision: u64::from_le_bytes(reader.take()?),
        };
        value.encode()?;
        Ok(value)
    }
}

/// Both requester and source sign the complete NPQ4 core in distinct TPQ1 owner
/// contexts. This payload itself has no signature and cannot authorize a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRegistrationV4 {
    pub lease_id: Hash,
    /// Exact previously committed statement, or zero for the first registration.
    pub prior_statement_id: Hash,
    pub manifest: QualifiedWorkTask,
}
impl TaskRegistrationV4 {
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        if self.lease_id == [0; 32] {
            return Err(LifecycleError::Identity);
        }
        let mut raw = Vec::with_capacity(TASK_REGISTRATION_BYTES);
        raw.extend(b"PQT4");
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
        if reader.take::<4>()? != *b"PQT4" {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_pq_lease_revocation_domains_lengths_and_exact_branch_identity_are_fresh() {
        let mut lease = DemandLeaseV4 {
            slot: 0,
            purpose: TaskPurpose::InferenceContraction,
            network: [1; 32],
            parameters: [2; 32],
            demand_id: [3; 32],
            requester: [4; 32],
            source: [5; 32],
            source_record: [6; 32],
            authorization_scope: [7; 32],
            availability_manifest: [8; 32],
            availability_root: [9; 32],
            generation: 1,
            revision: 1,
            not_before: 1,
            expires: 50,
            available_until: 150,
            cost_class: 1,
        };
        lease.demand_id = lease.derived_demand_id();
        let raw = lease.encode().unwrap();
        assert_eq!(raw.len(), 344);
        assert_eq!(DemandLeaseV4::decode(&raw).unwrap(), lease);
        assert!(crate::qualified_work_task::lifecycle_v2::DemandLeaseV2::decode(&raw).is_err());
        let mut alias = raw.clone();
        alias[..4].copy_from_slice(b"QDL2");
        alias[4..6].copy_from_slice(&2_u16.to_le_bytes());
        assert!(DemandLeaseV4::decode(&alias).is_err());
        assert!(crate::qualified_work_task::lifecycle_v2::DemandLeaseV2::decode(&alias).is_err());
        let request = DemandRevocationV4 {
            slot: 0,
            network: lease.network,
            parameters: lease.parameters,
            demand_id: lease.demand_id,
            requester: lease.requester,
            lease_id: lease.id().unwrap(),
            expected_revision: 1,
        };
        let raw = request.encode().unwrap();
        assert_eq!(raw.len(), 176);
        assert_eq!(DemandRevocationV4::decode(&raw).unwrap(), request);
        assert!(
            crate::qualified_work_task::lifecycle_v2::DemandRevocationV2::decode(&raw).is_err()
        );
        for length in [0, 144, 175] {
            assert!(DemandRevocationV4::decode(&raw[..length]).is_err());
        }
        let mut surplus = raw.clone();
        surplus.push(0);
        assert!(DemandRevocationV4::decode(&surplus).is_err());
        let mut same_id_other_branch = lease.clone();
        same_id_other_branch.source = [19; 32];
        assert_eq!(same_id_other_branch.demand_id, lease.demand_id);
        assert_ne!(same_id_other_branch.id().unwrap(), request.lease_id);
        assert_ne!(
            same_id_other_branch.bound_source_record().unwrap(),
            lease.bound_source_record().unwrap()
        );
    }
}

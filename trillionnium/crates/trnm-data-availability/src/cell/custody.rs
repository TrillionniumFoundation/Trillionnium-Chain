//! Complete-version custody observations over the existing physical archive.
//!
//! This observer never accepts a supplied ACK as proof of bytes: each counted
//! copy comes from `CellReleaseRetentionStoreV2::verify_release`. The owner pins
//! the entire policy before probing. Administrator, failure-domain and evidence
//! identities are declarations from that owner, not proof of physical or legal
//! independence. This module grants no storage funding, payment or execution
//! authority, and creates no renewal, repair, deletion or network side effect.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use sha2::{Digest, Sha256};

use super::{
    require, CellDigestV1, CellErrorV1, CellModelReleaseRootV1, CellReleaseRetentionContractV2,
    CellReleaseRetentionStoreV2, CellResultV1, CellVersionCommitmentV1, CellVersionManifestV1,
};

pub const MAX_CELL_CUSTODY_REPLICAS_V1: usize = 16;

/// Owner-pinned identity of one complete replica. The evidence digest names
/// separately retained domain evidence; this observer does not interpret it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellCustodyReplicaPinV1 {
    pub store_id: CellDigestV1,
    pub operation: CellDigestV1,
    pub contract_commitment: CellDigestV1,
    pub responsible_owner: CellDigestV1,
    pub administrator: CellDigestV1,
    pub failure_domain: CellDigestV1,
    pub domain_evidence: CellDigestV1,
    pub renewal_owner: CellDigestV1,
    pub repair_owner: CellDigestV1,
    pub replica_index: u16,
    pub retain_from_height: u64,
    pub retain_until_height: u64,
    pub repair_deadline_height: u64,
}

impl CellCustodyReplicaPinV1 {
    /// Bind the exact contract to its actual target configuration. The caller
    /// must independently approve the domain and continuation-owner identities.
    pub fn from_contract(
        store: &CellReleaseRetentionStoreV2,
        contract: &CellReleaseRetentionContractV2,
        administrator: CellDigestV1,
        domain_evidence: CellDigestV1,
        renewal_owner: CellDigestV1,
        repair_owner: CellDigestV1,
    ) -> CellResultV1<Self> {
        Ok(Self {
            store_id: store.store_id(),
            operation: contract.operation,
            contract_commitment: store.contract_commitment(contract)?,
            responsible_owner: contract.responsible_owner,
            administrator,
            failure_domain: contract.failure_domain,
            domain_evidence,
            renewal_owner,
            repair_owner,
            replica_index: contract.replica_index,
            retain_from_height: contract.retain_from_height,
            retain_until_height: contract.retain_until_height,
            repair_deadline_height: contract.repair_deadline_height,
        })
    }
}

/// One version, one fixed complete-replica roster. A different version requires
/// its own policy and full observation; object unions cannot satisfy this one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseCustodyPolicyV1 {
    pub root: CellModelReleaseRootV1,
    pub required_replicas: u16,
    pub renewal_lead_blocks: u64,
    /// Canonical replica-index order, exactly one pin for each required slot.
    pub replicas: Vec<CellCustodyReplicaPinV1>,
}

impl CellReleaseCustodyPolicyV1 {
    fn validate(&self) -> CellResultV1<()> {
        self.root.validate()?;
        require(
            (1..=MAX_CELL_CUSTODY_REPLICAS_V1).contains(&(self.required_replicas as usize))
                && self.replicas.len() == self.required_replicas as usize
                && self.renewal_lead_blocks > 0,
            "custody policy bounds",
        )?;
        let mut stores = BTreeSet::new();
        let mut owners = BTreeSet::new();
        let mut administrators = BTreeSet::new();
        let mut domains = BTreeSet::new();
        for (slot, pin) in self.replicas.iter().enumerate() {
            require(
                [
                    pin.store_id,
                    pin.operation,
                    pin.contract_commitment,
                    pin.responsible_owner,
                    pin.administrator,
                    pin.failure_domain,
                    pin.domain_evidence,
                    pin.renewal_owner,
                    pin.repair_owner,
                ]
                .iter()
                .all(|value| *value != [0; 32]),
                "custody identity",
            )?;
            require(
                pin.replica_index as usize == slot
                    && stores.insert(pin.store_id)
                    && owners.insert(pin.responsible_owner)
                    && administrators.insert(pin.administrator)
                    && domains.insert(pin.failure_domain),
                "custody duplicate store/owner/domain or slot",
            )?;
            require(
                pin.retain_from_height < pin.retain_until_height
                    && pin.retain_until_height <= i64::MAX as u64
                    && pin.repair_deadline_height >= pin.retain_from_height
                    && pin.repair_deadline_height < pin.retain_until_height,
                "custody immutable service window",
            )?;
        }
        self.payload_bytes()?;
        Ok(())
    }

    /// A fresh domain for the complete owner policy, not a signature or an
    /// independence certificate. The observer requires an independent pin.
    pub fn id(&self) -> CellResultV1<CellDigestV1> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-release-custody-policy.v1\0");
        let root = self.root.encode();
        hash.update((root.len() as u64).to_be_bytes());
        hash.update(root);
        hash.update(self.required_replicas.to_be_bytes());
        hash.update(self.renewal_lead_blocks.to_be_bytes());
        for pin in &self.replicas {
            for identity in [
                pin.store_id,
                pin.operation,
                pin.contract_commitment,
                pin.responsible_owner,
                pin.administrator,
                pin.failure_domain,
                pin.domain_evidence,
                pin.renewal_owner,
                pin.repair_owner,
            ] {
                hash.update(identity);
            }
            hash.update(pin.replica_index.to_be_bytes());
            hash.update(pin.retain_from_height.to_be_bytes());
            hash.update(pin.retain_until_height.to_be_bytes());
            hash.update(pin.repair_deadline_height.to_be_bytes());
        }
        Ok(hash.finalize().into())
    }

    fn payload_bytes(&self) -> CellResultV1<u64> {
        let mut objects = BTreeMap::new();
        for file in self.root.closure().files() {
            if let Some(prior) = objects.insert(file.manifest, file.payload_bytes) {
                require(prior == file.payload_bytes, "custody aliased object length")?;
            }
        }
        require(
            objects.len() == self.root.closure().release().cells().len(),
            "custody complete object set",
        )?;
        objects.values().try_fold(0_u64, |sum, bytes| {
            sum.checked_add(*bytes)
                .ok_or(CellErrorV1::Invalid("custody payload overflow"))
        })
    }
}

/// One owner-supplied finite observation reservation. Reusing this value across
/// retries retains every attempted store and full potential payload debit,
/// including failures. It is in-process accounting, not a persistent M12 ledger.
/// Metadata reads, CPU/RSS and filesystem stalls are not payload-byte measures;
/// the original absolute deadline is cooperative through the existing archive.
#[derive(Debug)]
pub struct CellCustodyProbeBudgetV1 {
    deadline: Instant,
    maximum_store_probes: u32,
    maximum_payload_bytes: u64,
    store_probes_committed: u32,
    payload_bytes_committed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellCustodyProbeUsageV1 {
    pub store_probes_committed: u32,
    pub payload_bytes_committed: u64,
}

impl CellCustodyProbeBudgetV1 {
    pub fn new(deadline: Instant, maximum_store_probes: u32, maximum_payload_bytes: u64) -> Self {
        Self {
            deadline,
            maximum_store_probes,
            maximum_payload_bytes,
            store_probes_committed: 0,
            payload_bytes_committed: 0,
        }
    }

    pub fn usage(&self) -> CellCustodyProbeUsageV1 {
        CellCustodyProbeUsageV1 {
            store_probes_committed: self.store_probes_committed,
            payload_bytes_committed: self.payload_bytes_committed,
        }
    }

    fn reserve(&mut self, bytes: u64) -> CellResultV1<()> {
        require(Instant::now() < self.deadline, "custody original deadline")?;
        let probes = self
            .store_probes_committed
            .checked_add(1)
            .ok_or(CellErrorV1::Invalid("custody probe overflow"))?;
        let payload = self
            .payload_bytes_committed
            .checked_add(bytes)
            .ok_or(CellErrorV1::Invalid("custody payload overflow"))?;
        require(
            probes <= self.maximum_store_probes && payload <= self.maximum_payload_bytes,
            "custody observation budget exhausted",
        )?;
        self.store_probes_committed = probes;
        self.payload_bytes_committed = payload;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CellCustodyReplicaStateV1 {
    /// Complete real target readback within this sampled service interval.
    Observed,
    StoreUnavailable,
    NotStarted,
    Expired,
    /// A refusal is Unknown, not evidence that all bytes are physically lost.
    ReadbackRefused(String),
    ContractMismatch,
    ProbeRefused(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellCustodyReplicaObservationV1 {
    pub pin: CellCustodyReplicaPinV1,
    pub state: CellCustodyReplicaStateV1,
}

/// Actual sequential local observations, not simultaneous availability, WAN
/// service, durable custody, native funding, payment or physical independence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseCustodyReportV1 {
    policy: CellDigestV1,
    release_root: CellDigestV1,
    /// Supplied by the existing current-chain owner; M09 cannot authenticate it.
    observed_height: u64,
    payload_bytes_per_complete_replica: u64,
    required_replicas: u16,
    complete_replicas_observed: u16,
    finished_before_deadline: bool,
    usage_before: CellCustodyProbeUsageV1,
    usage_after: CellCustodyProbeUsageV1,
    replicas: Vec<CellCustodyReplicaObservationV1>,
    renewal_lead_blocks: u64,
}

impl CellReleaseCustodyReportV1 {
    pub fn policy(&self) -> CellDigestV1 {
        self.policy
    }

    pub fn release_root(&self) -> CellDigestV1 {
        self.release_root
    }

    pub fn observed_height(&self) -> u64 {
        self.observed_height
    }

    pub fn payload_bytes_per_complete_replica(&self) -> u64 {
        self.payload_bytes_per_complete_replica
    }

    pub fn required_replicas(&self) -> u16 {
        self.required_replicas
    }

    pub fn complete_replicas_observed(&self) -> u16 {
        self.complete_replicas_observed
    }

    pub fn finished_before_deadline(&self) -> bool {
        self.finished_before_deadline
    }

    pub fn usage_before(&self) -> CellCustodyProbeUsageV1 {
        self.usage_before
    }

    pub fn usage_after(&self) -> CellCustodyProbeUsageV1 {
        self.usage_after
    }

    pub fn replicas(&self) -> &[CellCustodyReplicaObservationV1] {
        &self.replicas
    }

    /// Scoped byte observation only; no independence/funding/use qualification.
    pub fn complete_byte_coverage_observed(&self) -> bool {
        self.finished_before_deadline && self.complete_replicas_observed == self.required_replicas
    }
}

fn matches_contract(
    policy: &CellReleaseCustodyPolicyV1,
    pin: &CellCustodyReplicaPinV1,
    store: &CellReleaseRetentionStoreV2,
    contract: &CellReleaseRetentionContractV2,
) -> CellResultV1<bool> {
    Ok(contract.root == policy.root
        && contract.operation == pin.operation
        && contract.responsible_owner == pin.responsible_owner
        && contract.failure_domain == pin.failure_domain
        && contract.replica_index == pin.replica_index
        && contract.required_replicas == policy.required_replicas
        && contract.retain_from_height == pin.retain_from_height
        && contract.retain_until_height == pin.retain_until_height
        && contract.repair_deadline_height == pin.repair_deadline_height
        && store.contract_commitment(contract)? == pin.contract_commitment)
}

/// Observe exact archives supplied by the local owner, without copying,
/// reconciling, renewing, retiring or paying. Missing stores remain explicit.
/// The expected policy ID must come from the release/storage owner, not a peer.
/// `current_height` is that owner's original checked observation; a historical
/// report must not be reused as a new current service/funding capability.
pub fn observe_release_custody(
    policy: &CellReleaseCustodyPolicyV1,
    expected_policy: CellDigestV1,
    stores: &mut [&mut CellReleaseRetentionStoreV2],
    current_height: u64,
    budget: &mut CellCustodyProbeBudgetV1,
) -> CellResultV1<CellReleaseCustodyReportV1> {
    require(
        Instant::now() < budget.deadline,
        "custody original deadline",
    )?;
    require(policy.id()? == expected_policy, "custody policy pin")?;
    require(
        stores.len() <= MAX_CELL_CUSTODY_REPLICAS_V1,
        "custody store budget",
    )?;
    let expected_stores: BTreeSet<_> = policy.replicas.iter().map(|pin| pin.store_id).collect();
    let mut supplied = BTreeSet::new();
    for store in stores.iter() {
        require(
            expected_stores.contains(&store.store_id()) && supplied.insert(store.store_id()),
            "custody unexpected or duplicate store",
        )?;
    }
    let bytes = policy.payload_bytes()?;
    let usage_before = budget.usage();
    let mut replicas = Vec::with_capacity(policy.replicas.len());
    let mut complete_replicas_observed = 0_u16;
    for pin in &policy.replicas {
        let state = if current_height < pin.retain_from_height {
            CellCustodyReplicaStateV1::NotStarted
        } else if current_height >= pin.retain_until_height {
            CellCustodyReplicaStateV1::Expired
        } else if let Some(store) = stores
            .iter_mut()
            .find(|store| store.store_id() == pin.store_id)
        {
            if let Err(error) = budget.reserve(bytes) {
                CellCustodyReplicaStateV1::ProbeRefused(error.to_string())
            } else {
                match observe_replica(policy, pin, store, budget.deadline) {
                    Ok(true) => {
                        complete_replicas_observed += 1;
                        CellCustodyReplicaStateV1::Observed
                    }
                    Ok(false) => CellCustodyReplicaStateV1::ContractMismatch,
                    Err(error) => CellCustodyReplicaStateV1::ReadbackRefused(error.to_string()),
                }
            }
        } else {
            CellCustodyReplicaStateV1::StoreUnavailable
        };
        replicas.push(CellCustodyReplicaObservationV1 {
            pin: pin.clone(),
            state,
        });
    }
    Ok(CellReleaseCustodyReportV1 {
        policy: expected_policy,
        release_root: policy.root.id(),
        observed_height: current_height,
        payload_bytes_per_complete_replica: bytes,
        required_replicas: policy.required_replicas,
        complete_replicas_observed,
        finished_before_deadline: Instant::now() < budget.deadline,
        usage_before,
        usage_after: budget.usage(),
        replicas,
        renewal_lead_blocks: policy.renewal_lead_blocks,
    })
}

fn observe_replica(
    policy: &CellReleaseCustodyPolicyV1,
    pin: &CellCustodyReplicaPinV1,
    store: &mut CellReleaseRetentionStoreV2,
    deadline: Instant,
) -> CellResultV1<bool> {
    let contract = store.contract(pin.operation, deadline)?;
    if !matches_contract(policy, pin, store, &contract)? {
        return Ok(false);
    }
    let actual = store.verify_release(pin.operation, deadline)?;
    Ok(actual.acknowledged
        && !actual.retired
        && actual.operation == pin.operation
        && actual.release_root == policy.root.id()
        && actual.contract_commitment == pin.contract_commitment
        && actual.objects.len() == contract.objects.len()
        && actual
            .objects
            .iter()
            .zip(&contract.objects)
            .all(|(readback, object)| {
                readback.store_id == pin.store_id
                    && readback.operation == object.operation
                    && readback.funding_operation == object.funding_operation
                    && readback.manifest == object.manifest.id()
                    && readback.payload_bytes == object.manifest.size()
                    && readback.retain_from_height <= pin.retain_from_height
                    && readback.retain_until_height >= pin.retain_until_height
                    && readback.acknowledged
                    && !readback.retired
            }))
}

/// The independently retained policy pin accompanies its full declared roster.
#[derive(Clone, Copy, Debug)]
pub struct CellCustodyPolicyPinV1<'a> {
    pub policy: &'a CellReleaseCustodyPolicyV1,
    pub expected: CellDigestV1,
}

/// Complete TCV1 coverage counts only the intersection of model and environment
/// observations on the same exact target and declared control/failure domain.
/// The two component failures and aggregate original reservation stay visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionCustodyReportV1 {
    version: CellVersionCommitmentV1,
    model_policy: CellDigestV1,
    environment_policy: CellDigestV1,
    observed_height: u64,
    required_replicas: u16,
    complete_replica_slots: Vec<u16>,
    payload_bytes_per_complete_replica: u64,
    finished_before_deadline: bool,
    usage_before: CellCustodyProbeUsageV1,
    usage_after: CellCustodyProbeUsageV1,
    model: Result<CellReleaseCustodyReportV1, String>,
    environment: Result<CellReleaseCustodyReportV1, String>,
}

impl CellVersionCustodyReportV1 {
    pub fn version(&self) -> CellVersionCommitmentV1 {
        self.version
    }

    pub fn model_policy(&self) -> CellDigestV1 {
        self.model_policy
    }

    pub fn environment_policy(&self) -> CellDigestV1 {
        self.environment_policy
    }

    pub fn observed_height(&self) -> u64 {
        self.observed_height
    }

    pub fn required_replicas(&self) -> u16 {
        self.required_replicas
    }

    pub fn complete_replica_slots(&self) -> &[u16] {
        &self.complete_replica_slots
    }

    pub fn complete_replicas_observed(&self) -> u16 {
        self.complete_replica_slots.len() as u16
    }

    pub fn payload_bytes_per_complete_replica(&self) -> u64 {
        self.payload_bytes_per_complete_replica
    }

    pub fn finished_before_deadline(&self) -> bool {
        self.finished_before_deadline
    }

    pub fn usage_before(&self) -> CellCustodyProbeUsageV1 {
        self.usage_before
    }

    pub fn usage_after(&self) -> CellCustodyProbeUsageV1 {
        self.usage_after
    }

    pub fn model(&self) -> Result<&CellReleaseCustodyReportV1, &str> {
        self.model.as_ref().map_err(String::as_str)
    }

    pub fn environment(&self) -> Result<&CellReleaseCustodyReportV1, &str> {
        self.environment.as_ref().map_err(String::as_str)
    }

    /// Historical byte observations only, never independent custody, native
    /// funding, future service or execution authorization.
    pub fn complete_byte_coverage_observed(&self) -> bool {
        self.finished_before_deadline && self.complete_replicas_observed() == self.required_replicas
    }
}

/// Observe all declared model and environment bytes under the same original
/// budget. A model-only report cannot satisfy TCV1. Both policies need their own
/// independent owner pins; neither is learned from the byte-content manifest.
/// Runtime refusals of either component remain in the report and retain all
/// debits. Preflight pin, root and topology defects refuse before any probe.
pub fn observe_version_custody(
    version: &CellVersionManifestV1,
    expected_version: CellVersionCommitmentV1,
    model: CellCustodyPolicyPinV1<'_>,
    environment: CellCustodyPolicyPinV1<'_>,
    stores: &mut [&mut CellReleaseRetentionStoreV2],
    current_height: u64,
    budget: &mut CellCustodyProbeBudgetV1,
) -> CellResultV1<CellVersionCustodyReportV1> {
    require(
        Instant::now() < budget.deadline,
        "custody original deadline",
    )?;
    version.validate()?;
    require(
        version.commitment() == expected_version,
        "custody complete version pin",
    )?;
    require(
        model.policy.id()? == model.expected && environment.policy.id()? == environment.expected,
        "custody policy pin",
    )?;
    let environment_root = CellModelReleaseRootV1::new(version.environment().clone(), vec![])?;
    require(
        &model.policy.root == version.model() && environment.policy.root == environment_root,
        "custody complete version roots",
    )?;
    require(
        model.policy.required_replicas == environment.policy.required_replicas
            && model
                .policy
                .replicas
                .iter()
                .zip(&environment.policy.replicas)
                .all(|(left, right)| {
                    left.store_id == right.store_id
                        && left.replica_index == right.replica_index
                        && left.responsible_owner == right.responsible_owner
                        && left.administrator == right.administrator
                        && left.failure_domain == right.failure_domain
                        && left.domain_evidence == right.domain_evidence
                }),
        "custody complete version topology",
    )?;
    let payload_bytes_per_complete_replica =
        version
            .manifests()
            .iter()
            .try_fold(0_u64, |sum, manifest| {
                sum.checked_add(manifest.size())
                    .ok_or(CellErrorV1::Invalid("custody payload overflow"))
            })?;
    let usage_before = budget.usage();
    let observed_model =
        observe_release_custody(model.policy, model.expected, stores, current_height, budget)
            .map_err(|error| error.to_string());
    // No cloned budget or refreshed deadline between the original owners.
    let observed_environment = observe_release_custody(
        environment.policy,
        environment.expected,
        stores,
        current_height,
        budget,
    )
    .map_err(|error| error.to_string());
    let complete_replica_slots = match (&observed_model, &observed_environment) {
        (Ok(left), Ok(right))
            if left.finished_before_deadline && right.finished_before_deadline =>
        {
            left.replicas
                .iter()
                .zip(&right.replicas)
                .filter_map(|(model, environment)| {
                    (model.state == CellCustodyReplicaStateV1::Observed
                        && environment.state == CellCustodyReplicaStateV1::Observed)
                        .then_some(model.pin.replica_index)
                })
                .collect()
        }
        _ => Vec::new(),
    };
    Ok(CellVersionCustodyReportV1 {
        version: expected_version,
        model_policy: model.expected,
        environment_policy: environment.expected,
        observed_height: current_height,
        required_replicas: model.policy.required_replicas,
        complete_replica_slots,
        payload_bytes_per_complete_replica,
        finished_before_deadline: Instant::now() < budget.deadline,
        usage_before,
        usage_after: budget.usage(),
        model: observed_model,
        environment: observed_environment,
    })
}

/// Owner-supplied contactability, deliberately separate from funding or payment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellCustodySponsorStateV1 {
    Unobserved,
    Contactable,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellCustodySponsorObservationV1 {
    pub owner: CellDigestV1,
    pub state: CellCustodySponsorStateV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellCustodyRenewalActionV1 {
    NotDue,
    /// Contactable never means prepaid. A distinct native-funded successor is
    /// required; the immutable old physical term is never extended in place.
    FundingRequired,
    SponsorUnconfirmed,
    ReplacementSponsorRequired,
    /// The original promise ended. This action grants no permission to delete.
    PromiseExpired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellCustodyRecoveryActionV1 {
    None,
    AwaitServiceStart,
    /// Missing/readback-refused is unresolved: reconcile the old effect before
    /// separately funded repair/replacement; never blindly redispatch it.
    ReconcileThenRestore,
    ObservationRequired,
    RepairWindowClosed,
    PromiseExpired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellCustodyContinuationV1 {
    pub store_id: CellDigestV1,
    pub operation: CellDigestV1,
    pub renewal_owner: CellDigestV1,
    pub repair_owner: CellDigestV1,
    pub renewal: CellCustodyRenewalActionV1,
    pub recovery: CellCustodyRecoveryActionV1,
    /// Strictly before this original expiry; polling cannot move it forward.
    pub successor_required_before_height: u64,
    /// Original inclusive dispatch deadline; no sliding repair window.
    pub last_new_repair_height: u64,
    /// Complete bytes for this TMR1 component, not the complete TCV1 union or
    /// the amount of payload that a later repair will actually write.
    pub component_payload_bytes: u64,
}

/// Paired work for the same original target. Both observations retain their
/// exact independent contracts, owners, service terms and refusal reasons.
/// A healthy model component never cancels environment work, or vice versa.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionCustodyReplicaContinuationV1<'a> {
    model_observation: &'a CellCustodyReplicaObservationV1,
    environment_observation: &'a CellCustodyReplicaObservationV1,
    model: CellCustodyContinuationV1,
    environment: CellCustodyContinuationV1,
}

impl CellVersionCustodyReplicaContinuationV1<'_> {
    pub fn store_id(&self) -> CellDigestV1 {
        self.model_observation.pin.store_id
    }

    pub fn replica_index(&self) -> u16 {
        self.model_observation.pin.replica_index
    }

    pub fn model_observation(&self) -> &CellCustodyReplicaObservationV1 {
        self.model_observation
    }

    pub fn environment_observation(&self) -> &CellCustodyReplicaObservationV1 {
        self.environment_observation
    }

    pub fn model(&self) -> &CellCustodyContinuationV1 {
        &self.model
    }

    pub fn environment(&self) -> &CellCustodyContinuationV1 {
        &self.environment
    }
}

/// Bounded TCV1 work derived from both actual component reports. This borrows
/// the original evidence and pins; it does not clone the potentially large
/// version manifest, acquire a new allowance, pay, repair or extend a term.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionCustodyContinuationV1<'a> {
    observation: &'a CellVersionCustodyReportV1,
    replicas: Vec<CellVersionCustodyReplicaContinuationV1<'a>>,
}

impl CellVersionCustodyContinuationV1<'_> {
    pub fn observation(&self) -> &CellVersionCustodyReportV1 {
        self.observation
    }

    pub fn version(&self) -> CellVersionCommitmentV1 {
        self.observation.version
    }

    pub fn model_policy(&self) -> CellDigestV1 {
        self.observation.model_policy
    }

    pub fn environment_policy(&self) -> CellDigestV1 {
        self.observation.environment_policy
    }

    /// Unique declared TCM1 payload bytes in this version. Actual component
    /// probe reservations remain separately visible on the original report.
    pub fn unique_complete_version_payload_bytes(&self) -> u64 {
        self.observation.payload_bytes_per_complete_replica
    }

    pub fn replicas(&self) -> &[CellVersionCustodyReplicaContinuationV1<'_>] {
        &self.replicas
    }
}

impl CellVersionCustodyReportV1 {
    /// Pair the two complete component plans by the already verified target
    /// topology. A missing component report or late complete observation needs
    /// a new admitted observation, not a model-only plan labelled as TCV1.
    /// One sponsor union prevents different states for the same owner; no
    /// contactability state authenticates funds or a funded successor.
    pub fn plan_continuation(
        &self,
        sponsors: &[CellCustodySponsorObservationV1],
    ) -> CellResultV1<CellVersionCustodyContinuationV1<'_>> {
        let model = self
            .model
            .as_ref()
            .map_err(|_| CellErrorV1::Invalid("custody model observation required"))?;
        let environment = self
            .environment
            .as_ref()
            .map_err(|_| CellErrorV1::Invalid("custody environment observation required"))?;
        require(
            self.finished_before_deadline,
            "custody complete version observation required",
        )?;
        require(
            sponsors.len() <= 2 * MAX_CELL_CUSTODY_REPLICAS_V1,
            "custody version sponsor budget",
        )?;
        let model_owners: BTreeSet<_> = model
            .replicas
            .iter()
            .map(|entry| entry.pin.renewal_owner)
            .collect();
        let environment_owners: BTreeSet<_> = environment
            .replicas
            .iter()
            .map(|entry| entry.pin.renewal_owner)
            .collect();
        let mut declared = BTreeSet::new();
        for sponsor in sponsors {
            require(
                (model_owners.contains(&sponsor.owner)
                    || environment_owners.contains(&sponsor.owner))
                    && declared.insert(sponsor.owner),
                "custody unexpected or duplicate sponsor",
            )?;
        }
        let for_component = |owners: &BTreeSet<_>| {
            sponsors
                .iter()
                .filter(|sponsor| owners.contains(&sponsor.owner))
                .copied()
                .collect::<Vec<_>>()
        };
        let model_actions = model.plan_continuation(&for_component(&model_owners))?;
        let environment_actions =
            environment.plan_continuation(&for_component(&environment_owners))?;
        let replicas = model
            .replicas
            .iter()
            .zip(&environment.replicas)
            .zip(model_actions.into_iter().zip(environment_actions))
            .map(
                |((model_observation, environment_observation), (model, environment))| {
                    CellVersionCustodyReplicaContinuationV1 {
                        model_observation,
                        environment_observation,
                        model,
                        environment,
                    }
                },
            )
            .collect();
        Ok(CellVersionCustodyContinuationV1 {
            observation: self,
            replicas,
        })
    }
}

impl CellReleaseCustodyReportV1 {
    /// Finite work items only. No funds are authenticated/claimed, no tariff is
    /// assumed and no external operation runs. Sponsor loss cannot erase duties,
    /// lower the replica requirement, grant an extension or produce a refund.
    pub fn plan_continuation(
        &self,
        sponsors: &[CellCustodySponsorObservationV1],
    ) -> CellResultV1<Vec<CellCustodyContinuationV1>> {
        require(
            sponsors.len() <= MAX_CELL_CUSTODY_REPLICAS_V1,
            "custody sponsor budget",
        )?;
        let expected: BTreeSet<_> = self
            .replicas
            .iter()
            .map(|entry| entry.pin.renewal_owner)
            .collect();
        let mut declared = BTreeMap::new();
        for sponsor in sponsors {
            require(
                expected.contains(&sponsor.owner)
                    && declared.insert(sponsor.owner, sponsor.state).is_none(),
                "custody unexpected or duplicate sponsor",
            )?;
        }
        Ok(self
            .replicas
            .iter()
            .map(|entry| {
                let pin = &entry.pin;
                let remaining = pin.retain_until_height.saturating_sub(self.observed_height);
                let renewal = if remaining == 0 {
                    CellCustodyRenewalActionV1::PromiseExpired
                } else if remaining > self.renewal_lead_blocks {
                    CellCustodyRenewalActionV1::NotDue
                } else {
                    match declared
                        .get(&pin.renewal_owner)
                        .copied()
                        .unwrap_or(CellCustodySponsorStateV1::Unobserved)
                    {
                        CellCustodySponsorStateV1::Unobserved => {
                            CellCustodyRenewalActionV1::SponsorUnconfirmed
                        }
                        CellCustodySponsorStateV1::Contactable => {
                            CellCustodyRenewalActionV1::FundingRequired
                        }
                        CellCustodySponsorStateV1::Unavailable => {
                            CellCustodyRenewalActionV1::ReplacementSponsorRequired
                        }
                    }
                };
                let recovery = match &entry.state {
                    CellCustodyReplicaStateV1::Observed if self.finished_before_deadline => {
                        CellCustodyRecoveryActionV1::None
                    }
                    CellCustodyReplicaStateV1::Observed => {
                        CellCustodyRecoveryActionV1::ObservationRequired
                    }
                    CellCustodyReplicaStateV1::NotStarted => {
                        CellCustodyRecoveryActionV1::AwaitServiceStart
                    }
                    CellCustodyReplicaStateV1::Expired => {
                        CellCustodyRecoveryActionV1::PromiseExpired
                    }
                    CellCustodyReplicaStateV1::ProbeRefused(_) => {
                        CellCustodyRecoveryActionV1::ObservationRequired
                    }
                    _ if self.observed_height > pin.repair_deadline_height => {
                        CellCustodyRecoveryActionV1::RepairWindowClosed
                    }
                    _ => CellCustodyRecoveryActionV1::ReconcileThenRestore,
                };
                CellCustodyContinuationV1 {
                    store_id: pin.store_id,
                    operation: pin.operation,
                    renewal_owner: pin.renewal_owner,
                    repair_owner: pin.repair_owner,
                    renewal,
                    recovery,
                    successor_required_before_height: pin.retain_until_height,
                    last_new_repair_height: pin.repair_deadline_height,
                    component_payload_bytes: self.payload_bytes_per_complete_replica,
                }
            })
            .collect())
    }
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;

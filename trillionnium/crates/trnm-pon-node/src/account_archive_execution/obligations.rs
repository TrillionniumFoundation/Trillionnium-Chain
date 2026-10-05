//! Complete account-access discovery and bounded proof inputs for the explicit
//! complete-State research relation. Discovery executes the ordinary serial M06
//! relation, including both continuity scans and the mandatory prologue; it does
//! not maintain a second hand-written list of eligible obligations. Its output
//! remains untrusted witness material and must be checked again by execution.
use super::{check_parent_source, BlockInput, CheckedExecutionError, Result, ACCESS_REFUSED};
use crate::account_archive_prototype::{
    Account, AccountArchive, ArchiveError, CheckedAccounts, Checkpoint, Context, Witness,
    MAX_VIEW_ACCOUNTS, MAX_WITNESS_BYTES, WITNESS_SIBLINGS,
};
use crate::Settings;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, ExecutionError, ExecutionProgress, State},
};
use trnm_protocol::pon_wire::Hash;

pub const SCHEMA: &str = "pon-execution-account-witness-discovery-v1";
pub const MAX_EXECUTION_TRANSACTIONS: usize = 256;
pub const MAX_EXECUTION_ACCOUNTS: usize =
    continuity_v1::MAX_KEYS + 2 * MAX_EXECUTION_TRANSACTIONS + 1;

/// A research input bound, not a new consensus limit. Every original mandatory
/// or continuity recipient comes from one parent row. The current M06 relation
/// accesses at most two distinct account identities per transaction: tag 1 uses
/// sender/recipient and tag 5 uses sender/task provider; all other retained tags
/// only use sender (including release allocation 8 and claim 9). Newly created
/// obligation owners are these senders, and the new reward introduces one miner.
/// Consequently |parent keys| + 2 |transactions| + 1 covers every legal access,
/// including original absent recipients no longer needed by the final state.
/// The installed limits are checked explicitly; a future relation adding account
/// access or larger limits must revise this research contract, never silently cap
/// a new protocol's valid blocks. No witness or ancestor count can enlarge it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct WitnessBudget {
    pub parent_keys: usize,
    pub transactions: usize,
    pub maximum_accounts: usize,
    pub maximum_encoded_bytes: usize,
}
impl WitnessBudget {
    fn from_counts(parent_keys: usize, transactions: usize) -> Result<Self> {
        if parent_keys > continuity_v1::MAX_KEYS || transactions > MAX_EXECUTION_TRANSACTIONS {
            return Err(CheckedExecutionError::Budget);
        }
        let maximum_accounts = transactions
            .checked_mul(2)
            .and_then(|count| count.checked_add(parent_keys))
            .and_then(|count| count.checked_add(1))
            .ok_or(CheckedExecutionError::Budget)?;
        let maximum_encoded_bytes = maximum_accounts
            .checked_mul(MAX_WITNESS_BYTES)
            .ok_or(CheckedExecutionError::Budget)?;
        Ok(Self {
            parent_keys,
            transactions,
            maximum_accounts,
            maximum_encoded_bytes,
        })
    }

    pub fn for_block(settings: &Settings, parent_keys: usize, transactions: usize) -> Result<Self> {
        if settings.app.params["max_state_keys"].as_u64() != Some(continuity_v1::MAX_KEYS as u64)
            || settings.app.params["max_transactions"].as_u64()
                != Some(MAX_EXECUTION_TRANSACTIONS as u64)
        {
            return Err(CheckedExecutionError::Relation("CONFIG"));
        }
        Self::from_counts(parent_keys, transactions)
    }

    /// Inspect borrowed input dimensions before any witness copying or hashing.
    /// JSON decode allocations belong to the caller; this API accepts references
    /// and never allocates an encoding merely to check its maximum byte length.
    pub(super) fn check(&self, witnesses: &[Witness]) -> Result<usize> {
        if witnesses.len() > self.maximum_accounts {
            return Err(CheckedExecutionError::Budget);
        }
        let mut bytes = 0usize;
        for witness in witnesses {
            if witness.siblings.len() != WITNESS_SIBLINGS {
                return Err(ArchiveError::InvalidWitness.into());
            }
            let length = MAX_WITNESS_BYTES - if witness.account.is_none() { 16 } else { 0 };
            bytes = bytes
                .checked_add(length)
                .ok_or(CheckedExecutionError::Budget)?;
        }
        if bytes > self.maximum_encoded_bytes {
            return Err(CheckedExecutionError::Budget);
        }
        Ok(bytes)
    }
}

/// Larger *execution* queries use the original bounded query verifier in small
/// slices; its public 32-account contract and all original witnesses stay intact.
/// Only account values and owner identities are retained, not copied proof paths.
pub(super) struct ExecutionAccounts {
    accounts: BTreeMap<Hash, Option<Account>>,
}
impl ExecutionAccounts {
    pub(super) fn verify(
        context: Context,
        checkpoint: &Checkpoint,
        witnesses: &[Witness],
        progress: &impl Fn() -> Result<()>,
    ) -> Result<Self> {
        if witnesses.len() > MAX_EXECUTION_ACCOUNTS {
            return Err(CheckedExecutionError::Budget);
        }
        let map_error = |error| match error {
            ArchiveError::Context => CheckedExecutionError::Context,
            error => CheckedExecutionError::Archive(error),
        };
        // Empty inputs still check context, as the original verifier does.
        CheckedAccounts::verify(context, checkpoint, &[], &[]).map_err(map_error)?;
        let mut accounts = BTreeMap::new();
        for batch in witnesses.chunks(MAX_VIEW_ACCOUNTS) {
            progress()?;
            let requested: Vec<_> = batch.iter().map(|witness| witness.owner).collect();
            let verified = CheckedAccounts::verify(context, checkpoint, &requested, batch)
                .map_err(map_error)?;
            for owner in requested {
                if accounts.insert(owner, verified.account(owner)?).is_some() {
                    return Err(ArchiveError::InvalidWitness.into());
                }
            }
        }
        Ok(Self { accounts })
    }

    pub(super) fn account(
        &self,
        owner: Hash,
    ) -> std::result::Result<Option<Account>, ArchiveError> {
        self.accounts
            .get(&owner)
            .copied()
            .ok_or(ArchiveError::MissingWitness)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessDiscoveryProgress {
    BeforeBinding,
    Execution(ExecutionProgress),
    AccountAccess { owner: Hash },
    Witness { index: usize },
    BeforeOutput,
}

/// Observations of actual access gates, not signed obligations or admission.
/// Mandatory includes the parent's continuity reservation scan; successor
/// includes all still-reserved recipients and the new miner reward recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WitnessDiscoveryObservation {
    pub schema: &'static str,
    pub parent_checkpoint: Hash,
    pub parent_id: Hash,
    pub height: u64,
    pub successor_state_root: Hash,
    pub budget: WitnessBudget,
    pub mandatory_owners: Vec<Hash>,
    pub transaction_owners: Vec<Hash>,
    pub successor_owners: Vec<Hash>,
    pub requested_owners: Vec<Hash>,
    pub encoded_witness_bytes: usize,
    pub complete_native_execution: bool,
    pub recheck_required: bool,
    pub consensus_admission: bool,
    pub archive_mutated: bool,
}

#[derive(Debug)]
pub struct PreparedAccountWitnesses {
    pub accounts: Vec<Witness>,
    pub observation: WitnessDiscoveryObservation,
}

#[derive(Default)]
enum Phase {
    #[default]
    Mandatory,
    Transactions,
    Successor,
}
#[derive(Default)]
struct Discovery {
    phase: Phase,
    owners: BTreeSet<Hash>,
    mandatory: BTreeSet<Hash>,
    transactions: BTreeSet<Hash>,
    successor: BTreeSet<Hash>,
    failure: Option<CheckedExecutionError>,
}

pub fn prepare(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
) -> Result<PreparedAccountWitnesses> {
    prepare_with_progress(
        settings,
        archive,
        parent_checkpoint,
        parent_state,
        block,
        &|_| Ok(()),
    )
}

/// Explicit extra execution for witness planning. This does not execute through
/// a missing-proof fallback: checked execution remains a separate mandatory
/// caller step, rechecks exact original proofs and rejects omissions and extras.
pub fn prepare_with_progress(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    progress: &(impl Fn(WitnessDiscoveryProgress) -> Result<()> + Sync),
) -> Result<PreparedAccountWitnesses> {
    let budget = WitnessBudget::for_block(settings, parent_state.len(), block.transactions.len())?;
    progress(WitnessDiscoveryProgress::BeforeBinding)?;
    let (checkpoint, _) = check_parent_source(settings, archive, parent_checkpoint, parent_state)?;
    if checkpoint.branch() != block.parent_id {
        return Err(CheckedExecutionError::Parent);
    }
    if checkpoint.height().checked_add(1) != Some(block.height) {
        return Err(CheckedExecutionError::Height);
    }
    let discovery = Mutex::new(Discovery::default());
    let gate = |who: &str| -> pon_executor::Result<()> {
        let record = || -> Result<()> {
            let mut owner = [0; 32];
            if who.len() != 64
                || !who
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || hex::decode_to_slice(who, &mut owner).is_err()
            {
                return Err(CheckedExecutionError::AccountSource);
            }
            progress(WitnessDiscoveryProgress::AccountAccess { owner })?;
            let mut found = discovery
                .lock()
                .map_err(|_| CheckedExecutionError::Observation)?;
            if !found.owners.contains(&owner) && found.owners.len() >= budget.maximum_accounts {
                return Err(CheckedExecutionError::Budget);
            }
            found.owners.insert(owner);
            match found.phase {
                Phase::Mandatory => found.mandatory.insert(owner),
                Phase::Transactions => found.transactions.insert(owner),
                Phase::Successor => found.successor.insert(owner),
            };
            Ok(())
        };
        record().map_err(|error| {
            if let Ok(mut found) = discovery.lock() {
                found.failure = Some(error);
            }
            ACCESS_REFUSED
        })
    };
    let output = pon_executor::execute_with_account_point_access(
        parent_state,
        pon_executor::BlockExecution {
            transactions: block.transactions,
            height: block.height,
            miner: block.miner,
            parent_id: block.parent_id,
            workers: 1,
        },
        &settings.app,
        &gate,
        &|point| {
            progress(WitnessDiscoveryProgress::Execution(point))?;
            let mut found = discovery
                .lock()
                .map_err(|_| CheckedExecutionError::Observation)?;
            if point == ExecutionProgress::AfterMandatory {
                found.phase = Phase::Transactions;
            } else if point == ExecutionProgress::BeforeReward {
                found.phase = Phase::Successor;
            }
            Ok(())
        },
    );
    let found = discovery
        .into_inner()
        .map_err(|_| CheckedExecutionError::Observation)?;
    let output = match output {
        Ok(output) if found.failure.is_none() => output,
        Ok(_) => return Err(CheckedExecutionError::Observation),
        Err(ExecutionError::Relation(ACCESS_REFUSED)) => {
            return Err(found.failure.unwrap_or(CheckedExecutionError::Observation));
        }
        Err(ExecutionError::Relation(error)) => return Err(CheckedExecutionError::Relation(error)),
        Err(ExecutionError::Cancelled(error)) => return Err(error),
    };
    let mut accounts = Vec::with_capacity(found.owners.len());
    for (index, &owner) in found.owners.iter().enumerate() {
        progress(WitnessDiscoveryProgress::Witness { index })?;
        accounts.push(archive.witness(parent_checkpoint, owner)?.0);
    }
    let encoded_witness_bytes = budget.check(&accounts)?;
    progress(WitnessDiscoveryProgress::BeforeOutput)?;
    Ok(PreparedAccountWitnesses {
        accounts,
        observation: WitnessDiscoveryObservation {
            schema: SCHEMA,
            parent_checkpoint,
            parent_id: block.parent_id,
            height: block.height,
            successor_state_root: output.root,
            budget,
            mandatory_owners: found.mandatory.into_iter().collect(),
            transaction_owners: found.transactions.into_iter().collect(),
            successor_owners: found.successor.into_iter().collect(),
            requested_owners: found.owners.into_iter().collect(),
            encoded_witness_bytes,
            complete_native_execution: true,
            recheck_required: true,
            consensus_admission: false,
            archive_mutated: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_maximum_and_overflow_counts_have_finite_witness_budgets() {
        let settings = Settings::development(Some(1)).unwrap();
        let bound = WitnessBudget::for_block(&settings, 65_536, 256).unwrap();
        assert_eq!(bound.maximum_accounts, 66_049);
        assert_eq!(bound.maximum_encoded_bytes, 66_049 * MAX_WITNESS_BYTES);
        for (keys, transactions) in [(65_537, 0), (0, 257), (usize::MAX, 0), (0, usize::MAX)] {
            assert_eq!(
                WitnessBudget::for_block(&settings, keys, transactions),
                Err(CheckedExecutionError::Budget)
            );
        }
        // The aggregate limit rejects before inspecting malformed per-proof
        // vectors; no 256-sibling allocation or hash work is needed for rejection.
        let malformed = Witness {
            checkpoint: [0; 32],
            owner: [0; 32],
            account: None,
            siblings: vec![],
        };
        let tiny = WitnessBudget::for_block(&settings, 0, 0).unwrap();
        assert_eq!(
            tiny.check(&[malformed.clone(), malformed.clone()]),
            Err(CheckedExecutionError::Budget)
        );
        assert_eq!(
            tiny.check(&[malformed]),
            Err(ArchiveError::InvalidWitness.into())
        );
    }
}

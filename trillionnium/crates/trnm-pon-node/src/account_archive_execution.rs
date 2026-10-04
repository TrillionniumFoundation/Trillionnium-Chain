//! Explicit research execution over a complete, root-bound native parent State.
//!
//! Every semantic account point access is gated by an original-parent archive
//! witness, including recipients consulted by the selected continuity rules.
//! The current ordered
//! account value still comes from complete State and transaction-local writes.
//! Funds, non-account scans, capacity totals and full roots remain complete-State
//! operations. This is not a partial-State backend, a new consensus profile, an
//! archive publication operation, or a Node proof/admission capability.
use crate::account_archive_prototype::{
    account_root, accounts, AccountArchive, ArchiveError, CheckedAccounts, Context, Witness,
    MAX_VIEW_ACCOUNTS,
};
use crate::Settings;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Mutex;
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, ExecutionError, ExecutionProgress, State},
};
use trnm_protocol::pon_wire::Hash;

pub const SCHEMA: &str = "pon-checked-account-execution-v1";
const ACCESS_REFUSED: &str = "CHECKED_ACCOUNT_ACCESS";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckedExecutionError {
    Context,
    Parent,
    Height,
    SourceRoot,
    AccountSource,
    MissingWitness { owner: Hash },
    WitnessSource { owner: Hash },
    UnusedWitness { owners: Vec<Hash> },
    UncheckedWrite { owner: Hash },
    InvalidTransition,
    Budget,
    Observation,
    Cancelled,
    Archive(ArchiveError),
    Relation(&'static str),
}
impl std::fmt::Display for CheckedExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CheckedExecutionError {}
impl From<ArchiveError> for CheckedExecutionError {
    fn from(error: ArchiveError) -> Self {
        Self::Archive(error)
    }
}
pub type Result<T> = std::result::Result<T, CheckedExecutionError>;

/// Exact computation inputs. Execution is serial and has no caller-supplied
/// Config, worker override, proof authority or archive activation request.
#[derive(Clone, Copy)]
pub struct BlockInput<'a> {
    pub transactions: &'a [Vec<u8>],
    pub height: u64,
    pub miner: Hash,
    pub parent_id: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapacityObservation {
    pub actual_keys: usize,
    pub credit_account_reserve: usize,
    pub archive_reserve: usize,
    pub reward_queue_reserve: usize,
    pub required_keys: usize,
}
impl From<continuity_v1::Capacity> for CapacityObservation {
    fn from(value: continuity_v1::Capacity) -> Self {
        Self {
            actual_keys: value.actual_keys,
            credit_account_reserve: value.credit_account_reserve,
            archive_reserve: value.archive_reserve,
            reward_queue_reserve: value.reward_queue_reserve,
            required_keys: value.required_keys,
        }
    }
}

/// Observation only. Deserialization is deliberately not an authority constructor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutionObservation {
    pub schema: &'static str,
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
    pub parent_checkpoint: Hash,
    pub parent_id: Hash,
    pub height: u64,
    pub parent_state_root: Hash,
    pub successor_state_root: Hash,
    pub parent_account_root: Hash,
    pub successor_account_root: Hash,
    pub parent_account_count: u64,
    pub successor_account_count: u64,
    pub requested_owners: Vec<Hash>,
    pub used_owners: Vec<Hash>,
    pub parent_capacity: Option<CapacityObservation>,
    pub successor_capacity: Option<CapacityObservation>,
    pub workers: usize,
    pub complete_state_required: bool,
    pub aggregate_account_scans_are_full: bool,
    pub consensus_admission: bool,
    pub archive_mutated: bool,
}

#[derive(Debug)]
pub struct CheckedExecutionOutput {
    pub output: pon_executor::Output,
    pub observation: ExecutionObservation,
}

#[derive(Default)]
struct AccessObservation {
    used: BTreeSet<Hash>,
    failure: Option<CheckedExecutionError>,
}

fn capacity(
    state: &State,
    height: u64,
    settings: &Settings,
) -> Result<Option<CapacityObservation>> {
    if continuity_v1::enabled(&settings.app) {
        Ok(Some(
            continuity_v1::capacity(state, height, &settings.app)
                .map_err(CheckedExecutionError::Relation)?
                .into(),
        ))
    } else {
        Ok(None)
    }
}

pub fn execute(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    witnesses: &[Witness],
) -> Result<CheckedExecutionOutput> {
    execute_with_progress(
        settings,
        archive,
        parent_checkpoint,
        parent_state,
        block,
        witnesses,
        &|_| Ok(()),
    )
}

/// Check exact source and all supplied parent proofs before executing the real
/// ordered M06 relation. Missing and unused proofs never fall back to full-State
/// access. The complete parent itself remains immutable on every return.
pub fn execute_with_progress(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    witnesses: &[Witness],
    progress: &(impl Fn(ExecutionProgress) -> Result<()> + Sync),
) -> Result<CheckedExecutionOutput> {
    if witnesses.len() > MAX_VIEW_ACCOUNTS {
        return Err(CheckedExecutionError::Budget);
    }
    progress(ExecutionProgress::BeforeParentBinding)?;
    let checkpoint = archive.checkpoint(parent_checkpoint)?;
    let context = Context {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    };
    if checkpoint.branch() != block.parent_id {
        return Err(CheckedExecutionError::Parent);
    }
    if checkpoint.height().checked_add(1) != Some(block.height) {
        return Err(CheckedExecutionError::Height);
    }
    let parent_state_root =
        pon_executor::root(parent_state).map_err(CheckedExecutionError::Relation)?;
    if checkpoint.source_state_root() != Some(parent_state_root) {
        return Err(CheckedExecutionError::SourceRoot);
    }
    let parent_accounts = accounts(parent_state)?;
    if checkpoint.account_count() != parent_accounts.len() as u64
        || checkpoint.account_root() != account_root(&parent_accounts)?
    {
        return Err(CheckedExecutionError::AccountSource);
    }
    let mut requested: Vec<_> = witnesses.iter().map(|witness| witness.owner).collect();
    requested.sort_unstable();
    let checked =
        CheckedAccounts::verify(context, &checkpoint, &requested, witnesses).map_err(|error| {
            match error {
                ArchiveError::Context => CheckedExecutionError::Context,
                error => CheckedExecutionError::Archive(error),
            }
        })?;
    // Compare only with ORIGINAL parent values. Mandatory credits and earlier
    // transactions may legitimately change the current ordered value afterward.
    for &owner in &requested {
        if checked.account(owner)? != parent_accounts.get(&owner).copied() {
            return Err(CheckedExecutionError::WitnessSource { owner });
        }
    }
    let accesses = Mutex::new(AccessObservation::default());
    let executed = {
        let gate = |who: &str| -> pon_executor::Result<()> {
            let mut owner = [0; 32];
            if who.len() != 64
                || !who
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || hex::decode_to_slice(who, &mut owner).is_err()
            {
                let mut observed = accesses.lock().map_err(|_| ACCESS_REFUSED)?;
                observed.failure = Some(CheckedExecutionError::AccountSource);
                return Err(ACCESS_REFUSED);
            }
            let mut observed = accesses.lock().map_err(|_| ACCESS_REFUSED)?;
            match checked.account(owner) {
                Ok(_) => {
                    observed.used.insert(owner);
                    Ok(())
                }
                Err(ArchiveError::MissingWitness) => {
                    observed.failure = Some(CheckedExecutionError::MissingWitness { owner });
                    Err(ACCESS_REFUSED)
                }
                Err(error) => {
                    observed.failure = Some(CheckedExecutionError::Archive(error));
                    Err(ACCESS_REFUSED)
                }
            }
        };
        pon_executor::execute_with_account_point_access(
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
            progress,
        )
    };
    let accesses = accesses
        .into_inner()
        .map_err(|_| CheckedExecutionError::Observation)?;
    let output = match executed {
        Ok(output) => {
            if accesses.failure.is_some() {
                return Err(CheckedExecutionError::Observation);
            }
            output
        }
        Err(ExecutionError::Relation(ACCESS_REFUSED)) => {
            return Err(accesses
                .failure
                .unwrap_or(CheckedExecutionError::Observation));
        }
        Err(ExecutionError::Relation(error)) => {
            return Err(CheckedExecutionError::Relation(error));
        }
        Err(ExecutionError::Cancelled(error)) => return Err(error),
    };
    let unused: Vec<_> = requested
        .iter()
        .copied()
        .filter(|owner| !accesses.used.contains(owner))
        .collect();
    if !unused.is_empty() {
        return Err(CheckedExecutionError::UnusedWitness { owners: unused });
    }
    let successor_accounts = accounts(&output.state)?;
    for (owner, before) in &parent_accounts {
        if successor_accounts
            .get(owner)
            .is_none_or(|after| after.nonce < before.nonce)
        {
            return Err(CheckedExecutionError::InvalidTransition);
        }
    }
    for (owner, after) in &successor_accounts {
        if parent_accounts.get(owner) != Some(after) && !accesses.used.contains(owner) {
            return Err(CheckedExecutionError::UncheckedWrite { owner: *owner });
        }
    }
    let observation = ExecutionObservation {
        schema: SCHEMA,
        network: context.network,
        parameters: context.parameters,
        genesis: context.genesis,
        parent_checkpoint,
        parent_id: block.parent_id,
        height: block.height,
        parent_state_root,
        successor_state_root: output.root,
        parent_account_root: checkpoint.account_root(),
        successor_account_root: account_root(&successor_accounts)?,
        parent_account_count: checkpoint.account_count(),
        successor_account_count: successor_accounts.len() as u64,
        requested_owners: requested,
        used_owners: accesses.used.into_iter().collect(),
        parent_capacity: capacity(parent_state, checkpoint.height(), settings)?,
        successor_capacity: capacity(&output.state, block.height, settings)?,
        workers: 1,
        complete_state_required: true,
        aggregate_account_scans_are_full: true,
        consensus_admission: false,
        archive_mutated: false,
    };
    Ok(CheckedExecutionOutput {
        output,
        observation,
    })
}

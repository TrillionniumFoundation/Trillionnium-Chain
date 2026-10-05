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
    account_root, accounts,
    multiproof::{CheckedMultiproof, Multiproof, MultiproofObservation},
    Account, AccountArchive, ArchiveError, CheckedAccounts, Checkpoint, Context, Witness,
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

pub mod obligations;
pub mod state_witness;
use obligations::{ExecutionAccounts, WitnessBudget};
use state_witness::{
    BoundState, StateExecutionObservation, StatePhase, StateTransition, StateWitness,
    StateWitnessError, StateWitnessProgress,
};

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
    StateWitness(StateWitnessError),
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

/// Explicit research inputs; neither serialized claim is a parent authority.
#[derive(Clone, Copy)]
pub struct StateExecutionInput<'a> {
    pub accounts: &'a [Witness],
    pub state: &'a StateWitness,
}
#[derive(Debug)]
pub struct StateWitnessExecutionOutput {
    pub execution: CheckedExecutionOutput,
    pub state_observation: StateExecutionObservation,
}
#[derive(Clone, Copy)]
pub struct CompactStateExecutionInput<'a> {
    pub accounts: &'a Multiproof,
    pub state: &'a StateWitness,
}
#[derive(Debug)]
pub struct CompactStateWitnessExecutionOutput {
    pub execution: StateWitnessExecutionOutput,
    pub account_proof: MultiproofObservation,
}
struct StateControl<'a> {
    witness: &'a StateWitness,
    progress: &'a (dyn Fn(StateWitnessProgress) -> Result<()> + Sync),
}
struct ExecutionEvidence<'a> {
    accounts: AccountEvidence<'a>,
    state: Option<StateControl<'a>>,
}
struct InternalOutput {
    execution: CheckedExecutionOutput,
    state: Option<StateExecutionObservation>,
    compact: Option<MultiproofObservation>,
}
#[derive(Clone, Copy)]
enum AccountEvidence<'a> {
    Expanded(&'a [Witness]),
    Compact(&'a Multiproof),
}
enum CheckedAccountEvidence<'a> {
    Expanded {
        checked: ExecutionAccounts,
        witnesses: &'a [Witness],
    },
    Compact(CheckedMultiproof),
}
impl CheckedAccountEvidence<'_> {
    fn account(&self, owner: Hash) -> std::result::Result<Option<Account>, ArchiveError> {
        match self {
            Self::Expanded { checked, .. } => checked.account(owner),
            Self::Compact(checked) => checked.account(owner),
        }
    }
    fn transition(
        &self,
        bound: &BoundState<'_>,
        state: &State,
        receipts: &[Vec<u8>],
        phase: StatePhase,
        progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
    ) -> Result<StateTransition> {
        match self {
            Self::Expanded { witnesses, .. } => {
                bound.transition(state, witnesses, receipts, phase, progress)
            }
            Self::Compact(checked) => {
                bound.transition_compact(state, checked, receipts, phase, progress)
            }
        }
    }
}

#[derive(Default)]
struct AccessObservation {
    used: BTreeSet<Hash>,
    failure: Option<CheckedExecutionError>,
    mandatory: Option<StateTransition>,
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
    Ok(execute_inner(
        settings,
        archive,
        parent_checkpoint,
        parent_state,
        block,
        ExecutionEvidence {
            accounts: AccountEvidence::Expanded(witnesses),
            state: None,
        },
        progress,
    )?
    .execution)
}

/// Construct input claims from one checked complete native parent. The returned
/// serializable value is deliberately rechecked on every execution; it is not an
/// admission capability or a way to promote caller-selected aggregate totals.
pub fn prepare_state_witness(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
) -> Result<StateWitness> {
    let (checkpoint, parent_accounts) =
        check_parent_source(settings, archive, parent_checkpoint, parent_state)?;
    state_witness::prepare(settings, &checkpoint, parent_state, &parent_accounts)
}

fn check_parent_source(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
) -> Result<(Checkpoint, BTreeMap<Hash, Account>)> {
    let checkpoint = archive.checkpoint(parent_checkpoint)?;
    let context = Context {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    };
    CheckedAccounts::verify(context, &checkpoint, &[], &[])?;
    if checkpoint.source_state_root()
        != Some(pon_executor::root(parent_state).map_err(CheckedExecutionError::Relation)?)
    {
        return Err(CheckedExecutionError::SourceRoot);
    }
    let parent_accounts = accounts(parent_state)?;
    if checkpoint.account_count() != parent_accounts.len() as u64
        || checkpoint.account_root() != account_root(&parent_accounts)?
    {
        return Err(CheckedExecutionError::AccountSource);
    }
    Ok((checkpoint, parent_accounts))
}

pub fn execute_with_state_witness(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    input: StateExecutionInput<'_>,
) -> Result<StateWitnessExecutionOutput> {
    execute_with_state_witness_and_progress(
        settings,
        archive,
        parent_checkpoint,
        parent_state,
        block,
        input,
        &|_| Ok(()),
    )
}

pub fn execute_with_state_witness_and_progress(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    input: StateExecutionInput<'_>,
    progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync),
) -> Result<StateWitnessExecutionOutput> {
    progress(StateWitnessProgress::BeforeBinding)?;
    let result = execute_inner(
        settings,
        archive,
        parent_checkpoint,
        parent_state,
        block,
        ExecutionEvidence {
            accounts: AccountEvidence::Expanded(input.accounts),
            state: Some(StateControl {
                witness: input.state,
                progress,
            }),
        },
        &|point| progress(StateWitnessProgress::Execution(point)),
    )?;
    Ok(StateWitnessExecutionOutput {
        execution: result.execution,
        state_observation: result.state.ok_or(StateWitnessError::Observation)?,
    })
}

pub fn execute_with_compact_state_witness(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    input: CompactStateExecutionInput<'_>,
) -> Result<CompactStateWitnessExecutionOutput> {
    execute_with_compact_state_witness_and_progress(
        settings,
        archive,
        parent_checkpoint,
        parent_state,
        block,
        input,
        &|_| Ok(()),
    )
}

/// Actual complete M06 execution using AAM1 for the semantic account gate and
/// both mandatory/final proof-derived roots. The immutable parent is still the
/// independent full-State reference. No expanded AAW1 witnesses are constructed.
pub fn execute_with_compact_state_witness_and_progress(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    input: CompactStateExecutionInput<'_>,
    progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync),
) -> Result<CompactStateWitnessExecutionOutput> {
    progress(StateWitnessProgress::BeforeBinding)?;
    let result = execute_inner(
        settings,
        archive,
        parent_checkpoint,
        parent_state,
        block,
        ExecutionEvidence {
            accounts: AccountEvidence::Compact(input.accounts),
            state: Some(StateControl {
                witness: input.state,
                progress,
            }),
        },
        &|point| progress(StateWitnessProgress::Execution(point)),
    )?;
    Ok(CompactStateWitnessExecutionOutput {
        execution: StateWitnessExecutionOutput {
            execution: result.execution,
            state_observation: result.state.ok_or(StateWitnessError::Observation)?,
        },
        account_proof: result.compact.ok_or(StateWitnessError::Observation)?,
    })
}

fn execute_inner(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    block: BlockInput<'_>,
    evidence: ExecutionEvidence<'_>,
    progress: &(impl Fn(ExecutionProgress) -> Result<()> + Sync),
) -> Result<InternalOutput> {
    let budget = WitnessBudget::for_block(settings, parent_state.len(), block.transactions.len())?;
    match evidence.accounts {
        AccountEvidence::Expanded(witnesses) => {
            budget.check(witnesses)?;
        }
        AccountEvidence::Compact(proof) => {
            budget.check_compact(proof)?;
        }
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
    let mut requested: Vec<_> = match evidence.accounts {
        AccountEvidence::Expanded(witnesses) => {
            witnesses.iter().map(|witness| witness.owner).collect()
        }
        AccountEvidence::Compact(proof) => {
            proof.accounts.iter().map(|account| account.owner).collect()
        }
    };
    requested.sort_unstable();
    let checked = match evidence.accounts {
        AccountEvidence::Expanded(witnesses) => CheckedAccountEvidence::Expanded {
            checked: ExecutionAccounts::verify(context, &checkpoint, witnesses, &|| {
                progress(ExecutionProgress::BeforeParentBinding)
            })?,
            witnesses,
        },
        AccountEvidence::Compact(proof) => CheckedAccountEvidence::Compact(
            CheckedMultiproof::verify_with_progress(context, &checkpoint, proof, &|_| {
                progress(ExecutionProgress::BeforeParentBinding)
            })?,
        ),
    };
    // Compare only with ORIGINAL parent values. Mandatory credits and earlier
    // transactions may legitimately change the current ordered value afterward.
    for &owner in &requested {
        if checked.account(owner)? != parent_accounts.get(&owner).copied() {
            return Err(CheckedExecutionError::WitnessSource { owner });
        }
    }
    let state_bound = evidence
        .state
        .as_ref()
        .map(|control| {
            let bound = BoundState::bind(
                settings,
                &checkpoint,
                parent_state,
                &parent_accounts,
                control.witness,
            )?;
            (control.progress)(StateWitnessProgress::AfterBinding)?;
            Ok::<_, CheckedExecutionError>(bound)
        })
        .transpose()?;
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
        let execution = pon_executor::BlockExecution {
            transactions: block.transactions,
            height: block.height,
            miner: block.miner,
            parent_id: block.parent_id,
            workers: 1,
        };
        if let (Some(bound), Some(control)) = (state_bound.as_ref(), evidence.state.as_ref()) {
            let completed = |before: &State, after: &State, receipts: &[Vec<u8>]| {
                let verified = (|| {
                    (control.progress)(StateWitnessProgress::BeforeMandatoryVerification)?;
                    bound.check_parent(before)?;
                    let result = checked.transition(
                        bound,
                        after,
                        receipts,
                        StatePhase::Mandatory,
                        control.progress,
                    )?;
                    (control.progress)(StateWitnessProgress::AfterMandatoryVerification)?;
                    Ok::<_, CheckedExecutionError>(result)
                })();
                let mut observed = accesses.lock().map_err(|_| ACCESS_REFUSED)?;
                match verified {
                    Ok(result) if observed.mandatory.is_none() => {
                        observed.mandatory = Some(result);
                        Ok(())
                    }
                    Ok(_) => {
                        observed.failure = Some(StateWitnessError::Mandatory.into());
                        Err(ACCESS_REFUSED)
                    }
                    Err(error) => {
                        observed.failure = Some(error);
                        Err(ACCESS_REFUSED)
                    }
                }
            };
            pon_executor::execute_with_authenticated_state_input(
                parent_state,
                execution,
                &settings.app,
                &gate,
                &pon_executor::MandatoryStateInput {
                    non_accounts: &bound.non_accounts,
                    completed: &completed,
                },
                progress,
            )
        } else {
            pon_executor::execute_with_account_point_access(
                parent_state,
                execution,
                &settings.app,
                &gate,
                progress,
            )
        }
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
    let state = if let (Some(bound), Some(control)) = (state_bound, evidence.state) {
        (control.progress)(StateWitnessProgress::BeforeSuccessorVerification)?;
        let successor = checked.transition(
            &bound,
            &output.state,
            &output.receipts,
            StatePhase::Successor,
            control.progress,
        )?;
        if successor.commitment.state_root != output.root {
            return Err(StateWitnessError::Commitment.into());
        }
        (control.progress)(StateWitnessProgress::AfterSuccessorVerification)?;
        let observed = StateExecutionObservation {
            schema: state_witness::EXECUTION_SCHEMA,
            parent_checkpoint,
            parent_id: block.parent_id,
            height: block.height,
            miner: block.miner,
            parent: bound.parent,
            mandatory: accesses.mandatory.ok_or(StateWitnessError::Mandatory)?,
            successor,
            non_account_witness_count: bound.non_accounts.len(),
            non_account_witness_bytes: bound.witness_bytes,
            complete_non_account_partition: true,
            account_roots_from_merged_proofs: true,
            full_state_reference_checked: true,
            complete_state_required: true,
            consensus_admission: false,
            archive_mutated: false,
        };
        (control.progress)(StateWitnessProgress::BeforeOutput)?;
        Some(observed)
    } else {
        None
    };
    Ok(InternalOutput {
        execution: CheckedExecutionOutput {
            output,
            observation,
        },
        state,
        compact: match checked {
            CheckedAccountEvidence::Compact(checked) => Some(checked.observation().clone()),
            CheckedAccountEvidence::Expanded { .. } => None,
        },
    })
}

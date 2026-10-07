//! Complete non-account input and proof-derived account updates for the explicit
//! checked-execution research path. Raw serialized claims grant no authority.
//!
//! A private bound value is constructed only after checking the complete native
//! parent, installed context and archive checkpoint. Its account aggregate is a
//! full-parent anchor, not a sum inferred from membership proofs. Every later
//! account update uses original-parent witnesses, merges their shared sparse
//! paths, and preserves nonce and existence. The complete non-account partition
//! is still supplied and scanned: no efficient range proof or partial-State
//! backend is claimed. Complete State remains the independent comparison path.
use super::obligations::MAX_EXECUTION_ACCOUNTS;
use super::{CheckedExecutionError, Result};
use crate::account_archive_prototype::{
    accounts, AccountAggregateObservation,
    multiproof::{CheckedMultiproof, MultiproofProgress},
    Account, Checkpoint, Context, ResearchUpdate, Witness,
};
use crate::Settings;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use trnm_mvcc_fee::pon_executor::{self, ExecutionProgress, State};
use trnm_protocol::pon_wire::{hash, Hash};

pub const COMMITMENT_SCHEMA: &str = "pon-authenticated-state-commitment-v1";
pub const EXECUTION_SCHEMA: &str = "pon-authenticated-state-execution-v1";
pub const GROWTH_COMMITMENT_SCHEMA_V2: &str = "pon-permanent-account-growth-commitment-v2";
pub const MAX_PERMANENT_ACCOUNTS_V2: u64 = 1_000_000;
pub const MAX_WORKING_KEYS_V2: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateWitnessError {
    Context,
    Commitment,
    Partition,
    CanonicalOrder,
    AccountRow,
    Aggregate,
    Conservation,
    AccountDelta,
    ProofUpdate,
    Mandatory,
    Observation,
    Relation(&'static str),
}
impl From<StateWitnessError> for CheckedExecutionError {
    fn from(value: StateWitnessError) -> Self {
        Self::StateWitness(value)
    }
}
fn relation<T>(value: pon_executor::Result<T>) -> Result<T> {
    value.map_err(|error| StateWitnessError::Relation(error).into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatePhase {
    Mandatory,
    Successor,
}
/// These are cooperative boundaries, not preemption inside a native scan,
/// serialization, signature or hash operation. The final check precedes output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateWitnessProgress {
    BeforeBinding,
    AfterBinding,
    Execution(ExecutionProgress),
    BeforeMandatoryVerification,
    AfterMandatoryVerification,
    BeforeSuccessorVerification,
    AfterSuccessorVerification,
    BeforeOutput,
    AccountProof {
        phase: StatePhase,
        index: usize,
    },
    AccountUpdate {
        phase: StatePhase,
        index: usize,
    },
    AccountMerge {
        phase: StatePhase,
        index: usize,
    },
    /// Only the separately selected monetary range relation emits this event.
    ObligationRange {
        index: usize,
    },
}

/// Untrusted observation/input claims. Only the private BoundState below can
/// authorize their use within one immutable parent operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCommitment {
    pub schema: String,
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
    pub state_root: Hash,
    pub account_root: Hash,
    pub account_count: u64,
    pub account_balance: u64,
    pub non_account_root: Hash,
    pub non_account_count: u64,
    pub escrow_balance: u64,
    pub reward_balance: u64,
    pub issued: u64,
    pub id: Hash,
}
impl StateCommitment {
    fn digest(&self) -> Hash {
        hash(
            b"checked-state-commitment-v1",
            &[
                &self.network,
                &self.parameters,
                &self.genesis,
                &self.state_root,
                &self.account_root,
                &self.account_count.to_le_bytes(),
                &self.account_balance.to_le_bytes(),
                &self.non_account_root,
                &self.non_account_count.to_le_bytes(),
                &self.escrow_balance.to_le_bytes(),
                &self.reward_balance.to_le_bytes(),
                &self.issued.to_le_bytes(),
            ],
        )
    }
}

/// Research-only successor relation that separates permanent account history
/// from the bounded non-account working partition. It is not installed in any
/// header parameters, genesis, native admission or signature domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrowthStateCommitmentV2 {
    pub schema: String,
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
    pub permanent_account_root: Hash,
    pub permanent_account_count: u64,
    pub permanent_account_balance: u64,
    pub maximum_permanent_accounts: u64,
    pub working_root: Hash,
    pub working_count: u64,
    pub maximum_working_keys: u64,
    pub escrow_balance: u64,
    pub reward_balance: u64,
    pub issued: u64,
    pub id: Hash,
}
impl GrowthStateCommitmentV2 {
    fn digest(&self) -> Hash {
        hash(
            b"permanent-account-growth-commitment-v2",
            &[
                &self.network,
                &self.parameters,
                &self.genesis,
                &self.permanent_account_root,
                &self.permanent_account_count.to_le_bytes(),
                &self.permanent_account_balance.to_le_bytes(),
                &self.maximum_permanent_accounts.to_le_bytes(),
                &self.working_root,
                &self.working_count.to_le_bytes(),
                &self.maximum_working_keys.to_le_bytes(),
                &self.escrow_balance.to_le_bytes(),
                &self.reward_balance.to_le_bytes(),
                &self.issued.to_le_bytes(),
            ],
        )
    }
}

/// Bind a verified permanent-account archive aggregate to a complete bounded
/// non-account partition. The archive observation is constructed from actual
/// authenticated bytes; raw caller count/balance claims cannot call this path.
pub fn growth_commitment_v2(
    settings: &Settings,
    accounts: &AccountAggregateObservation,
    working: &State,
) -> Result<GrowthStateCommitmentV2> {
    let context = accounts.context();
    if context.network != settings.network()
        || context.parameters != settings.parameters()
        || context.genesis != settings.genesis()
    {
        return Err(StateWitnessError::Context.into());
    }
    if accounts.account_count() > MAX_PERMANENT_ACCOUNTS_V2
        || working.len() > MAX_WORKING_KEYS_V2
        || working.keys().any(|key| key.starts_with("account:"))
    {
        return Err(CheckedExecutionError::Budget);
    }
    let (escrow_balance, reward_balance, issued) = components(working)?;
    if total(
        [
            accounts.account_balance(),
            escrow_balance,
            reward_balance,
        ]
        .into_iter(),
    )? != issued
    {
        return Err(StateWitnessError::Conservation.into());
    }
    let working_root = relation(pon_executor::root(working))?;
    let mut out = GrowthStateCommitmentV2 {
        schema: GROWTH_COMMITMENT_SCHEMA_V2.into(),
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
        permanent_account_root: accounts.account_root(),
        permanent_account_count: accounts.account_count(),
        permanent_account_balance: accounts.account_balance(),
        maximum_permanent_accounts: MAX_PERMANENT_ACCOUNTS_V2,
        working_root,
        working_count: working.len() as u64,
        maximum_working_keys: MAX_WORKING_KEYS_V2 as u64,
        escrow_balance,
        reward_balance,
        issued,
        id: [0; 32],
    };
    out.id = out.digest();
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRow {
    pub key: String,
    pub value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateWitness {
    pub parent_checkpoint: Hash,
    pub parent_id: Hash,
    pub parent_height: u64,
    pub commitment: StateCommitment,
    pub non_accounts: Vec<StateRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountChange {
    pub owner: Hash,
    pub before: Option<Account>,
    pub after: Account,
}
/// This wrapper distinguishes absent data (`None`) from present JSON null
/// (`Some(RecordValue { value: Null })`) in a serialized change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecordValue {
    pub value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StateChange {
    pub key: String,
    pub before: Option<RecordValue>,
    pub after: Option<RecordValue>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StateTransition {
    pub commitment: StateCommitment,
    /// Both mandatory and successor changes start at the ORIGINAL parent.
    pub account_changes: Vec<AccountChange>,
    pub non_account_changes: Vec<StateChange>,
    pub receipts: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StateExecutionObservation {
    pub schema: &'static str,
    pub parent_checkpoint: Hash,
    pub parent_id: Hash,
    pub height: u64,
    pub miner: Hash,
    pub parent: StateCommitment,
    pub mandatory: StateTransition,
    pub successor: StateTransition,
    pub non_account_witness_count: usize,
    /// Exact compact JSON encoding length of the supplied Vec<StateRow>.
    pub non_account_witness_bytes: usize,
    pub complete_non_account_partition: bool,
    pub account_roots_from_merged_proofs: bool,
    pub full_state_reference_checked: bool,
    pub complete_state_required: bool,
    pub consensus_admission: bool,
    pub archive_mutated: bool,
}

fn non_accounts(state: &State) -> State {
    state
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
fn number(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| StateWitnessError::Aggregate.into())
}
fn total(mut values: impl Iterator<Item = u64>) -> Result<u64> {
    values
        .try_fold(0u64, |sum, value| sum.checked_add(value))
        .ok_or_else(|| StateWitnessError::Aggregate.into())
}
fn components(state: &State) -> Result<(u64, u64, u64)> {
    let mut escrow = 0u64;
    let mut rewards = 0u64;
    for (key, value) in state {
        if key.starts_with("task:") || key.starts_with("quota:") || key.starts_with("release:") {
            escrow = escrow
                .checked_add(number(value, "remaining")?)
                .ok_or(StateWitnessError::Aggregate)?;
        } else if key.starts_with("reward:") {
            rewards = rewards
                .checked_add(number(value, "amount")?)
                .ok_or(StateWitnessError::Aggregate)?;
        }
    }
    let issued = state
        .get("meta:issued")
        .and_then(Value::as_u64)
        .ok_or(StateWitnessError::Aggregate)?;
    Ok((escrow, rewards, issued))
}
fn commitment(
    context: Context,
    state_root: Hash,
    account_root: Hash,
    account_count: u64,
    account_balance: u64,
    non_accounts: &State,
) -> Result<StateCommitment> {
    let (escrow_balance, reward_balance, issued) = components(non_accounts)?;
    if total([account_balance, escrow_balance, reward_balance].into_iter())? != issued {
        return Err(StateWitnessError::Conservation.into());
    }
    let mut out = StateCommitment {
        schema: COMMITMENT_SCHEMA.into(),
        network: context.network,
        parameters: context.parameters,
        genesis: context.genesis,
        state_root,
        account_root,
        account_count,
        account_balance,
        non_account_root: relation(pon_executor::root(non_accounts))?,
        non_account_count: non_accounts.len() as u64,
        escrow_balance,
        reward_balance,
        issued,
        id: [0; 32],
    };
    out.id = out.digest();
    Ok(out)
}

pub(super) fn prepare(
    settings: &Settings,
    checkpoint: &Checkpoint,
    state: &State,
    account_values: &BTreeMap<Hash, Account>,
) -> Result<StateWitness> {
    let partition = non_accounts(state);
    Ok(StateWitness {
        parent_checkpoint: checkpoint.id(),
        parent_id: checkpoint.branch(),
        parent_height: checkpoint.height(),
        commitment: commitment(
            Context {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis(),
            },
            checkpoint
                .source_state_root()
                .ok_or(StateWitnessError::Context)?,
            checkpoint.account_root(),
            checkpoint.account_count(),
            total(account_values.values().map(|value| value.balance))?,
            &partition,
        )?,
        non_accounts: partition
            .into_iter()
            .map(|(key, value)| StateRow { key, value })
            .collect(),
    })
}

/// Rebuild claims from complete actual bytes for the durable research sidecar
/// and the explicit native authenticated backend's independent full reference.
/// This is not a public authority constructor or a partial-State root.
pub(crate) fn commitment_from_complete_state(
    settings: &Settings,
    state: &State,
) -> Result<StateCommitment> {
    let account_values = accounts(state)?;
    commitment(
        Context {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
        },
        relation(pon_executor::root(state))?,
        crate::account_archive_prototype::account_root(&account_values)?,
        account_values.len() as u64,
        total(account_values.values().map(|value| value.balance))?,
        &non_accounts(state),
    )
}

/// Opaque operation-local source, never constructed from a digest claim alone.
pub(super) struct BoundState<'a> {
    pub parent: StateCommitment,
    pub non_accounts: State,
    pub witness_bytes: usize,
    parent_state: &'a State,
    parent_accounts: &'a BTreeMap<Hash, Account>,
}
enum OriginalAccounts<'a> {
    Expanded(&'a [Witness]),
    Compact(&'a CheckedMultiproof),
}
impl<'a> BoundState<'a> {
    pub fn bind(
        settings: &Settings,
        checkpoint: &Checkpoint,
        state: &'a State,
        account_values: &'a BTreeMap<Hash, Account>,
        witness: &StateWitness,
    ) -> Result<Self> {
        if witness.parent_checkpoint != checkpoint.id()
            || witness.parent_id != checkpoint.branch()
            || witness.parent_height != checkpoint.height()
        {
            return Err(StateWitnessError::Context.into());
        }
        if witness.non_accounts.len() > 65_536 {
            return Err(CheckedExecutionError::Budget);
        }
        let mut previous: Option<&str> = None;
        for row in &witness.non_accounts {
            if row.key.starts_with("account:") {
                return Err(StateWitnessError::AccountRow.into());
            }
            if previous.is_some_and(|key| key >= row.key.as_str()) {
                return Err(StateWitnessError::CanonicalOrder.into());
            }
            previous = Some(&row.key);
        }
        // Exact full partition comparison keeps every unrecognized/retained
        // namespace. No prefix allowlist can silently hide a future obligation.
        if !state
            .iter()
            .filter(|(key, _)| !key.starts_with("account:"))
            .eq(witness
                .non_accounts
                .iter()
                .map(|row| (&row.key, &row.value)))
        {
            return Err(StateWitnessError::Partition.into());
        }
        // Copy only after the complete borrowed comparison, so a malformed
        // supplied payload cannot make this layer clone arbitrary extra bytes.
        let rows: State = witness
            .non_accounts
            .iter()
            .map(|row| (row.key.clone(), row.value.clone()))
            .collect();
        let expected = commitment(
            Context {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis(),
            },
            checkpoint
                .source_state_root()
                .ok_or(StateWitnessError::Context)?,
            checkpoint.account_root(),
            checkpoint.account_count(),
            total(account_values.values().map(|value| value.balance))?,
            &rows,
        )?;
        if witness.commitment != expected {
            return Err(StateWitnessError::Commitment.into());
        }
        if relation(pon_executor::root(&rows))? != expected.non_account_root
            || rows.len() as u64 != expected.non_account_count
        {
            return Err(StateWitnessError::Partition.into());
        }
        Ok(Self {
            parent: expected,
            non_accounts: rows,
            witness_bytes: serde_json::to_vec(&witness.non_accounts)
                .map_err(|_| StateWitnessError::Observation)?
                .len(),
            parent_state: state,
            parent_accounts: account_values,
        })
    }

    pub fn transition(
        &self,
        state: &State,
        witnesses: &[Witness],
        receipts: &[Vec<u8>],
        phase: StatePhase,
        progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
    ) -> Result<StateTransition> {
        self.transition_accounts(
            state,
            OriginalAccounts::Expanded(witnesses),
            receipts,
            phase,
            progress,
        )
    }

    pub fn transition_compact(
        &self,
        state: &State,
        accounts: &CheckedMultiproof,
        receipts: &[Vec<u8>],
        phase: StatePhase,
        progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
    ) -> Result<StateTransition> {
        self.transition_accounts(
            state,
            OriginalAccounts::Compact(accounts),
            receipts,
            phase,
            progress,
        )
    }

    fn transition_accounts(
        &self,
        state: &State,
        proofs: OriginalAccounts<'_>,
        receipts: &[Vec<u8>],
        phase: StatePhase,
        progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
    ) -> Result<StateTransition> {
        let after_accounts = accounts(state)?;
        for (owner, before) in self.parent_accounts {
            if after_accounts
                .get(owner)
                .is_none_or(|after| after.nonce < before.nonce)
            {
                return Err(StateWitnessError::AccountDelta.into());
            }
        }
        let original: BTreeMap<_, _> = match &proofs {
            OriginalAccounts::Expanded(witnesses) => witnesses
                .iter()
                .map(|witness| (witness.owner, witness.account))
                .collect(),
            OriginalAccounts::Compact(checked) => checked.values().collect(),
        };
        let mut changes = Vec::new();
        for (&owner, &after) in &after_accounts {
            let before = self.parent_accounts.get(&owner).copied();
            if before != Some(after) {
                if original.get(&owner) != Some(&before) {
                    return Err(CheckedExecutionError::UncheckedWrite { owner });
                }
                changes.push(AccountChange {
                    owner,
                    before,
                    after,
                });
            }
        }
        // All subtractions happen before additions, independent of account
        // ordering and without transient overflow when funds move at u64::MAX.
        let removed = total(
            changes
                .iter()
                .filter_map(|change| change.before.map(|a| a.balance)),
        )?;
        let added = total(changes.iter().map(|change| change.after.balance))?;
        let balance = self
            .parent
            .account_balance
            .checked_sub(removed)
            .and_then(|value| value.checked_add(added))
            .ok_or(StateWitnessError::Aggregate)?;
        let count = self
            .parent
            .account_count
            .checked_add(
                changes
                    .iter()
                    .filter(|change| change.before.is_none())
                    .count() as u64,
            )
            .ok_or(StateWitnessError::Aggregate)?;
        let account_root = match proofs {
            OriginalAccounts::Expanded(witnesses) => merged_account_root(
                self.parent.account_root,
                witnesses,
                &changes,
                phase,
                progress,
            )?,
            OriginalAccounts::Compact(checked) => {
                let updates: Vec<_> = changes
                    .iter()
                    .map(|change| ResearchUpdate {
                        owner: change.owner,
                        before: change.before,
                        after: change.after,
                    })
                    .collect();
                checked
                    .root_for_updates(&updates, &|point| match point {
                        MultiproofProgress::Update { index } => {
                            progress(StateWitnessProgress::AccountUpdate { phase, index })
                        }
                        MultiproofProgress::Hash { index } => {
                            progress(StateWitnessProgress::AccountMerge { phase, index })
                        }
                        _ => Ok(()),
                    })?
                    .0
            }
        };
        // These complete rebuilds are an independent reference; none supplies
        // the proof-derived root/count/sum that is returned above.
        if account_root != crate::account_archive_prototype::account_root(&after_accounts)?
            || count != after_accounts.len() as u64
            || balance != total(after_accounts.values().map(|value| value.balance))?
        {
            return Err(StateWitnessError::AccountDelta.into());
        }
        let after_non_accounts = non_accounts(state);
        let keys: BTreeSet<_> = self
            .non_accounts
            .keys()
            .chain(after_non_accounts.keys())
            .collect();
        let non_account_changes = keys
            .into_iter()
            .filter_map(|key| {
                let before = self.non_accounts.get(key);
                let after = after_non_accounts.get(key);
                (before != after).then(|| StateChange {
                    key: key.clone(),
                    before: before.cloned().map(|value| RecordValue { value }),
                    after: after.cloned().map(|value| RecordValue { value }),
                })
            })
            .collect();
        let next = commitment(
            Context {
                network: self.parent.network,
                parameters: self.parent.parameters,
                genesis: self.parent.genesis,
            },
            relation(pon_executor::root(state))?,
            account_root,
            count,
            balance,
            &after_non_accounts,
        )?;
        if phase == StatePhase::Mandatory && next.issued != self.parent.issued {
            return Err(StateWitnessError::Mandatory.into());
        }
        Ok(StateTransition {
            commitment: next,
            account_changes: changes,
            non_account_changes,
            receipts: receipts.to_vec(),
        })
    }

    pub fn check_parent(&self, state: &State) -> Result<()> {
        if state != self.parent_state {
            return Err(StateWitnessError::Mandatory.into());
        }
        Ok(())
    }
}

fn account_path(owner: Hash) -> Hash {
    hash(b"account-archive-key-v1", &[&owner])
}
fn account_leaf(owner: Hash, account: Account) -> Hash {
    hash(
        b"account-archive-leaf-v1",
        &[
            &owner,
            &account.balance.to_le_bytes(),
            &account.nonce.to_le_bytes(),
        ],
    )
}
fn account_branch(left: Hash, right: Hash) -> Hash {
    hash(b"account-archive-branch-v1", &[&left, &right])
}
struct ChangedPath<'a> {
    path: Hash,
    original: &'a Witness,
    change: &'a AccountChange,
    index: usize,
}

/// Combine only changed paths, in hash-path order. Each unchanged sibling is
/// taken from an independently root-checked ORIGINAL proof; each changed sibling
/// is recursively recomputed. A single path uses at most 256 hashes between
/// cancellation boundaries. No sparse map with 512 entries per proof is built:
/// original validation retains owner/path sets and witness references; updates
/// retain one reference record per change plus a depth-256 recursion stack.
fn changed_subtree(
    paths: &[ChangedPath<'_>],
    depth: usize,
    phase: StatePhase,
    progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
) -> Result<Hash> {
    let first = paths.first().ok_or(StateWitnessError::ProofUpdate)?;
    if paths.len() == 1 {
        progress(StateWitnessProgress::AccountMerge {
            phase,
            index: first.index,
        })?;
        let mut digest = account_leaf(first.change.owner, first.change.after);
        for d in (depth..256).rev() {
            digest = if first.path[d / 8] & (0x80 >> (d % 8)) != 0 {
                account_branch(first.original.siblings[d], digest)
            } else {
                account_branch(digest, first.original.siblings[d])
            };
        }
        return Ok(digest);
    }
    if depth >= 256 {
        return Err(StateWitnessError::ProofUpdate.into());
    }
    let split = paths.partition_point(|path| path.path[depth / 8] & (0x80 >> (depth % 8)) == 0);
    let (left_paths, right_paths) = paths.split_at(split);
    let left = if left_paths.is_empty() {
        first.original.siblings[depth]
    } else {
        changed_subtree(left_paths, depth + 1, phase, progress)?
    };
    let right = if right_paths.is_empty() {
        first.original.siblings[depth]
    } else {
        changed_subtree(right_paths, depth + 1, phase, progress)?
    };
    Ok(account_branch(left, right))
}

/// Every original proof is verified before any leaf changes. Updated sibling
/// subtrees are merged rather than overwritten by another original proof path.
fn merged_account_root(
    expected: Hash,
    witnesses: &[Witness],
    changes: &[AccountChange],
    phase: StatePhase,
    progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
) -> Result<Hash> {
    if witnesses.len() > MAX_EXECUTION_ACCOUNTS || changes.len() > witnesses.len() {
        return Err(CheckedExecutionError::Budget);
    }
    let mut originals = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for (index, witness) in witnesses.iter().enumerate() {
        progress(StateWitnessProgress::AccountProof { phase, index })?;
        let path = account_path(witness.owner);
        if witness.siblings.len() != 256
            || originals.insert(witness.owner, witness).is_some()
            || !paths.insert(path)
        {
            return Err(StateWitnessError::ProofUpdate.into());
        }
        let mut digest = witness.account.map_or_else(
            || hash(b"account-archive-empty-v1", &[]),
            |account| account_leaf(witness.owner, account),
        );
        for depth in (0..256).rev() {
            digest = if path[depth / 8] & (0x80 >> (depth % 8)) != 0 {
                account_branch(witness.siblings[depth], digest)
            } else {
                account_branch(digest, witness.siblings[depth])
            };
        }
        if digest != expected {
            return Err(StateWitnessError::ProofUpdate.into());
        }
    }
    let mut changed = Vec::with_capacity(changes.len());
    let mut previous = None;
    for (index, change) in changes.iter().enumerate() {
        progress(StateWitnessProgress::AccountUpdate { phase, index })?;
        let original = originals
            .get(&change.owner)
            .ok_or(StateWitnessError::ProofUpdate)?;
        if previous.is_some_and(|owner| owner >= change.owner)
            || original.account != change.before
            || change.before == Some(change.after)
            || change
                .before
                .is_some_and(|before| change.after.nonce < before.nonce)
        {
            return Err(StateWitnessError::ProofUpdate.into());
        }
        previous = Some(change.owner);
        changed.push(ChangedPath {
            path: account_path(change.owner),
            original,
            change,
            index,
        });
    }
    if changes.is_empty() {
        return Ok(expected);
    }
    changed.sort_unstable_by_key(|change| change.path);
    changed_subtree(&changed, 0, phase, progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_archive_prototype::{account_root, AccountArchive, Limits};
    use serde_json::json;

    fn archive(state: &State) -> (tempfile::TempDir, Settings, AccountArchive, Checkpoint) {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut archive = AccountArchive::open(
            &dir.path().join("state.sqlite"),
            Context {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis(),
            },
            Limits::default(),
        )
        .unwrap();
        // This is an explicitly supplied component State, not an admitted Node
        // genesis or a signed ledger-capacity observation.
        let checkpoint = archive
            .project_initial(state, pon_executor::root(state).unwrap())
            .unwrap();
        (dir, settings, archive, checkpoint)
    }
    fn shared_prefix_owners() -> (Hash, Hash) {
        let mut prior = BTreeMap::new();
        for number in 0u64..=65_536 {
            let mut owner = [0; 32];
            owner[..8].copy_from_slice(&number.to_le_bytes());
            let path = account_path(owner);
            if let Some(previous) = prior.insert([path[0], path[1]], owner) {
                return (previous, owner);
            }
        }
        panic!("65,537 paths must share one of 65,536 sixteen-bit prefixes");
    }
    fn state(account_values: &BTreeMap<Hash, Account>, issued: u64) -> State {
        let mut state = State::from([("meta:issued".into(), json!(issued))]);
        for (owner, value) in account_values {
            state.insert(format!("account:{}", hex::encode(owner)), json!(value));
        }
        state
    }

    #[test]
    fn merged_original_proofs_preserve_shared_paths_absence_and_input_permutations() {
        let (left, inserted) = shared_prefix_owners();
        assert_eq!(account_path(left)[..2], account_path(inserted)[..2]);
        let other = [255; 32];
        let old = BTreeMap::from([
            (
                left,
                Account {
                    balance: 1000,
                    nonce: 17,
                },
            ),
            (
                other,
                Account {
                    balance: 100,
                    nonce: 3,
                },
            ),
        ]);
        let (_dir, _settings, archive, checkpoint) = archive(&state(&old, 1100));
        let witnesses: Vec<_> = [left, inserted, other]
            .into_iter()
            .map(|owner| archive.witness(checkpoint.id(), owner).unwrap().0)
            .collect();
        let next = BTreeMap::from([
            (
                left,
                Account {
                    balance: 700,
                    nonce: 18,
                },
            ),
            (
                inserted,
                Account {
                    balance: 350,
                    nonce: 1,
                },
            ),
            (
                other,
                Account {
                    balance: 50,
                    nonce: 4,
                },
            ),
        ]);
        let changes: Vec<_> = next
            .iter()
            .map(|(&owner, &after)| AccountChange {
                owner,
                before: old.get(&owner).copied(),
                after,
            })
            .collect();
        let original = checkpoint.account_root();
        let wanted = account_root(&next).unwrap();
        for proofs in [witnesses.clone(), witnesses.iter().rev().cloned().collect()] {
            assert_eq!(
                merged_account_root(original, &proofs, &changes, StatePhase::Successor, &|_| Ok(
                    ()
                ))
                .unwrap(),
                wanted
            );
        }
        assert_ne!(original, wanted);
        assert_eq!(archive.checkpoint(checkpoint.id()).unwrap(), checkpoint);
        let mut corrupted = witnesses.clone();
        corrupted[0].siblings[200][0] ^= 1;
        assert_eq!(
            merged_account_root(
                original,
                &corrupted,
                &changes,
                StatePhase::Successor,
                &|_| Ok(())
            )
            .unwrap_err(),
            StateWitnessError::ProofUpdate.into()
        );
        let mut duplicate = witnesses;
        duplicate.push(duplicate[0].clone());
        assert_eq!(
            merged_account_root(
                original,
                &duplicate,
                &changes,
                StatePhase::Successor,
                &|_| Ok(())
            )
            .unwrap_err(),
            StateWitnessError::ProofUpdate.into()
        );
    }

    #[test]
    fn authenticated_deltas_preserve_maximum_funds_and_present_null_records() {
        let a = [1; 32];
        let b = [2; 32];
        let old = BTreeMap::from([
            (
                a,
                Account {
                    balance: 1,
                    nonce: 3,
                },
            ),
            (
                b,
                Account {
                    balance: u64::MAX - 1,
                    nonce: 4,
                },
            ),
        ]);
        let mut parent = state(&old, u64::MAX);
        parent.insert("retained:delete".into(), Value::Null);
        parent.insert("retained:update".into(), Value::Null);
        let (_dir, settings, archive, checkpoint) = archive(&parent);
        let witness = prepare(&settings, &checkpoint, &parent, &old).unwrap();
        let bound = BoundState::bind(&settings, &checkpoint, &parent, &old, &witness).unwrap();
        let proofs: Vec<_> = [a, b]
            .into_iter()
            .map(|owner| archive.witness(checkpoint.id(), owner).unwrap().0)
            .collect();
        let mut next = parent.clone();
        next.insert(
            format!("account:{}", hex::encode(a)),
            json!({"balance":u64::MAX,"nonce":4}),
        );
        next.insert(
            format!("account:{}", hex::encode(b)),
            json!({"balance":0,"nonce":5}),
        );
        next.remove("retained:delete");
        next.insert("retained:update".into(), json!(7));
        next.insert("retained:insert".into(), Value::Null);
        let transition = bound
            .transition(&next, &proofs, &[], StatePhase::Mandatory, &|_| Ok(()))
            .unwrap();
        assert_eq!(transition.commitment.account_balance, u64::MAX);
        assert_eq!(transition.commitment.account_count, 2);
        assert_eq!(transition.commitment.issued, u64::MAX);
        let values = serde_json::to_value(&transition.non_account_changes).unwrap();
        assert_eq!(
            values[0],
            json!({"key":"retained:delete","before":{"value":null},"after":null})
        );
        assert_eq!(
            values[1],
            json!({"key":"retained:insert","before":null,"after":{"value":null}})
        );
        assert_eq!(
            values[2],
            json!({"key":"retained:update","before":{"value":null},"after":{"value":7}})
        );
        assert_eq!(archive.checkpoint(checkpoint.id()).unwrap(), checkpoint);
        assert_eq!(parent["retained:delete"], Value::Null);
    }

    #[test]
    fn authenticated_changes_refuse_hidden_writes_deletion_and_nonce_rewind() {
        let a = [1; 32];
        let b = [2; 32];
        let old = BTreeMap::from([
            (
                a,
                Account {
                    balance: 50,
                    nonce: 3,
                },
            ),
            (
                b,
                Account {
                    balance: 50,
                    nonce: 4,
                },
            ),
        ]);
        let parent = state(&old, 100);
        let (_dir, settings, archive, checkpoint) = archive(&parent);
        let witness = prepare(&settings, &checkpoint, &parent, &old).unwrap();
        let bound = BoundState::bind(&settings, &checkpoint, &parent, &old, &witness).unwrap();
        let proof = archive.witness(checkpoint.id(), a).unwrap().0;
        let mut hidden = parent.clone();
        hidden.insert(
            format!("account:{}", hex::encode(b)),
            json!({"balance":50,"nonce":5}),
        );
        assert_eq!(
            bound
                .transition(
                    &hidden,
                    std::slice::from_ref(&proof),
                    &[],
                    StatePhase::Successor,
                    &|_| Ok(())
                )
                .unwrap_err(),
            CheckedExecutionError::UncheckedWrite { owner: b }
        );
        let mut removed = parent.clone();
        removed.remove(&format!("account:{}", hex::encode(b)));
        let mut rewind = parent.clone();
        rewind.insert(
            format!("account:{}", hex::encode(a)),
            json!({"balance":50,"nonce":2}),
        );
        for invalid in [removed, rewind] {
            assert_eq!(
                bound
                    .transition(
                        &invalid,
                        std::slice::from_ref(&proof),
                        &[],
                        StatePhase::Successor,
                        &|_| Ok(())
                    )
                    .unwrap_err(),
                StateWitnessError::AccountDelta.into()
            );
        }
    }

    #[test]
    fn authenticated_binding_rejects_self_consistent_forged_totals_and_partition_omission() {
        let owner = [1; 32];
        let old = BTreeMap::from([(
            owner,
            Account {
                balance: 100,
                nonce: 3,
            },
        )]);
        let mut parent = state(&old, 118);
        parent.insert("task:future".into(), json!({"remaining":7,"deadline":100}));
        parent.insert("reward:future".into(), json!({"amount":11,"maturity":20}));
        parent.insert("retained:null".into(), Value::Null);
        let (_dir, settings, _archive, checkpoint) = archive(&parent);
        let witness = prepare(&settings, &checkpoint, &parent, &old).unwrap();
        let mut balance = witness.clone();
        balance.commitment.account_balance += 1;
        balance.commitment.issued += 1;
        balance.commitment.id = balance.commitment.digest();
        let mut count = witness.clone();
        count.commitment.account_count += 1;
        count.commitment.id = count.commitment.digest();
        let mut root = witness.clone();
        root.commitment.state_root[0] ^= 1;
        root.commitment.id = root.commitment.digest();
        for invalid in [balance, count, root] {
            assert!(matches!(
                BoundState::bind(&settings, &checkpoint, &parent, &old, &invalid),
                Err(CheckedExecutionError::StateWitness(
                    StateWitnessError::Commitment
                ))
            ));
        }
        for omitted in ["task:future", "reward:future", "retained:null"] {
            let mut invalid = witness.clone();
            invalid.non_accounts.retain(|row| row.key != omitted);
            assert!(matches!(
                BoundState::bind(&settings, &checkpoint, &parent, &old, &invalid),
                Err(CheckedExecutionError::StateWitness(
                    StateWitnessError::Partition
                ))
            ));
        }
    }
}


#[cfg(test)]
mod growth_v2_tests {
    use super::*;
    use crate::account_archive_prototype::{AccountArchive, Context, Limits};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn owner(number: u64) -> Hash {
        let mut out = [0; 32];
        out[..8].copy_from_slice(&number.to_le_bytes());
        out
    }

    fn archive_context(settings: &Settings) -> Context {
        Context {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
        }
    }

    fn permanent_accounts(count: u64) -> BTreeMap<Hash, Account> {
        (0..count)
            .map(|number| {
                (
                    owner(number),
                    Account {
                        balance: number,
                        nonce: number % 17,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn growth_v2_binds_archive_context_bounds_and_monetary_conservation() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut archive = AccountArchive::open(
            &directory.path().join("accounts.sqlite"),
            archive_context(&settings),
            Limits::default(),
        )
        .unwrap();
        let values = permanent_accounts(4);
        let checkpoint = archive
            .seed_research_accounts([9; 32], &values, &mut || Ok(()))
            .unwrap();
        let aggregate = archive
            .aggregate_observation(checkpoint.id(), &mut || Ok(()))
            .unwrap();
        assert_eq!(aggregate.account_count(), 4);
        assert_eq!(aggregate.account_balance(), 6);
        assert_eq!(aggregate.account_root(), checkpoint.account_root());
        assert_eq!(aggregate.node_rows_read(), 7);

        let working = State::from([("meta:issued".into(), json!(6))]);
        let committed = growth_commitment_v2(&settings, &aggregate, &working).unwrap();
        assert_eq!(committed.schema, GROWTH_COMMITMENT_SCHEMA_V2);
        assert_eq!(committed.permanent_account_count, 4);
        assert_eq!(committed.permanent_account_balance, 6);
        assert_eq!(committed.working_count, 1);
        assert_eq!(committed.maximum_permanent_accounts, MAX_PERMANENT_ACCOUNTS_V2);
        assert_eq!(committed.maximum_working_keys, MAX_WORKING_KEYS_V2 as u64);
        assert_ne!(committed.id, [0; 32]);

        let wrong_settings = Settings::development(Some(2)).unwrap();
        assert_eq!(
            growth_commitment_v2(&wrong_settings, &aggregate, &working).unwrap_err(),
            StateWitnessError::Context.into()
        );
        let account_in_working = State::from([
            ("meta:issued".into(), json!(6)),
            (
                format!("account:{}", hex::encode(owner(0))),
                json!({"balance":0,"nonce":0}),
            ),
        ]);
        assert_eq!(
            growth_commitment_v2(&settings, &aggregate, &account_in_working).unwrap_err(),
            CheckedExecutionError::Budget
        );
        let unconserved = State::from([("meta:issued".into(), json!(7))]);
        assert_eq!(
            growth_commitment_v2(&settings, &aggregate, &unconserved).unwrap_err(),
            StateWitnessError::Conservation.into()
        );
    }

    #[test]
    #[ignore = "explicit release-only 65,537 permanent-account growth relation; not native admission"]
    fn growth_v2_crosses_legacy_total_key_cap_without_changing_old_profile() {
        if cfg!(debug_assertions) {
            panic!("run the 65,537-account relation with --release");
        }
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut archive = AccountArchive::open(
            &directory.path().join("accounts.sqlite"),
            archive_context(&settings),
            Limits::default(),
        )
        .unwrap();
        let values = permanent_accounts(65_537);
        let checkpoint = archive
            .seed_research_accounts([10; 32], &values, &mut || Ok(()))
            .unwrap();
        let aggregate = archive
            .aggregate_observation(checkpoint.id(), &mut || Ok(()))
            .unwrap();
        let balance = values
            .values()
            .try_fold(0u64, |sum, account| sum.checked_add(account.balance))
            .unwrap();
        let working = State::from([("meta:issued".into(), json!(balance))]);
        let committed = growth_commitment_v2(&settings, &aggregate, &working).unwrap();
        assert_eq!(committed.permanent_account_count, 65_537);
        assert_eq!(committed.permanent_account_balance, balance);
        assert_eq!(committed.working_count, 1);
        assert_eq!(committed.maximum_working_keys, 65_536);
    }
}

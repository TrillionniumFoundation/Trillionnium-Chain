//! Native-only binding to the cold-audited, generation-fenced storage owner.
//! Public JSON observations cannot construct either the source or a verified parent.
use super::*;
use crate::account_archive_prototype::{multiproof::MultiproofProgress, ArchiveError};
use crate::store::growth::CheckedRootSource;

/// A computation relation and the caller's original control failure have
/// different owners. A serialized marker cannot manufacture a control error.
#[derive(Debug)]
pub(crate) enum NativeGrowthFailure {
    Relation(CheckedExecutionError),
    Control(crate::Error),
}
impl From<CheckedExecutionError> for NativeGrowthFailure {
    fn from(error: CheckedExecutionError) -> Self {
        Self::Relation(error)
    }
}
impl From<ArchiveError> for NativeGrowthFailure {
    fn from(error: ArchiveError) -> Self {
        Self::Relation(error.into())
    }
}
impl From<StateWitnessError> for NativeGrowthFailure {
    fn from(error: StateWitnessError) -> Self {
        Self::Relation(error.into())
    }
}

pub(crate) fn bind(
    settings: &Settings,
    source: &CheckedRootSource,
    working: &State,
) -> Result<VerifiedGrowthStateCommitmentV2> {
    let value = source.commitment();
    let (escrow, reward, issued) = components(working)?;
    if value.schema != GROWTH_COMMITMENT_SCHEMA_V2
        || value.network != settings.network()
        || value.parameters != settings.parameters()
        || value.genesis != settings.genesis()
        || value.id != value.digest()
        || value.id != source.header_root()
        || value.permanent_account_root != source.accounts().digest
        || value.permanent_account_count != source.accounts().count
        || value.permanent_account_balance != source.accounts().balance
        || value.permanent_account_count > MAX_PERMANENT_ACCOUNTS_V2
        || value.maximum_permanent_accounts != MAX_PERMANENT_ACCOUNTS_V2
        || value.maximum_working_keys != MAX_WORKING_KEYS_V2 as u64
        || value.working_count != working.len() as u64
        || working.len() > MAX_WORKING_KEYS_V2
        || working.keys().any(|key| key.starts_with("account:"))
        || value.working_root != relation(pon_executor::root(working))?
        || (value.escrow_balance, value.reward_balance, value.issued) != (escrow, reward, issued)
        || total([value.permanent_account_balance, escrow, reward].into_iter())? != issued
    {
        return Err(StateWitnessError::Commitment.into());
    }
    Ok(VerifiedGrowthStateCommitmentV2 {
        observation: value.clone(),
    })
}

/// Every account value comes from the original-parent proof; omitted accounts
/// retain their authenticated root and aggregates. No full account scan occurs.
pub(crate) fn successor_with_progress(
    parent: &VerifiedGrowthStateCommitmentV2,
    proof: &CheckedMultiproof,
    view: &State,
    progress: &(impl Fn(MultiproofProgress) -> crate::Result<()> + ?Sized),
) -> std::result::Result<VerifiedGrowthStateCommitmentV2, NativeGrowthFailure> {
    let after = accounts(view)?;
    let original: BTreeMap<_, _> = proof.values().collect();
    for (&owner, before) in &original {
        if let Some(before) = before {
            if after
                .get(&owner)
                .is_none_or(|next| next.nonce < before.nonce)
            {
                return Err(StateWitnessError::AccountDelta.into());
            }
        }
    }
    let mut updates = Vec::new();
    for (&owner, &next) in &after {
        let before = *original
            .get(&owner)
            .ok_or(CheckedExecutionError::UncheckedWrite { owner })?;
        if before != Some(next) {
            updates.push(ResearchUpdate {
                owner,
                before,
                after: next,
            });
        }
    }
    let removed = total(
        updates
            .iter()
            .filter_map(|row| row.before.map(|a| a.balance)),
    )?;
    let added = total(updates.iter().map(|row| row.after.balance))?;
    let count = parent
        .permanent_account_count
        .checked_add(updates.iter().filter(|row| row.before.is_none()).count() as u64)
        .ok_or(StateWitnessError::Aggregate)?;
    let balance = parent
        .permanent_account_balance
        .checked_sub(removed)
        .and_then(|n| n.checked_add(added))
        .ok_or(StateWitnessError::Aggregate)?;
    let (root, _) = proof.root_for_updates(&updates, &|point| {
        progress(point).map_err(NativeGrowthFailure::Control)
    })?;
    let working = non_accounts(view);
    let (escrow_balance, reward_balance, issued) = components(&working)?;
    if count > MAX_PERMANENT_ACCOUNTS_V2
        || working.len() > MAX_WORKING_KEYS_V2
        || total([balance, escrow_balance, reward_balance].into_iter())? != issued
    {
        return Err(StateWitnessError::Conservation.into());
    }
    let mut value = GrowthStateCommitmentV2 {
        schema: GROWTH_COMMITMENT_SCHEMA_V2.into(),
        network: parent.network,
        parameters: parent.parameters,
        genesis: parent.genesis,
        permanent_account_root: root,
        permanent_account_count: count,
        permanent_account_balance: balance,
        maximum_permanent_accounts: MAX_PERMANENT_ACCOUNTS_V2,
        working_root: relation(pon_executor::root(&working))?,
        working_count: working.len() as u64,
        maximum_working_keys: MAX_WORKING_KEYS_V2 as u64,
        escrow_balance,
        reward_balance,
        issued,
        id: [0; 32],
    };
    value.id = value.digest();
    Ok(VerifiedGrowthStateCommitmentV2 { observation: value })
}

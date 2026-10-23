//! Versioned permanent-account execution over a bounded authenticated view.
//!
//! This module supplies computation, never parent or consensus authority. The
//! native owner authenticates the parent aggregates and every account in `view`.
//! Existing transaction, mandatory, signature and receipt code remains shared.
use super::{
    add, canonical, continuity_v1, execute_with_state_inputs, field, funds, num, require,
    AccountPointAccess, BlockExecution, Config, ControlledResult, ExecutionControl,
    ExecutionProgress, Output, Result, State, StateInputs,
};
use std::collections::BTreeSet;
use trnm_protocol::pon_wire::Hash;

pub const PROFILE: &str = "permanent-account-growth-native-v2";
pub const MAX_ACCOUNTS: u64 = 1_000_000;
pub const MAX_WORKING_KEYS: usize = 65_536;
pub const MAX_WORKING_BYTES: usize = 262_144;
pub const MAX_MANDATORY_OWNERS: usize = 32;
pub const MAX_WITNESS_ACCOUNTS: usize = 1024;
pub const MAX_WITNESS_BYTES: usize = 786_432;
pub const MAX_PACKET_BYTES: usize = 1_048_576;

/// Untrusted M06 computation inputs. Only the native verified-parent bridge may
/// use the resulting computation in admission; these numbers authenticate nothing.
#[derive(Clone, Copy, Debug)]
pub struct AccountPartition {
    pub parent_count: u64,
    pub parent_balance: u64,
}

fn present(state: &State) -> Result<(u64, u64)> {
    state
        .iter()
        .filter(|(key, _)| key.starts_with("account:"))
        .try_fold((0u64, 0u64), |(count, balance), (_, value)| {
            field(value, "nonce")?;
            Ok((add(count, 1)?, add(balance, field(value, "balance")?)?))
        })
}

/// Complete future monetary owners, not only records which mature this block.
/// The fixed fanout reserves a worst-case 256-level multiproof for mandatory work
/// before accepting optional liabilities. Thirty-two owners fit below the packet
/// ceiling together with W1 and the growth header; optional transactions share
/// the remaining actual encoded budget.
pub fn mandatory_owners(state: &State) -> Result<BTreeSet<String>> {
    let mut owners = BTreeSet::new();
    for (key, value) in state {
        let obligation = if key.starts_with("reward:") {
            field(value, "amount")?;
            true
        } else if key.starts_with("task:")
            || key.starts_with("quota:")
            || key.starts_with("release:")
        {
            field(value, "remaining")? > 0
        } else {
            false
        };
        if obligation {
            let owner = value
                .get("owner")
                .and_then(serde_json::Value::as_str)
                .ok_or("STATE")?;
            require(
                owner.len() == 64
                    && owner
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "STATE",
            )?;
            owners.insert(owner.to_owned());
            require(
                owners.len() <= MAX_MANDATORY_OWNERS,
                "GROWTH_MANDATORY_CAPACITY",
            )?;
        }
    }
    Ok(owners)
}

impl AccountPartition {
    pub(super) fn check_parent(
        &self,
        state: &State,
        height: u64,
        cfg: &Config,
        access: Option<&AccountPointAccess<'_>>,
    ) -> Result<()> {
        let (covered_count, covered_balance) = present(state)?;
        require(
            self.parent_count >= covered_count
                && self.parent_count <= MAX_ACCOUNTS
                && self.parent_balance >= covered_balance,
            "GROWTH_AGGREGATE",
        )?;
        let liabilities = funds(state)?.checked_sub(covered_balance).ok_or("RANGE")?;
        require(
            add(self.parent_balance, liabilities)?
                == num(state.get("meta:issued").ok_or("STATE")?)?,
            "CONSERVATION",
        )?;
        self.check_capacity(state, self.parent_count, height, cfg, access)
    }

    pub(super) fn check_successor(
        &self,
        parent: &State,
        state: &State,
        height: u64,
        cfg: &Config,
        access: Option<&AccountPointAccess<'_>>,
    ) -> Result<()> {
        let (prior_count, prior_balance) = present(parent)?;
        let (next_count, next_balance) = present(state)?;
        for (key, before) in parent.iter().filter(|(key, _)| key.starts_with("account:")) {
            let after = state.get(key).ok_or("GROWTH_ACCOUNT_DELETION")?;
            require(
                field(after, "nonce")? >= field(before, "nonce")?,
                "GROWTH_NONCE_REWIND",
            )?;
        }
        let count = self
            .parent_count
            .checked_sub(prior_count)
            .and_then(|n| n.checked_add(next_count))
            .ok_or("RANGE")?;
        let balance = self
            .parent_balance
            .checked_sub(prior_balance)
            .and_then(|n| n.checked_add(next_balance))
            .ok_or("RANGE")?;
        let liabilities = funds(state)?.checked_sub(next_balance).ok_or("RANGE")?;
        require(
            add(balance, liabilities)? == num(state.get("meta:issued").ok_or("STATE")?)?,
            "CONSERVATION",
        )?;
        self.check_capacity(state, count, height, cfg, access)
    }

    fn check_capacity(
        &self,
        state: &State,
        account_count: u64,
        height: u64,
        cfg: &Config,
        access: Option<&AccountPointAccess<'_>>,
    ) -> Result<()> {
        require(
            cfg.params["state_profile"] == PROFILE && continuity_v1::enabled(cfg),
            "GROWTH_PROFILE",
        )?;
        continuity_v1::check_maintenance(state, continuity_v1::maintenance_task()?, cfg)?;
        let capacity = continuity_v1::capacity_with_account_access(state, height, cfg, access)?;
        let working_count = state
            .keys()
            .filter(|key| !key.starts_with("account:"))
            .count();
        require(
            working_count
                .checked_add(capacity.archive_reserve)
                .and_then(|n| n.checked_add(capacity.reward_queue_reserve))
                .is_some_and(|n| n <= MAX_WORKING_KEYS),
            "STATE_CAPACITY",
        )?;
        require(
            account_count
                .checked_add(capacity.credit_account_reserve as u64)
                .is_some_and(|n| n <= MAX_ACCOUNTS),
            "STATE_CAPACITY",
        )?;
        let mut bytes = 0usize;
        for (key, value) in state.iter().filter(|(key, _)| !key.starts_with("account:")) {
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(8))
                .ok_or("RANGE")?;
            bytes = bytes.checked_add(canonical(value)?.len()).ok_or("RANGE")?;
            require(bytes <= MAX_WORKING_BYTES, "GROWTH_WORKING_BYTES")?;
        }
        // Reserve the mandatory reward queue and future evaluation archives in
        // bytes as well as keys. This cannot depend on free disk or a cache hit.
        let future_bytes = capacity
            .reward_queue_reserve
            .checked_mul(256)
            .and_then(|n| {
                capacity
                    .archive_reserve
                    .checked_mul(4096 + 160 + 8)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(bytes))
            .ok_or("RANGE")?;
        require(future_bytes <= MAX_WORKING_BYTES, "GROWTH_WORKING_BYTES")?;
        mandatory_owners(state)?;
        Ok(())
    }
}

/// Execute exactly the existing M06 relation using only proved accounts and the
/// complete bounded working partition. The caller supplies the proof-derived
/// commitment; it must bind the exact original parent and resulting changes.
pub fn execute_with_commitment<E: Send>(
    view: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    partition: &AccountPartition,
    account_access: &AccountPointAccess<'_>,
    commitment: impl FnMut(&State, &State) -> Result<Hash>,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<Output, E> {
    execute_with_commitment_observed(
        view,
        block,
        cfg,
        GrowthExecutionInputs {
            partition,
            account_access,
            observer: None,
        },
        commitment,
        progress,
    )
}

/// Computation-only inputs; the native owner still binds the original proof and
/// authenticates the completed output against its actual stored block header.
pub struct GrowthExecutionInputs<'a> {
    pub partition: &'a AccountPartition,
    pub account_access: &'a AccountPointAccess<'a>,
    pub observer: Option<&'a dyn super::CanonicalTransitionObserver>,
}
pub fn execute_with_commitment_observed<E: Send>(
    view: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    inputs: GrowthExecutionInputs<'_>,
    commitment: impl FnMut(&State, &State) -> Result<Hash>,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<Output, E> {
    require(block.workers == 1, "GROWTH_WORKERS")?;
    require(cfg.params["state_profile"] == PROFILE, "GROWTH_PROFILE")?;
    execute_with_state_inputs(
        view,
        block,
        cfg,
        commitment,
        &ExecutionControl::new(progress, &()),
        StateInputs {
            accounts: Some(inputs.account_access),
            mandatory: None,
            monetary: None,
            growth: Some(inputs.partition),
            observer: inputs.observer,
            #[cfg(test)]
            experimental_skip_repeated_senders: false,
        },
    )
}

/// Validate the complete, explicit development genesis input. This performs no
/// native authentication and must never be substituted for a verified parent.
pub fn check_complete_genesis(state: &State, cfg: &Config) -> Result<()> {
    let (parent_count, parent_balance) = present(state)?;
    AccountPartition {
        parent_count,
        parent_balance,
    }
    .check_parent(state, 0, cfg, None)
}

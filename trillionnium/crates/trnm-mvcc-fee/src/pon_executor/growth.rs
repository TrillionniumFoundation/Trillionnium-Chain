//! Versioned permanent-account execution over a bounded authenticated view.
//!
//! This module supplies computation, never parent or consensus authority. The
//! native owner authenticates the parent aggregates and every account in `view`.
//! Existing transaction, mandatory, signature and receipt code remains shared.
use super::{
    add, canonical, continuity_v1, execute_with_state_inputs, field, funds, num, prefix_rows,
    require, AccountPointAccess, BlockExecution, Config, ControlledResult, ExecutionControl,
    ExecutionProgress, Output, Result, State, StateInputs, MONETARY_OBLIGATION_PREFIXES,
};
use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Included, Unbounded};
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
    prefix_rows(state, "account:").try_fold((0u64, 0u64), |(count, balance), (_, value)| {
        field(value, "nonce")?;
        Ok((add(count, 1)?, add(balance, field(value, "balance")?)?))
    })
}

// `account:` has the exact exclusive successor `account;`. Borrow both other
// ranges in original order; no account's value or claimed cached count is used
// to decide which working rows must be checked.
fn working_rows(state: &State) -> impl Iterator<Item = (&String, &serde_json::Value)> {
    state
        .range::<str, _>((Unbounded, Excluded("account:")))
        .chain(state.range::<str, _>((Included("account;"), Unbounded)))
}

/// Complete future monetary owners, not only records which mature this block.
/// The fixed fanout reserves a worst-case 256-level multiproof for mandatory work
/// before accepting optional liabilities. Thirty-two owners fit below the packet
/// ceiling together with W1 and the growth header; optional transactions share
/// the remaining actual encoded budget.
pub fn mandatory_owners(state: &State) -> Result<BTreeSet<String>> {
    let mut owners = BTreeSet::new();
    // All four complete namespaces in lexical order, including future and
    // zero-valued rows. No scan of unrelated accounts or model bytes is needed.
    for (key, value) in MONETARY_OBLIGATION_PREFIXES
        .into_iter()
        .flat_map(|prefix| prefix_rows(state, prefix))
    {
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
        for (key, before) in prefix_rows(parent, "account:") {
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
        let working_count = working_rows(state).count();
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
        for (key, value) in working_rows(state) {
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
    execute_with_commitment_observed_control(
        view,
        block,
        cfg,
        inputs,
        commitment,
        &ExecutionControl::new(progress, &()),
    )
}

/// Bounded signature preparation with the caller's original worker accounting.
/// State effects and witness access stay on the canonical caller thread; every
/// started preparation worker is joined before this operation can return.
pub fn execute_with_commitment_observed_control<E: Send>(
    view: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    inputs: GrowthExecutionInputs<'_>,
    commitment: impl FnMut(&State, &State) -> Result<Hash>,
    control: &ExecutionControl<'_, E>,
) -> ControlledResult<Output, E> {
    require([1, 2, 4, 8].contains(&block.workers), "GROWTH_WORKERS")?;
    require(cfg.params["state_profile"] == PROFILE, "GROWTH_PROFILE")?;
    execute_with_state_inputs(
        view,
        block,
        cfg,
        commitment,
        control,
        StateInputs {
            accounts: Some(inputs.account_access),
            mandatory: None,
            monetary: None,
            growth: Some(inputs.partition),
            observer: inputs.observer,
            #[cfg(test)]
            force_account_conflict_speculation: false,
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

#[cfg(test)]
mod range_tests {
    use super::*;
    use serde_json::json;

    fn original_present(state: &State) -> Result<(u64, u64)> {
        state
            .iter()
            .filter(|(key, _)| key.starts_with("account:"))
            .try_fold((0u64, 0u64), |(count, balance), (_, value)| {
                field(value, "nonce")?;
                Ok((add(count, 1)?, add(balance, field(value, "balance")?)?))
            })
    }

    fn original_owners(state: &State) -> Result<BTreeSet<String>> {
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

    #[test]
    fn borrowed_working_ranges_preserve_all_nonaccount_keys_and_pointer_identity() {
        let state: State = [
            "",
            "\0",
            "account",
            "account9",
            "account:",
            "account:\0",
            "account:invalid",
            "account:\u{10ffff}",
            "account;",
            "account;\0",
            "account\u{10ffff}",
            "contribution:",
            "meta:issued",
            "模型:甲",
            "\u{10ffff}",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, key)| (key.to_owned(), json!(index)))
        .collect();
        let original = state.iter().filter(|(key, _)| !key.starts_with("account:"));
        assert!(working_rows(&state).eq(original));
        for (key, value) in working_rows(&state) {
            let (actual_key, actual_value) = state.get_key_value(key).unwrap();
            assert!(std::ptr::eq(key, actual_key));
            assert!(std::ptr::eq(value, actual_value));
        }
        assert!(working_rows(&State::new()).next().is_none());
    }

    #[test]
    fn proved_account_aggregation_keeps_malformed_suffix_rows_overflow_and_error_order() {
        let mut state: State = (0..2048)
            .map(|index| (format!("model:{index:08x}"), json!({"opaque":true})))
            .collect();
        for count in [0, 1, 512, MAX_WITNESS_ACCOUNTS] {
            for index in 0..count {
                state.insert(
                    format!("account:{index:064x}"),
                    json!({"balance":index,"nonce":17}),
                );
            }
            assert_eq!(present(&state), original_present(&state));
        }
        // This calculation has never validated account-key syntax. Such a row
        // must remain included rather than disappearing as an absent account;
        // the caller's original canonical-key gate remains responsible for it.
        state.insert(
            "account:invalid".into(),
            json!({"balance":3,"nonce":u64::MAX}),
        );
        assert_eq!(present(&state), original_present(&state));
        state.insert("account:".into(), json!({"balance":u64::MAX,"nonce":0}));
        assert_eq!(present(&state), Err("RANGE"));
        assert_eq!(present(&state), original_present(&state));
        state.insert("account:".into(), json!({"balance":u64::MAX}));
        assert_eq!(present(&state), original_present(&state));
        assert!(present(&state).is_err());
    }

    #[test]
    fn mandatory_owner_ranges_keep_shared_future_zero_and_lexical_capacity_errors() {
        let mut state: State = (0..4096)
            .map(|index| (format!("account:{index:064x}"), json!(null)))
            .collect();
        for prefix in ["quota:", "release:", "task:"] {
            state.insert(prefix.into(), json!({"remaining":0}));
            state.insert(
                format!("{prefix}future"),
                json!({"remaining":1,"deadline":u64::MAX,"owner":format!("{:064x}", 17)}),
            );
        }
        state.insert(
            "reward:zero".into(),
            json!({"amount":0,"owner":format!("{:064x}", 18)}),
        );
        for key in ["quota", "quota;", "release;", "reward;", "task;", "模型:甲"] {
            state.insert(key.into(), json!(null));
        }
        assert_eq!(mandatory_owners(&state), original_owners(&state));
        assert_eq!(mandatory_owners(&state).unwrap().len(), 2);
        for key in ["quota:", "release:", "reward:", "task:"] {
            let mut malformed = state.clone();
            malformed.insert(key.into(), json!(null));
            assert_eq!(mandatory_owners(&malformed), original_owners(&malformed));
            assert!(mandatory_owners(&malformed).is_err());
        }
        for index in 0..=MAX_MANDATORY_OWNERS {
            state.insert(
                format!("quota:{index:03}"),
                json!({"remaining":1,"owner":format!("{index:064x}")}),
            );
        }
        state.insert("reward:bad".into(), json!(null));
        assert_eq!(mandatory_owners(&state), Err("GROWTH_MANDATORY_CAPACITY"));
        assert_eq!(mandatory_owners(&state), original_owners(&state));
    }
}

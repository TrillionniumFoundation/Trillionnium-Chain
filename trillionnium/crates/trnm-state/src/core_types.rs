use std::collections::BTreeMap;
use std::sync::RwLock;

use trnm_types::{GovParamObject, GovProposalObject, Hash32, TaskObject};

use crate::{PendingGovParamUpdate, PendingResolveApproval};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    Task(TaskObject),
    GovProposal(GovProposalObject),
    GovParam(GovParamObject),
}

#[derive(Debug)]
pub struct StateStore {
    pub(crate) objects: BTreeMap<u64, VersionedObject>,
    pub(crate) balances: BTreeMap<String, u128>,
    pub(crate) pending_gov_updates: BTreeMap<String, PendingGovParamUpdate>,
    pub(crate) gov_param_key_index: BTreeMap<String, u64>,
    pub(crate) pending_resolve_approvals: BTreeMap<u64, PendingResolveApproval>,
    pub(crate) monetary_state: MonetaryState,
    pub(crate) state_root_cache: RwLock<Option<Hash32>>,
}

#[derive(Debug, Clone)]
pub(crate) struct VersionedObject {
    pub(crate) version: u64,
    pub(crate) value: ObjectValue,
}

impl Default for StateStore {
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            balances: BTreeMap::new(),
            pending_gov_updates: BTreeMap::new(),
            gov_param_key_index: BTreeMap::new(),
            pending_resolve_approvals: BTreeMap::new(),
            monetary_state: MonetaryState::default(),
            state_root_cache: RwLock::new(None),
        }
    }
}

impl Clone for StateStore {
    fn clone(&self) -> Self {
        let cached = self
            .state_root_cache
            .read()
            .expect("state root cache poisoned")
            .clone();
        Self {
            objects: self.objects.clone(),
            balances: self.balances.clone(),
            pending_gov_updates: self.pending_gov_updates.clone(),
            gov_param_key_index: self.gov_param_key_index.clone(),
            pending_resolve_approvals: self.pending_resolve_approvals.clone(),
            monetary_state: self.monetary_state.clone(),
            state_root_cache: RwLock::new(cached),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MonetaryState {
    pub last_tick_height: u64,
    pub tick_count: u64,
    pub total_minted: u128,
    pub total_burned: u128,
    pub net_issuance: i128,
}

pub type MonetaryStateSnapshot = MonetaryState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTickEvent {
    pub block_height: u64,
    pub interval_blocks: u64,
    pub cooldown_blocks: u64,
    pub minted: u128,
    pub burned: u128,
    pub net_delta: i128,
    pub total_minted: u128,
    pub total_burned: u128,
    pub net_issuance: i128,
    pub tick_count: u64,
    pub interval_param_version: u64,
    pub issuance_param_version: u64,
    pub burn_param_version: u64,
    pub cooldown_param_version: u64,
}

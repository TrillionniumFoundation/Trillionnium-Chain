use crate::account_archive_execution::state_witness::{
    growth_commitment_from_complete_state_v2, growth_profile_binding_v2,
};
use crate::{ensure, maintenance, qualified_task_lifecycle, Error, Result, Settings};
use serde_json::json;
use trnm_mvcc_fee::{continuity_v1, pon_executor::growth as limits};
use trnm_protocol::pon_wire::hash;

impl Settings {
    /// Select a fresh development network, parameters, genesis and storage schema.
    /// This is not live migration: the exact source genesis is committed, while
    /// its context-bound bootstrap records are regenerated for the new network.
    pub fn with_permanent_account_growth_v2(mut self, namespace: &str) -> Result<Self> {
        ensure(
            self.app.task_profile() == continuity_v1::PROFILE
                && self.app.params.get("state_profile").is_none()
                && self.operator_bootstrap.is_none()
                && self.operator_material.is_none()
                && self.checkpoint_tile_paths.is_none(),
            "GROWTH_PROFILE_SOURCE",
        )?;
        let source = growth_commitment_from_complete_state_v2(&self, &self.initial)
            .map_err(super::execution_error)?;
        let binding =
            growth_profile_binding_v2(&self, &source, namespace).map_err(super::execution_error)?;
        let (a, b) = maintenance();
        let model: Vec<_> = a.iter().flat_map(|v| v.to_le_bytes()).collect();
        let input: Vec<_> = b.iter().flat_map(|v| v.to_le_bytes()).collect();
        let old_bootstrap = qualified_task_lifecycle::bootstrap_state(&self.app, &model, &input)?;
        for (key, value) in old_bootstrap.state {
            ensure(
                self.initial.remove(&key) == Some(value),
                "GROWTH_PROFILE_SOURCE",
            )?;
        }
        ensure(
            self.initial.remove(continuity_v1::MAINTENANCE_KEY)
                == Some(continuity_v1::maintenance_record(&self.app)?),
            "GROWTH_PROFILE_SOURCE",
        )?;
        self.app.params["state_profile"] = json!(limits::PROFILE);
        self.app.params["growth_limits"] = json!({
            "accounts": limits::MAX_ACCOUNTS, "working_keys": limits::MAX_WORKING_KEYS,
            "working_bytes": limits::MAX_WORKING_BYTES, "mandatory_owners": limits::MAX_MANDATORY_OWNERS,
            "witness_accounts": limits::MAX_WITNESS_ACCOUNTS, "witness_bytes": limits::MAX_WITNESS_BYTES,
            "packet_bytes": limits::MAX_PACKET_BYTES,
        });
        self.app.params["growth_source_binding"] = json!(hex::encode(binding.id));
        let parameters = hash(
            b"native-permanent-account-growth-parameters-v2",
            &[
                &binding.candidate_parameters,
                &serde_json::to_vec(&self.app.params)?,
                trnm_protocol::pon_growth::WIRE_PROFILE,
            ],
        );
        self.app.network = hash(
            b"native-permanent-account-growth-network-v2",
            &[&self.network(), &parameters],
        );
        self.app.parameters = parameters;
        self.genesis = hash(
            b"native-permanent-account-growth-genesis-v2",
            &[&binding.candidate_genesis, &self.network(), &parameters],
        );
        self.initial
            .extend(qualified_task_lifecycle::bootstrap_state(&self.app, &model, &input)?.state);
        self.initial
            .extend(continuity_v1::bootstrap_state(&self.app)?);
        limits::check_complete_genesis(&self.initial, &self.app)?;
        let actual = growth_commitment_from_complete_state_v2(&self, &self.initial)
            .map_err(super::execution_error)?;
        ensure(
            actual.permanent_account_count == source.permanent_account_count
                && actual.permanent_account_root == source.permanent_account_root
                && actual.permanent_account_balance == source.permanent_account_balance
                && actual.issued == source.issued,
            "GROWTH_PROFILE_SOURCE",
        )?;
        Ok(self)
    }
    pub fn is_permanent_account_growth_v2(&self) -> bool {
        self.app.params["state_profile"] == limits::PROFILE
    }
}

pub(super) fn require(settings: &Settings) -> Result<()> {
    ensure(
        settings.is_permanent_account_growth_v2()
            && settings.app.task_profile() == continuity_v1::PROFILE,
        "GROWTH_PROFILE",
    )?;
    let expected = json!({
        "accounts": limits::MAX_ACCOUNTS, "working_keys": limits::MAX_WORKING_KEYS,
        "working_bytes": limits::MAX_WORKING_BYTES, "mandatory_owners": limits::MAX_MANDATORY_OWNERS,
        "witness_accounts": limits::MAX_WITNESS_ACCOUNTS, "witness_bytes": limits::MAX_WITNESS_BYTES,
        "packet_bytes": limits::MAX_PACKET_BYTES,
    });
    ensure(
        settings.app.params["growth_limits"] == expected,
        "GROWTH_PROFILE_LIMITS",
    )
    .map_err(Error::local_integrity)
}

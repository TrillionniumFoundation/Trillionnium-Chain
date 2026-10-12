//! Local capacity obligations under one checked active branch generation.
//! No observation is a transaction, mining, storage or admission authority.
use super::Node;
use crate::{ensure, Error, Result};
use serde::Serialize;
use trnm_mvcc_fee::continuity_v1;

/// A current state-key observation, not a forecast of the next block's admission.
/// Private fields and no Deserialize keep this separate from caller-provided data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapacityObservation {
    schema: &'static str,
    network: String,
    parameters: String,
    genesis: String,
    observed_tip: String,
    active_generation: u64,
    observed_height: u64,
    state_root: String,
    maximum_keys: usize,
    actual_keys: usize,
    retained_account_keys: usize,
    actual_non_account_keys: usize,
    credit_account_reserve: usize,
    archive_reserve: usize,
    reward_queue_reserve: usize,
    required_keys: usize,
    unreserved_keys: usize,
    next_block_admission_guaranteed: bool,
}

// This origin applies only after reading the checked local active state. Never
// promote the progress callback's own error to a local-integrity failure.
fn retained_capacity_error(error: continuity_v1::CapacityScanError<Error>) -> Error {
    match error {
        continuity_v1::CapacityScanError::State(error) => Error::from(error).local_integrity(),
        continuity_v1::CapacityScanError::Cancelled(error) => error,
    }
}

impl Node {
    /// Reads actual canonical KV bytes and verifies the committed root through
    /// read_active. The capacity arithmetic reuses the sole revision12 algorithm.
    pub fn capacity_observation(&self) -> Result<CapacityObservation> {
        self.capacity_observation_with_progress(&mut || Ok(()))
    }

    /// Actual state reads, liability scanning and account counting check progress
    /// every 256 rows. Existing root/reconstruction stages remain nonpreemptive.
    /// Neither a partial observation nor an old active generation is published.
    pub fn capacity_observation_with_progress(
        &self,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<CapacityObservation> {
        ensure(
            continuity_v1::enabled(&self.settings.app),
            "CONTINUITY_PROFILE",
        )?;
        self.ready()?;
        let slot = self.slot()?;
        let (tip, generation, state) = self.read_active_with_progress(progress)?;
        let observed = self.record(tip).map_err(Error::local_integrity)?;
        progress()?;
        let capacity = continuity_v1::capacity_with_progress(
            &state,
            observed.height,
            &self.settings.app,
            progress,
        )
        .map_err(retained_capacity_error)?;
        let unreserved_keys = continuity_v1::MAX_KEYS
            .checked_sub(capacity.required_keys)
            .ok_or_else(|| Error::from("STATE_CAPACITY").local_integrity())?;
        let mut accounts = 0;
        for (index, key) in state.keys().enumerate() {
            if index % 256 == 0 {
                progress()?;
            }
            accounts += usize::from(key.starts_with("account:"));
        }
        progress()?;
        ensure(
            self.active()? == (tip, generation) && self.slot()? == slot,
            "STALE_VIEW",
        )?;
        Ok(CapacityObservation {
            schema: "pon-continuity-capacity-observation-v1",
            network: hex::encode(self.settings.network()),
            parameters: hex::encode(self.settings.parameters()),
            genesis: hex::encode(self.settings.genesis()),
            observed_tip: hex::encode(tip),
            active_generation: generation,
            observed_height: observed.height,
            state_root: hex::encode(observed.root),
            maximum_keys: continuity_v1::MAX_KEYS,
            actual_keys: capacity.actual_keys,
            retained_account_keys: accounts,
            actual_non_account_keys: capacity.actual_keys - accounts,
            credit_account_reserve: capacity.credit_account_reserve,
            archive_reserve: capacity.archive_reserve,
            reward_queue_reserve: capacity.reward_queue_reserve,
            required_keys: capacity.required_keys,
            unreserved_keys,
            next_block_admission_guaranteed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorCode, ErrorKind};
    use std::error::Error as _;
    use trnm_mvcc_fee::continuity_v1::CapacityScanError;

    #[test]
    fn retained_state_and_callback_lookalikes_keep_different_stop_authority() {
        let retained = retained_capacity_error(CapacityScanError::State("STATE_CAPACITY"));
        let cancelled = retained_capacity_error(CapacityScanError::Cancelled(Error::new(
            ErrorCode::StateCapacity,
        )));
        assert_eq!(retained.to_string(), cancelled.to_string());
        assert_eq!(retained.kind(), ErrorKind::LocalStructure);
        assert!(retained.requires_owner_stop());
        assert_eq!(cancelled.kind(), ErrorKind::Capacity);
        assert!(!cancelled.requires_owner_stop());
    }

    #[test]
    fn real_scan_cancellation_remains_cancelled_at_the_node_boundary() {
        let cfg = trnm_mvcc_fee::pon_executor::Config::installed_with_profiles(
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap();
        let state = trnm_mvcc_fee::pon_executor::State::new();
        let error = continuity_v1::capacity_with_progress(&state, 0, &cfg, &mut || {
            Err(Error::new(ErrorCode::PublicRequestCancelled))
        })
        .map_err(retained_capacity_error)
        .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert!(!error.requires_owner_stop());
    }

    #[test]
    fn callback_error_preserves_its_source_and_diagnostic() {
        let input = Error::from(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "STORAGE_HASH",
        ));
        let diagnostic = input.to_string();
        let output = retained_capacity_error(CapacityScanError::Cancelled(input));
        assert_eq!(output.to_string(), diagnostic);
        assert_eq!(output.kind(), ErrorKind::Transport);
        assert_eq!(output.source().unwrap().to_string(), "STORAGE_HASH");
        assert!(!output.requires_owner_stop());
    }
}

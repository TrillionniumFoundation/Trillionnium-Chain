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

impl Node {
    /// Reads actual canonical KV bytes and verifies the committed root through
    /// read_active. The capacity arithmetic reuses the sole revision12 algorithm.
    pub fn capacity_observation(&self) -> Result<CapacityObservation> {
        self.capacity_observation_with_progress(&mut || Ok(()))
    }

    /// State reads, this liability scan and account counting check progress every
    /// 256 rows. Existing root/read-validation arithmetic is still nonpreemptive.
    /// Scan callback errors retain their exact origin, code, kind and source.
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
        .map_err(|error| match error {
            continuity_v1::CapacityScanError::State(error) => Error::from(error).local_integrity(),
            continuity_v1::CapacityScanError::Progress(error) => error,
        })?;
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
mod progress_tests {
    use super::*;
    use crate::{ErrorCode, ErrorKind, Settings};

    fn settings() -> Settings {
        Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap()
    }

    #[test]
    fn scan_callbacks_preserve_cancellation_capacity_and_remote_failure_origins() {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), settings(), 1).unwrap();
        let before = node.read_active().unwrap();
        let expected = node.capacity_observation().unwrap();
        let mut read_calls = 0;
        node.read_active_with_progress(&mut || {
            read_calls += 1;
            Ok(())
        })
        .unwrap();
        let mut total = 0;
        assert_eq!(
            node.capacity_observation_with_progress(&mut || {
                total += 1;
                Ok(())
            })
            .unwrap(),
            expected
        );
        let chunks = before
            .2
            .len()
            .div_ceil(continuity_v1::CAPACITY_PROGRESS_ROWS);
        // Read, pre-scan, each liability chunk, scan completion, account chunks,
        // and final view fence. Removing scan progress must fail this regression.
        assert_eq!(total, read_calls + 2 * chunks + 3);
        for cut in read_calls + 2..=read_calls + chunks + 2 {
            for kind in [
                ErrorKind::Cancelled,
                ErrorKind::Capacity,
                ErrorKind::RemoteRefusal,
                ErrorKind::ProtocolInvalid,
            ] {
                let mut calls = 0;
                let error = node
                    .capacity_observation_with_progress(&mut || {
                        calls += 1;
                        if calls != cut {
                            return Ok(());
                        }
                        Err(match kind {
                            ErrorKind::Cancelled => Error::new(ErrorCode::PublicRequestCancelled),
                            ErrorKind::Capacity => Error::new(ErrorCode::StateCapacity),
                            ErrorKind::RemoteRefusal => Error::remote("CONTINUITY_STATE"),
                            _ => Error::new(ErrorCode::ContinuityState),
                        })
                    })
                    .unwrap_err();
                assert_eq!(calls, cut);
                assert_eq!(error.kind(), kind);
                assert!(!error.requires_owner_stop());
                assert_eq!(node.read_active().unwrap(), before);
                assert_eq!(node.capacity_observation().unwrap(), expected);
            }
        }
    }

    #[test]
    fn a_generation_change_during_the_liability_scan_cannot_publish_a_report() {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), settings(), 1).unwrap();
        let before = node.read_active().unwrap();
        let expected = node.capacity_observation().unwrap();
        let mut read_calls = 0;
        node.read_active_with_progress(&mut || {
            read_calls += 1;
            Ok(())
        })
        .unwrap();
        let mut calls = 0;
        let error = node
            .capacity_observation_with_progress(&mut || {
                calls += 1;
                if calls == read_calls + 2 {
                    node.db
                        .execute("UPDATE active SET generation=?", [before.1 + 1])
                        .unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "STALE_VIEW");
        assert!(!error.requires_owner_stop());
        node.db
            .execute("UPDATE active SET generation=?", [before.1])
            .unwrap();
        assert_eq!(node.read_active().unwrap(), before);
        assert_eq!(node.capacity_observation().unwrap(), expected);
    }
}

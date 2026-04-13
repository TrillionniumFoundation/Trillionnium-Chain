use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct ConsumptionRecordKey {
    pub task_id: u64,
    pub consumer_id: String,
    pub output_hash: String,
    pub billing_window_id: String,
}

impl ConsumptionRecordKey {
    pub fn storage_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.task_id, self.consumer_id, self.output_hash, self.billing_window_id
        )
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsumptionRecordStatus {
    Submitted,
    Challenged,
    Accepted,
    Discounted,
    Rejected,
    Slashed,
}

impl Default for ConsumptionRecordStatus {
    fn default() -> Self {
        Self::Submitted
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConsumptionRecord {
    pub key: ConsumptionRecordKey,
    pub worker_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub consumer_class: String,
    pub consumed_spans_root: String,
    pub consumed_token_count: u64,
    pub claimed_consumption_units: u128,
    pub credited_consumption_units: Option<u128>,
    pub consumer_nonce: u64,
    pub accepted_at_unix_ms: u64,
    pub status: ConsumptionRecordStatus,
    pub resolution_code: Option<String>,
}

impl ConsumptionRecord {
    pub fn is_persistable_snapshot_for(&self, key: &ConsumptionRecordKey) -> bool {
        key.task_id != 0
            && self.key == *key
            && !key.consumer_id.trim().is_empty()
            && !key.output_hash.trim().is_empty()
            && !key.billing_window_id.trim().is_empty()
            && !self.worker_id.trim().is_empty()
            && !self.tokenizer_id.trim().is_empty()
            && !self.tokenizer_version.trim().is_empty()
            && !self.consumer_class.trim().is_empty()
            && !self.consumed_spans_root.trim().is_empty()
            && self.consumed_token_count > 0
            && self.claimed_consumption_units > 0
            && self.credited_consumption_units.map_or(true, |credited| {
                credited > 0 && credited <= self.claimed_consumption_units
            })
            && self.consumer_nonce > 0
            && self.accepted_at_unix_ms > 0
            && self
                .resolution_code
                .as_ref()
                .map_or(true, |code| !code.trim().is_empty())
    }

    pub fn is_compatible_with_consumer_nonce(&self, consumer_nonce: u64) -> bool {
        consumer_nonce >= self.consumer_nonce
    }

    pub fn is_compatible_with_billing_window_policy(&self, policy: &BillingWindowPolicy) -> bool {
        policy.is_receipt_compatible(&self.key.billing_window_id, self.accepted_at_unix_ms)
            && self.credited_consumption_units.map_or(true, |credited| {
                policy
                    .per_consumer_max_credited_units
                    .map_or(true, |cap| credited <= cap)
                    && policy
                        .per_task_max_credited_units
                        .map_or(true, |cap| credited <= cap)
            })
    }

    pub fn is_compatible_with_task_summary(&self, summary: &TaskConsumptionSummary) -> bool {
        summary.task_id == self.key.task_id
            && summary.receipt_count > 0
            && summary.total_consumed_tokens >= u128::from(self.consumed_token_count)
            && summary.total_claimed_consumption_units >= self.claimed_consumption_units
            && summary.total_credited_consumption_units
                >= self.credited_consumption_units.unwrap_or_default()
            && match self.status {
                ConsumptionRecordStatus::Accepted | ConsumptionRecordStatus::Discounted => {
                    summary.accepted_receipt_count > 0
                }
                _ => true,
            }
            && match self.status {
                ConsumptionRecordStatus::Challenged
                | ConsumptionRecordStatus::Rejected
                | ConsumptionRecordStatus::Slashed => summary.challenged_receipt_count > 0,
                _ => true,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BillingWindowPolicy {
    pub billing_window_id: String,
    pub open_at_unix_ms: u64,
    pub close_at_unix_ms: u64,
    pub per_consumer_max_credited_units: Option<u128>,
    pub per_task_max_credited_units: Option<u128>,
    pub policy_version: u64,
}

impl BillingWindowPolicy {
    pub fn is_persistable_snapshot_for(&self, billing_window_id: &str) -> bool {
        !billing_window_id.trim().is_empty()
            && self.billing_window_id == billing_window_id
            && self.open_at_unix_ms > 0
            && self.close_at_unix_ms > self.open_at_unix_ms
            && self.policy_version > 0
            && self
                .per_consumer_max_credited_units
                .map_or(true, |cap| cap > 0)
            && self.per_task_max_credited_units.map_or(true, |cap| cap > 0)
            && match (
                self.per_consumer_max_credited_units,
                self.per_task_max_credited_units,
            ) {
                (Some(consumer_cap), Some(task_cap)) => consumer_cap <= task_cap,
                _ => true,
            }
    }

    pub fn covers_acceptance_at(&self, accepted_at_unix_ms: u64) -> bool {
        self.open_at_unix_ms <= accepted_at_unix_ms && accepted_at_unix_ms < self.close_at_unix_ms
    }

    pub fn is_receipt_compatible(&self, billing_window_id: &str, accepted_at_unix_ms: u64) -> bool {
        self.is_persistable_snapshot_for(billing_window_id)
            && self.covers_acceptance_at(accepted_at_unix_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskConsumptionSummary {
    pub task_id: u64,
    pub receipt_count: u64,
    pub accepted_receipt_count: u64,
    pub challenged_receipt_count: u64,
    pub total_consumed_tokens: u128,
    pub total_claimed_consumption_units: u128,
    pub total_credited_consumption_units: u128,
    pub last_settlement_height: Option<u64>,
}

impl TaskConsumptionSummary {
    pub fn is_persistable_snapshot_for(&self, task_id: u64) -> bool {
        task_id != 0
            && self.task_id == task_id
            && self.accepted_receipt_count <= self.receipt_count
            && self.challenged_receipt_count <= self.receipt_count
            && self.total_credited_consumption_units <= self.total_claimed_consumption_units
            && self
                .last_settlement_height
                .map_or(true, |height| height > 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConsumptionSettlementStateSnapshot {
    pub key: ConsumptionRecordKey,
    pub record: Option<ConsumptionRecord>,
    pub consumer_nonce: Option<u64>,
    pub billing_window_policy: Option<BillingWindowPolicy>,
    pub task_summary: Option<TaskConsumptionSummary>,
}

impl ConsumptionSettlementStateSnapshot {
    pub fn matches_boundary(&self, key: &ConsumptionRecordKey) -> bool {
        self.key == *key
            && self.key.task_id != 0
            && !self.key.consumer_id.trim().is_empty()
            && !self.key.output_hash.trim().is_empty()
            && !self.key.billing_window_id.trim().is_empty()
    }

    pub fn has_record_compatible_billing_window_policy(&self) -> bool {
        match (&self.record, &self.billing_window_policy) {
            (Some(record), Some(policy)) => record.is_compatible_with_billing_window_policy(policy),
            _ => true,
        }
    }

    pub fn has_record_compatible_consumer_nonce(&self) -> bool {
        match (&self.record, self.consumer_nonce) {
            (Some(record), Some(consumer_nonce)) => {
                record.is_compatible_with_consumer_nonce(consumer_nonce)
            }
            _ => true,
        }
    }

    pub fn has_record_compatible_task_summary(&self) -> bool {
        match (&self.record, &self.task_summary) {
            (Some(record), Some(summary)) => record.is_compatible_with_task_summary(summary),
            _ => true,
        }
    }

    pub fn is_persistable_snapshot_for(&self, key: &ConsumptionRecordKey) -> bool {
        self.matches_boundary(key)
            && self
                .record
                .as_ref()
                .map_or(true, |record| record.is_persistable_snapshot_for(key))
            && self.consumer_nonce.map_or(true, |nonce| nonce > 0)
            && self.has_record_compatible_consumer_nonce()
            && self.billing_window_policy.as_ref().map_or(true, |policy| {
                policy.is_persistable_snapshot_for(&key.billing_window_id)
            })
            && self.has_record_compatible_billing_window_policy()
            && self.task_summary.as_ref().map_or(true, |summary| {
                summary.is_persistable_snapshot_for(key.task_id)
            })
            && self.has_record_compatible_task_summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateStore;

    fn sample_record() -> ConsumptionRecord {
        ConsumptionRecord {
            key: ConsumptionRecordKey {
                task_id: 42,
                consumer_id: "consumer-bravo".to_string(),
                output_hash: "abc123".to_string(),
                billing_window_id: "bw-1".to_string(),
            },
            worker_id: "worker-alpha".to_string(),
            tokenizer_id: "llama3-tokenizer".to_string(),
            tokenizer_version: "1.0.0".to_string(),
            consumer_class: "bonded_api_client".to_string(),
            consumed_spans_root: "def456".to_string(),
            consumed_token_count: 17,
            claimed_consumption_units: 17,
            credited_consumption_units: Some(15),
            consumer_nonce: 7,
            accepted_at_unix_ms: 1_775_683_200_123,
            status: ConsumptionRecordStatus::Submitted,
            resolution_code: None,
        }
    }

    fn sample_billing_window_policy() -> BillingWindowPolicy {
        BillingWindowPolicy {
            billing_window_id: "bw-1".to_string(),
            open_at_unix_ms: 1_775_683_200_000,
            close_at_unix_ms: 1_775_769_600_000,
            per_consumer_max_credited_units: Some(1_000),
            per_task_max_credited_units: Some(10_000),
            policy_version: 1,
        }
    }

    fn sample_task_consumption_summary() -> TaskConsumptionSummary {
        TaskConsumptionSummary {
            task_id: 42,
            receipt_count: 2,
            accepted_receipt_count: 1,
            challenged_receipt_count: 1,
            total_consumed_tokens: 34,
            total_claimed_consumption_units: 34,
            total_credited_consumption_units: 17,
            last_settlement_height: Some(77),
        }
    }

    #[test]
    fn consumption_record_key_storage_key_is_stable() {
        let key = ConsumptionRecordKey {
            task_id: 42,
            consumer_id: "consumer-bravo".to_string(),
            output_hash: "abc123".to_string(),
            billing_window_id: "bw-1".to_string(),
        };
        assert_eq!(key.storage_key(), "42:consumer-bravo:abc123:bw-1");
    }

    #[test]
    fn state_root_changes_when_consumption_record_changes() {
        let mut st = StateStore::default();
        let before = st.state_root();
        st.put_consumption_record(sample_record());
        let after = st.state_root();
        assert_ne!(before, after);
    }

    #[test]
    fn restore_consumption_record_clears_inconsistent_snapshot() {
        let mut st = StateStore::default();
        let record = sample_record();
        st.put_consumption_record(record.clone());

        let mut invalid = record.clone();
        invalid.credited_consumption_units = Some(invalid.claimed_consumption_units + 1);
        st.restore_consumption_record(&record.key, Some(invalid));

        assert_eq!(st.consumption_record(&record.key), None);
    }

    #[test]
    fn state_root_changes_when_consumer_consumption_nonce_changes() {
        let mut st = StateStore::default();
        let before = st.state_root();
        st.set_consumer_consumption_nonce("consumer-bravo", 7);
        let after = st.state_root();
        assert_ne!(before, after);
    }

    #[test]
    fn billing_window_policy_roundtrip_persists_in_state_store() {
        let mut st = StateStore::default();
        let policy = sample_billing_window_policy();

        assert!(st.set_billing_window_policy(policy.clone()).is_none());
        assert_eq!(
            st.billing_window_policy(&policy.billing_window_id),
            Some(policy.clone())
        );
        assert_eq!(
            st.clear_billing_window_policy(&policy.billing_window_id),
            Some(policy)
        );
        assert_eq!(st.billing_window_policy("bw-1"), None);
    }

    #[test]
    fn state_root_changes_when_billing_window_policy_changes() {
        let mut st = StateStore::default();
        let before = st.state_root();
        st.set_billing_window_policy(sample_billing_window_policy());
        let after = st.state_root();
        assert_ne!(before, after);
    }

    #[test]
    fn billing_window_policy_snapshot_roundtrip_restores_policy_and_state_root() {
        let mut st = StateStore::default();
        let policy = sample_billing_window_policy();
        st.set_billing_window_policy(policy.clone());
        let expected_root = st.state_root();
        let snapshot = st.billing_window_policy_snapshot(&policy.billing_window_id);

        assert_eq!(
            st.clear_billing_window_policy(&policy.billing_window_id),
            Some(policy.clone())
        );
        st.restore_billing_window_policy(&policy.billing_window_id, snapshot);

        assert_eq!(
            st.billing_window_policy(&policy.billing_window_id),
            Some(policy)
        );
        assert_eq!(st.state_root(), expected_root);
    }

    #[test]
    fn restore_billing_window_policy_clears_invalid_snapshot() {
        let mut st = StateStore::default();
        let policy = sample_billing_window_policy();
        st.set_billing_window_policy(policy.clone());

        let mut invalid = policy;
        invalid.close_at_unix_ms = invalid.open_at_unix_ms;
        st.restore_billing_window_policy("bw-1", Some(invalid));

        assert_eq!(st.billing_window_policy("bw-1"), None);
    }

    #[test]
    fn set_billing_window_policy_clears_invalid_policy() {
        let mut st = StateStore::default();
        let policy = sample_billing_window_policy();
        st.set_billing_window_policy(policy.clone());

        let mut invalid = policy.clone();
        invalid.per_consumer_max_credited_units = Some(0);

        assert_eq!(st.set_billing_window_policy(invalid), Some(policy));
        assert_eq!(st.billing_window_policy("bw-1"), None);
    }

    #[test]
    fn set_billing_window_policy_clears_policy_incompatible_with_persisted_record() {
        let mut st = StateStore::default();
        let record = sample_record();
        let key = record.key.clone();
        st.put_consumption_record(record.clone());

        let mut incompatible = sample_billing_window_policy();
        incompatible.close_at_unix_ms = record.accepted_at_unix_ms;

        assert_eq!(st.set_billing_window_policy(incompatible), None);
        assert_eq!(st.billing_window_policy(&key.billing_window_id), None);
    }

    #[test]
    fn restore_billing_window_policy_clears_policy_incompatible_with_persisted_record() {
        let mut st = StateStore::default();
        let record = sample_record();
        let key = record.key.clone();
        let policy = sample_billing_window_policy();
        st.put_consumption_record(record.clone());
        st.set_billing_window_policy(policy.clone());

        let mut incompatible = policy.clone();
        incompatible.close_at_unix_ms = record.accepted_at_unix_ms;

        st.restore_billing_window_policy(&key.billing_window_id, Some(incompatible));

        assert_eq!(st.billing_window_policy(&key.billing_window_id), None);
    }

    #[test]
    fn billing_window_policy_receipt_compatibility_uses_half_open_window() {
        let policy = sample_billing_window_policy();

        assert!(policy.is_receipt_compatible(&policy.billing_window_id, policy.open_at_unix_ms,));
        assert!(
            policy.is_receipt_compatible(&policy.billing_window_id, policy.close_at_unix_ms - 1,)
        );
        assert!(!policy.is_receipt_compatible(&policy.billing_window_id, policy.close_at_unix_ms,));
        assert!(!policy.is_receipt_compatible("bw-2", policy.open_at_unix_ms,));
    }

    #[test]
    fn state_store_billing_window_lookup_requires_covered_acceptance_time() {
        let mut st = StateStore::default();
        let policy = sample_billing_window_policy();
        st.set_billing_window_policy(policy.clone());

        assert_eq!(
            st.billing_window_policy_for_acceptance(
                &policy.billing_window_id,
                policy.open_at_unix_ms,
            ),
            Some(policy.clone())
        );
        assert_eq!(
            st.billing_window_policy_for_acceptance(
                &policy.billing_window_id,
                policy.close_at_unix_ms,
            ),
            None
        );
        assert_eq!(
            st.billing_window_policy_for_acceptance("bw-2", policy.open_at_unix_ms),
            None
        );
    }

    #[test]
    fn task_consumption_summary_snapshot_roundtrip_restores_summary_and_state_root() {
        let mut st = StateStore::default();
        let summary = sample_task_consumption_summary();
        st.set_task_consumption_summary(summary.clone());
        let expected_root = st.state_root();
        let snapshot = st.task_consumption_summary_snapshot(summary.task_id);

        assert_eq!(
            st.clear_task_consumption_summary(summary.task_id),
            Some(summary.clone())
        );
        st.restore_task_consumption_summary(summary.task_id, snapshot);

        assert_eq!(st.task_consumption_summary(summary.task_id), Some(summary));
        assert_eq!(st.state_root(), expected_root);
    }

    #[test]
    fn restore_task_consumption_summary_clears_inconsistent_snapshot() {
        let mut st = StateStore::default();
        let summary = sample_task_consumption_summary();
        st.set_task_consumption_summary(summary.clone());

        let mut invalid = summary;
        invalid.accepted_receipt_count = invalid.receipt_count.saturating_add(1);
        st.restore_task_consumption_summary(42, Some(invalid));

        assert_eq!(st.task_consumption_summary(42), None);
    }

    #[test]
    fn set_task_consumption_summary_clears_inconsistent_summary() {
        let mut st = StateStore::default();
        let summary = sample_task_consumption_summary();
        st.set_task_consumption_summary(summary.clone());

        let mut invalid = summary.clone();
        invalid.accepted_receipt_count = invalid.receipt_count.saturating_add(1);

        assert_eq!(st.set_task_consumption_summary(invalid), Some(summary));
        assert_eq!(st.task_consumption_summary(42), None);
    }

    #[test]
    fn consumption_settlement_state_snapshot_roundtrip_restores_state_root() {
        let mut st = StateStore::default();
        let record = sample_record();
        let key = record.key.clone();
        let policy = sample_billing_window_policy();
        let summary = sample_task_consumption_summary();

        st.put_consumption_record(record.clone());
        st.set_consumer_consumption_nonce(&key.consumer_id, record.consumer_nonce);
        st.set_billing_window_policy(policy.clone());
        st.set_task_consumption_summary(summary.clone());

        let expected_root = st.state_root();
        let snapshot = st.consumption_settlement_state_snapshot(&key);
        assert!(snapshot.is_persistable_snapshot_for(&key));

        assert_eq!(st.remove_consumption_record(&key), Some(record.clone()));
        st.set_consumer_consumption_nonce(&key.consumer_id, record.consumer_nonce + 1);
        assert_eq!(
            st.clear_billing_window_policy(&key.billing_window_id),
            Some(policy.clone())
        );
        assert_eq!(
            st.clear_task_consumption_summary(key.task_id),
            Some(summary.clone())
        );

        st.restore_consumption_settlement_state(&key, snapshot);

        assert_eq!(st.consumption_record(&key), Some(record));
        assert_eq!(
            st.consumer_consumption_nonce(&key.consumer_id),
            Some(sample_record().consumer_nonce)
        );
        assert_eq!(
            st.billing_window_policy(&key.billing_window_id),
            Some(policy)
        );
        assert_eq!(st.task_consumption_summary(key.task_id), Some(summary));
        assert_eq!(st.state_root(), expected_root);
    }

    #[test]
    fn settlement_snapshot_rejects_billing_policy_outside_receipt_window() {
        let record = sample_record();
        let key = record.key.clone();
        let summary = sample_task_consumption_summary();
        let mut incompatible_policy = sample_billing_window_policy();
        incompatible_policy.close_at_unix_ms = record.accepted_at_unix_ms;

        let snapshot = ConsumptionSettlementStateSnapshot {
            key: key.clone(),
            record: Some(record.clone()),
            consumer_nonce: Some(record.consumer_nonce),
            billing_window_policy: Some(incompatible_policy),
            task_summary: Some(summary),
        };

        assert!(!snapshot.has_record_compatible_billing_window_policy());
        assert!(!snapshot.is_persistable_snapshot_for(&key));
    }

    #[test]
    fn settlement_snapshot_rejects_billing_policy_that_undercaps_record_credit() {
        let record = sample_record();
        let key = record.key.clone();
        let summary = sample_task_consumption_summary();
        let mut incompatible_policy = sample_billing_window_policy();
        incompatible_policy.per_consumer_max_credited_units = Some(
            record
                .credited_consumption_units
                .expect("sample record credited units")
                - 1,
        );

        let snapshot = ConsumptionSettlementStateSnapshot {
            key: key.clone(),
            record: Some(record.clone()),
            consumer_nonce: Some(record.consumer_nonce),
            billing_window_policy: Some(incompatible_policy),
            task_summary: Some(summary),
        };

        assert!(!snapshot.has_record_compatible_billing_window_policy());
        assert!(!snapshot.is_persistable_snapshot_for(&key));
    }

    #[test]
    fn settlement_snapshot_rejects_billing_policy_that_undercaps_record_task_credit() {
        let record = sample_record();
        let key = record.key.clone();
        let summary = sample_task_consumption_summary();
        let mut incompatible_policy = sample_billing_window_policy();
        incompatible_policy.per_task_max_credited_units = Some(
            record
                .credited_consumption_units
                .expect("sample record credited units")
                - 1,
        );

        let snapshot = ConsumptionSettlementStateSnapshot {
            key: key.clone(),
            record: Some(record.clone()),
            consumer_nonce: Some(record.consumer_nonce),
            billing_window_policy: Some(incompatible_policy),
            task_summary: Some(summary),
        };

        assert!(!snapshot.has_record_compatible_billing_window_policy());
        assert!(!snapshot.is_persistable_snapshot_for(&key));
    }

    #[test]
    fn settlement_snapshot_rejects_regressed_consumer_nonce() {
        let record = sample_record();
        let key = record.key.clone();

        let snapshot = ConsumptionSettlementStateSnapshot {
            key: key.clone(),
            record: Some(record.clone()),
            consumer_nonce: Some(record.consumer_nonce - 1),
            billing_window_policy: Some(sample_billing_window_policy()),
            task_summary: Some(sample_task_consumption_summary()),
        };

        assert!(!snapshot.has_record_compatible_consumer_nonce());
        assert!(!snapshot.is_persistable_snapshot_for(&key));
    }

    #[test]
    fn settlement_snapshot_rejects_task_summary_that_undercounts_record() {
        let record = sample_record();
        let key = record.key.clone();
        let mut summary = sample_task_consumption_summary();
        summary.total_claimed_consumption_units = record.claimed_consumption_units - 1;

        let snapshot = ConsumptionSettlementStateSnapshot {
            key: key.clone(),
            record: Some(record.clone()),
            consumer_nonce: Some(record.consumer_nonce),
            billing_window_policy: Some(sample_billing_window_policy()),
            task_summary: Some(summary),
        };

        assert!(!snapshot.has_record_compatible_task_summary());
        assert!(!snapshot.is_persistable_snapshot_for(&key));
    }

    #[test]
    fn settlement_snapshot_omits_and_restore_discards_incompatible_billing_policy() {
        let mut st = StateStore::default();
        let record = sample_record();
        let key = record.key.clone();
        let summary = sample_task_consumption_summary();
        let mut incompatible_policy = sample_billing_window_policy();
        incompatible_policy.close_at_unix_ms = record.accepted_at_unix_ms;

        st.put_consumption_record(record.clone());
        st.set_consumer_consumption_nonce(&key.consumer_id, record.consumer_nonce);
        st.set_billing_window_policy(incompatible_policy.clone());
        st.set_task_consumption_summary(summary.clone());

        let snapshot = st.consumption_settlement_state_snapshot(&key);
        assert_eq!(snapshot.record, Some(record.clone()));
        assert_eq!(snapshot.billing_window_policy, None);
        assert!(snapshot.is_persistable_snapshot_for(&key));

        st.restore_consumption_settlement_state(
            &key,
            ConsumptionSettlementStateSnapshot {
                key: key.clone(),
                record: Some(record.clone()),
                consumer_nonce: Some(record.consumer_nonce),
                billing_window_policy: Some(incompatible_policy),
                task_summary: Some(summary.clone()),
            },
        );

        assert_eq!(st.consumption_record(&key), Some(record));
        assert_eq!(
            st.consumer_consumption_nonce(&key.consumer_id),
            Some(sample_record().consumer_nonce)
        );
        assert_eq!(st.billing_window_policy(&key.billing_window_id), None);
        assert_eq!(st.task_consumption_summary(key.task_id), Some(summary));
    }

    #[test]
    fn settlement_snapshot_omits_and_restore_discards_policy_that_undercaps_record_credit() {
        let mut st = StateStore::default();
        let record = sample_record();
        let key = record.key.clone();
        let summary = sample_task_consumption_summary();
        let mut incompatible_policy = sample_billing_window_policy();
        incompatible_policy.per_consumer_max_credited_units = Some(
            record
                .credited_consumption_units
                .expect("sample record credited units")
                - 1,
        );

        st.put_consumption_record(record.clone());
        st.set_consumer_consumption_nonce(&key.consumer_id, record.consumer_nonce);
        st.set_billing_window_policy(incompatible_policy.clone());
        st.set_task_consumption_summary(summary.clone());

        let snapshot = st.consumption_settlement_state_snapshot(&key);
        assert_eq!(snapshot.record, Some(record.clone()));
        assert_eq!(snapshot.billing_window_policy, None);
        assert!(snapshot.is_persistable_snapshot_for(&key));

        st.restore_consumption_settlement_state(
            &key,
            ConsumptionSettlementStateSnapshot {
                key: key.clone(),
                record: Some(record.clone()),
                consumer_nonce: Some(record.consumer_nonce),
                billing_window_policy: Some(incompatible_policy),
                task_summary: Some(summary.clone()),
            },
        );

        assert_eq!(st.consumption_record(&key), Some(record));
        assert_eq!(
            st.consumer_consumption_nonce(&key.consumer_id),
            Some(sample_record().consumer_nonce)
        );
        assert_eq!(st.billing_window_policy(&key.billing_window_id), None);
        assert_eq!(st.task_consumption_summary(key.task_id), Some(summary));
    }

    #[test]
    fn settlement_snapshot_omits_and_restore_discards_policy_that_undercaps_task_credit() {
        let mut st = StateStore::default();
        let record = sample_record();
        let key = record.key.clone();
        let summary = sample_task_consumption_summary();
        let mut incompatible_policy = sample_billing_window_policy();
        incompatible_policy.per_task_max_credited_units = Some(
            record
                .credited_consumption_units
                .expect("sample record credited units")
                - 1,
        );

        st.put_consumption_record(record.clone());
        st.set_consumer_consumption_nonce(&key.consumer_id, record.consumer_nonce);
        st.set_billing_window_policy(incompatible_policy.clone());
        st.set_task_consumption_summary(summary.clone());

        let snapshot = st.consumption_settlement_state_snapshot(&key);
        assert_eq!(snapshot.record, Some(record.clone()));
        assert_eq!(snapshot.billing_window_policy, None);
        assert!(snapshot.is_persistable_snapshot_for(&key));

        st.restore_consumption_settlement_state(
            &key,
            ConsumptionSettlementStateSnapshot {
                key: key.clone(),
                record: Some(record.clone()),
                consumer_nonce: Some(record.consumer_nonce),
                billing_window_policy: Some(incompatible_policy),
                task_summary: Some(summary.clone()),
            },
        );

        assert_eq!(st.consumption_record(&key), Some(record));
        assert_eq!(
            st.consumer_consumption_nonce(&key.consumer_id),
            Some(sample_record().consumer_nonce)
        );
        assert_eq!(st.billing_window_policy(&key.billing_window_id), None);
        assert_eq!(st.task_consumption_summary(key.task_id), Some(summary));
    }

    #[test]
    fn settlement_snapshot_restore_discards_regressed_consumer_nonce_and_undercounted_summary() {
        let mut st = StateStore::default();
        let record = sample_record();
        let key = record.key.clone();
        let policy = sample_billing_window_policy();
        let mut summary = sample_task_consumption_summary();
        summary.total_claimed_consumption_units = record.claimed_consumption_units - 1;

        st.restore_consumption_settlement_state(
            &key,
            ConsumptionSettlementStateSnapshot {
                key: key.clone(),
                record: Some(record.clone()),
                consumer_nonce: Some(record.consumer_nonce - 1),
                billing_window_policy: Some(policy.clone()),
                task_summary: Some(summary),
            },
        );

        assert_eq!(st.consumption_record(&key), Some(record));
        assert_eq!(st.consumer_consumption_nonce(&key.consumer_id), None);
        assert_eq!(
            st.billing_window_policy(&key.billing_window_id),
            Some(policy)
        );
        assert_eq!(st.task_consumption_summary(key.task_id), None);
    }
}

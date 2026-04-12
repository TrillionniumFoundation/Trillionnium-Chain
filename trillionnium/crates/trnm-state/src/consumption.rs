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
}

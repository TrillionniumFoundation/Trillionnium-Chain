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
}

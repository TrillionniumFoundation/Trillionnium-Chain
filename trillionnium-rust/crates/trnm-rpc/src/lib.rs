pub mod reliability;

mod relay;

use serde::{Deserialize, Serialize};
use trnm_types::{GovProposalStatus, TaskStatus};

pub use relay::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskQueryResponse {
    pub task_id: u64,
    pub status: TaskStatus,
    pub worker: Option<String>,
    pub bounty: u128,
    pub result_hash_hex: Option<String>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovProposalQueryResponse {
    pub proposal_id: u64,
    pub title: String,
    pub proposer: String,
    pub status: GovProposalStatus,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovParamQueryResponse {
    pub key: String,
    pub value: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQueryResponse {
    pub event_type: String,
    pub task_id: u64,
    pub from_status: String,
    pub to_status: String,
    pub actor: String,
    pub tx_id: u64,
    pub block_height: u64,
    pub state_root: String,
    pub ts_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRequestQueryResponse {
    pub request_id: String,
    pub task_id: u64,
    pub channel: String,
    pub user_id: String,
    pub session_id: String,
    pub text: String,
    pub idempotency_key: String,
    pub status: String,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFullQueryResponse {
    pub request: MessageRequestQueryResponse,
    pub verifier_status: Option<String>,
    pub resolution_code: Option<String>,
    pub result_hash: Option<String>,
    pub commit_tx_hash: Option<String>,
    pub reveal_tx_hash: Option<String>,
    pub events: Vec<EventQueryResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rpc_schema_smoke_task_fields_stable() {
        let task = TaskQueryResponse {
            task_id: 1,
            status: TaskStatus::Open,
            worker: None,
            bounty: 100,
            result_hash_hex: None,
            version: 1,
        };
        let v = serde_json::to_value(task).unwrap();
        let obj = v.as_object().unwrap();
        for k in [
            "task_id",
            "status",
            "worker",
            "bounty",
            "result_hash_hex",
            "version",
        ] {
            assert!(obj.contains_key(k), "missing key: {}", k);
        }
    }

    #[test]
    fn rpc_schema_smoke_event_fields_stable() {
        let evt = EventQueryResponse {
            event_type: "commit".into(),
            task_id: 1,
            from_status: "Assigned".into(),
            to_status: "Committed".into(),
            actor: "worker1".into(),
            tx_id: 7,
            block_height: 2,
            state_root: "abc".into(),
            ts_unix_ms: 1,
        };
        let v = serde_json::to_value(evt).unwrap();
        assert_eq!(
            v,
            json!({
                "event_type":"commit",
                "task_id":1,
                "from_status":"Assigned",
                "to_status":"Committed",
                "actor":"worker1",
                "tx_id":7,
                "block_height":2,
                "state_root":"abc",
                "ts_unix_ms":1
            })
        );
    }
}

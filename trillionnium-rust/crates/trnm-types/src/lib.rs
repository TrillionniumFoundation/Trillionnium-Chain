use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    pub id: u64,
    pub version: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    Open = 0,
    Assigned = 1,
    Committed = 2,
    Revealed = 3,
    Challenged = 4,
    Completed = 5,
    Slashed = 6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskObject {
    pub task_id: u64,
    pub creator: String,
    pub bounty: u128,
    pub status: TaskStatus,
    pub worker: Option<String>,
    pub committed_hash: Option<Hash32>,
    pub result_hash: Option<Hash32>,
    pub reveal_salt: Option<[u8; 32]>,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tx {
    pub id: u64,
    pub read_set: Vec<ObjectRef>,
    pub write_set: Vec<ObjectRef>,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_structs() {
        let tx = Tx {
            id: 1,
            read_set: vec![ObjectRef { id: 7, version: 1 }],
            write_set: vec![ObjectRef { id: 8, version: 2 }],
            payload: vec![1, 2, 3],
        };
        assert_eq!(tx.id, 1);
        assert_eq!(TaskStatus::Open, TaskStatus::Open);
    }
}

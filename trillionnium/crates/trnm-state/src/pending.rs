use trnm_types::ObjectRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingGovParamUpdate {
    pub key_id: u64,
    pub key: String,
    pub value: String,
    pub activate_at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingResolveApproval {
    pub(crate) slash_worker: bool,
    pub(crate) confirmations: u8,
    pub(crate) first_approver: String,
    pub(crate) authority_set: String,
    pub(crate) task_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingResolveApprovalSnapshot {
    pub slash_worker: bool,
    pub confirmations: u8,
    pub first_approver: String,
    pub authority_set: String,
    pub task_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovParamUpdateOutcome {
    Applied(ObjectRef),
    Scheduled { activate_at_height: u64 },
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovPendingUpdateAction {
    Enforce,
    Replace,
    Cancel,
}

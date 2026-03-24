use trnm_state::{
    GovParamUpdateOutcome, GovPendingUpdateAction, PendingResolveApprovalSnapshot, StateStore,
};
use trnm_types::{TaskObject, TaskStatus};

const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
const DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER: &str = "governance.resolve_authority";

#[path = "lifecycle.rs"]
mod lifecycle;
#[path = "members.rs"]
mod members;
#[path = "toggle.rs"]
mod toggle;
#[path = "unpause.rs"]
mod unpause;

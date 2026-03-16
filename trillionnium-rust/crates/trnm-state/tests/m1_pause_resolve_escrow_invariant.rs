use trnm_state::{GovParamUpdateOutcome, GovPendingUpdateAction, StateStore};

const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
const DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER: &str = "governance.resolve_authority";

#[path = "m1_pause_resolve_escrow_invariant/toggle.rs"]
mod m1_pause_resolve_escrow_invariant_toggle;

#[path = "m1_pause_resolve_escrow_invariant/unpause.rs"]
mod m1_pause_resolve_escrow_invariant_unpause;

#[path = "m1_pause_resolve_escrow_invariant/members.rs"]
mod m1_pause_resolve_escrow_invariant_members;

#[path = "m1_pause_resolve_escrow_invariant/lifecycle.rs"]
mod m1_pause_resolve_escrow_invariant_lifecycle;

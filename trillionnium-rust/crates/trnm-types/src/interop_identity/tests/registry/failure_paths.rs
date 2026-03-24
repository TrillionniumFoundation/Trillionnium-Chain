use super::*;

#[path = "failure_paths/controller_mismatch.rs"]
mod controller_mismatch;
#[path = "failure_paths/lifecycle_and_issue_inputs.rs"]
mod lifecycle_and_issue_inputs;
#[path = "failure_paths/missing_subject_and_unknown_token.rs"]
mod missing_subject_and_unknown_token;
#[path = "failure_paths/renew_actor_sanitation.rs"]
mod renew_actor_sanitation;
#[path = "failure_paths/revoke_actor_sanitation.rs"]
mod revoke_actor_sanitation;
#[path = "failure_paths/verify_actor_sanitation.rs"]
mod verify_actor_sanitation;

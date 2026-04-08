use super::*;

#[path = "resolve_auth/authority_validation.rs"]
mod authority_validation;
#[path = "resolve_auth/failure_paths.rs"]
mod failure_paths;
#[path = "resolve_auth/multisig_pending.rs"]
mod multisig_pending;
#[path = "resolve_auth/pause_precedence/mod.rs"]
mod pause_precedence;
#[path = "resolve_auth/system_accounts/mod.rs"]
mod system_accounts;

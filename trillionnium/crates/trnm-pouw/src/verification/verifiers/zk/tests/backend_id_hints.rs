use super::*;

#[path = "backend_id_hints/backend_id.rs"]
mod backend_id;
#[path = "backend_id_hints/selected_backend_fail_closed.rs"]
mod selected_backend_fail_closed;
#[path = "backend_id_hints/legacy_and_explicit_zk.rs"]
mod legacy_and_explicit_zk;
#[path = "backend_id_hints/canonicalization.rs"]
mod canonicalization;
#[path = "backend_id_hints/alias_handling.rs"]
mod alias_handling;

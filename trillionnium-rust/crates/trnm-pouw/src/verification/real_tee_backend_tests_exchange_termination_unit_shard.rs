pub(super) use super::*;

#[path = "real_tee_backend_tests_exchange_termination_unit_shard/support.rs"]
mod support;
#[path = "real_tee_backend_tests_exchange_termination_unit_shard/unit_exchange_success.rs"]
mod unit_exchange_success;
#[path = "real_tee_backend_tests_exchange_termination_unit_shard/unit_exchange_fail_closed.rs"]
mod unit_exchange_fail_closed;
#[path = "real_tee_backend_tests_exchange_termination_unit_shard/shard_exchange_success.rs"]
mod shard_exchange_success;
#[path = "real_tee_backend_tests_exchange_termination_unit_shard/shard_exchange_fail_closed.rs"]
mod shard_exchange_fail_closed;

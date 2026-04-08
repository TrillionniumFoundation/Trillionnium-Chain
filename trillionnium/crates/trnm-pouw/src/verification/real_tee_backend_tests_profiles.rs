use super::*;

#[path = "real_tee_backend_tests_profiles_clients.rs"]
mod helpers_clients;
use helpers_clients::*;

#[path = "real_tee_backend_tests_profiles_telemetry_helpers.rs"]
mod helpers_telemetry;
use helpers_telemetry::*;

#[path = "real_tee_backend_tests_profiles_http_runtime.rs"]
mod helpers_http_runtime;
use helpers_http_runtime::*;

#[path = "real_tee_backend_tests_profiles_http_session.rs"]
mod helpers_http_session;
use helpers_http_session::*;

#[path = "real_tee_backend_tests_profiles_registry.rs"]
mod tests_registry;

#[path = "real_tee_backend_tests_profiles_codec.rs"]
mod tests_codec;

#[path = "real_tee_backend_tests_profiles_provider.rs"]
mod tests_provider;

#[path = "real_tee_backend_tests_profiles_telemetry.rs"]
mod tests_telemetry;

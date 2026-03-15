#[cfg(test)]
#[path = "proof_adapter_tests_standard.rs"]
mod standard_tests;

#[cfg(test)]
#[path = "proof_adapter_tests_normalization.rs"]
mod normalization_tests;

#[cfg(test)]
#[path = "proof_adapter_tests_tee.rs"]
mod tee_tests;

#[cfg(test)]
#[path = "proof_adapter_tests_zk.rs"]
mod zk_tests;

#[cfg(test)]
#[path = "proof_adapter_tests_builder.rs"]
mod builder_tests;

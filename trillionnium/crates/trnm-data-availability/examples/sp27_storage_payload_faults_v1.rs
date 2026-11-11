//! Explicit SP27-05 provider payload-fault policy, cold restore and sealed use.
#[cfg(target_os = "linux")]
#[path = "cell_sealed_research_v2/mod.rs"]
pub mod linux;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run_payload_faults()
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("Linux immutable memfd and original wait4 owner required".into())
}

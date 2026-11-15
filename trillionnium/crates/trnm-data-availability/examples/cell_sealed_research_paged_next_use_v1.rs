//! Explicit paged RS(6,4) research custody, cold consumer reconstruction and
//! sealed local next use under one original operation deadline.
#[cfg(target_os = "linux")]
#[path = "cell_sealed_research_v2/mod.rs"]
pub mod linux;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run_paged()
}
#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("Linux immutable memfd and original wait4 owner required".into())
}

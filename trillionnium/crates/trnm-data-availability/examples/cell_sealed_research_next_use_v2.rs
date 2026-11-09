//! Same-operation complete BEP52 transfer, TCA3 cold recovery, CTS1 admission,
//! and two actual CHB1 sealed-byte forwards. Explicit loopback research only.

#[cfg(target_os = "linux")]
#[path = "cell_sealed_research_v2/mod.rs"]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("Linux immutable memfd and original wait4 owner required".into())
}

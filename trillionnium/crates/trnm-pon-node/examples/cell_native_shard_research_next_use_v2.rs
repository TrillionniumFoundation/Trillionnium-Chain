//! Actual pinned BT acquisition -> funded local native paged RS46 cycle ->
//! cold four-shard reconstruction -> original CTS1 and sealed-worker forwards.
//! Explicit known-key development research; all production permissions stay false.

#[cfg(target_os = "linux")]
mod cell_native_shard_research_v2;
#[cfg(target_os = "linux")]
#[path = "../../trnm-data-availability/examples/cell_sealed_research_v2/mod.rs"]
mod original;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Keep the unchanged original complete-copy entry reachable as a separate
    // owner. This explicit entry selects the native shard callback instead.
    let _ = original::run;
    original::run_with_retention(cell_native_shard_research_v2::retain)
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("Linux immutable memfd and original wait4 owner required".into())
}

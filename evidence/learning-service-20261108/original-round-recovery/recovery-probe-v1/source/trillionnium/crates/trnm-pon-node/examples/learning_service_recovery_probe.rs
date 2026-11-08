//! Bounded same-owner development reorg and restoration probe.
#[cfg(unix)]
#[path = "support/learning_service_recovery_probe_unix.rs"]
mod platform;

#[cfg(unix)]
fn main() -> trnm_pon_node::Result<()> {
    platform::run()
}

#[cfg(not(unix))]
fn main() {
    eprintln!(
        "UNSUPPORTED: learning_service_recovery_probe requires the Unix native owner profile"
    );
    std::process::exit(2);
}

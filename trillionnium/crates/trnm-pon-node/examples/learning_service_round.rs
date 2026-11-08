//! Native development service settlement for one original inherited operation.
//! The owner implementation requires Unix file identity, locking and durability.
#[cfg(unix)]
#[path = "support/learning_service_round_unix.rs"]
mod platform;

#[cfg(unix)]
fn main() -> trnm_pon_node::Result<()> {
    platform::run()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("UNSUPPORTED: learning_service_round requires the Unix native owner profile");
    std::process::exit(2);
}

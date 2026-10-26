//! Research-only compact output of unchanged production W1 packets.
#[path = "support/w1_deferred_producer.rs"]
mod producer;
#[path = "support/w1_compact_miner.rs"]
mod research;

fn main() {
    if let Err(error) = research::Options::read().and_then(research::run) {
        eprintln!("COMPACT_RESEARCH_FAILURE: {error}");
        std::process::exit(1);
    }
}

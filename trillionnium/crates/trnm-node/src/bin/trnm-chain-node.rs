use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use trnm_node::live::node::{load_live_chain_config, LiveChain};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-chain-node",
    version,
    about = "TRNM development-only signed durable loopback devnet node (not a production PoCO node)"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = load_live_chain_config(&args.config)?;
    let listen_addr = config.listen_addr;
    let chain = Arc::new(LiveChain::open(config)?);
    println!(
        "[chain] listening={} chain_id={} genesis_hash_hex={} development_only=true production_ready=false",
        listen_addr,
        chain.config().chain_id,
        chain.genesis_hash_hex()
    );
    chain.serve()
}

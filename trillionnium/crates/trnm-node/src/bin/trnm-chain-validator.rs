use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use trnm_node::live::validator::{load_validator_config, ValidatorService};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-chain-validator",
    version,
    about = "TRNM development-only loopback devnet validator with durable Ed25519 anti-equivocation state"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = load_validator_config(&args.config)?;
    let address = config.listen_addr;
    let service = Arc::new(ValidatorService::open(config)?);
    println!(
        "[validator] listening={} public_key_hex={} development_only=true production_ready=false",
        address,
        service.public_key_hex()
    );
    service.serve()
}

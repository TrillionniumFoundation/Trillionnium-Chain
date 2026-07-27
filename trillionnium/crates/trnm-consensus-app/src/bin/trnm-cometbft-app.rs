use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use tendermint_abci::ServerBuilder;
use trnm_consensus_app::{CometBftApplication, ConsensusAppConfig};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-cometbft-app",
    version,
    about = "TRNM deterministic ABCI++ application adapter for CometBFT"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, default_value = "127.0.0.1:26658")]
    listen_addr: SocketAddr,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config: ConsensusAppConfig = serde_json::from_slice(
        &fs::read(&args.config)
            .with_context(|| format!("read app config {}", args.config.display()))?,
    )
    .with_context(|| format!("decode app config {}", args.config.display()))?;
    let app = CometBftApplication::new(config)?;
    let server = ServerBuilder::default().bind(args.listen_addr, app)?;
    eprintln!("[trnm-cometbft-app] listening={}", server.local_addr());
    server.listen()?;
    Ok(())
}

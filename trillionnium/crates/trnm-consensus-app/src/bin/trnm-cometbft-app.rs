use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use tendermint_abci::ServerBuilder;
use trnm_consensus_app::{CometBftApplication, ConsensusAppConfig, TestCrashPlan, TestCrashStage};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum UnsafeTestCrashStage {
    ProcessProposal,
    FinalizeBlock,
    CommitAfterPersist,
}

impl From<UnsafeTestCrashStage> for TestCrashStage {
    fn from(value: UnsafeTestCrashStage) -> Self {
        match value {
            UnsafeTestCrashStage::ProcessProposal => Self::ProcessProposal,
            UnsafeTestCrashStage::FinalizeBlock => Self::FinalizeBlock,
            UnsafeTestCrashStage::CommitAfterPersist => Self::CommitAfterPersist,
        }
    }
}

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
    #[arg(long, value_enum, hide = true, requires_all = ["unsafe_test_crash_height", "unsafe_test_crash_marker"])]
    unsafe_test_crash_stage: Option<UnsafeTestCrashStage>,
    #[arg(long, hide = true, requires_all = ["unsafe_test_crash_stage", "unsafe_test_crash_marker"])]
    unsafe_test_crash_height: Option<u64>,
    #[arg(long, hide = true, requires_all = ["unsafe_test_crash_stage", "unsafe_test_crash_height"])]
    unsafe_test_crash_marker: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config: ConsensusAppConfig = serde_json::from_slice(
        &fs::read(&args.config)
            .with_context(|| format!("read app config {}", args.config.display()))?,
    )
    .with_context(|| format!("decode app config {}", args.config.display()))?;
    let app = match (
        args.unsafe_test_crash_stage,
        args.unsafe_test_crash_height,
        args.unsafe_test_crash_marker,
    ) {
        (Some(stage), Some(height), Some(marker_path)) => {
            CometBftApplication::new_with_test_crash_plan(
                config,
                TestCrashPlan {
                    stage: stage.into(),
                    height,
                    marker_path,
                },
            )?
        }
        (None, None, None) => CometBftApplication::new(config)?,
        _ => unreachable!("clap enforces complete unsafe test crash arguments"),
    };
    let server = ServerBuilder::default().bind(args.listen_addr, app)?;
    eprintln!("[trnm-cometbft-app] listening={}", server.local_addr());
    server.listen()?;
    Ok(())
}

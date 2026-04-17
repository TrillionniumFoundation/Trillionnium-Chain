use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "trnm-cli",
    version,
    about = "Trillionnium native CLI (wallet/query/tx tooling)"
)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) cmd: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Transaction related commands
    Tx {
        #[command(subcommand)]
        tx: TxCommand,
    },
    /// Wallet related commands
    Wallet {
        #[command(subcommand)]
        wallet: WalletCommand,
    },
    /// Query commands (RPC/model-facing)
    Query {
        #[command(subcommand)]
        query: QueryCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TxCommand {
    /// Legacy commit-result tx (compatibility-only; scheduled for retirement, do not use for new operator flows)
    CommitResult {
        task_id: u64,
        worker: String,
        commit_hash: String,
        nonce: u64,
    },
    /// Legacy reveal-result tx (compatibility-only; scheduled for retirement, do not use for new operator flows)
    RevealResult {
        task_id: u64,
        result_hash: String,
        salt_hex: String,
    },
    /// Query tx lifecycle status by hash
    Query { tx_hash: String },
    /// Wait until tx reaches committed/fail lifecycle state
    Wait {
        tx_hash: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// Transfer balance from one wallet to another
    Transfer {
        #[arg(long, default_value = "default")]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value = "trnm")]
        denom: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum WalletCommand {
    /// Create a new local wallet
    Create {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Alias of wallet create (backward compatible)
    Generate {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import private key hex into local wallet store
    Import {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        private_key_hex: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print derived address from local wallet
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Sign arbitrary text with a local wallet
    Sign {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum QueryCommand {
    /// Query account balance via new RPC/model contract
    Balance {
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long, default_value = "trnm")]
        denom: String,
    },
    /// Query task status / audit view via RPC
    Task { task_id: u64 },
    /// Query task event timeline / audit view via RPC
    Events {
        task_id: u64,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        summary: bool,
    },
    /// Query full request timeline / audit view via RPC
    RequestFull {
        request_id: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        summary: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BalanceQueryResponse {
    pub(crate) address: String,
    pub(crate) balance: String,
    pub(crate) denom: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TransferTxRequest {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) amount: String,
    pub(crate) denom: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TransferTxResponse {
    pub(crate) tx_hash: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TxQueryResponse {
    pub(crate) tx_hash: String,
    pub(crate) status: String,
    pub(crate) error: Option<String>,
}

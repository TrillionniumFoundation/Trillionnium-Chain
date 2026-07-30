use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use trnm_consensus_app::{run_persistent_scale_gate, PersistentScaleConfig, PersistentScaleReport};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-persistent-scale",
    about = "Run the persistent SQLite AppHash v4 scale gate",
    after_help = "Defaults are the formal 1,000,000-object plus 1,000,000-update profile. \
                  The work directory must be absent or empty and is always preserved."
)]
struct Cli {
    #[arg(long)]
    work_dir: PathBuf,

    #[arg(long, default_value_t = 1_000_000)]
    objects: u64,

    #[arg(long, default_value_t = 1_000_000)]
    updates: u64,

    #[arg(long, default_value_t = 10_000)]
    batch_size: u64,

    #[arg(long, default_value_t = 10_000)]
    live_set: u64,

    #[arg(long, default_value_t = 64)]
    prune_retain_versions: u64,

    #[arg(long, default_value_t = 256)]
    prune_batch_rows: usize,

    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    prune_batch_logical_bytes: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let report = run_persistent_scale_gate(PersistentScaleConfig {
        work_dir: cli.work_dir,
        objects: cli.objects,
        updates: cli.updates,
        batch_size: cli.batch_size,
        live_set: cli.live_set,
        prune_retain_versions: cli.prune_retain_versions,
        prune_batch_rows: cli.prune_batch_rows,
        prune_batch_logical_bytes: cli.prune_batch_logical_bytes,
    });
    match print_report(&report) {
        Ok(()) if report.passed => ExitCode::SUCCESS,
        Ok(()) => {
            eprintln!(
                "persistent AppHash v4 scale gate failed: {}",
                report.failure_reason.as_deref().unwrap_or("unknown reason")
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("serialize persistent AppHash v4 scale report: {error}");
            ExitCode::from(2)
        }
    }
}

fn print_report(report: &PersistentScaleReport) -> serde_json::Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

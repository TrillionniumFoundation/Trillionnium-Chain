use std::process::ExitCode;

use clap::Parser;
use trnm_consensus_app::{run_auth_tree_scale_gate, AuthTreeScaleConfig};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-auth-tree-scale",
    about = "Run the executable AppHash v4 JMT scale gate",
    after_help = "Defaults exercise 1,000,000 objects and 1,000,000 updates. \
                  Smaller workloads are reported as smoke/custom runs and never as the million gate."
)]
struct Cli {
    #[arg(long, default_value_t = 1_000_000)]
    objects: u64,

    #[arg(long, default_value_t = 1_000_000)]
    updates: u64,

    #[arg(long, default_value_t = 10_000)]
    batch_size: u64,

    #[arg(long, default_value_t = 10_000)]
    live_set: u64,

    #[arg(long, default_value_t = 10)]
    window_batches: u64,

    #[arg(long, default_value_t = 3.0)]
    max_late_p95_ratio: f64,

    #[arg(long, default_value_t = 5_000)]
    latency_slack_us: u64,

    #[arg(long, default_value_t = 64)]
    prune_retain_versions: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let report = run_auth_tree_scale_gate(AuthTreeScaleConfig {
        objects: cli.objects,
        updates: cli.updates,
        batch_size: cli.batch_size,
        live_set: cli.live_set,
        window_batches: cli.window_batches,
        max_late_p95_ratio: cli.max_late_p95_ratio,
        latency_slack_us: cli.latency_slack_us,
        prune_retain_versions: cli.prune_retain_versions,
    });
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("serialize AppHash v4 scale report: {error}");
            return ExitCode::from(2);
        }
    }
    if report.passed {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "AppHash v4 scale gate failed: {}",
            report.failure_reason.as_deref().unwrap_or("unknown reason")
        );
        ExitCode::FAILURE
    }
}

use super::*;

#[path = "block_apply.rs"]
mod block_apply;
pub(crate) use block_apply::*;

#[path = "block_bft.rs"]
mod block_bft;
pub(crate) use block_bft::*;

#[path = "block_persist.rs"]
mod block_persist;
pub(crate) use block_persist::*;

#[path = "block_timeout.rs"]
mod block_timeout;
pub(crate) use block_timeout::*;

#[path = "loop_block.rs"]
mod loop_block;
pub(crate) use loop_block::*;

#[path = "loop_init.rs"]
mod loop_init;
pub(crate) use loop_init::*;

#[path = "metrics_aggregation.rs"]
mod metrics_aggregation;
pub(crate) use metrics_aggregation::*;

#[path = "metrics_emit.rs"]
mod metrics_emit;
pub(crate) use metrics_emit::*;

#[path = "loop_metrics.rs"]
mod loop_metrics;

#[path = "loop_types.rs"]
mod loop_types;
pub(crate) use loop_types::*;

pub(crate) fn execute_runtime_loop(args: Args) -> Result<()> {
    let cfg = load_config(&args.config)?;
    log_runtime_start(&args, &cfg);

    let (wal_dir, recovered, restored_lock) = initialize_runtime_recovery(&args)?;
    let mut runtime = build_runtime_state(&args, cfg, wal_dir, recovered, restored_lock)?;
    let mut metrics = RuntimeMetrics::new(args.validators.max(1));

    while execute_runtime_height(&args, &mut runtime, &mut metrics)? {}

    emit_runtime_summary(&runtime, &metrics);
    Ok(())
}

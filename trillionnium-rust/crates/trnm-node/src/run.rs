use anyhow::Result;
use std::{collections::HashSet, thread, time::Duration};

use crate::args::Args;
use crate::run_apply::ApplyRuntimeTelemetry;
use crate::run_bft::BftHeightTelemetry;
use crate::run_bootstrap::{bootstrap_node_runtime, BootstrappedNodeRuntime};
use crate::run_height::{execute_height_step, HeightLoopControl};
use crate::run_metrics::RuntimeMetrics;

pub(crate) fn run_node(args: Args) -> Result<()> {
    let boot = bootstrap_node_runtime(&args)?;
    let BootstrappedNodeRuntime {
        cfg,
        wal_dir,
        restored_lock,
        height,
        state,
        mempool,
        wal_entries,
        checkpoints,
        bft_jitter,
    } = boot;

    let mut restored_lock = restored_lock;
    let mut height = height;
    let mut state = state;
    let mut mempool = mempool;
    let mut wal_entries = wal_entries;
    let mut checkpoints = checkpoints;
    let mut bft_jitter = bft_jitter;
    let mut known_task_ids: HashSet<u64> = HashSet::new();
    let mut runtime_metrics = RuntimeMetrics::default();
    let mut apply_telemetry = ApplyRuntimeTelemetry::default();
    let mut bft_telemetry = BftHeightTelemetry::new(args.validators);

    loop {
        match execute_height_step(
            &args,
            &cfg.node_id,
            height,
            &mut restored_lock,
            &mut state,
            &mut mempool,
            &mut known_task_ids,
            &wal_dir,
            &mut wal_entries,
            &mut checkpoints,
            &mut bft_jitter,
            &mut runtime_metrics,
            &mut apply_telemetry,
            &mut bft_telemetry,
        )? {
            HeightLoopControl::Continue => {
                height += 1;
                thread::sleep(Duration::from_millis(args.block_ms));
            }
            HeightLoopControl::Exit => break,
        }
    }

    runtime_metrics.emit_summary(&apply_telemetry, &bft_telemetry, &bft_jitter.leader_health);

    Ok(())
}

use super::*;

pub(crate) fn maybe_apply_timeouts(
    args: &Args,
    runtime: &mut RuntimeState,
    metrics: &mut RuntimeMetrics,
    last_state_root_hex: &mut Option<String>,
) {
    let scan_every = args.pouw_timeout_scan_every_blocks.max(1);
    if args.pouw_timeout_scan && runtime.height % scan_every == 0 {
        let migrated = scan_and_apply_timeouts(
            &mut runtime.state,
            &runtime.known_task_ids,
            runtime.height,
            9_000_000,
        );
        metrics.timeout_migrated_total += migrated;
        if migrated > 0 {
            *last_state_root_hex = None;
            println!(
                "[timeout] height={} migrated={} cumulative_migrated={}",
                runtime.height, migrated, metrics.timeout_migrated_total
            );
        }
    }
}

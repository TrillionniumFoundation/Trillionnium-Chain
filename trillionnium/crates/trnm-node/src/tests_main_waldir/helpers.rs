use super::*;

pub(super) fn args_with_wal_dir(wal_dir: String, wal_mode: WalDirMode) -> Args {
    Args {
        config: "configs/node1.toml".into(),
        block_ms: 1000,
        max_blocks: 10,
        demo_tasks: 2,
        demo_keys: 2,
        parallel_workers: 4,
        txs_per_block: 4,
        validators: 4,
        byzantine: 0,
        bft_max_rounds: 3,
        bft_fault_rounds: 0,
        bft_missed_proposal_threshold: 2,
        bft_leader_penalty_rounds: 2,
        bft_round_change_backoff_ms: 5,
        bft_round_change_backoff_max_ms: 40,
        bft_wal_dir: wal_dir,
        bft_wal_mode: wal_mode,
        bft_checkpoint_interval: 5,
        pouw_timeout_scan: true,
        pouw_timeout_scan_every_blocks: 1,
        enable_da_ordering_decouple: false,
        rl_advisor_shadow: false,
        rl_advisor_shadow_topk: 4,
    }
}

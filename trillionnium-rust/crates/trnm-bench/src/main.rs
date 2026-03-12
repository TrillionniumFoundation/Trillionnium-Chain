use clap::Parser;
use std::time::Instant;
use trnm_executor::{
    auto_adaptive_decision, build_parallel_groups_profile_with_strategy, resolve_grouping_strategy,
    GroupingStrategy,
};
use trnm_types::{ObjectRef, Tx};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Workload {
    Classic,
    Mixed,
    HotStreak,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum StrategyArg {
    Default,
    Original,
    FootprintDesc,
    WriteFirst,
    WriteLast,
    HotBucketInterleave,
    AutoAdaptive,
    AggressiveGreedy,
}

impl StrategyArg {
    fn resolve_profile(self, txs: &[Tx]) -> (Vec<Vec<Tx>>, trnm_executor::GroupingProfile) {
        match self {
            StrategyArg::Default => trnm_executor::build_parallel_groups_profile(txs),
            explicit => {
                build_parallel_groups_profile_with_strategy(txs, GroupingStrategy::from(explicit))
            }
        }
    }
}

impl From<StrategyArg> for GroupingStrategy {
    fn from(v: StrategyArg) -> Self {
        match v {
            StrategyArg::Default | StrategyArg::Original => GroupingStrategy::Original,
            StrategyArg::FootprintDesc => GroupingStrategy::FootprintDesc,
            StrategyArg::WriteFirst => GroupingStrategy::WriteFirst,
            StrategyArg::WriteLast => GroupingStrategy::WriteLast,
            StrategyArg::HotBucketInterleave => GroupingStrategy::HotBucketInterleave,
            StrategyArg::AutoAdaptive => GroupingStrategy::AutoAdaptive,
            StrategyArg::AggressiveGreedy => GroupingStrategy::AggressiveGreedy,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "trnm-bench",
    about = "TRNM load bench with configurable conflict rate"
)]
struct Args {
    /// Number of transactions
    #[arg(long, default_value_t = 20_000)]
    txs: usize,

    /// Number of hot keys (smaller = higher conflict)
    #[arg(long, default_value_t = 2_000)]
    keys: usize,

    /// Workload model
    #[arg(long, value_enum, default_value_t = Workload::Classic)]
    workload: Workload,

    /// Grouping strategy
    #[arg(long, value_enum, default_value_t = StrategyArg::Default)]
    strategy: StrategyArg,

    /// Read-set fanout for mixed workload
    #[arg(long, default_value_t = 3)]
    read_fanout: usize,

    /// Write every N txs for mixed workload (1 = write every tx)
    #[arg(long, default_value_t = 1)]
    write_every: usize,

    /// Print executor profiling stats
    #[arg(long, default_value_t = false)]
    profile: bool,
}

fn main() {
    let args = Args::parse();
    let n = args.txs.max(1);
    let keys = args.keys.max(1);

    let txs = match args.workload {
        Workload::Classic => build_classic_txs(n, keys),
        Workload::Mixed => {
            build_mixed_txs(n, keys, args.read_fanout.max(1), args.write_every.max(1))
        }
        Workload::HotStreak => {
            build_hot_streak_txs(n, keys, args.read_fanout.max(1), args.write_every.max(1))
        }
    };

    let t0 = Instant::now();
    let (groups, profile) = args.strategy.resolve_profile(&txs);
    let dt = t0.elapsed();
    let effective_strategy = match args.strategy {
        StrategyArg::Default => GroupingStrategy::Original,
        explicit => resolve_grouping_strategy(&txs, explicit.into()),
    };

    let grouped: usize = groups.iter().map(|g| g.len()).sum();
    let conflict_rate = 1.0f64 - (keys as f64 / n as f64).min(1.0);

    println!("bench_parallel_grouping");
    println!("workload={:?}", args.workload);
    println!("strategy={:?}", args.strategy);
    println!("effective_strategy={:?}", effective_strategy);
    println!("txs={}", n);
    println!("keys={}", keys);
    println!("estimated_conflict_rate={:.4}", conflict_rate);
    println!("groups={}", groups.len());
    println!("grouped={}", grouped);
    println!("elapsed_ms={}", dt.as_millis());

    if args.profile {
        println!("profile.tx_count={}", profile.tx_count);
        println!("profile.group_count={}", profile.group_count);
        println!("profile.grouped_count={}", profile.grouped_count);
        println!("profile.max_group_size={}", profile.max_group_size);
        println!("profile.min_group_size={}", profile.min_group_size);
        println!("profile.avg_group_size={:.4}", profile.avg_group_size);
        println!("profile.hot_object_share={:.4}", profile.hot_object_share);
        println!("profile.conflict_checks={}", profile.conflict_checks);
        println!("profile.conflict_hits={}", profile.conflict_hits);
        println!(
            "profile.candidate_groups_scanned={}",
            profile.candidate_groups_scanned
        );
        println!("profile.stage_ww_checks={}", profile.stage_ww_checks);
        println!("profile.stage_ww_hits={}", profile.stage_ww_hits);
        println!("profile.stage_wr_checks={}", profile.stage_wr_checks);
        println!("profile.stage_wr_hits={}", profile.stage_wr_hits);
        println!("profile.stage_rw_checks={}", profile.stage_rw_checks);
        println!("profile.stage_rw_hits={}", profile.stage_rw_hits);
        let hit_rate = if profile.conflict_checks == 0 {
            0.0
        } else {
            profile.conflict_hits as f64 / profile.conflict_checks as f64
        };
        println!("profile.conflict_hit_rate={:.4}", hit_rate);

        if matches!(
            args.strategy,
            StrategyArg::Default | StrategyArg::AutoAdaptive
        ) {
            let d = auto_adaptive_decision(&txs);
            println!("profile.auto.use_hot_bucket={}", d.use_hot_bucket);
            println!("profile.auto.reason={}", d.reason);
            println!("profile.auto.sample_len={}", d.sample_len);
            println!("profile.auto.streak_ratio={:.4}", d.streak_ratio);
            println!("profile.auto.streak_threshold={:.4}", d.streak_threshold);
            println!("profile.auto.min_margin={:.4}", d.min_margin);
            println!("profile.auto.hot_key_share={:.4}", d.hot_key_share);
            println!("profile.auto.min_hot_key_share={:.4}", d.min_hot_key_share);
            println!(
                "profile.auto.expected_gain_score={:.4}",
                d.expected_gain_score
            );
            println!(
                "profile.auto.min_expected_gain_score={:.4}",
                d.min_expected_gain_score
            );
        }
    }
}

fn build_classic_txs(n: usize, keys: usize) -> Vec<Tx> {
    let mut txs = Vec::with_capacity(n);
    for i in 0..n {
        let task_id = (i % keys) as u64;
        let obj = ObjectRef {
            id: task_id,
            version: 1,
        };
        txs.push(Tx {
            id: i as u64,
            read_set: vec![obj.clone()],
            write_set: vec![obj],
            payload: vec![],
        });
    }
    txs
}

fn build_mixed_txs(n: usize, keys: usize, read_fanout: usize, write_every: usize) -> Vec<Tx> {
    let mut txs = Vec::with_capacity(n);
    for i in 0..n {
        let mut read_set = Vec::with_capacity(read_fanout);
        for j in 0..read_fanout {
            let id = ((i + j * 7) % keys) as u64;
            read_set.push(ObjectRef { id, version: 1 });
        }

        let write_set = if i % write_every == 0 {
            let id = ((i * 13 + 3) % keys) as u64;
            vec![ObjectRef { id, version: 1 }]
        } else {
            vec![]
        };

        txs.push(Tx {
            id: i as u64,
            read_set,
            write_set,
            payload: vec![],
        });
    }
    txs
}

fn build_hot_streak_txs(n: usize, keys: usize, read_fanout: usize, write_every: usize) -> Vec<Tx> {
    let mut txs = Vec::with_capacity(n);
    let streak = 16usize;
    let hotspot_pool = keys.clamp(1, 8);
    let side_domain = keys.saturating_sub(hotspot_pool);
    for i in 0..n {
        // Keep hot-streak workloads concentrated on a tiny rotating hotspot pool so
        // the named scenario continues to exercise auto-adaptive hotspot detection
        // in default bench runs instead of diffusing across the full key domain.
        let hot = ((i / streak) % hotspot_pool) as u64;
        let mut read_set = Vec::with_capacity(read_fanout);
        read_set.push(ObjectRef {
            id: hot,
            version: 1,
        });

        for j in 1..read_fanout {
            // Offset side reads away from the hotspot pool while keeping them inside
            // the declared key budget. When the key budget is fully consumed by the
            // hotspot pool (e.g. keys=1), fall back to the hot key instead of probing
            // a zero-width side domain.
            let side = if side_domain == 0 {
                hot
            } else {
                hotspot_pool as u64 + ((i + j * 11) % side_domain) as u64
            };
            read_set.push(ObjectRef {
                id: side,
                version: 1,
            });
        }

        let write_set = if i % write_every == 0 {
            vec![ObjectRef {
                id: hot,
                version: 1,
            }]
        } else {
            vec![]
        };

        txs.push(Tx {
            id: i as u64,
            read_set,
            write_set,
            payload: vec![],
        });
    }
    txs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_streak_default_workload_triggers_auto_adaptive_hotspot_detection() {
        let txs = build_hot_streak_txs(20_000, 2_000, 3, 1);
        let decision = auto_adaptive_decision(&txs);

        assert!(
            decision.use_hot_bucket,
            "default hot-streak bench should exercise adaptive hotspot path"
        );
        assert_eq!(decision.reason, "hotspot_detected");
    }

    #[test]
    fn hot_streak_single_key_budget_stays_in_hot_domain_without_panicking() {
        let txs = build_hot_streak_txs(64, 1, 3, 1);

        assert_eq!(txs.len(), 64);
        assert!(txs
            .iter()
            .all(|tx| tx.read_set.iter().all(|obj| obj.id == 0)));
        assert!(txs
            .iter()
            .all(|tx| tx.write_set.iter().all(|obj| obj.id == 0)));
    }

    #[test]
    fn hot_streak_auto_adaptive_profile_keeps_hot_bucket_fast_path_counters_zeroed() {
        let txs = build_hot_streak_txs(20_000, 2_000, 3, 1);
        let decision = auto_adaptive_decision(&txs);
        let (_groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);

        assert!(
            decision.use_hot_bucket,
            "expected hot-streak workload to stay on hot-bucket path"
        );
        assert_eq!(profile.tx_count, txs.len());
        assert_eq!(profile.grouped_count, txs.len());
        assert_eq!(profile.candidate_groups_scanned, 0);
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
        assert_eq!(profile.stage_ww_checks, 0);
        assert_eq!(profile.stage_ww_hits, 0);
        assert_eq!(profile.stage_wr_checks, 0);
        assert_eq!(profile.stage_wr_hits, 0);
        assert_eq!(profile.stage_rw_checks, 0);
        assert_eq!(profile.stage_rw_hits, 0);
        assert!(
            profile.hot_object_share > 0.0,
            "hot-streak auto-adaptive profile should report a non-zero hot-object share"
        );
    }

    #[test]
    fn classic_bench_default_path_matches_executor_default_strategy_output() {
        let txs = build_classic_txs(2_048, 256);
        let (default_groups, default_profile) = StrategyArg::Default.resolve_profile(&txs);
        let (executor_groups, executor_profile) =
            trnm_executor::build_parallel_groups_profile(&txs);

        assert_profiles_match(
            &default_groups,
            &default_profile,
            &executor_groups,
            &executor_profile,
        );
    }

    #[test]
    fn hot_streak_bench_auto_adaptive_matches_executor_profile_and_decision() {
        let txs = build_hot_streak_txs(20_000, 2_000, 3, 1);
        let decision = auto_adaptive_decision(&txs);
        let (bench_groups, bench_profile) =
            build_parallel_groups_profile_with_strategy(&txs, StrategyArg::AutoAdaptive.into());
        let (executor_groups, executor_profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);

        assert!(
            decision.use_hot_bucket,
            "expected hot-streak bench to stay on hot-bucket path"
        );
        assert_eq!(decision.reason, "hotspot_detected");
        assert_profiles_match(
            &bench_groups,
            &bench_profile,
            &executor_groups,
            &executor_profile,
        );
    }

    #[test]
    fn mixed_bench_default_path_matches_executor_default_strategy_output() {
        let txs = build_mixed_txs(2_048, 256, 3, 2);
        let (bench_groups, bench_profile) = StrategyArg::Default.resolve_profile(&txs);
        let (executor_groups, executor_profile) =
            trnm_executor::build_parallel_groups_profile(&txs);

        assert_profiles_match(
            &bench_groups,
            &bench_profile,
            &executor_groups,
            &executor_profile,
        );
    }

    #[test]
    fn hot_streak_bench_default_path_matches_executor_original_strategy_output() {
        let txs = build_hot_streak_txs(20_000, 2_000, 3, 1);
        let (bench_groups, bench_profile) = StrategyArg::Default.resolve_profile(&txs);
        let (executor_groups, executor_profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);

        assert_profiles_match(
            &bench_groups,
            &bench_profile,
            &executor_groups,
            &executor_profile,
        );
    }

    #[test]
    fn hot_streak_bench_default_path_stays_distinct_from_auto_adaptive_executor_output() {
        let txs = build_hot_streak_txs(20_000, 2_000, 3, 1);
        let (bench_groups, bench_profile) = StrategyArg::Default.resolve_profile(&txs);
        let (auto_groups, auto_profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);

        assert_ne!(bench_groups, auto_groups);
        assert_ne!(bench_profile.group_count, auto_profile.group_count);
        assert!(
            auto_profile.hot_object_share > bench_profile.hot_object_share,
            "auto-adaptive hot-streak path should surface a stronger hotspot signal than default"
        );
    }

    #[test]
    fn effective_strategy_reports_real_auto_adaptive_resolution() {
        let hot_streak = build_hot_streak_txs(20_000, 2_000, 3, 1);
        assert!(matches!(
            resolve_grouping_strategy(&hot_streak, StrategyArg::AutoAdaptive.into()),
            GroupingStrategy::HotBucketInterleave
        ));

        let classic = build_classic_txs(2_048, 256);
        assert!(matches!(
            resolve_grouping_strategy(&classic, StrategyArg::Default.into()),
            GroupingStrategy::Original
        ));
    }

    fn assert_profiles_match(
        left_groups: &[Vec<trnm_executor::Tx>],
        left_profile: &trnm_executor::GroupingProfile,
        right_groups: &[Vec<trnm_executor::Tx>],
        right_profile: &trnm_executor::GroupingProfile,
    ) {
        assert_eq!(left_groups, right_groups);
        assert_eq!(left_profile.tx_count, right_profile.tx_count);
        assert_eq!(left_profile.group_count, right_profile.group_count);
        assert_eq!(left_profile.grouped_count, right_profile.grouped_count);
        assert_eq!(left_profile.max_group_size, right_profile.max_group_size);
        assert_eq!(left_profile.min_group_size, right_profile.min_group_size);
        assert_eq!(left_profile.conflict_checks, right_profile.conflict_checks);
        assert_eq!(left_profile.conflict_hits, right_profile.conflict_hits);
        assert_eq!(
            left_profile.candidate_groups_scanned,
            right_profile.candidate_groups_scanned
        );
        assert_eq!(left_profile.stage_ww_checks, right_profile.stage_ww_checks);
        assert_eq!(left_profile.stage_ww_hits, right_profile.stage_ww_hits);
        assert_eq!(left_profile.stage_wr_checks, right_profile.stage_wr_checks);
        assert_eq!(left_profile.stage_wr_hits, right_profile.stage_wr_hits);
        assert_eq!(left_profile.stage_rw_checks, right_profile.stage_rw_checks);
        assert_eq!(left_profile.stage_rw_hits, right_profile.stage_rw_hits);
        assert!((left_profile.avg_group_size - right_profile.avg_group_size).abs() < f64::EPSILON);
        assert!(
            (left_profile.hot_object_share - right_profile.hot_object_share).abs() < f64::EPSILON
        );
    }
}

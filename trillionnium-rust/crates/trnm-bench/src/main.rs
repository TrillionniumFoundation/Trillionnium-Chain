use clap::Parser;
use std::time::Instant;
use trnm_executor::{
    auto_adaptive_decision, build_parallel_groups_profile_with_strategy, GroupingStrategy,
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
    Original,
    FootprintDesc,
    WriteFirst,
    WriteLast,
    HotBucketInterleave,
    AutoAdaptive,
    AggressiveGreedy,
}

impl From<StrategyArg> for GroupingStrategy {
    fn from(v: StrategyArg) -> Self {
        match v {
            StrategyArg::Original => GroupingStrategy::Original,
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
    #[arg(long, value_enum, default_value_t = StrategyArg::Original)]
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
    let (groups, profile) = build_parallel_groups_profile_with_strategy(&txs, args.strategy.into());
    let dt = t0.elapsed();

    let grouped: usize = groups.iter().map(|g| g.len()).sum();
    let conflict_rate = 1.0f64 - (keys as f64 / n as f64).min(1.0);

    println!("bench_parallel_grouping");
    println!("workload={:?}", args.workload);
    println!("strategy={:?}", args.strategy);
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

        if matches!(args.strategy, StrategyArg::AutoAdaptive) {
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
    for i in 0..n {
        let hot = ((i / streak) % keys) as u64;
        let mut read_set = Vec::with_capacity(read_fanout);
        read_set.push(ObjectRef {
            id: hot,
            version: 1,
        });

        for j in 1..read_fanout {
            let side = ((i + j * 11) % keys) as u64;
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

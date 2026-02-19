use clap::Parser;
use std::time::Instant;
use trnm_executor::{build_parallel_groups_profile_with_strategy, GroupingStrategy};
use trnm_types::{ObjectRef, Tx};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Workload {
    Classic,
    Mixed,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum StrategyArg {
    Original,
    FootprintDesc,
    WriteFirst,
    WriteLast,
    HotBucketInterleave,
}

impl From<StrategyArg> for GroupingStrategy {
    fn from(v: StrategyArg) -> Self {
        match v {
            StrategyArg::Original => GroupingStrategy::Original,
            StrategyArg::FootprintDesc => GroupingStrategy::FootprintDesc,
            StrategyArg::WriteFirst => GroupingStrategy::WriteFirst,
            StrategyArg::WriteLast => GroupingStrategy::WriteLast,
            StrategyArg::HotBucketInterleave => GroupingStrategy::HotBucketInterleave,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "trnm-bench", about = "TRNM load bench with configurable conflict rate")]
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
        let hit_rate = if profile.conflict_checks == 0 {
            0.0
        } else {
            profile.conflict_hits as f64 / profile.conflict_checks as f64
        };
        println!("profile.conflict_hit_rate={:.4}", hit_rate);
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

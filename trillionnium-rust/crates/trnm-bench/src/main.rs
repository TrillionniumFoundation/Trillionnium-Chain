use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
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

    /// Persist profile output under run/bench (enabled by default when --profile is set)
    #[arg(long, default_value_t = true)]
    persist_profile: bool,

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

    let capture_started_at = SystemTime::now();
    let capture_started_at_epoch = capture_started_at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let capture_started_at_iso = chrono_like_iso(capture_started_at);

    let t0 = Instant::now();
    let (groups, profile) = build_parallel_groups_profile_with_strategy(&txs, args.strategy.into());
    let dt = t0.elapsed();

    let grouped: usize = groups.iter().map(|g| g.len()).sum();
    let conflict_rate = 1.0f64 - (keys as f64 / n as f64).min(1.0);

    let mut lines = vec![
        "bench_parallel_grouping".to_string(),
        format!("workload={:?}", args.workload),
        format!("strategy={:?}", args.strategy),
        format!("txs={}", n),
        format!("keys={}", keys),
        format!("read_fanout={}", args.read_fanout.max(1)),
        format!("write_every={}", args.write_every.max(1)),
        format!("persist_profile={}", args.persist_profile),
        format!("estimated_conflict_rate={:.4}", conflict_rate),
        format!("groups={}", groups.len()),
        format!("grouped={}", grouped),
        format!("elapsed_ms={}", dt.as_millis()),
    ];

    if args.profile {
        let coverage_ratio = grouped as f64 / n as f64;
        let groups_per_1k_txs = groups.len() as f64 * 1000.0 / n as f64;
        let grouping_efficiency = if groups.is_empty() {
            0.0
        } else {
            grouped as f64 / groups.len() as f64
        };
        lines.extend([
            format!("profile.report.workload={:?}", args.workload),
            format!("profile.report.strategy={:?}", args.strategy),
            format!("profile.report.txs={}", n),
            format!("profile.report.keys={}", keys),
            format!("profile.report.read_fanout={}", args.read_fanout.max(1)),
            format!("profile.report.write_every={}", args.write_every.max(1)),
            format!("profile.report.persist_profile={}", args.persist_profile),
            format!("profile.report.capture_started_at_epoch={}", capture_started_at_epoch),
            format!("profile.report.capture_started_at_iso={}", capture_started_at_iso),
            format!("profile.report.elapsed_ms={}", dt.as_millis()),
            format!("profile.report.estimated_conflict_rate={:.4}", conflict_rate),
            format!("profile.report.coverage_ratio={:.4}", coverage_ratio),
            format!("profile.report.groups_per_1k_txs={:.4}", groups_per_1k_txs),
            format!("profile.report.grouping_efficiency={:.4}", grouping_efficiency),
            "profile.report.autopilot_hint=persisted_profile_capture".to_string(),
            format!("profile.tx_count={}", profile.tx_count),
            format!("profile.group_count={}", profile.group_count),
            format!("profile.grouped_count={}", profile.grouped_count),
            format!("profile.max_group_size={}", profile.max_group_size),
            format!("profile.min_group_size={}", profile.min_group_size),
            format!("profile.avg_group_size={:.4}", profile.avg_group_size),
            format!("profile.hot_object_share={:.4}", profile.hot_object_share),
            format!("profile.conflict_checks={}", profile.conflict_checks),
            format!("profile.conflict_hits={}", profile.conflict_hits),
            format!(
                "profile.candidate_groups_scanned={}",
                profile.candidate_groups_scanned
            ),
            format!("profile.stage_ww_checks={}", profile.stage_ww_checks),
            format!("profile.stage_ww_hits={}", profile.stage_ww_hits),
            format!("profile.stage_wr_checks={}", profile.stage_wr_checks),
            format!("profile.stage_wr_hits={}", profile.stage_wr_hits),
            format!("profile.stage_rw_checks={}", profile.stage_rw_checks),
            format!("profile.stage_rw_hits={}", profile.stage_rw_hits),
        ]);
        let hit_rate = if profile.conflict_checks == 0 {
            0.0
        } else {
            profile.conflict_hits as f64 / profile.conflict_checks as f64
        };
        lines.push(format!("profile.conflict_hit_rate={:.4}", hit_rate));

        if matches!(args.strategy, StrategyArg::AutoAdaptive) {
            let d = auto_adaptive_decision(&txs);
            lines.extend([
                format!("profile.auto.use_hot_bucket={}", d.use_hot_bucket),
                format!("profile.auto.reason={}", d.reason),
                format!("profile.auto.sample_len={}", d.sample_len),
                format!("profile.auto.streak_ratio={:.4}", d.streak_ratio),
                format!("profile.auto.streak_threshold={:.4}", d.streak_threshold),
                format!("profile.auto.min_margin={:.4}", d.min_margin),
                format!("profile.auto.hot_key_share={:.4}", d.hot_key_share),
                format!("profile.auto.min_hot_key_share={:.4}", d.min_hot_key_share),
                format!("profile.auto.expected_gain_score={:.4}", d.expected_gain_score),
                format!(
                    "profile.auto.min_expected_gain_score={:.4}",
                    d.min_expected_gain_score
                ),
            ]);
        }

        if args.persist_profile {
            match persist_profile_report(&mut lines, capture_started_at_epoch) {
                Ok(_) => {}
                Err(err) => lines.push(format!("profile.report.persist_error={err}")),
            }
        }
    }

    for line in lines {
        println!("{line}");
    }
}

fn persist_profile_report(lines: &mut Vec<String>, capture_started_at_epoch: u64) -> std::io::Result<PathBuf> {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("run")
        .join("bench");
    fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join(format!(
        "executor-profile-summary-{capture_started_at_epoch}.txt"
    ));
    let resolved_path = fs::canonicalize(&out_dir)
        .unwrap_or_else(|_| out_dir.clone())
        .join(
            out_path
                .file_name()
                .map(|name| name.to_os_string())
                .unwrap_or_default(),
        );
    let basename = out_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| out_path.display().to_string());
    lines.push(format!("profile.report.path={}", resolved_path.display()));
    lines.push(format!("profile.report.artifact_basename={basename}"));
    fs::write(&out_path, format!("{}\n", lines.join("\n")))?;
    fs::canonicalize(&out_path).or(Ok(out_path))
}

fn chrono_like_iso(ts: SystemTime) -> String {
    let total_seconds = ts
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    )
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe.div_euclid(1_460) + doe.div_euclid(36_524) - doe.div_euclid(146_096))
        .div_euclid(365);
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe.div_euclid(4) - yoe.div_euclid(100));
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year, month, day)
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

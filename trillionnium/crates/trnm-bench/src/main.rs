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
        let ungrouped_count = n.saturating_sub(grouped);
        let grouping_complete = ungrouped_count == 0;
        let groups_per_1k_txs = groups.len() as f64 * 1000.0 / n as f64;
        let grouping_efficiency = if groups.is_empty() {
            0.0
        } else {
            grouped as f64 / groups.len() as f64
        };
        let effective_read_fanout = match args.workload {
            Workload::Classic => 1,
            Workload::Mixed | Workload::HotStreak => args.read_fanout.max(1),
        };
        let effective_write_ratio = match args.workload {
            Workload::Classic => 1.0,
            Workload::Mixed | Workload::HotStreak => 1.0 / args.write_every.max(1) as f64,
        };
        let workload_signature = format!(
            "{:?}/txs={}/keys={}/reads={}/write_ratio={:.4}/strategy={:?}",
            args.workload, n, keys, effective_read_fanout, effective_write_ratio, args.strategy
        );
        lines.extend([
            format!("profile.report.workload={:?}", args.workload),
            format!("profile.report.strategy={:?}", args.strategy),
            format!("profile.report.txs={}", n),
            format!("profile.report.keys={}", keys),
            format!("profile.report.read_fanout={}", args.read_fanout.max(1)),
            format!("profile.report.write_every={}", args.write_every.max(1)),
            format!(
                "profile.report.effective_read_fanout={}",
                effective_read_fanout
            ),
            format!(
                "profile.report.effective_write_ratio={:.4}",
                effective_write_ratio
            ),
            format!("profile.report.workload_signature={}", workload_signature),
            format!("profile.report.persist_profile={}", args.persist_profile),
            format!(
                "profile.report.capture_started_at_epoch={}",
                capture_started_at_epoch
            ),
            format!(
                "profile.report.capture_started_at_iso={}",
                capture_started_at_iso
            ),
            "profile.report.capture_stamp_family=epoch".to_string(),
            format!("profile.report.capture_stamp={}", capture_started_at_epoch),
            format!(
                "profile.report.capture_stamp_epoch={}",
                capture_started_at_epoch
            ),
            format!("profile.report.elapsed_ms={}", dt.as_millis()),
            format!(
                "profile.report.estimated_conflict_rate={:.4}",
                conflict_rate
            ),
            format!("profile.report.coverage_ratio={:.4}", coverage_ratio),
            format!("profile.report.ungrouped_count={}", ungrouped_count),
            format!("profile.report.grouping_complete={}", grouping_complete),
            format!("profile.report.groups_per_1k_txs={:.4}", groups_per_1k_txs),
            format!(
                "profile.report.grouping_efficiency={:.4}",
                grouping_efficiency
            ),
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
            format!(
                "profile.retry_fallback_new_groups={}",
                profile.retry_fallback_new_groups
            ),
            format!("profile.stage_ww_checks={}", profile.stage_ww_checks),
            format!("profile.stage_ww_hits={}", profile.stage_ww_hits),
            format!("profile.stage_wr_checks={}", profile.stage_wr_checks),
            format!("profile.stage_wr_hits={}", profile.stage_wr_hits),
            format!("profile.stage_rw_checks={}", profile.stage_rw_checks),
            format!("profile.stage_rw_hits={}", profile.stage_rw_hits),
        ]);
        let hit_rate = ratio(profile.conflict_hits, profile.conflict_checks);
        let conflict_checks_per_tx = profile.conflict_checks_per_tx();
        let conflict_hits_per_tx = profile.conflict_hits_per_tx();
        let candidate_groups_per_tx = profile.candidate_groups_per_tx();
        let reused_group_placements = profile.reused_group_placements();
        let reused_group_share = profile.reused_group_share();
        let new_group_share = profile.new_group_share();
        let retry_pressure = profile.retry_pressure();
        let retry_fallback_new_group_share = profile.retry_fallback_new_group_share();
        let retry_fallback_share_of_new_groups = profile.retry_fallback_share_of_new_groups();
        let retry_fallback_share_of_retry_hits = profile.retry_fallback_share_of_retry_hits();
        let retry_fallback_scan_share = profile.retry_fallback_scan_share();
        let candidate_groups_per_retry_hit = profile.candidate_groups_per_retry_hit();
        let candidate_groups_per_reused_placement = profile.candidate_groups_per_reused_placement();
        let retry_scan_reuse_rate = profile.retry_scan_reuse_rate();
        let retry_reuse_salvage_rate = profile.retry_reuse_salvage_rate();
        let retry_scan_hit_rate = profile.retry_scan_hit_rate();
        let retry_scan_misses = profile.retry_scan_misses();
        let retry_scan_miss_rate = profile.retry_scan_miss_rate();
        let retry_scan_misses_per_tx = profile.retry_scan_misses_per_tx();
        let retry_scan_misses_per_group = profile.retry_scan_misses_per_group();
        let retry_scan_overhang_per_hit = profile.retry_scan_overhang_per_hit();
        let retry_scan_overhang_per_reused_placement =
            profile.retry_scan_overhang_per_reused_placement();
        let retry_fallback_share_of_retry_misses = profile.retry_fallback_share_of_retry_misses();
        let stage_ww_hit_rate = profile.ww_retry_hit_rate();
        let stage_wr_hit_rate = profile.wr_retry_hit_rate();
        let stage_rw_hit_rate = profile.rw_retry_hit_rate();
        let stage_ww_hits_per_tx = profile.ww_retry_hits_per_tx();
        let stage_wr_hits_per_tx = profile.wr_retry_hits_per_tx();
        let stage_rw_hits_per_tx = profile.rw_retry_hits_per_tx();
        let stage_ww_retry_share = profile.ww_retry_share();
        let stage_wr_retry_share = profile.wr_retry_share();
        let stage_rw_retry_share = profile.rw_retry_share();
        let dominant_retry_stage = profile.dominant_retry_stage();
        let dominant_retry_share = profile.dominant_retry_share();
        let dominant_attributed_retry_share = profile.dominant_attributed_retry_share();
        let dominant_retry_lead_hits = profile.dominant_retry_lead_hits();
        let dominant_retry_lead_share = profile.dominant_retry_lead_share();
        let dominant_attributed_retry_lead_share = profile.dominant_attributed_retry_lead_share();
        let attributed_retry_hits = profile.attributed_retry_hits();
        let unattributed_retry_hits = profile.unattributed_retry_hits();
        let unattributed_retry_share = profile.unattributed_retry_share();
        let retry_attribution_coverage = profile.retry_attribution_coverage();
        let retry_stage_overlap_hits = profile.retry_stage_overlap_hits();
        let retry_stage_overlap_share = profile.retry_stage_overlap_share();
        let retry_stage_overlap_share_of_attributed =
            profile.retry_stage_overlap_share_of_attributed();
        let singly_attributed_retry_hits = profile.singly_attributed_retry_hits();
        let singly_attributed_retry_share = profile.singly_attributed_retry_share();
        let singly_attributed_retry_share_of_attributed =
            profile.singly_attributed_retry_share_of_attributed();
        let retry_stage_concentration = profile.retry_stage_concentration();
        let retry_stage_mix_entropy = profile.retry_stage_mix_entropy();
        lines.push(format!("profile.conflict_hit_rate={:.4}", hit_rate));
        // Block-STM-style speculative tuning cares less about raw conflicts alone
        // than about how much retry pressure and candidate-lane scanning each tx
        // induces. Keep these as derived telemetry only so scheduler semantics stay
        // deterministic and benchmark output remains backward-compatible.
        lines.push(format!(
            "profile.conflict_checks_per_tx={:.4}",
            conflict_checks_per_tx
        ));
        lines.push(format!(
            "profile.conflict_hits_per_tx={:.4}",
            conflict_hits_per_tx
        ));
        lines.push(format!(
            "profile.candidate_groups_per_tx={:.4}",
            candidate_groups_per_tx
        ));
        lines.push(format!(
            "profile.reused_group_placements={}",
            reused_group_placements
        ));
        lines.push(format!(
            "profile.reused_group_share={:.4}",
            reused_group_share
        ));
        lines.push(format!("profile.new_group_share={:.4}", new_group_share));
        lines.push(format!("profile.retry_pressure={:.4}", retry_pressure));
        lines.push(format!(
            "profile.retry_fallback_new_group_share={:.4}",
            retry_fallback_new_group_share
        ));
        lines.push(format!(
            "profile.retry_fallback_share_of_new_groups={:.4}",
            retry_fallback_share_of_new_groups
        ));
        lines.push(format!(
            "profile.retry_fallback_share_of_retry_hits={:.4}",
            retry_fallback_share_of_retry_hits
        ));
        lines.push(format!(
            "profile.retry_fallback_scan_share={:.4}",
            retry_fallback_scan_share
        ));
        lines.push(format!(
            "profile.candidate_groups_per_retry_hit={:.4}",
            candidate_groups_per_retry_hit
        ));
        lines.push(format!(
            "profile.candidate_groups_per_reused_placement={:.4}",
            candidate_groups_per_reused_placement
        ));
        lines.push(format!(
            "profile.retry_scan_reuse_rate={:.4}",
            retry_scan_reuse_rate
        ));
        lines.push(format!(
            "profile.retry_reuse_salvage_rate={:.4}",
            retry_reuse_salvage_rate
        ));
        lines.push(format!(
            "profile.retry_scan_hit_rate={:.4}",
            retry_scan_hit_rate
        ));
        lines.push(format!("profile.retry_scan_misses={}", retry_scan_misses));
        lines.push(format!(
            "profile.retry_scan_miss_rate={:.4}",
            retry_scan_miss_rate
        ));
        lines.push(format!(
            "profile.retry_scan_misses_per_tx={:.4}",
            retry_scan_misses_per_tx
        ));
        lines.push(format!(
            "profile.retry_scan_misses_per_group={:.4}",
            retry_scan_misses_per_group
        ));
        lines.push(format!(
            "profile.retry_scan_overhang_per_hit={:.4}",
            retry_scan_overhang_per_hit
        ));
        lines.push(format!(
            "profile.retry_scan_overhang_per_reused_placement={:.4}",
            retry_scan_overhang_per_reused_placement
        ));
        lines.push(format!(
            "profile.retry_fallback_share_of_retry_misses={:.4}",
            retry_fallback_share_of_retry_misses
        ));
        lines.push(format!(
            "profile.stage_ww_hit_rate={:.4}",
            stage_ww_hit_rate
        ));
        lines.push(format!(
            "profile.stage_wr_hit_rate={:.4}",
            stage_wr_hit_rate
        ));
        lines.push(format!(
            "profile.stage_rw_hit_rate={:.4}",
            stage_rw_hit_rate
        ));
        lines.push(format!(
            "profile.stage_ww_hits_per_tx={:.4}",
            stage_ww_hits_per_tx
        ));
        lines.push(format!(
            "profile.stage_wr_hits_per_tx={:.4}",
            stage_wr_hits_per_tx
        ));
        lines.push(format!(
            "profile.stage_rw_hits_per_tx={:.4}",
            stage_rw_hits_per_tx
        ));
        lines.push(format!(
            "profile.stage_ww_retry_share={:.4}",
            stage_ww_retry_share
        ));
        lines.push(format!(
            "profile.stage_wr_retry_share={:.4}",
            stage_wr_retry_share
        ));
        lines.push(format!(
            "profile.stage_rw_retry_share={:.4}",
            stage_rw_retry_share
        ));
        lines.push(format!(
            "profile.dominant_retry_stage={}",
            dominant_retry_stage
        ));
        lines.push(format!(
            "profile.dominant_retry_share={:.4}",
            dominant_retry_share
        ));
        lines.push(format!(
            "profile.dominant_attributed_retry_share={:.4}",
            dominant_attributed_retry_share
        ));
        lines.push(format!(
            "profile.dominant_retry_lead_hits={}",
            dominant_retry_lead_hits
        ));
        lines.push(format!(
            "profile.dominant_retry_lead_share={:.4}",
            dominant_retry_lead_share
        ));
        lines.push(format!(
            "profile.dominant_attributed_retry_lead_share={:.4}",
            dominant_attributed_retry_lead_share
        ));
        lines.push(format!(
            "profile.attributed_retry_hits={}",
            attributed_retry_hits
        ));
        lines.push(format!(
            "profile.unattributed_retry_hits={}",
            unattributed_retry_hits
        ));
        lines.push(format!(
            "profile.unattributed_retry_share={:.4}",
            unattributed_retry_share
        ));
        lines.push(format!(
            "profile.retry_attribution_coverage={:.4}",
            retry_attribution_coverage
        ));
        lines.push(format!(
            "profile.retry_stage_overlap_hits={}",
            retry_stage_overlap_hits
        ));
        lines.push(format!(
            "profile.retry_stage_overlap_share={:.4}",
            retry_stage_overlap_share
        ));
        lines.push(format!(
            "profile.retry_stage_overlap_share_of_attributed={:.4}",
            retry_stage_overlap_share_of_attributed
        ));
        lines.push(format!(
            "profile.singly_attributed_retry_hits={}",
            singly_attributed_retry_hits
        ));
        lines.push(format!(
            "profile.singly_attributed_retry_share={:.4}",
            singly_attributed_retry_share
        ));
        lines.push(format!(
            "profile.singly_attributed_retry_share_of_attributed={:.4}",
            singly_attributed_retry_share_of_attributed
        ));
        lines.push(format!(
            "profile.retry_stage_concentration={:.4}",
            retry_stage_concentration
        ));
        lines.push(format!(
            "profile.retry_stage_mix_entropy={:.4}",
            retry_stage_mix_entropy
        ));

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
                format!(
                    "profile.auto.expected_gain_score={:.4}",
                    d.expected_gain_score
                ),
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

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn default_bench_output_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("run")
        .join("bench")
}

fn persist_profile_report(
    lines: &mut Vec<String>,
    capture_started_at_epoch: u64,
) -> std::io::Result<PathBuf> {
    persist_profile_report_into(lines, &default_bench_output_dir(), capture_started_at_epoch)
}

fn persist_profile_report_into(
    lines: &mut Vec<String>,
    out_dir: &std::path::Path,
    capture_started_at_epoch: u64,
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(out_dir)?;
    let out_path = out_dir.join(format!(
        "executor-profile-summary-{capture_started_at_epoch}.txt"
    ));
    let resolved_path = fs::canonicalize(out_dir)
        .unwrap_or_else(|_| out_dir.to_path_buf())
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

    let line_count_prefix = "profile.report.output_line_count=";
    let byte_count_prefix = "profile.report.output_bytes=";
    let mut output_line_count = 0usize;
    let mut output_bytes = 0usize;
    let persisted_content = loop {
        let mut persisted_lines = lines.clone();
        persisted_lines.push(format!("{line_count_prefix}{output_line_count}"));
        persisted_lines.push(format!("{byte_count_prefix}{output_bytes}"));
        let persisted_content = format!("{}\n", persisted_lines.join("\n"));
        let next_line_count = persisted_content.lines().count();
        let next_output_bytes = persisted_content.len();
        if next_line_count == output_line_count && next_output_bytes == output_bytes {
            break persisted_content;
        }
        output_line_count = next_line_count;
        output_bytes = next_output_bytes;
    };

    fs::write(&out_path, persisted_content)?;
    fs::canonicalize(&out_path).or(Ok(out_path))
}

fn chrono_like_iso(ts: SystemTime) -> String {
    let total_seconds = ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
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
    let keys = keys.max(1);
    let read_fanout = read_fanout.max(1);
    let write_every = write_every.max(1);
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
            let mut side = ((i + j * 11) % keys) as u64;
            let mut probes = 0usize;
            while probes < keys && read_set.iter().any(|existing| existing.id == side) {
                side = ((side as usize + 1) % keys) as u64;
                probes += 1;
            }
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
    use super::{
        build_hot_streak_txs, build_mixed_txs, chrono_like_iso, persist_profile_report_into,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use trnm_executor::GroupingProfile;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("trnm-bench-{label}-{nanos}"))
    }

    #[test]
    fn persist_profile_report_into_writes_self_describing_artifact_in_requested_dir() {
        let out_dir = unique_temp_dir("persist-profile");
        let mut lines = vec![
            "bench_parallel_grouping".to_string(),
            "profile.report.persist_profile=true".to_string(),
        ];

        let path = persist_profile_report_into(&mut lines, &out_dir, 1_700_000_000)
            .expect("profile artifact should persist into isolated test dir");
        let content =
            fs::read_to_string(&path).expect("persisted profile artifact should be readable");
        let resolved_out_dir = fs::canonicalize(&out_dir)
            .expect("isolated output dir should canonicalize after persistence");

        assert!(path.starts_with(&resolved_out_dir));
        assert!(content
            .contains("profile.report.artifact_basename=executor-profile-summary-1700000000.txt"));
        assert!(content.contains(&format!("profile.report.path={}", path.display())));
        assert!(content.contains(&format!(
            "profile.report.output_line_count={}",
            content.lines().count()
        )));
        assert!(content.contains(&format!("profile.report.output_bytes={}", content.len())));

        fs::remove_dir_all(&out_dir).expect("temp bench profile dir should be removable");
    }

    #[test]
    fn mixed_workload_respects_read_fanout_and_write_every_stride() {
        let txs = build_mixed_txs(6, 97, 3, 2);

        assert_eq!(txs.len(), 6);
        for (idx, tx) in txs.iter().enumerate() {
            assert_eq!(
                tx.read_set.len(),
                3,
                "tx {idx} should keep configured read fanout"
            );
            if idx % 2 == 0 {
                assert_eq!(
                    tx.write_set.len(),
                    1,
                    "tx {idx} should emit one write on the configured stride"
                );
            } else {
                assert!(
                    tx.write_set.is_empty(),
                    "tx {idx} should stay read-only off the configured stride"
                );
            }
        }
    }

    #[test]
    fn hot_streak_workload_keeps_deterministic_block_stm_style_streaks() {
        let txs = build_hot_streak_txs(40, 5, 3, 2);

        assert_eq!(txs.len(), 40);

        let streak0 = txs[0].read_set[0].id;
        for tx in &txs[..16] {
            assert_eq!(
                tx.read_set[0].id, streak0,
                "first streak should stay on one hot object"
            );
        }

        let streak1 = txs[16].read_set[0].id;
        assert_ne!(
            streak1, streak0,
            "next streak should rotate to a different hot object when keys allow it"
        );
        for tx in &txs[16..32] {
            assert_eq!(
                tx.read_set[0].id, streak1,
                "second streak should stay on its rotated hot object"
            );
        }

        for (idx, tx) in txs.iter().enumerate() {
            assert_eq!(
                tx.read_set.len(),
                3,
                "tx {idx} should keep configured read fanout"
            );
            if idx % 2 == 0 {
                assert_eq!(
                    tx.write_set.len(),
                    1,
                    "tx {idx} should write the streak hot key on the configured stride"
                );
                assert_eq!(tx.write_set[0].id, tx.read_set[0].id);
            } else {
                assert!(
                    tx.write_set.is_empty(),
                    "tx {idx} should stay read-only between write strides"
                );
            }
        }
    }

    #[test]
    fn hot_streak_workload_avoids_duplicate_side_reads_when_keyspace_allows() {
        let txs = build_hot_streak_txs(8, 3, 3, 2);

        for (idx, tx) in txs.iter().enumerate() {
            let ids = tx.read_set.iter().map(|obj| obj.id).collect::<Vec<_>>();
            assert_eq!(ids.len(), 3, "tx {idx} should keep configured read fanout");
            assert_eq!(
                ids[0],
                tx.write_set.first().map(|obj| obj.id).unwrap_or(ids[0]),
                "tx {idx} should keep the hot key in the first read slot"
            );

            let unique = ids
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                unique.len(),
                ids.len(),
                "tx {idx} should avoid duplicate side reads when keys >= read_fanout"
            );
        }
    }

    #[test]
    fn hot_streak_workload_fail_closes_zero_inputs_to_single_key_single_read_stride() {
        let txs = build_hot_streak_txs(4, 0, 0, 0);

        assert_eq!(txs.len(), 4);
        for (idx, tx) in txs.iter().enumerate() {
            assert_eq!(
                tx.read_set.len(),
                1,
                "tx {idx} should clamp zero fanout to one read"
            );
            assert_eq!(
                tx.read_set[0].id, 0,
                "tx {idx} should clamp zero keyspace to one hot key"
            );
            assert_eq!(
                tx.write_set.len(),
                1,
                "tx {idx} should clamp zero write stride to every tx"
            );
            assert_eq!(tx.write_set[0].id, tx.read_set[0].id);
        }
    }

    #[test]
    fn chrono_like_iso_formats_unix_epoch_and_next_second_stably() {
        assert_eq!(chrono_like_iso(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            chrono_like_iso(UNIX_EPOCH + Duration::from_secs(1)),
            "1970-01-01T00:00:01Z"
        );
    }

    #[test]
    fn retry_stage_overlap_share_reports_double_counted_retry_hits() {
        let profile = GroupingProfile {
            tx_count: 8,
            group_count: 3,
            grouped_count: 8,
            max_group_size: 3,
            min_group_size: 2,
            avg_group_size: 8.0 / 3.0,
            hot_object_share: 0.5,
            conflict_checks: 9,
            conflict_hits: 4,
            candidate_groups_scanned: 6,
            retry_fallback_new_groups: 0,
            stage_ww_checks: 4,
            stage_ww_hits: 2,
            stage_wr_checks: 3,
            stage_wr_hits: 2,
            stage_rw_checks: 2,
            stage_rw_hits: 1,
        };

        assert_eq!(profile.attributed_retry_hits(), 5);
        assert_eq!(profile.unattributed_retry_hits(), 0);
        assert_eq!(profile.unattributed_retry_share(), 0.0);
        assert_eq!(profile.retry_attribution_coverage(), 1.0);
        assert_eq!(profile.retry_stage_overlap_hits(), 1);
        assert!((profile.retry_stage_overlap_share() - 0.25).abs() < f64::EPSILON);
        assert!((profile.retry_stage_overlap_share_of_attributed() - 0.2).abs() < f64::EPSILON);
        assert_eq!(profile.singly_attributed_retry_hits(), 4);
        assert!((profile.singly_attributed_retry_share() - 1.0).abs() < f64::EPSILON);
        assert!((profile.singly_attributed_retry_share_of_attributed() - 0.8).abs() < f64::EPSILON);
        assert!((profile.retry_stage_concentration() - 0.5625).abs() < f64::EPSILON);
        assert!((profile.retry_stage_mix_entropy() - 0.9602297178607612).abs() < 1e-12);
        assert!((profile.retry_scan_overhang_per_hit() - 0.5).abs() < f64::EPSILON);
        assert!((profile.retry_scan_overhang_per_reused_placement() - 0.4).abs() < f64::EPSILON);
        assert!((profile.retry_fallback_share_of_retry_misses() - 0.0).abs() < f64::EPSILON);
        assert!((profile.candidate_groups_per_reused_placement() - 1.2).abs() < f64::EPSILON);
        assert!((profile.retry_scan_reuse_rate() - (5.0 / 6.0)).abs() < f64::EPSILON);
        assert_eq!(profile.retry_reuse_salvage_rate(), 1.0);
        assert_eq!(profile.reused_group_placements(), 5);
        assert!((profile.reused_group_share() - 0.625).abs() < f64::EPSILON);
        assert!((profile.new_group_share() - 0.375).abs() < f64::EPSILON);
        assert_eq!(profile.retry_fallback_new_groups, 0);
        assert_eq!(profile.retry_fallback_new_group_share(), 0.0);
        assert_eq!(profile.retry_fallback_share_of_new_groups(), 0.0);
        assert_eq!(profile.retry_fallback_share_of_retry_hits(), 0.0);
    }

    #[test]
    fn retry_fallback_new_group_share_tracks_scan_exhaustion_pressure() {
        let profile = GroupingProfile {
            tx_count: 8,
            group_count: 5,
            grouped_count: 8,
            max_group_size: 2,
            min_group_size: 1,
            avg_group_size: 1.6,
            hot_object_share: 0.5,
            conflict_checks: 9,
            conflict_hits: 4,
            candidate_groups_scanned: 6,
            retry_fallback_new_groups: 2,
            stage_ww_checks: 4,
            stage_ww_hits: 2,
            stage_wr_checks: 3,
            stage_wr_hits: 1,
            stage_rw_checks: 2,
            stage_rw_hits: 1,
        };

        assert!((profile.retry_fallback_new_group_share() - 0.25).abs() < f64::EPSILON);
        assert!((profile.retry_fallback_share_of_new_groups() - 0.4).abs() < f64::EPSILON);
        assert!((profile.retry_fallback_share_of_retry_hits() - 0.5).abs() < f64::EPSILON);
        assert!((profile.retry_fallback_scan_share() - (2.0 / 6.0)).abs() < f64::EPSILON);
        assert!(
            (profile.retry_fallback_share_of_retry_misses() - (2.0 / 2.0)).abs() < f64::EPSILON
        );
        assert!((profile.retry_reuse_salvage_rate() - (3.0 / 5.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_scan_hit_and_miss_metrics_partition_candidate_scans() {
        let profile = GroupingProfile {
            tx_count: 8,
            group_count: 4,
            grouped_count: 8,
            max_group_size: 3,
            min_group_size: 1,
            avg_group_size: 2.0,
            hot_object_share: 0.5,
            conflict_checks: 9,
            conflict_hits: 4,
            candidate_groups_scanned: 9,
            retry_fallback_new_groups: 2,
            stage_ww_checks: 3,
            stage_ww_hits: 2,
            stage_wr_checks: 3,
            stage_wr_hits: 1,
            stage_rw_checks: 3,
            stage_rw_hits: 1,
        };

        assert_eq!(profile.retry_scan_misses(), 5);
        assert!((profile.retry_scan_hit_rate() - (4.0 / 9.0)).abs() < f64::EPSILON);
        assert!((profile.retry_scan_miss_rate() - (5.0 / 9.0)).abs() < f64::EPSILON);
        assert!(
            ((profile.retry_scan_hit_rate() + profile.retry_scan_miss_rate()) - 1.0).abs() < 1e-12
        );
        assert!((profile.retry_scan_misses_per_tx() - (5.0 / 8.0)).abs() < f64::EPSILON);
        assert!((profile.retry_scan_misses_per_group() - (5.0 / 4.0)).abs() < f64::EPSILON);
        assert!((profile.retry_scan_overhang_per_hit() - (5.0 / 4.0)).abs() < f64::EPSILON);
        assert!((profile.retry_scan_overhang_per_reused_placement() - 1.25).abs() < f64::EPSILON);
        assert!((profile.retry_fallback_share_of_retry_misses() - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_telemetry_zero_denominator_metrics_fail_closed_to_zero() {
        let profile = GroupingProfile {
            tx_count: 4,
            group_count: 4,
            grouped_count: 4,
            max_group_size: 1,
            min_group_size: 1,
            avg_group_size: 1.0,
            hot_object_share: 0.25,
            conflict_checks: 0,
            conflict_hits: 0,
            candidate_groups_scanned: 0,
            retry_fallback_new_groups: 0,
            stage_ww_checks: 0,
            stage_ww_hits: 0,
            stage_wr_checks: 0,
            stage_wr_hits: 0,
            stage_rw_checks: 0,
            stage_rw_hits: 0,
        };

        assert_eq!(profile.conflict_checks_per_tx(), 0.0);
        assert_eq!(profile.conflict_hits_per_tx(), 0.0);
        assert_eq!(profile.candidate_groups_per_tx(), 0.0);
        assert_eq!(profile.reused_group_placements(), 0);
        assert_eq!(profile.reused_group_share(), 0.0);
        assert_eq!(profile.new_group_share(), 1.0);
        assert_eq!(profile.retry_pressure(), 0.0);
        assert_eq!(profile.retry_fallback_new_group_share(), 0.0);
        assert_eq!(profile.candidate_groups_per_retry_hit(), 0.0);
        assert_eq!(profile.candidate_groups_per_reused_placement(), 0.0);
        assert_eq!(profile.retry_scan_hit_rate(), 0.0);
        assert_eq!(profile.retry_reuse_salvage_rate(), 0.0);
        assert_eq!(profile.retry_scan_misses(), 0);
        assert_eq!(profile.retry_scan_miss_rate(), 0.0);
        assert_eq!(profile.retry_scan_reuse_rate(), 0.0);
        assert_eq!(profile.retry_fallback_share_of_new_groups(), 0.0);
        assert_eq!(profile.retry_fallback_share_of_retry_hits(), 0.0);
        assert_eq!(profile.retry_fallback_scan_share(), 0.0);
        assert_eq!(profile.retry_scan_misses_per_tx(), 0.0);
        assert_eq!(profile.retry_scan_misses_per_group(), 0.0);
        assert_eq!(profile.retry_scan_overhang_per_hit(), 0.0);
        assert_eq!(profile.retry_scan_overhang_per_reused_placement(), 0.0);
        assert_eq!(profile.retry_fallback_share_of_retry_misses(), 0.0);
        assert_eq!(profile.ww_retry_hit_rate(), 0.0);
        assert_eq!(profile.wr_retry_hit_rate(), 0.0);
        assert_eq!(profile.rw_retry_hit_rate(), 0.0);
        assert_eq!(profile.dominant_retry_stage(), "none");
        assert_eq!(profile.dominant_retry_share(), 0.0);
        assert_eq!(profile.dominant_attributed_retry_share(), 0.0);
        assert_eq!(profile.dominant_retry_lead_hits(), 0);
        assert_eq!(profile.dominant_retry_lead_share(), 0.0);
        assert_eq!(profile.dominant_attributed_retry_lead_share(), 0.0);
        assert_eq!(profile.attributed_retry_hits(), 0);
        assert_eq!(profile.unattributed_retry_hits(), 0);
        assert_eq!(profile.unattributed_retry_share(), 0.0);
        assert_eq!(profile.retry_attribution_coverage(), 0.0);
        assert_eq!(profile.retry_stage_overlap_hits(), 0);
        assert_eq!(profile.retry_stage_overlap_share(), 0.0);
        assert_eq!(profile.retry_stage_overlap_share_of_attributed(), 0.0);
        assert_eq!(profile.singly_attributed_retry_hits(), 0);
        assert_eq!(profile.singly_attributed_retry_share(), 0.0);
        assert_eq!(profile.singly_attributed_retry_share_of_attributed(), 0.0);
        assert_eq!(profile.retry_stage_concentration(), 0.0);
        assert_eq!(profile.retry_stage_mix_entropy(), 0.0);
    }
}

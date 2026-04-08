# Profiling Closeout Baseline
generated_at=2026-03-12T16:52:02.390454

## Inputs
- node_log: None
- node_log_status: missing
- bench_dir: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench
- bench_dir_status: present
- bench_dir_producer: mkdir -p run/bench
- bench_dir_newest_artifact: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
- classic_bench: None
- classic_bench_status: missing
- mixed_bench: None
- mixed_bench_status: missing
- executor_profile: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
- executor_profile_status: present

## Input Freshness
- bench_dir: freshness=stale age_seconds=911 anchor=executor-profile-summary-1773304610.txt
- node_log: freshness=missing age_seconds=n/a
- classic_bench: freshness=missing age_seconds=n/a
- mixed_bench: freshness=missing age_seconds=n/a
- executor_profile: freshness=stale age_seconds=911

## Input Readiness
- bench_dir: present | producer=mkdir -p run/bench
- node_log: missing | producer=cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log
- classic_bench: missing | producer=./scripts/run_bench_matrix.sh
- mixed_bench: missing | producer=./scripts/run_bench_mixed_matrix.sh
- executor_profile: present | producer=cargo run -q -p trnm-bench -- --profile

## Artifact Lineage
- bench_dir: status=present freshness=stale age_seconds=911 updated_at=2026-03-12T16:36:50.815011 basename=executor-profile-summary-1773304610.txt path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench producer=mkdir -p run/bench anchor=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
- node_log: status=missing freshness=missing age_seconds=n/a updated_at=n/a basename=None path=None producer=cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log
- classic_bench: status=missing freshness=missing age_seconds=n/a updated_at=n/a basename=None path=None producer=./scripts/run_bench_matrix.sh
- mixed_bench: status=missing freshness=missing age_seconds=n/a updated_at=n/a basename=None path=None producer=./scripts/run_bench_mixed_matrix.sh
- executor_profile: status=present freshness=stale age_seconds=911 updated_at=2026-03-12T16:36:50.815011 basename=executor-profile-summary-1773304610.txt path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt producer=cargo run -q -p trnm-bench -- --profile

## Artifact Discovery
- node_log_candidates: selected=None candidate_count=0
  - none: pattern produced no matches
- classic_bench_candidates: selected=None candidate_count=0
  - none: pattern produced no matches
- mixed_bench_candidates: selected=None candidate_count=0
  - none: pattern produced no matches
- executor_profile_candidates: selected=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt candidate_count=44
  - candidate_window: newest=executor-profile-summary-1773304610.txt oldest=executor-profile-summary-1773287502.txt spread_seconds=17108 newest_freshness=stale oldest_freshness=old
  - candidate_freshness_counts: fresh=0 stale=15 old=29
  - selected_status: is_newest=true rank=1/44 freshness=stale updated_at=2026-03-12T16:36:50.815011 age_seconds=911 delta_vs_newest_seconds=0
  - recent_1: basename=executor-profile-summary-1773304610.txt updated_at=2026-03-12T16:36:50.815011 freshness=stale path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
  - recent_2: basename=executor-profile-summary-1773304041.txt updated_at=2026-03-12T16:27:21.083054 freshness=stale path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304041.txt
  - recent_3: basename=executor-profile-summary-1773303576.txt updated_at=2026-03-12T16:19:36.328882 freshness=stale path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773303576.txt
  - remaining_candidates: 41

## Artifact Capture Stamps
- node_log: capture_stamp=unavailable path=None
- classic_bench: capture_stamp=unavailable path=None
- mixed_bench: capture_stamp=unavailable path=None
- executor_profile: capture_stamp_family=epoch capture_stamp=1773304610 capture_stamp_epoch=1773304610 path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
- selected_capture_stamp_alignment: partial
- selected_capture_stamp_alignment_reason: some selected artifacts do not expose a recognizable capture stamp: node_log, classic_bench, mixed_bench

## Benchmark Artifact Pool Health
- classic_bench_candidates: status=empty action=produce selected=None selected_freshness=missing candidate_count=0 fresh=0 stale=0 old=0 old_backlog=0
- mixed_bench_candidates: status=empty action=produce selected=None selected_freshness=missing candidate_count=0 fresh=0 stale=0 old=0 old_backlog=0
- executor_profile_candidates: status=refresh_required action=refresh selected=executor-profile-summary-1773304610.txt selected_freshness=stale candidate_count=44 fresh=0 stale=15 old=29 old_backlog=44

## Benchmark Pool Action Summary
- benchmark_pool_status_counts: empty=2 refresh_required=1 backlog_present=0 backlog_heavy=0 tight=0
- benchmark_pool_action_counts: produce=2 refresh=1 keep_latest=0 keep_latest_and_consider_archive=0
- benchmark_pool_attention: classic_bench_candidates:empty:produce, mixed_bench_candidates:empty:produce, executor_profile_candidates:refresh_required:refresh
- benchmark_pool_backlog_totals: candidate_count=44 fresh=0 stale=15 old=29 old_backlog=44
- benchmark_pool_followup_command_chain: ./scripts/run_bench_matrix.sh && ./scripts/run_bench_mixed_matrix.sh && cargo run -q -p trnm-bench -- --profile

## Benchmark Archive Candidates
- classic_bench_candidates: archive_candidate_count=0 keep_latest=2 preview=none remaining=0
- mixed_bench_candidates: archive_candidate_count=0 keep_latest=2 preview=none remaining=0
- executor_profile_candidates: archive_candidate_count=42 keep_latest=2 preview=executor-profile-summary-1773303576.txt, executor-profile-summary-1773302805.txt, executor-profile-summary-1773302320.txt, executor-profile-summary-1773302235.txt, executor-profile-summary-1773301657.txt remaining=37

## Benchmark Archive Summary
- benchmark_archive_candidate_total: 42
- benchmark_archive_freshness_counts: stale=13 old=29
- benchmark_archive_attention: executor_profile_candidates:42
- benchmark_archive_hotspots: executor_profile_candidates:42
- benchmark_archive_recommendation: review_archive_candidates_before_manual_cleanup

## Baseline Report Pool Health
- baseline_closeout_reports: status=refresh_required action=refresh selected=profiling-closeout-baseline-20260312-163650.md selected_freshness=stale candidate_count=69 fresh=0 stale=16 old=53 old_backlog=69
- baseline_closeout_report_candidates: selected=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-165202.md candidate_count=69
  - candidate_window: newest=profiling-closeout-baseline-20260312-163650.md oldest=profiling-closeout-baseline-20260310-153834.md spread_seconds=88030 newest_freshness=stale oldest_freshness=old
  - candidate_freshness_counts: fresh=0 stale=16 old=53
  - selected_status: is_newest=false rank=not_in_candidate_set freshness=missing updated_at=n/a age_seconds=n/a delta_vs_newest_seconds=n/a
  - recent_1: basename=profiling-closeout-baseline-20260312-163650.md updated_at=2026-03-12T16:36:50.850030 freshness=stale path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-163650.md
  - recent_2: basename=profiling-closeout-baseline-20260312-162721.md updated_at=2026-03-12T16:27:21.121861 freshness=stale path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-162721.md
  - recent_3: basename=profiling-closeout-baseline-20260312-161936.md updated_at=2026-03-12T16:19:36.363113 freshness=stale path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-161936.md
  - remaining_candidates: 66
- baseline_closeout_report_candidates: archive_candidate_count=67 keep_latest=2 preview=profiling-closeout-baseline-20260312-161936.md, profiling-closeout-baseline-20260312-161843.md, profiling-closeout-baseline-20260312-160646.md, profiling-closeout-baseline-20260312-160539.md, profiling-closeout-baseline-20260312-155840.md remaining=62
- baseline_closeout_report_followup: refresh_closeout_report_set

## Baseline Report Action Summary
- baseline_closeout_report_decision: REFRESH_RECOMMENDED
- baseline_closeout_report_reason: status=refresh_required action=refresh
- baseline_closeout_report_action_counts: candidate_count=69 fresh=0 stale=16 old=53 old_backlog=69 archive_candidate_count=67
- baseline_closeout_report_selected: profiling-closeout-baseline-20260312-163650.md
- baseline_closeout_report_followup_command_chain: python3 scripts/profiling_closeout_report.py
- baseline_closeout_report_followup: refresh_closeout_report_set

## Data Completeness
- must_run_gate_artifact_posture: partial_persisted_bench_artifacts
- autopilot_assessment: PARTIAL_CLOSEOUT (some persisted closeout artifacts are present, but the evidence set is incomplete)
- note: closeout is usable for directional review, but curator/autopilot decisions should prefer a full 4/4 evidence set
- status: PARTIAL (node_log, classic_bench, mixed_bench missing)
- present_inputs: executor_profile
- missing_inputs: node_log, classic_bench, mixed_bench
- stale_inputs: bench_dir, executor_profile
- old_inputs: none
- readiness_score: 1/4
- autopilot_severity: RED
- total_evidence_coverage: 1/4 (node_log + classic_bench + mixed_bench + executor_profile)
- benchmark_artifact_coverage_note: benchmark_artifact_coverage below excludes node_log by design; use total_evidence_coverage for the full closeout evidence set

## Curator Verdict
- curator_verdict: RED
- curator_reason: missing inputs: node_log, classic_bench, mixed_bench

## Closeout Action Summary
- closeout_decision: INCOMPLETE
- closeout_decision_reason: missing evidence inputs must be produced before closeout is reviewable
- closeout_action_counts: missing=3 stale=2 old=0 ready=-1
- closeout_capture_cohesion: insufficient_artifacts
- closeout_capture_spread_seconds: n/a
- closeout_blockers: node_log, classic_bench, mixed_bench, bench_dir, executor_profile
- closeout_ready_inputs: 
- closeout_followup_command_chain: cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log && ./scripts/run_bench_matrix.sh && ./scripts/run_bench_mixed_matrix.sh && mkdir -p run/bench && cargo run -q -p trnm-bench -- --profile

## Autopilot Recommended Next Steps
- produce node_log: cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log
- produce classic_bench: ./scripts/run_bench_matrix.sh
- produce mixed_bench: ./scripts/run_bench_mixed_matrix.sh
- refresh bench_dir: existing artifact is stale; regenerate before curator/autopilot review
- refresh executor_profile: existing artifact is stale; regenerate before curator/autopilot review

## Benchmark Next Step Matrix
- classic_bench: action=produce freshness=missing age_seconds=n/a updated_at=n/a path=None producer=./scripts/run_bench_matrix.sh reason=missing benchmark artifact
- mixed_bench: action=produce freshness=missing age_seconds=n/a updated_at=n/a path=None producer=./scripts/run_bench_mixed_matrix.sh reason=missing benchmark artifact
- executor_profile: action=refresh freshness=stale age_seconds=911 updated_at=2026-03-12T16:36:50.815011 path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt producer=cargo run -q -p trnm-bench -- --profile reason=artifact is stale and should be regenerated before review

## Benchmark Action Summary
- benchmark_decision: INCOMPLETE
- benchmark_decision_reason: missing benchmark artifacts must be produced before benchmark closeout is reviewable
- benchmark_action_counts: produce=2 refresh=1 keep=0
- benchmark_capture_cohesion: insufficient_artifacts
- benchmark_capture_spread_seconds: n/a
- benchmark_blockers: classic_bench:produce:missing, mixed_bench:produce:missing, executor_profile:refresh:stale
- benchmark_ready_inputs: none
- benchmark_followup_command_chain: ./scripts/run_bench_matrix.sh && ./scripts/run_bench_mixed_matrix.sh && cargo run -q -p trnm-bench -- --profile

## Block Metrics
- scheduler_elapsed_ms: n/a
- preexec_elapsed_ms: n/a
- commit_elapsed_ms: n/a
- state_root_total_ms: n/a
- critical_wait_blocks: n/a
- rollback_count: n/a
- groups: n/a
- elapsed_ms: n/a

## Consensus Summary
- consensus summary: missing

## Benchmark Summary
- benchmark_artifact_coverage: 1/3 (classic_bench + mixed_bench + executor_profile)
- classic_bench_rows: 0
- mixed_bench_rows: 0
- classic_bench_freshness: missing
- mixed_bench_freshness: missing
- executor_profile_freshness: stale
bench_parallel_grouping
workload=Classic
strategy=Original
txs=20000
keys=2000
read_fanout=3
write_every=1
persist_profile=true
estimated_conflict_rate=0.9000
groups=10
grouped=20000
elapsed_ms=46
profile.report.workload=Classic
profile.report.strategy=Original
profile.report.txs=20000
profile.report.keys=2000
profile.report.read_fanout=3
profile.report.write_every=1
profile.report.persist_profile=true
profile.report.capture_started_at_epoch=1773304610
profile.report.capture_started_at_iso=unix:1773304610
profile.report.elapsed_ms=46
profile.report.estimated_conflict_rate=0.9000
profile.report.coverage_ratio=1.0000
profile.report.groups_per_1k_txs=0.5000
profile.report.grouping_efficiency=2000.0000
profile.report.autopilot_hint=persisted_profile_capture
profile.tx_count=20000
profile.group_count=10
profile.grouped_count=20000
profile.max_group_size=2000
profile.min_group_size=2000
profile.avg_group_size=2000.0000
profile.hot_object_share=0.0005
profile.conflict_checks=60000
profile.conflict_hits=54000
profile.candidate_groups_scanned=0
profile.stage_ww_checks=0
profile.stage_ww_hits=0
profile.stage_wr_checks=0
profile.stage_wr_hits=0
profile.stage_rw_checks=0
profile.stage_rw_hits=0
profile.conflict_hit_rate=0.9000
profile.report.path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
profile.report.artifact_basename=executor-profile-summary-1773304610.txt

### Executor Profile Context
- executor_profile.profile.report.workload: Classic
- executor_profile.profile.report.strategy: Original
- executor_profile.profile.report.txs: 20000
- executor_profile.profile.report.keys: 2000
- executor_profile.profile.report.read_fanout: 3
- executor_profile.profile.report.write_every: 1
- executor_profile.profile.report.persist_profile: true
- executor_profile.profile.report.elapsed_ms: 46
- executor_profile.profile.report.path: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
- executor_profile.profile.report.autopilot_hint: persisted_profile_capture
- executor_profile.selected_artifact_path: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773304610.txt
- executor_profile.selected_artifact_exists: true
- executor_profile.embedded_report_path_exists: true
- executor_profile.embedded_report_path_matches_selected: true

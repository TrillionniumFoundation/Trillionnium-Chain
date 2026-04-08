# Profiling Closeout Baseline
generated_at=2026-03-12T22:57:46.240831

## Inputs
- node_log: None
- node_log_status: missing
- bench_dir: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench
- bench_dir_status: present
- bench_dir_producer: mkdir -p run/bench
- bench_dir_newest_artifact: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
- classic_bench: None
- classic_bench_status: missing
- mixed_bench: None
- mixed_bench_status: missing
- executor_profile: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
- executor_profile_status: present

## Input Freshness
- bench_dir: freshness=fresh age_seconds=0 anchor=executor-profile-summary-1773327466.txt
- node_log: freshness=missing age_seconds=n/a
- classic_bench: freshness=missing age_seconds=n/a
- mixed_bench: freshness=missing age_seconds=n/a
- executor_profile: freshness=fresh age_seconds=0

## Input Readiness
- bench_dir: present | producer=mkdir -p run/bench
- node_log: missing | producer=cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log
- classic_bench: missing | producer=./scripts/run_bench_matrix.sh
- mixed_bench: missing | producer=./scripts/run_bench_mixed_matrix.sh
- executor_profile: present | producer=cargo run -q -p trnm-bench -- --profile

## Artifact Lineage
- bench_dir: status=present freshness=fresh age_seconds=0 updated_at=2026-03-12T22:57:46.206341 size_bytes=1530 basename=executor-profile-summary-1773327466.txt path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench producer=mkdir -p run/bench anchor=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
- node_log: status=missing freshness=missing age_seconds=n/a updated_at=n/a size_bytes=n/a basename=None path=None producer=cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log
- classic_bench: status=missing freshness=missing age_seconds=n/a updated_at=n/a size_bytes=n/a basename=None path=None producer=./scripts/run_bench_matrix.sh
- mixed_bench: status=missing freshness=missing age_seconds=n/a updated_at=n/a size_bytes=n/a basename=None path=None producer=./scripts/run_bench_mixed_matrix.sh
- executor_profile: status=present freshness=fresh age_seconds=0 updated_at=2026-03-12T22:57:46.206341 size_bytes=1530 basename=executor-profile-summary-1773327466.txt path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt producer=cargo run -q -p trnm-bench -- --profile

## Artifact Discovery
- node_log_candidates: selected=None matched_count=0 existing_count=0 missing_count=0 pending_selected=false
  - none: pattern produced no matches
- classic_bench_candidates: selected=None matched_count=0 existing_count=0 missing_count=0 pending_selected=false
  - none: pattern produced no matches
- mixed_bench_candidates: selected=None matched_count=0 existing_count=0 missing_count=0 pending_selected=false
  - none: pattern produced no matches
- executor_profile_candidates: selected=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt matched_count=83 existing_count=83 missing_count=0 pending_selected=false
  - candidate_window: newest=executor-profile-summary-1773327466.txt oldest=executor-profile-summary-1773287502.txt spread_seconds=39964 newest_freshness=fresh oldest_freshness=old
  - candidate_freshness_counts: fresh=3 stale=11 old=69
  - selected_status: is_newest=true rank=1/83 freshness=fresh updated_at=2026-03-12T22:57:46.206341 size_bytes=1530 age_seconds=0 delta_vs_newest_seconds=0
  - recent_1: basename=executor-profile-summary-1773327466.txt size_bytes=1530 updated_at=2026-03-12T22:57:46.206341 freshness=fresh path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
  - recent_2: basename=executor-profile-summary-1773327347.txt size_bytes=1459 updated_at=2026-03-12T22:55:47.102421 freshness=fresh path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327347.txt
  - recent_3: basename=executor-profile-summary-1773326587.txt size_bytes=1459 updated_at=2026-03-12T22:43:07.091231 freshness=fresh path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773326587.txt
  - remaining_candidates: 80

## Artifact Capture Stamps
- node_log: exists=false basename=None capture_stamp_family=unavailable capture_stamp=unavailable capture_stamp_epoch=unavailable path=None
- classic_bench: exists=false basename=None capture_stamp_family=unavailable capture_stamp=unavailable capture_stamp_epoch=unavailable path=None
- mixed_bench: exists=false basename=None capture_stamp_family=unavailable capture_stamp=unavailable capture_stamp_epoch=unavailable path=None
- executor_profile: exists=true basename=executor-profile-summary-1773327466.txt capture_stamp_family=epoch capture_stamp=1773327466 capture_stamp_epoch=1773327466 path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
- selected_capture_stamp_alignment: partial
- selected_capture_stamp_alignment_reason: some selected artifacts do not expose a recognizable capture stamp: node_log, classic_bench, mixed_bench

## Benchmark Artifact Pool Health
- classic_bench_candidates: status=empty action=produce selected=None selected_freshness=missing pending_selected=false candidate_count=0 missing_count=0 fresh=0 stale=0 old=0 old_backlog=0
- mixed_bench_candidates: status=empty action=produce selected=None selected_freshness=missing pending_selected=false candidate_count=0 missing_count=0 fresh=0 stale=0 old=0 old_backlog=0
- executor_profile_candidates: status=backlog_heavy action=keep_latest_and_consider_archive selected=executor-profile-summary-1773327466.txt selected_freshness=fresh pending_selected=false candidate_count=83 missing_count=0 fresh=3 stale=11 old=69 old_backlog=80

## Benchmark Pool Action Summary
- classic_bench_selection: selected=none rank=missing newest=unknown candidate_count=0
- mixed_bench_selection: selected=none rank=missing newest=unknown candidate_count=0
- executor_profile_selection: selected=executor-profile-summary-1773327466.txt rank=1/83 newest=true
- benchmark_pool_status_counts: empty=2 refresh_required=0 backlog_present=0 backlog_heavy=1 tight=0
- benchmark_pool_action_counts: produce=2 refresh=0 keep_latest=0 keep_latest_and_consider_archive=1
- benchmark_pool_attention: classic_bench_candidates:empty:produce, mixed_bench_candidates:empty:produce, executor_profile_candidates:backlog_heavy:keep_latest_and_consider_archive
- benchmark_pool_backlog_totals: candidate_count=83 fresh=3 stale=11 old=69 old_backlog=80
- benchmark_pool_followup_command_chain: ./scripts/run_bench_matrix.sh && ./scripts/run_bench_mixed_matrix.sh

## Benchmark Archive Candidates
- classic_bench_candidates: archive_candidate_count=0 keep_latest=2 preview=none remaining=0
- mixed_bench_candidates: archive_candidate_count=0 keep_latest=2 preview=none remaining=0
- executor_profile_candidates: archive_candidate_count=80 keep_latest=2 preview=executor-profile-summary-1773325943.txt, executor-profile-summary-1773325880.txt, executor-profile-summary-1773324996.txt, executor-profile-summary-1773324411.txt, executor-profile-summary-1773323612.txt remaining=75

## Benchmark Archive Summary
- benchmark_archive_candidate_total: 80
- benchmark_archive_freshness_counts: stale=11 old=69
- benchmark_archive_attention: executor_profile_candidates:80
- benchmark_archive_hotspots: executor_profile_candidates:80
- benchmark_archive_recommendation: review_archive_candidates_before_manual_cleanup
- benchmark_archive_review_command_chain: ls -1t run/bench/executor-profile-summary-*.txt | sed -n '3,$p'

## Baseline Report Pool Health
- baseline_closeout_reports: status=backlog_heavy action=keep_latest_and_consider_archive selected=profiling-closeout-baseline-20260312-225746.md selected_freshness=fresh pending_selected=true candidate_count=103 missing_count=0 fresh=2 stale=13 old=88 old_backlog=101
- baseline_closeout_report_candidates: selected=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-225746.md matched_count=104 existing_count=103 missing_count=0 pending_selected=true
  - candidate_window: newest=profiling-closeout-baseline-20260312-225547.md oldest=profiling-closeout-baseline-20260310-153834.md spread_seconds=110766 newest_freshness=fresh oldest_freshness=old
  - candidate_freshness_counts: fresh=2 stale=13 old=88
  - selected_status: is_newest=pending_write_newest rank=1/103 freshness=fresh updated_at=2026-03-12T22:57:46 size_bytes=n/a age_seconds=0 delta_vs_newest_seconds=n/a
  - recent_1: basename=profiling-closeout-baseline-20260312-225547.md size_bytes=18626 updated_at=2026-03-12T22:55:47.141455 freshness=fresh path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-225547.md
  - recent_2: basename=profiling-closeout-baseline-20260312-224306.md size_bytes=18634 updated_at=2026-03-12T22:43:06.159977 freshness=fresh path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-224306.md
  - recent_3: basename=profiling-closeout-baseline-20260312-223223.md size_bytes=18622 updated_at=2026-03-12T22:32:23.266257 freshness=stale path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/docs/reports/profiling-closeout-baseline-20260312-223223.md
  - remaining_candidates: 100
- baseline_closeout_report_candidates: archive_candidate_count=101 keep_latest=2 preview=profiling-closeout-baseline-20260312-223223.md, profiling-closeout-baseline-20260312-223120.md, profiling-closeout-baseline-20260312-221636.md, profiling-closeout-baseline-20260312-221500.md, profiling-closeout-baseline-20260312-220652.md remaining=96

## Baseline Report Action Summary
- baseline_closeout_report_selection: selected=profiling-closeout-baseline-20260312-225746.md rank=1/103 newest=pending_write_newest
- baseline_closeout_report_status: backlog_heavy
- baseline_closeout_report_action: keep_latest_and_consider_archive
- baseline_closeout_report_decision: ARCHIVE_RECOMMENDED
- baseline_closeout_report_reason: status=backlog_heavy action=keep_latest_and_consider_archive
- baseline_closeout_report_action_counts: candidate_count=103 fresh=2 stale=13 old=88 old_backlog=101 archive_candidate_count=101
- baseline_closeout_report_selected: profiling-closeout-baseline-20260312-225746.md
- baseline_closeout_report_followup_command_chain: none
- baseline_closeout_report_archive_review_command_chain: ls -1t docs/reports/profiling-closeout-baseline-*.md | sed -n '3,$p'
- baseline_closeout_report_followup: review_archive_candidates_before_manual_cleanup

## Data Completeness
- must_run_gate_artifact_posture: partial_persisted_bench_artifacts
- autopilot_assessment: PARTIAL_CLOSEOUT (some persisted closeout artifacts are present, but the evidence set is incomplete)
- note: closeout is usable for directional review, but curator/autopilot decisions should prefer a full 4/4 evidence set
- status: PARTIAL (node_log, classic_bench, mixed_bench missing)
- present_inputs: executor_profile
- missing_inputs: node_log, classic_bench, mixed_bench
- stale_inputs: none
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
- closeout_action_counts: missing=3 stale=0 old=0 ready=1
- closeout_capture_cohesion: insufficient_artifacts
- closeout_capture_spread_seconds: n/a
- closeout_blockers: node_log, classic_bench, mixed_bench
- closeout_ready_inputs: executor_profile
- closeout_followup_command_chain: cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log && ./scripts/run_bench_matrix.sh && ./scripts/run_bench_mixed_matrix.sh

## Autopilot Recommended Next Steps
- produce node_log: cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log
- produce classic_bench: ./scripts/run_bench_matrix.sh
- produce mixed_bench: ./scripts/run_bench_mixed_matrix.sh

## Benchmark Next Step Matrix
- classic_bench: action=produce freshness=missing age_seconds=n/a updated_at=n/a path=None producer=./scripts/run_bench_matrix.sh reason=missing benchmark artifact
- mixed_bench: action=produce freshness=missing age_seconds=n/a updated_at=n/a path=None producer=./scripts/run_bench_mixed_matrix.sh reason=missing benchmark artifact
- executor_profile: action=keep freshness=fresh age_seconds=0 updated_at=2026-03-12T22:57:46.206341 path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt producer=cargo run -q -p trnm-bench -- --profile reason=artifact is fresh enough for curator/autopilot review

## Benchmark Action Summary
- benchmark_decision: INCOMPLETE
- benchmark_decision_reason: missing benchmark artifacts must be produced before benchmark closeout is reviewable
- benchmark_action_counts: produce=2 refresh=0 keep=1
- benchmark_capture_cohesion: insufficient_artifacts
- benchmark_capture_spread_seconds: n/a
- benchmark_blockers: classic_bench:produce:missing, mixed_bench:produce:missing
- benchmark_ready_inputs: executor_profile
- benchmark_followup_command_chain: ./scripts/run_bench_matrix.sh && ./scripts/run_bench_mixed_matrix.sh

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
- benchmark_selected_capture_alignment: partial
- benchmark_selected_capture_alignment_reason: some selected artifacts do not expose a recognizable capture stamp: classic_bench, mixed_bench
- benchmark_selected_capture_epochs: classic=unavailable mixed=unavailable executor_profile=1773327466
- classic_bench_rows: 0
- mixed_bench_rows: 0
- classic_bench_freshness: missing
- mixed_bench_freshness: missing
- executor_profile_freshness: fresh

### Executor Profile Context
- executor_profile.profile.report.workload: Classic
- executor_profile.profile.report.strategy: Original
- executor_profile.profile.report.txs: 20000
- executor_profile.profile.report.keys: 2000
- executor_profile.profile.report.read_fanout: 3
- executor_profile.profile.report.write_every: 1
- executor_profile.profile.report.persist_profile: true
- executor_profile.profile.report.capture_started_at_epoch: 1773327466
- executor_profile.profile.report.capture_started_at_iso: 2026-03-12T14:57:46Z
- executor_profile.profile.report.elapsed_ms: 43
- executor_profile.profile.report.path: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
- executor_profile.profile.report.artifact_basename: executor-profile-summary-1773327466.txt
- executor_profile.profile.report.ungrouped_count: 0
- executor_profile.profile.report.grouping_complete: true
- executor_profile.profile.report.autopilot_hint: persisted_profile_capture
- executor_profile.selected_artifact_path: /Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
- executor_profile.selected_artifact_exists: true
- executor_profile.selected_artifact_basename: executor-profile-summary-1773327466.txt
- executor_profile.selected_capture_stamp_epoch: 1773327466
- executor_profile.raw_line_count: 48
- executor_profile.embedded_artifact_basename_matches_selected: true
- executor_profile.embedded_capture_epoch_matches_selected: true
- executor_profile.embedded_report_path_exists: true
- executor_profile.embedded_report_path_matches_selected: true
- executor_profile.integrity_status: OK
- executor_profile.integrity_reason: basename_match=true, capture_epoch_match=true, report_path_match=true

### Executor Profile Raw KV
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
elapsed_ms=43
profile.report.workload=Classic
profile.report.strategy=Original
profile.report.txs=20000
profile.report.keys=2000
profile.report.read_fanout=3
profile.report.write_every=1
profile.report.persist_profile=true
profile.report.capture_started_at_epoch=1773327466
profile.report.capture_started_at_iso=2026-03-12T14:57:46Z
profile.report.elapsed_ms=43
profile.report.estimated_conflict_rate=0.9000
profile.report.coverage_ratio=1.0000
profile.report.ungrouped_count=0
profile.report.grouping_complete=true
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
profile.report.path=/Users/qianqi/.openclaw/workspace/trnm-lane-worktrees/L11/trillionnium/run/bench/executor-profile-summary-1773327466.txt
profile.report.artifact_basename=executor-profile-summary-1773327466.txt

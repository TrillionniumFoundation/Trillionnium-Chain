#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

PROFILE="${TRNM_PERSISTENT_SCALE_PROFILE:-smoke}"
EVIDENCE_ROOT="${TRNM_PERSISTENT_SCALE_EVIDENCE_ROOT:-$PWD/run/persistent-scale/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
BIN="${TRNM_PERSISTENT_SCALE_BIN:-}"

case "$PROFILE" in
  smoke)
    objects=10000
    updates=10000
    batch_size=1000
    live_set=1000
    retain_versions=8
    timeout_seconds=600
    memory_max=1536M
    memory_max_bytes=1610612736
    minimum_available_kib=2097152
    minimum_disk_kib=8388608
    ;;
  formal)
    objects=1000000
    updates=1000000
    batch_size=10000
    live_set=10000
    retain_versions=64
    timeout_seconds=7200
    memory_max=3G
    memory_max_bytes=3221225472
    minimum_available_kib=5242880
    minimum_disk_kib=50331648
    ;;
  *)
    printf 'unsupported TRNM_PERSISTENT_SCALE_PROFILE=%s (allowed: smoke, formal)\n' "$PROFILE" >&2
    exit 2
    ;;
esac

for command_name in cargo git jq prlimit sha256sum sync timeout; do
  command -v "$command_name" >/dev/null
done
test -x /usr/bin/time

git_worktree_clean=false
if [[ -z "$(git status --porcelain --untracked-files=all)" ]]; then
  git_worktree_clean=true
fi
if [[ "$PROFILE" == "formal" ]]; then
  if [[ "$git_worktree_clean" != "true" ]]; then
    printf 'formal persistent scale gate requires a clean Git worktree\n' >&2
    exit 2
  fi
  if [[ -n "$BIN" ]]; then
    printf 'formal persistent scale gate builds the binary from the clean checked-out HEAD; external binaries are not accepted\n' >&2
    exit 2
  fi
fi

available_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
disk_available_kib="$(df -Pk "$PWD" | awk 'NR==2 {print $4}')"
if [[ -z "$available_kib" || "$available_kib" -lt "$minimum_available_kib" ]]; then
  printf 'persistent scale preflight failed: MemAvailable=%s KiB required=%s KiB\n' \
    "${available_kib:-unknown}" "$minimum_available_kib" >&2
  exit 2
fi
if [[ -z "$disk_available_kib" || "$disk_available_kib" -lt "$minimum_disk_kib" ]]; then
  printf 'persistent scale preflight failed: disk_available=%s KiB required=%s KiB\n' \
    "${disk_available_kib:-unknown}" "$minimum_disk_kib" >&2
  exit 2
fi

if [[ -e "$EVIDENCE_ROOT" ]]; then
  if [[ ! -d "$EVIDENCE_ROOT" || -n "$(find "$EVIDENCE_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    printf 'persistent scale evidence directory must be absent or empty: %s\n' "$EVIDENCE_ROOT" >&2
    exit 2
  fi
else
  mkdir -p -- "$EVIDENCE_ROOT"
fi
mkdir -- "$EVIDENCE_ROOT/data"

if [[ -z "$BIN" ]]; then
  target_dir="${CARGO_TARGET_DIR:-$PWD/target}"
  if [[ "$target_dir" != /* ]]; then
    target_dir="$PWD/$target_dir"
  fi
  cargo build \
    --release \
    --locked \
    -p trnm-consensus-app \
    --features scale-gate \
    --bin trnm-persistent-scale
  BIN="$target_dir/release/trnm-persistent-scale"
fi
test -x "$BIN"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git_head="$(git rev-parse HEAD)"
binary_sha256="$(sha256sum "$BIN" | awk '{print $1}')"
report_tmp="$EVIDENCE_ROOT/report.json.tmp"
report="$EVIDENCE_ROOT/report.json"
time_report="$EVIDENCE_ROOT/time.txt"
expected_initial_batches=$(((objects + batch_size - 1) / batch_size))
expected_update_batches=$(((updates + batch_size - 1) / batch_size))
prune_batch_rows=256
prune_batch_logical_bytes=4194304

gate_args=(
  --work-dir "$EVIDENCE_ROOT/data"
  --objects "$objects"
  --updates "$updates"
  --batch-size "$batch_size"
  --live-set "$live_set"
  --prune-retain-versions "$retain_versions"
  --prune-batch-rows "$prune_batch_rows"
  --prune-batch-logical-bytes "$prune_batch_logical_bytes"
)

set +e
if command -v systemd-run >/dev/null \
  && command -v systemctl >/dev/null \
  && systemctl --user show-environment >/dev/null 2>&1; then
  timeout --signal=TERM --kill-after=30 "$timeout_seconds" \
    systemd-run --user --scope --quiet \
      --property="MemoryMax=$memory_max" \
      /usr/bin/time -v -o "$time_report" \
      "$BIN" "${gate_args[@]}" >"$report_tmp"
  status=$?
  resource_limiter=systemd_user_scope
else
  if [[ "$PROFILE" == "formal" ]]; then
    printf 'formal persistent scale gate requires a working systemd user scope for MemoryMax\n' >&2
    status=2
    resource_limiter=unavailable
  else
    timeout --signal=TERM --kill-after=30 "$timeout_seconds" \
      prlimit --as="$memory_max_bytes" -- \
      /usr/bin/time -v -o "$time_report" \
      "$BIN" "${gate_args[@]}" >"$report_tmp"
    status=$?
    resource_limiter=prlimit_address_space
  fi
fi
set -e

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
time_report_valid=false
time_report_sha256=""
if [[ -s "$time_report" ]] && awk '
  /Command being timed:/ { command_seen=1 }
  /Elapsed \(wall clock\) time/ { elapsed_seen=1 }
  /Maximum resident set size \(kbytes\): [0-9]+$/ { rss_seen=1 }
  /Exit status: 0$/ { exit_ok=1 }
  END { exit !(command_seen && elapsed_seen && rss_seen && exit_ok) }
' "$time_report"; then
  sync -f "$time_report"
  time_report_sha256="$(sha256sum "$time_report" | awk '{print $1}')"
  time_report_valid=true
fi
if [[ "$time_report_valid" != "true" && "$status" -eq 0 ]]; then
  status=5
fi
if [[ -s "$report_tmp" ]] \
  && jq -s -e 'length == 1 and (.[0] | type == "object")' "$report_tmp" >/dev/null 2>&1; then
  mv -- "$report_tmp" "$report"
  sync -f "$report"
  report_sha256="$(sha256sum "$report" | awk '{print $1}')"
  report_valid=true
else
  report_sha256=""
  report_valid=false
fi
if [[ "$report_valid" != "true" && "$status" -eq 0 ]]; then
  status=3
fi

report_assertions_passed=false
if [[ "$report_valid" == "true" ]] && jq -e \
  --arg profile "$PROFILE" \
  --argjson objects "$objects" \
  --argjson updates "$updates" \
  --argjson batch_size "$batch_size" \
  --argjson live_set "$live_set" \
  --argjson retain_versions "$retain_versions" \
  --argjson prune_batch_rows "$prune_batch_rows" \
  --argjson prune_batch_logical_bytes "$prune_batch_logical_bytes" \
  --argjson expected_initial_batches "$expected_initial_batches" \
  --argjson expected_update_batches "$expected_update_batches" \
  '
    .schema == "trnm_apphash_v4_persistent_scale_report_v2"
    and .scope.persistent_sqlite == true
    and .scope.sqlite_synchronous_full == true
    and .scope.single_process == true
    and .scope.single_host == true
    and .scope.canonical_finalize_block == false
    and .scope.cometbft_end_to_end == false
    and .scope.public_testnet_evidence == false
    and .passed == true
    and .failure_reason == null
    and .completed_exactly == true
    and .parameters.objects == $objects
    and .parameters.updates == $updates
    and .parameters.batch_size == $batch_size
    and .parameters.fixed_live_set == $live_set
    and .parameters.prune_retain_versions == $retain_versions
    and .parameters.prune_batch_rows == $prune_batch_rows
    and .parameters.prune_batch_logical_bytes == $prune_batch_logical_bytes
    and .completed.objects == $objects
    and .completed.updates == $updates
    and .completed.initial_load_batches == $expected_initial_batches
    and .completed.update_batches == $expected_update_batches
    and (.batch_metrics | length) == ($expected_initial_batches + $expected_update_batches)
    and (.phase_latency | length) == 2
    and ([.proofs[] | select(.verified_by_store == true)] | length) == (.proofs | length)
    and (.proofs | length) >= 8
    and (.prune as $prune
      | $prune.complete == true
        and $prune.latest_root_unchanged == true
        and $prune.snapshot_pin_yields > 0
        and $prune.snapshot_pin_yield_observed == true
        and $prune.retries.snapshot_pinned == $prune.snapshot_pin_yields
        and $prune.writer_yielded_batches > 0
        and $prune.commit_samples == 32
        and $prune.prune_pending_commit_samples >= 4
        and $prune.prune_pending_commit_samples <= $prune.commit_samples
        and $prune.commit_latency.samples == $prune.commit_samples
        and $prune.commit_p95_guardrail_us == 50000
        and $prune.commit_max_ceiling_us == 250000
        and $prune.commit_latency.p95_us <= $prune.commit_p95_guardrail_us
        and $prune.commit_latency.max_us <= $prune.commit_max_ceiling_us
        and $prune.requested_floor
          == ($prune.collision_requested_floor + $prune.commit_samples)
        and $prune.query_floor_after_request == $prune.requested_floor
        and $prune.target_after_request == $prune.requested_floor
        and $prune.final_query_floor == $prune.requested_floor
        and $prune.final_target == null
        and $prune.floor_minus_one_rejected == true
        and $prune.batch_budget_semantics
          == "progress_preserving_soft_limit_after_first_row"
        and $prune.batch_latency.samples == $prune.batches
        and $prune.batch_p99_guardrail_us == 50000
        and $prune.batch_max_ceiling_us == 250000
        and $prune.batch_latency.p99_us <= $prune.batch_p99_guardrail_us
        and $prune.batch_latency.max_us <= $prune.batch_max_ceiling_us
        and $prune.latency_guardrails_passed == true
        and $prune.adaptive_target_us == 25000
        and $prune.adaptive_batching_observed == true
        and ($prune.adaptive_batch_reductions + $prune.adaptive_batch_increases) > 0
        and $prune.initial_batch_rows == (($prune_batch_rows / 2) | floor)
        and $prune.initial_batch_logical_bytes
          == (($prune_batch_logical_bytes / 2) | floor)
        and $prune.minimum_batch_rows >= 1
        and $prune.minimum_batch_rows <= $prune_batch_rows
        and $prune.minimum_batch_logical_bytes >= 65536
        and $prune.minimum_batch_logical_bytes <= $prune_batch_logical_bytes
        and $prune.final_batch_rows >= 1
        and $prune.final_batch_rows <= $prune_batch_rows
        and $prune.final_batch_logical_bytes >= 65536
        and $prune.final_batch_logical_bytes <= $prune_batch_logical_bytes
        and $prune.removals.nodes > 0
        and $prune.removals.value_versions > 0
        and $prune.removals.stale_indices > 0
        and $prune.removals.roots > 0)
    and .restart.exact_head_match == true
    and (.snapshot as $snapshot
      | $snapshot.format == 4
        and $snapshot.total_bytes > 0
        and $snapshot.chunks > 0
        and $snapshot.exact_head_match == true
        and $snapshot.source_height == $snapshot.restored_height
        and $snapshot.source_app_hash_hex == $snapshot.restored_app_hash_hex
        and $snapshot.continued_after_restore == true
        and $snapshot.continued_height == ($snapshot.source_height + 1)
        and $snapshot.restart_after_continue_match == true
        and (if $snapshot.chunks > 1
          then $snapshot.resumed_across_restart == true
            and $snapshot.chunks_before_restart > 0
            and $snapshot.chunks_before_restart < $snapshot.chunks
          else $snapshot.resumed_across_restart == false
            and $snapshot.chunks_before_restart == 0
          end))
    and ([.database_metrics[]
      | select(.journal_mode == "wal" and .synchronous == 2)] | length)
      == (.database_metrics | length)
    and any(.database_metrics[];
      .stage == "after_snapshot_restore"
      and .auth_stale_values == 0
      and .auth_roots == 1)
    and .file_peaks.database_logical_bytes > 0
    and .file_peaks.snapshot_logical_bytes > 0
    and .file_peaks.restore_staging_logical_bytes > 0
    and .file_peaks.temporary_logical_bytes > 0
    and .file_peaks.work_dir_logical_bytes > 0
    and (if $profile == "formal"
      then .workload_class == "at_least_1m_objects_and_1m_updates"
        and .measurement_profile == "release"
        and .million_gate_eligible == true
        and .snapshot.chunks > 1
        and .snapshot.total_bytes <= 1073741824
        and .snapshot.resumed_across_restart == true
        and .file_peaks.wal_logical_bytes > 0
        and any(.database_metrics[];
          .stage == "after_snapshot_restore"
          and .page_size == 4096
          and .page_count <= 262144
          and .objects <= 1100000
          and .auth_nodes <= 2000000
          and .auth_values <= 1100001
          and .auth_preimages <= 1100001)
      else .workload_class == "smoke_or_custom_below_1m_not_a_million_gate"
        and .million_gate_eligible == false
      end)
  ' "$report" >/dev/null; then
  report_assertions_passed=true
fi
if [[ "$report_assertions_passed" != "true" && "$status" -eq 0 ]]; then
  status=4
fi

jq -n \
  --arg schema trnm_persistent_scale_evidence_v3 \
  --arg profile "$PROFILE" \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --arg git_head "$git_head" \
  --arg binary "$BIN" \
  --arg binary_sha256 "$binary_sha256" \
  --arg report "$report" \
  --arg report_sha256 "$report_sha256" \
  --arg time_report "$time_report" \
  --arg time_report_sha256 "$time_report_sha256" \
  --arg resource_limiter "$resource_limiter" \
  --arg memory_max "$memory_max" \
  --argjson status "$status" \
  --argjson report_valid "$report_valid" \
  --argjson report_assertions_passed "$report_assertions_passed" \
  --argjson time_report_valid "$time_report_valid" \
  --argjson git_worktree_clean "$git_worktree_clean" \
  --argjson objects "$objects" \
  --argjson updates "$updates" \
  --argjson batch_size "$batch_size" \
  --argjson live_set "$live_set" \
  --argjson retain_versions "$retain_versions" \
  --argjson prune_batch_rows "$prune_batch_rows" \
  --argjson prune_batch_logical_bytes "$prune_batch_logical_bytes" \
  --argjson timeout_seconds "$timeout_seconds" \
  --argjson preflight_mem_available_kib "$available_kib" \
  --argjson preflight_disk_available_kib "$disk_available_kib" \
  '{
    schema: $schema,
    profile: $profile,
    scope: {
      persistent_sqlite: true,
      single_process: true,
      single_host: true,
      canonical_finalize_block: false,
      cometbft_end_to_end: false,
      public_testnet_evidence: false
    },
    started_at: $started_at,
    finished_at: $finished_at,
    git_head: $git_head,
    git_worktree_clean: $git_worktree_clean,
    binary: $binary,
    binary_sha256: $binary_sha256,
    report: $report,
    report_sha256: $report_sha256,
    report_valid: $report_valid,
    report_assertions_passed: $report_assertions_passed,
    time_report: $time_report,
    time_report_sha256: $time_report_sha256,
    time_report_valid: $time_report_valid,
    exit_status: $status,
    resource_limiter: $resource_limiter,
    memory_max: $memory_max,
    workload: {
      objects: $objects,
      updates: $updates,
      batch_size: $batch_size,
      live_set: $live_set,
      prune_retain_versions: $retain_versions,
      prune_batch_rows: $prune_batch_rows,
      prune_batch_logical_bytes: $prune_batch_logical_bytes
    },
    timeout_seconds: $timeout_seconds,
    preflight: {
      mem_available_kib: $preflight_mem_available_kib,
      disk_available_kib: $preflight_disk_available_kib
    }
  }' >"$EVIDENCE_ROOT/evidence.json"
sync -f "$EVIDENCE_ROOT/evidence.json"

if [[ "$status" -ne 0
  || "$report_valid" != "true"
  || "$report_assertions_passed" != "true"
  || "$time_report_valid" != "true" ]]; then
  printf 'TRNM_PERSISTENT_SCALE_FAILED profile=%s status=%s evidence=%s\n' \
    "$PROFILE" "$status" "$EVIDENCE_ROOT" >&2
  exit "${status:-1}"
fi

printf 'TRNM_PERSISTENT_SCALE_OK profile=%s evidence=%s report_sha256=%s\n' \
  "$PROFILE" "$EVIDENCE_ROOT" "$report_sha256"

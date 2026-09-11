#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUNS="${RUNS:-3}"
if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
  echo "[FAIL] RUNS must be a positive integer: $RUNS" >&2
  exit 2
fi

if [[ -n "${EXPECTED_WORKTREE_ROOT:-}" ]]; then
  actual_root="$(git rev-parse --show-toplevel)"
  expected_root="$(cd "$EXPECTED_WORKTREE_ROOT" && pwd -P)"
  if [[ "$(cd "$actual_root" && pwd -P)" != "$expected_root" ]]; then
    echo "[FAIL] worktree root mismatch: expected=$expected_root actual=$actual_root" >&2
    exit 2
  fi
fi

if [[ -n "${EXPECTED_HEAD:-}" ]]; then
  actual_head="$(git rev-parse HEAD)"
  if [[ "$actual_head" != "$EXPECTED_HEAD" ]]; then
    echo "[FAIL] HEAD mismatch: expected=$EXPECTED_HEAD actual=$actual_head" >&2
    exit 2
  fi
fi

# EXPECTED_BRANCH_REF is intentionally not used as authority in pull-request CI:
# exact source commit/tree is stronger than a mutable branch name.

TS="$(date +%Y%m%d-%H%M%S)"
OUT="${BFT_RESTART_RECOVERY_OUT:-$ROOT/run/bft-restart-recovery-$TS.txt}"
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

echo "schema=trnm-native-poco-restart-recovery-v1" >> "$OUT"
echo "source_head=$(git rev-parse HEAD)" >> "$OUT"
echo "source_tree=$(git rev-parse 'HEAD^{tree}')" >> "$OUT"
echo "runs=$RUNS" >> "$OUT"
echo "consensus=native-poco-bft" >> "$OUT"
echo "legacy_harness=false" >> "$OUT"

run_case() {
  local filter="$1"
  cargo test -q -p trnm-poco-node \
    --features g1-process-test-support \
    --test g1_process_host_e2e \
    "$filter" \
    --locked --offline -- --exact --nocapture
}

for i in $(seq 1 "$RUNS"); do
  echo "[native-restart] run=$i/$RUNS clean-restart"
  if ! run_case real_process_checktx_native_apphash_and_wal_commit_are_observable; then
    echo "failed_case=clean_restart" >> "$OUT"
    echo "failed_run=$i" >> "$OUT"
    echo "status=FAIL" >> "$OUT"
    echo "[FAIL] native clean restart recovery failed run=$i report=$OUT" >&2
    exit 1
  fi

  echo "[native-restart] run=$i/$RUNS post-application-commit-sigkill"
  if ! run_case sigkill_after_application_commit_recovers_exact_wal_handoff; then
    echo "failed_case=post_application_commit_sigkill" >> "$OUT"
    echo "failed_run=$i" >> "$OUT"
    echo "status=FAIL" >> "$OUT"
    echo "[FAIL] native SIGKILL recovery failed run=$i report=$OUT" >&2
    exit 1
  fi

  echo "[native-restart] run=$i/$RUNS ambiguous-handoff-fail-closed"
  if ! run_case sigkill_after_handoff_without_application_evidence_stays_fail_closed; then
    echo "failed_case=ambiguous_handoff_fail_closed" >> "$OUT"
    echo "failed_run=$i" >> "$OUT"
    echo "status=FAIL" >> "$OUT"
    echo "[FAIL] native ambiguous-handoff fence failed run=$i report=$OUT" >&2
    exit 1
  fi
done

echo "status=PASS" >> "$OUT"
echo "report=$OUT"
echo "[OK] native PoCO restart/recovery matrix passed runs=$RUNS"

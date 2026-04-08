#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/p1-rust-sidecar.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'P1_SUMMARY_PATH="run/p1-integration-gate/summary-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}.json"'
  'mkdir -p "$(dirname "$P1_SUMMARY_PATH")"'
  '"status": "warn-missing-artifacts"'
  '"status": "ok"'
  '"run_dir": "' 
  'cat >"$P1_SUMMARY_PATH" <<EOF'
  'echo "p1_summary_json=$P1_SUMMARY_PATH" >> "$GITHUB_OUTPUT"'
  'summary_json: ${{ steps.p1-summary.outputs.p1_summary_json }}'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing P1 artifact summary guard line: $line" >&2
    exit 1
  fi
done

if grep -Fq 'echo "::warning::No run/p1-integration-gate artifacts found"' "$WF" && ! grep -Fq 'cat >"$P1_SUMMARY_PATH" <<EOF' "$WF"; then
  echo "[FAIL] warning-only missing-artifacts path must emit structured summary evidence" >&2
  exit 1
fi

echo "[PASS] p1_trillionnium_artifact_summary_guard_test"

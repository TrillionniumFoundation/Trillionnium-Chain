#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# A retired adapter must not remain runnable just because no workflow names it.
# Reject dangling links too, so restoring an external target cannot revive it.
retired_paths=(
  scripts/v2/trnm_tx_cli_real_adapter.sh
  scripts/v2/trnm_tx_cli_real_adapter.template.sh
  scripts/v2/worker_real_cli.env.example
)
for retired_path in "${retired_paths[@]}"; do
  if [[ -e "$retired_path" || -L "$retired_path" ]]; then
    echo "[FAIL] retired worker adapter path returned: $retired_path" >&2
    exit 3
  fi
done

active_workflows=()
for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
  [[ -f "$workflow" ]] || continue
  active_workflows+=("$workflow")
done
[[ "${#active_workflows[@]}" -gt 0 ]] || {
  echo "[FAIL] no active workflows found" >&2
  exit 2
}

automation_inputs=(
  scripts/auto_iterate.tasks
  scripts/auto_relay_codegen.steps
)

retired_refs=(
  run_worker_receipt_gates_real_cli.sh
  trnm_tx_cli_wrapper.sh
  worker_real_cli_
  worker_real_cli.env.example
  worker_agent_onboard_mvp.sh
  trnm_tx_cli_real_adapter
  TRNM_WORKER_ALLOW_EXTERNAL_TX_CLI
  REQUIRE_REAL_TX_CLI
)

for workflow in "${active_workflows[@]}"; do
  [[ -f "$workflow" ]] || { echo "[FAIL] active workflow missing: $workflow" >&2; exit 2; }
  for retired_ref in "${retired_refs[@]}"; do
    if grep -Fq -- "$retired_ref" "$workflow"; then
      echo "[FAIL] retired worker real-CLI reference returned to $workflow: $retired_ref" >&2
      exit 3
    fi
  done
done

for automation_input in "${automation_inputs[@]}"; do
  [[ -f "$automation_input" ]] || {
    echo "[FAIL] automation input missing: $automation_input" >&2
    exit 3
  }
  for retired_ref in "${retired_refs[@]}"; do
    if grep -Fq -- "$retired_ref" "$automation_input"; then
      echo "[FAIL] retired worker integration task returned to $automation_input: $retired_ref" >&2
      exit 3
    fi
  done
done

grep -Fq -- './scripts/v2/worker_poco_cli_cutover_workflow_guard_test.sh' \
  .github/workflows/trnm-gate-quick-check.yml || {
  echo "[FAIL] cutover workflow regression missing from quick-check" >&2
  exit 6
}

[[ -x scripts/v2/worker_poco_cli_cutover_gate.sh ]] || {
  echo "[FAIL] active PoCO CLI cutover gate is not executable" >&2
  exit 7
}

echo "[OK] retired worker adapter paths are absent and active workflows preserve the native PoCO CLI cutover"

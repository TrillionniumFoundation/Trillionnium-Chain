#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
DEFAULT_WORKFLOW="$ROOT/.github/workflows/trnm-poco-bft-v0.yml"

fail() {
  printf 'PoCO-BFT workflow trigger truth failed: %s\n' "$*" >&2
  exit 1
}

check_workflow() {
  local workflow="$1"
  [[ -f "$workflow" ]] || fail "missing workflow: $workflow"
  python3 - "$workflow" "$ROOT/trillionnium/Cargo.toml" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
workspace = pathlib.Path(sys.argv[2])
text = path.read_text(encoding="utf-8")
lines = text.splitlines()


def fail(message: str) -> None:
    raise SystemExit(f"{path}: {message}")

if not workspace.is_file():
    fail(f"missing workspace manifest {workspace}")
workspace_text = workspace.read_text(encoding="utf-8")
for retired_member in ('"crates/trnm-consensus-app"', '"crates/trnm-node"'):
    if retired_member in workspace_text:
        fail(f"retired consensus member remains active: {retired_member}")

for required in ("on:", "jobs:", "  schedule:", "  workflow_dispatch:", "  pull_request:", "  push:"):
    if required not in text:
        fail(f"missing required workflow structure: {required}")

# Keep the scheduled gate anchored to main and keep PR/push coverage on the
# native consensus, safety, execution, persistence and workflow-control paths.
if "branches:\n      - main" not in text:
    fail("push trigger must include main")
required_paths = (
    "trillionnium/crates/trnm-consensus-core/**",
    "trillionnium/crates/trnm-consensus-safety-rules/**",
    "trillionnium/crates/trnm-consensus-safety-store/**",
    "trillionnium/crates/trnm-consensus-types/**",
    "trillionnium/crates/trnm-consensus-crypto/**",
    "trillionnium/crates/trnm-native-execution-v0/**",
    "trillionnium/crates/trnm-poco-node/**",
    "trillionnium/crates/trnm-state-sync-v0/**",
    "scripts/ci/check_poco_bft_v0_**",
    ".github/workflows/trnm-poco-bft-v0.yml",
)
for item in required_paths:
    if item not in text:
        fail(f"missing native PoCO trigger coverage: {item}")

for retired_path in (
    "trillionnium/crates/trnm-consensus-app/**",
    "trillionnium/crates/trnm-node/**",
):
    if retired_path in text:
        fail(f"retired consensus path remains in workflow trigger: {retired_path}")

for forbidden in (
    "cometbft",
    "tendermint",
    "contents: write",
    "id-token: write",
    "deployments: write",
    "production_consensus_activation=true",
    "production_ready=true",
):
    if forbidden.lower() in text.lower():
        fail(f"forbidden workflow authority/residue marker: {forbidden}")

for required_marker in (
    "permissions:\n  contents: read",
    "production_consensus_activation=false",
    "production_ready=false",
    "github.ref == 'refs/heads/main'",
    "github.triggering_actor == github.actor",
):
    if required_marker not in text:
        fail(f"missing safety marker: {required_marker}")

# Every job must be explicitly gated; this prevents a later helper job from
# silently bypassing the same actor/repository/main-schedule boundary.
jobs_index = lines.index("jobs:")
job_starts = [i for i in range(jobs_index + 1, len(lines)) if re.fullmatch(r"  [A-Za-z0-9_-]+:\s*", lines[i])]
if not job_starts:
    fail("jobs section contains no jobs")
for n, start in enumerate(job_starts):
    end = job_starts[n + 1] if n + 1 < len(job_starts) else len(lines)
    block = "\n".join(lines[start:end])
    if "    if:" not in block:
        fail(f"job at line {start + 1} has no explicit actor/event gate")

print(f"poco_bft_workflow_trigger_truth=passed jobs={len(job_starts)}")
PY
}

self_test() {
  check_workflow "$DEFAULT_WORKFLOW"
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN
  cp "$DEFAULT_WORKFLOW" "$tmp"
  python3 - "$tmp" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
s = p.read_text(encoding="utf-8")
s = s.replace("  workflow_dispatch:\n", "", 1)
p.write_text(s, encoding="utf-8")
PY
  if check_workflow "$tmp" >/dev/null 2>&1; then
    fail "self-test accepted workflow without workflow_dispatch"
  fi
  cp "$DEFAULT_WORKFLOW" "$tmp"
  printf '\n# cometbft residue mutant\n' >> "$tmp"
  if check_workflow "$tmp" >/dev/null 2>&1; then
    fail "self-test accepted retired consensus residue"
  fi
  printf 'poco_bft_workflow_trigger_truth_self_test=passed\n'
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  "")
    check_workflow "$DEFAULT_WORKFLOW"
    ;;
  *)
    check_workflow "$1"
    ;;
esac

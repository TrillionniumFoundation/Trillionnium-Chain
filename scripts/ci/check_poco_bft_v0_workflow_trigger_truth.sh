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
  python3 - "$workflow" "${2:-$ROOT/trillionnium/Cargo.toml}" <<'PY'
import fnmatch
import pathlib
import re
import sys
import tomllib

path = pathlib.Path(sys.argv[1])
workspace = pathlib.Path(sys.argv[2])
text = path.read_text(encoding="utf-8")
lines = text.splitlines()


def fail(message: str) -> None:
    raise SystemExit(f"{path}: {message}")

if not workspace.is_file():
    fail(f"missing workspace manifest {workspace}")
workspace_data = tomllib.loads(workspace.read_text(encoding="utf-8"))["workspace"]
members = workspace_data["members"]
if not isinstance(members, list) or not all(isinstance(member, str) for member in members):
    fail("workspace.members must be an array of paths")
retired_members = ("crates/trnm-consensus-" + "app", "crates/trnm-" + "node")
for retired_member in retired_members:
    retired_path = workspace.parent.joinpath(retired_member).resolve()
    if any(fnmatch.fnmatchcase(str(retired_path), str(workspace.parent.joinpath(member).resolve()))
           for member in members):
        fail(f"retired consensus member remains active: {retired_member}")

for required in ("on:", "jobs:", "  schedule:", "  workflow_dispatch:", "  pull_request:", "  push:"):
    if required not in text:
        fail(f"missing required workflow structure: {required}")
if "branches: [main]" not in text and "branches:\n      - main" not in text:
    fail("push trigger must include main")

required_paths = (
    "trillionnium/crates/trnm-consensus-core/**",
    "trillionnium/crates/trnm-consensus-safety-rules/**",
    "trillionnium/crates/trnm-consensus-safety-store/**",
    "trillionnium/crates/trnm-consensus-types/**",
    "trillionnium/crates/trnm-consensus-crypto/**",
    "trillionnium/crates/trnm-native-execution-v0/**",
    "trillionnium/crates/trnm-poco-node/**",
    "trillionnium/crates/trnm-consensus-external-watermark/**",
    "trillionnium/crates/trnm-consensus-peer-lease/**",
    "trillionnium/crates/trnm-consensus-remote-signer-service/**",
    "scripts/ci/check_poco_bft_v0_*",
    ".github/workflows/trnm-poco-bft-v0.yml",
)
for item in required_paths:
    if item not in text:
        fail(f"missing native PoCO trigger coverage: {item}")

retired_paths = (
    "trillionnium/crates/trnm-consensus-" + "app/**",
    "trillionnium/crates/trnm-" + "node/**",
)
for retired_path in retired_paths:
    if retired_path in text:
        fail(f"retired consensus path remains in workflow trigger: {retired_path}")

for forbidden in (
    "contents: write",
    "id-token: write",
    "deployments: write",
    "production_consensus_activation=true",
    "production_ready=true",
):
    if forbidden.lower() in text.lower():
        fail(f"forbidden workflow authority marker: {forbidden}")

for required_marker in (
    "permissions:\n  contents: read",
    "production_consensus_activation=false",
    "production_ready=false",
    "github.ref == 'refs/heads/main'",
    "github.triggering_actor == github.actor",
):
    if required_marker not in text:
        fail(f"missing safety marker: {required_marker}")

jobs_index = lines.index("jobs:")
job_starts = [i for i in range(jobs_index + 1, len(lines)) if re.fullmatch(r"  [A-Za-z0-9_-]+:\s*", lines[i])]
if len(job_starts) != 6:
    fail(f"expected six separated PoCO gate jobs, found {len(job_starts)}")
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
  local tmp manifest
  tmp="$(mktemp)"
  manifest="$(mktemp)"
  trap 'rm -f "$tmp" "$manifest"' RETURN

  # Prefix-sharing active crates and comments must not look like retired members.
  printf '%s\n' '[workspace]' \
    'members = ["crates/trnm-node-io", "crates/trnm-node-host"]' \
    '# crates/trnm-node' > "$manifest"
  check_workflow "$DEFAULT_WORKFLOW" "$manifest"
  for member in "crates/trnm-consensus-""app" "crates/trnm-""node" \
    './crates/trnm-node/' 'crates/trnm-*'; do
    printf '[workspace]\nmembers = ["%s"]\n' "$member" > "$manifest"
    if check_workflow "$DEFAULT_WORKFLOW" "$manifest" >/dev/null 2>&1; then
      fail "self-test accepted retired workspace member: $member"
    fi
  done
  printf '%s\n' '[workspace]' 'members = "crates/trnm-node-io"' > "$manifest"
  if check_workflow "$DEFAULT_WORKFLOW" "$manifest" >/dev/null 2>&1; then
    fail "self-test accepted malformed workspace members"
  fi

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
  printf '\n  - %s\n' "trillionnium/crates/trnm-consensus-""app/**" >> "$tmp"
  if check_workflow "$tmp" >/dev/null 2>&1; then
    fail "self-test accepted retired consensus trigger path"
  fi

  printf 'poco_bft_workflow_trigger_truth_self_test=passed\n'
}

case "${1:-}" in
  --self-test) self_test ;;
  "") check_workflow "$DEFAULT_WORKFLOW" ;;
  *) check_workflow "$1" ;;
esac

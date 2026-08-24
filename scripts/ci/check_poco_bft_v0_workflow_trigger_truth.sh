#!/usr/bin/env bash
set -euo pipefail

# Static contract for the PoCO-BFT workflow trigger. The workflow has had
# schedule branches in every job for some time; this check makes the trigger
# explicit and keeps scheduled runs inside the development-only fail-closed
# boundary used by manual and PR runs.

SCRIPT_DIR="$(cd -- "$(dirname -- "$BASH_SOURCE")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
DEFAULT_WORKFLOW="$ROOT/.github/workflows/trnm-poco-bft-v0.yml"
EXPECTED_CRON='17 3 * * 1'

fail() {
  printf 'PoCO-BFT workflow trigger truth failed: %s\n' "$*" >&2
  exit 1
}

check_workflow() {
  local workflow="$1"
  [[ -f "$workflow" ]] || fail "missing workflow: $workflow"
  python3 - "$workflow" "$EXPECTED_CRON" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
expected_cron = sys.argv[2]
text = path.read_text(encoding="utf-8")
lines = text.splitlines()

def fail(message: str) -> None:
    raise SystemExit(f"{path}: {message}")

def top_level_index(name: str) -> int:
    matches = [
        index for index, line in enumerate(lines)
        if re.fullmatch(rf"{re.escape(name)}:\s*", line)
    ]
    if len(matches) != 1:
        fail(f"expected exactly one top-level {name}: key")
    return matches[0]

on_index = top_level_index("on")
jobs_index = top_level_index("jobs")
if on_index > jobs_index:
    fail("top-level on: must precede jobs:")

# Read only direct children of the top-level on mapping. This avoids a
# PyYAML dependency (whose YAML 1.1 parser treats on as a boolean) while
# rejecting an indented/dead schedule hidden in a job body.
on_children = []
for index in range(on_index + 1, len(lines)):
    line = lines[index]
    if line and not line.startswith((" ", "\t", "#")):
        break
    match = re.fullmatch(r"  ([A-Za-z0-9_-]+):(?:\s*(.*))?", line)
    if match:
        on_children.append((match.group(1), index))

child_names = [name for name, _ in on_children]
for required in ("schedule", "workflow_dispatch", "pull_request", "push"):
    if child_names.count(required) != 1:
        fail(f"top-level on: must contain exactly one {required}: trigger")

schedule_index = next(index for name, index in on_children if name == "schedule")
dispatch_index = next(index for name, index in on_children if name == "workflow_dispatch")
if schedule_index >= dispatch_index:
    fail("schedule trigger must be declared before workflow_dispatch")

cron_values = []
for index in range(schedule_index + 1, dispatch_index):
    match = re.fullmatch(
        r"""    -\s+cron:\s*(['"]?)([^'"]+)\1\s*(?:#.*)?""",
        lines[index],
    )
    if match:
        cron_values.append(match.group(2).strip())
if cron_values != [expected_cron]:
    fail(f"expected one weekly cron {expected_cron!r}, found {cron_values!r}")

# Every job must retain the repository and actor gates. A schedule event is
# trusted only because GitHub creates it on the canonical repository/default
# branch; it must not weaken the self-hosted runner boundary for other events.
job_blocks = []
job_start = None
job_name = None
for index in range(jobs_index + 1, len(lines) + 1):
    line = lines[index] if index < len(lines) else ""
    match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
    if match:
        if job_start is not None:
            job_blocks.append((job_name, lines[job_start:index]))
        job_name = match.group(1)
        job_start = index
if job_start is not None:
    job_blocks.append((job_name, lines[job_start:]))
if not job_blocks:
    fail("jobs: contains no jobs")

required_fragments = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain'",
    "github.event_name == 'schedule'",
    "github.ref == 'refs/heads/main'",
    "github.actor == 'ProfAlexQI'",
    "github.triggering_actor == 'ProfAlexQI'",
    "github.event.pull_request.head.repo.full_name == github.repository",
)
for name, block_lines in job_blocks:
    block = "\n".join(block_lines)
    if "    if:" not in block:
        fail(f"job {name} has no explicit event/actor gate")
    for fragment in required_fragments:
        if fragment not in block:
            fail(f"job {name} is missing trigger guard: {fragment}")
    if not re.search(
        r"github\.event_name == 'schedule'\s*&&\s*"
        r"github\.ref == 'refs/heads/main'\s*\|\|",
        block,
    ):
        fail(f"job {name} does not make the main-only schedule branch explicit")
    runs_on = re.search(r"(?m)^    runs-on:\s*(.+)$", block)
    if runs_on is None or not all(
        label in runs_on.group(1) for label in ("self-hosted", "x230", "trillionnium-chain")
    ):
        fail(f"job {name} lost the pinned self-hosted X230 runner labels")

# This workflow may build/test and upload development-only evidence, but it
# must never gain deployment or activation capability through a trigger edit.
for pattern, description in (
    (r"(?mi)^\s*environment\s*:", "deployment environment"),
    (r"(?mi)^\s*(?:deployment|ssh|scp|rsync)\s*:", "deployment/remote step"),
    (r"(?mi)^\s*(?:run|uses):.*\b(?:ssh|scp|rsync)\b", "remote command"),
    (r"(?mi)production(?:_consensus)?_activation\s*=\s*true", "production activation"),
    (r"(?mi)validator_run_7_completed\s*=\s*true", "validator completion claim"),
    (r"(?mi)production_ready\s*=\s*true", "production readiness claim"),
    (r"(?mi)^\s*contents\s*:\s*write\s*$", "contents write permission"),
    (r"(?mi)^\s*(?:deployments|id-token)\s*:\s*write\s*$", "elevated workflow permission"),
):
    if re.search(pattern, text):
        fail(f"forbidden {description} in scheduled workflow")

if not re.search(r"(?m)^permissions:\s*\n\s{2}contents:\s*read\s*$", text):
    fail("workflow must keep permissions.contents=read")
for marker in (
    "production_consensus_activation=false",
    "production_ready=false",
    "deployable_node=false",
):
    if marker not in text:
        fail(f"development-only artifact boundary lost marker: {marker}")

print(f"poco_bft_workflow_trigger_truth=passed cron={expected_cron} jobs={len(job_blocks)}")
PY
}

run_self_test() {
  local temp_root fixture
  local tmp_base
  tmp_base="$(printenv TMPDIR 2>/dev/null || printf '/tmp')"
  temp_root="$(mktemp -d "$tmp_base/trnm-poco-trigger-truth.XXXXXX")"
  trap 'rm -rf "$temp_root"' RETURN
  fixture="$temp_root/workflow.yml"
  cp -- "$DEFAULT_WORKFLOW" "$fixture"

  check_workflow "$fixture" >/dev/null

  # Removing the trigger must fail even though every job still contains a
  # dead github.event_name == schedule branch.
  python3 - "$fixture" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = '  schedule:\n    - cron: "17 3 * * 1"\n'
if text.count(needle) != 1:
    raise SystemExit("schedule fixture not found")
path.write_text(text.replace(needle, "", 1), encoding="utf-8")
PY
  if check_workflow "$fixture" >/dev/null 2>&1; then
    fail "self-test accepted a workflow with no schedule trigger"
  fi

  cp -- "$DEFAULT_WORKFLOW" "$fixture"
  sed -i 's/cron: "17 3 \* \* 1"/cron: "0 0 0 0 0"/' "$fixture"
  if check_workflow "$fixture" >/dev/null 2>&1; then
    fail "self-test accepted an invalid cron expression"
  fi

  cp -- "$DEFAULT_WORKFLOW" "$fixture"
  sed -i "0,/github.actor == 'ProfAlexQI'/s//github.actor == 'untrusted'/" "$fixture"
  if check_workflow "$fixture" >/dev/null 2>&1; then
    fail "self-test accepted a weakened actor gate"
  fi

  cp -- "$DEFAULT_WORKFLOW" "$fixture"
  sed -i "0,/github.ref == 'refs\/heads\/main'/s//github.ref == 'refs\/heads\/untrusted'/" "$fixture"
  if check_workflow "$fixture" >/dev/null 2>&1; then
    fail "self-test accepted a weakened schedule branch ref gate"
  fi

  cp -- "$DEFAULT_WORKFLOW" "$fixture"
  sed -i '0,/contents: read/s//contents: write/' "$fixture"
  if check_workflow "$fixture" >/dev/null 2>&1; then
    fail "self-test accepted elevated workflow permissions"
  fi

  printf '%s\n' \
    'poco_bft_workflow_trigger_truth_self_test=passed schedule=required,weekly dispatch=required actor_gate=preserved deployment=forbidden'
}

if [[ $# -gt 0 && "$1" == "--self-test" ]]; then
  [[ $# -eq 1 ]] || fail "usage: $0 [--self-test]"
  check_workflow "$DEFAULT_WORKFLOW"
  run_self_test
else
  [[ $# -eq 0 ]] || fail "usage: $0 [--self-test]"
  check_workflow "$DEFAULT_WORKFLOW"
fi

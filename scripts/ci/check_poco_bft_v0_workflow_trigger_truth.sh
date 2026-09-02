#!/usr/bin/env bash
set -euo pipefail

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
  python3 - "$workflow" "$EXPECTED_CRON" "$ROOT/trillionnium/Cargo.toml" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
expected_cron = sys.argv[2]
workspace_manifest = pathlib.Path(sys.argv[3])
text = path.read_text(encoding="utf-8")
lines = text.splitlines()

if not workspace_manifest.is_file():
    raise SystemExit(f"{path}: missing workspace manifest: {workspace_manifest}")
workspace_text = workspace_manifest.read_text(encoding="utf-8")
legacy_marker = '"crates/trnm-consensus-app"'
if legacy_marker not in workspace_text:
    raise SystemExit(f"{path}: expected excluded migration package marker {legacy_marker!r}")

def fail(message: str) -> None:
    raise SystemExit(f"{path}: {message}")

def top_level_index(name: str) -> int:
    matches = [
        index
        for index, line in enumerate(lines)
        if re.fullmatch(rf"{re.escape(name)}:\s*", line)
    ]
    if len(matches) != 1:
        fail(f"expected exactly one top-level {name}: key")
    return matches[0]

on_index = top_level_index("on")
jobs_index = top_level_index("jobs")
if on_index > jobs_index:
    fail("top-level on: must precede jobs:")

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

def direct_child_block(name: str) -> str:
    child_indexes = [index for child, index in on_children if child == name]
    if len(child_indexes) != 1:
        fail(f"top-level on: missing unique {name}: trigger")
    start = child_indexes[0]
    end = len(lines)
    for _, index in on_children:
        if index > start:
            end = index
            break
    return "\n".join(lines[start:end])

for trigger_name in ("pull_request", "push"):
    trigger_block = direct_child_block(trigger_name)
    if "trillionnium/crates/trnm-consensus-app/**" in trigger_block:
        fail(
            f"{trigger_name}: trigger still watches excluded migration package "
            "trillionnium/crates/trnm-consensus-app/**"
        )

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

actor_guard = re.compile(
    r"\(\(github\.actor == 'ProfAlexQI'\s*\|\|\s*"
    r"github\.actor == 'Tomasrgbsf'\)\s*&&\s*"
    r"github\.triggering_actor == github\.actor",
    re.S,
)
required_fragments = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain'",
    "github.event_name == 'schedule'",
    "github.ref == 'refs/heads/main'",
    "github.event.pull_request.head.repo.full_name == github.repository",
)
for name, block_lines in job_blocks:
    block = "\n".join(block_lines)
    if "    if:" not in block:
        fail(f"job {name} has no explicit event/actor gate")
    for fragment in required_fragments:
        if fragment not in block:
            fail(f"job {name} is missing trigger guard: {fragment}")
    if actor_guard.search(block) is None:
        fail(
            f"job {name} must restrict non-scheduled execution to the approved "
            "maintainer set and require triggering_actor == actor"
        )
    if not re.search(
        r"github\.event_name == 'schedule'\s*&&\s*"
        r"github\.ref == 'refs/heads/main'\s*\|\|",
        block,
    ):
        fail(f"job {name} does not make the main-only schedule branch explicit")
    runs_on = re.search(r"(?m)^    runs-on:\s*(.+)$", block)
    if runs_on is None or not all(
        label in runs_on.group(1)
        for label in ("self-hosted", "x230", "trillionnium-chain")
    ):
        fail(f"job {name} lost the pinned self-hosted X230 runner labels")

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

print(
    f"poco_bft_workflow_trigger_truth=passed cron={expected_cron} "
    f"jobs={len(job_blocks)} actor_policy=approved-maintainers"
)
PY
}

mutate_fixture() {
  local fixture="$1" mutation="$2"
  python3 - "$fixture" "$mutation" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]
text = path.read_text(encoding="utf-8")

if mutation == "remove-schedule":
    needle = '  schedule:\n    - cron: "17 3 * * 1"\n'
    if text.count(needle) != 1:
        raise SystemExit("schedule fixture not found")
    text = text.replace(needle, "", 1)
elif mutation == "bad-cron":
    needle = 'cron: "17 3 * * 1"'
    if needle not in text:
        raise SystemExit("cron fixture not found")
    text = text.replace(needle, 'cron: "0 0 0 0 0"', 1)
elif mutation == "weaken-actor":
    pattern = re.compile(
        r"\(\(github\.actor == 'ProfAlexQI'\s*\|\|\s*"
        r"github\.actor == 'Tomasrgbsf'\)\s*&&\s*"
        r"github\.triggering_actor == github\.actor"
    )
    text, count = pattern.subn("github.actor == 'untrusted'", text, count=1)
    if count != 1:
        raise SystemExit("actor fixture not found")
elif mutation == "bad-main-ref":
    needle = "github.ref == 'refs/heads/main'"
    if needle not in text:
        raise SystemExit("main-ref fixture not found")
    text = text.replace(needle, "github.ref == 'refs/heads/untrusted'", 1)
elif mutation == "legacy-trigger":
    for trigger in ("pull_request", "push"):
        marker = f"  {trigger}:\n"
        start = text.find(marker)
        if start < 0:
            raise SystemExit(f"missing trigger fixture: {trigger}")
        end_match = re.search(r"\n  [A-Za-z0-9_-]+:\s*\n", text[start + len(marker):])
        end = start + len(marker) + (
            end_match.start() if end_match else len(text) - start - len(marker)
        )
        block = text[start:end]
        needle = '      - "trillionnium/Cargo.lock"\n'
        if block.count(needle) != 1:
            raise SystemExit(f"path fixture not found under {trigger}")
        block = block.replace(
            needle,
            '      - "trillionnium/crates/trnm-consensus-app/**"\n' + needle,
            1,
        )
        text = text[:start] + block + text[end:]
elif mutation == "write-permission":
    needle = "  contents: read"
    if needle not in text:
        raise SystemExit("permission fixture not found")
    text = text.replace(needle, "  contents: write", 1)
else:
    raise SystemExit(f"unknown mutation: {mutation}")

path.write_text(text, encoding="utf-8")
PY
}

run_self_test() {
  local temp_root fixture mutation
  local tmp_base
  tmp_base="$(printenv TMPDIR 2>/dev/null || printf '/tmp')"
  temp_root="$(mktemp -d "$tmp_base/trnm-poco-trigger-truth.XXXXXX")"
  trap 'rm -rf "$temp_root"' RETURN
  fixture="$temp_root/workflow.yml"

  check_workflow "$DEFAULT_WORKFLOW" >/dev/null
  for mutation in \
    remove-schedule \
    bad-cron \
    weaken-actor \
    bad-main-ref \
    legacy-trigger \
    write-permission; do
    cp -- "$DEFAULT_WORKFLOW" "$fixture"
    mutate_fixture "$fixture" "$mutation"
    if check_workflow "$fixture" >/dev/null 2>&1; then
      fail "self-test accepted mutation: $mutation"
    fi
  done

  printf '%s\n' \
    'poco_bft_workflow_trigger_truth_self_test=passed schedule=required,weekly actor_policy=approved-maintainers same_repo_pr=required deployment=forbidden'
}

if [[ $# -gt 0 && "$1" == "--self-test" ]]; then
  [[ $# -eq 1 ]] || fail "usage: $0 [--self-test]"
  check_workflow "$DEFAULT_WORKFLOW"
  run_self_test
else
  [[ $# -eq 0 ]] || fail "usage: $0 [--self-test]"
  check_workflow "$DEFAULT_WORKFLOW"
fi

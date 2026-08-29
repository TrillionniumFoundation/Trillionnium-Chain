#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$root"

required=(
  docs/development/plan-evidence-manifest-v1.json
  docs/development/CURRENT_SNAPSHOT_V1.json
  docs/schemas/plan-evidence-manifest-v1.schema.json
  docs/schemas/current-snapshot-v1.schema.json
  scripts/ci/generate_current_snapshot_v1.py
  docs/development/plan-manifest-v1.toml
  docs/development/packages/TRNM_G0_TRUTH_PROVENANCE_V1.md
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing-or-empty:$path" >&2; exit 2; }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 scripts/ci/generate_current_snapshot_v1.py \
  --evidence docs/development/plan-evidence-manifest-v1.json \
  --output "$tmp/snapshot.json" --self-test
cmp -s docs/development/CURRENT_SNAPSHOT_V1.json "$tmp/snapshot.json" || {
  echo "current-snapshot-not-reproducible" >&2; exit 3;
}

python3 - <<'PY'
import json, pathlib
root=pathlib.Path('.')
manifest=json.loads((root/'docs/development/plan-evidence-manifest-v1.json').read_text())
assert (json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()==(root/'docs/development/plan-evidence-manifest-v1.json').read_bytes()
snapshot=json.loads((root/'docs/development/CURRENT_SNAPSHOT_V1.json').read_text())
manifest_schema=json.loads((root/'docs/schemas/plan-evidence-manifest-v1.schema.json').read_text())
snapshot_schema=json.loads((root/'docs/schemas/current-snapshot-v1.schema.json').read_text())
assert manifest_schema['title']=='TRNM Plan Evidence Manifest v1'
assert snapshot_schema['title']=='TRNM Current Snapshot v1'
assert snapshot['generated_from']=='docs/development/plan-evidence-manifest-v1.json'
assert snapshot['workflow_evidence']['g0_eligible_success']==0
assert snapshot['package_status']['terminal_outcome']=='BLOCKED_UPSTREAM'
assert snapshot['package_status']['blockers'][0]['id']=='A00-DOC-GATE-ASSERTION-CONFLICT'
assert snapshot['default_branch']['commit']=='b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9'
assert snapshot['latest_candidate']['commit']=='6e0189e351015ef3230f217ca7ff86149baedcf0'
assert snapshot['documentation_control']['commit']=='8bfd73f0cf1b785a29ae212f13212e51fe34231e'
assert snapshot['assessed_plan_source']['commit']=='8198fea0307eb368df34ff77ffc272a6b0e655ec'
assert snapshot['live_plan_tip']['commit']=='92449b8e101642f39d644d863db7bb60dea488f7'
for key in ('production_candidate','production_consensus_activation','release_ready','v1_normative_freeze','v1_node_support'):
    assert snapshot['machine_truth'][key] is False, key
assert all(row['value'] is False and row['mutable_by_package'] is False for row in snapshot['guard_rows'])
plan=(root/'docs/development/plan-manifest-v1.toml').read_text()
for token in (
    'assessed_commit = "8198fea0307eb368df34ff77ffc272a6b0e655ec"',
    'observed_control_commit = "8bfd73f0cf1b785a29ae212f13212e51fe34231e"',
    'observed_candidate_commit = "6e0189e351015ef3230f217ca7ff86149baedcf0"',
    'package_outcome = "BLOCKED_UPSTREAM"',
    'remote_g0_gate_pass = false',
):
    assert token in plan, token
print('current snapshot v1: reproducible candidate observation; G0 promotion blocked upstream')
PY

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --check
fi

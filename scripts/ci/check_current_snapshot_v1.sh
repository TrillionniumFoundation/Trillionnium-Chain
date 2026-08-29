#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$root"

required=(
  docs/development/CURRENT_SNAPSHOT_V1.json
  docs/schemas/current-snapshot-v1.schema.json
  docs/schemas/agent-handoff-v1.schema.json
  scripts/ci/check_agent_handoff_v1.py
  docs/development/packages/TRNM_G0_TRUTH_PROVENANCE_V2.md
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing-or-empty:$path" >&2; exit 2; }
done

python3 scripts/ci/check_agent_handoff_v1.py --self-test
python3 - <<'PY'
import json
from pathlib import Path
root=Path('.')
snapshot=json.loads((root/'docs/development/CURRENT_SNAPSHOT_V1.json').read_text())
schema=json.loads((root/'docs/schemas/current-snapshot-v1.schema.json').read_text())
handoff_schema=json.loads((root/'docs/schemas/agent-handoff-v1.schema.json').read_text())
assert schema['title']=='TRNM Current Snapshot v1'
assert handoff_schema['title']=='TRNM Agent Handoff v1'
assert snapshot['schema']=='trnm-current-snapshot-v1'
assert snapshot['as_of']=='2026-08-30'
assert snapshot['repository']=='TrillionniumFoundation/Trillionnium-Chain'
assert snapshot['default_branch_head_observed']=='b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9'
assert snapshot['latest_candidate']['commit']=='6e0189e351015ef3230f217ca7ff86149baedcf0'
assert snapshot['assessed_plan_source']['commit']=='8198fea0307eb368df34ff77ffc272a6b0e655ec'
assert snapshot['observed_control_plane']['commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
chain=snapshot['revalidated_candidate_chain']
assert [row['agent'] for row in chain]==['A12','A13','A14','A15','A16','A17']
assert len({row['commit'] for row in chain})==len(chain)
assert all(row['workflow_status']=='completed' and row['workflow_conclusion']=='success' for row in chain)
assert all(row['accepted'] is False for row in chain)
assert chain[4]['candidate_status']=='STOP_CONDITION'
assert snapshot['external_blockers']==[
  'EXT-REVIEW-001','EXT-G1-CAMPAIGN-001','EXT-ANCHOR-HSM-001',
  'EXT-POWERLOSS-001','EXT-AUDIT-001','EXT-SOAK-ACTIVATION-001'
]
for key in ('production_candidate','production_consensus_activation','v1_normative_freeze','v1_node_support','v1_release_ready'):
    assert snapshot['machine_truth'][key] is False, key
assert snapshot['evidence_contract']['exact_head_completed_success_required'] is True
assert snapshot['evidence_contract']['candidate_acceptance_implies_gate_exit'] is False
print('current snapshot v1: live refs, exact candidate chain and handoff contract verified; no Gate promotion')
PY

git diff --check

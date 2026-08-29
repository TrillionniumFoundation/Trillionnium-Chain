#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=65deea3f1e9b25f3b6f57d30363857ed5bb16857

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 scripts/ci/check_agent_handoff_v1.py --path docs/evidence/g3-g5/G3_G5_AGENT_HANDOFF_V2.json
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g3-g5/G3_G5_SOURCE_MANIFEST_V2.json').read_text())
a16=json.loads(Path('docs/evidence/g2f/G2F_AGENT_HANDOFF_V2.json').read_text())
a16_source=json.loads(Path('docs/evidence/g2f/G2F_SOURCE_MANIFEST_V2.json').read_text())
assert m['schema']=='trnm-g3-g5-source-manifest-v2'
assert m['base_pr']==37
assert m['base_commit']=='65deea3f1e9b25f3b6f57d30363857ed5bb16857'
assert m['base_tree']=='48f9e468747d45401834e3cef7f9834112fddee9'
assert m['imported_a17_commit']=='f9acc32d422aef9b9132d6ddc830e64639c6ff8d'
assert m['imported_paths']==11
assert a16['status']=='STOP_CONDITION'
assert a16['base_commit']=='847634df4c3f349d797a0a50eb0438b0537ac322'
assert a16['head_commit']=='6d093ce67fd3c5fff2ee8822b0fe56842578026d'
assert 'A16-HANDOFF-SCHEMA-VALIDATION' in a16['gaps_closed']
assert a16_source['cross_plane_candidate_inputs_present'] is True
assert a16_source['handoff_schema_validated'] is True
assert a16_source['accepted_upstream_interfaces'] is False
assert m['cross_plane_candidate_lineage_present'] is True
assert m['handoff_schema_validated'] is True
assert m['accepted_g0_g2f_evidence'] is False
assert m['control_replay_commit']==a16['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a16['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert m['synthetic_decision_root']=='e7c04e43e24b42b9e3d305b00af83a1aee86343f5d0e3f287a030f0de1520414'
assert Path('docs/evidence/g3-g5/EXTERNAL_EVIDENCE_CAMPAIGN_TEMPLATE_V1.json').is_file()
assert Path('tools/benchmark-contract/external_evidence_gate_v1.py').is_file()
assert m['external_evidence_template_present'] is True
assert m['strict_external_evidence_evaluator_present'] is True
for key in ('real_external_evidence_present','real_claim_authorized','benchmark_results_present','surpass_claim_allowed','public_testnet_ready','production_candidate','production_consensus_activation','release_ready','g3_exit','g4_exit','g5_exit'):
    assert m[key] is False, key
workflow_names=sorted(path.name for path in Path('.github/workflows').glob('*.yml'))
assert len(workflow_names)==13, workflow_names
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflow_names), workflow_names
print('G3-G5 source binding v2: synchronized A16 STOP input, handoff schema, strict external evaluator and all real claims disabled')
PY
git diff --check

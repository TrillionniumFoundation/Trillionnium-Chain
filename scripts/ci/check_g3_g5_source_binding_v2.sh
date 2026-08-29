#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=3abba5882aa077187c67064ed7f5535bdd4289b1

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g3-g5/G3_G5_SOURCE_MANIFEST_V2.json').read_text())
a16=json.loads(Path('docs/evidence/g2f/G2F_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g3-g5-source-manifest-v2'
assert m['base_pr']==37
assert m['base_commit']=='3abba5882aa077187c67064ed7f5535bdd4289b1'
assert m['base_tree']=='f0609d1b1f659c12a99f1746060932d60b613a04'
assert m['imported_a17_commit']=='f9acc32d422aef9b9132d6ddc830e64639c6ff8d'
assert m['imported_paths']==11
assert m['control_replay_commit']==a16['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a16['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert a16['status']=='STOP_CONDITION'
assert a16['base_commit']=='5068df3aa46b4585204396b41eedaa8fe2f4a7d9'
assert a16['head_commit']=='6d093ce67fd3c5fff2ee8822b0fe56842578026d'
workflow_names=sorted(path.name for path in Path('.github/workflows').glob('*.yml'))
assert len(workflow_names)==13, workflow_names
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflow_names), workflow_names
assert m['synthetic_decision_root']=='e7c04e43e24b42b9e3d305b00af83a1aee86343f5d0e3f287a030f0de1520414'
for key in ('real_claim_authorized','benchmark_results_present','surpass_claim_allowed','public_testnet_ready','production_candidate','production_consensus_activation','g3_exit','g4_exit','g5_exit'):
    assert m[key] is False, key
print('G3-G5 source binding v2: exact rustfmt-closed A16 STOP input, frozen workflow route and all real claims disabled')
PY
git diff --check

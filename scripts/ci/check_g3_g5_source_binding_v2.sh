#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=10a61e8e98bb2ea360404d5dcb24367a649b27a1

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g3-g5/G3_G5_SOURCE_MANIFEST_V2.json').read_text())
a16=json.loads(Path('docs/evidence/g2f/G2F_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g3-g5-source-manifest-v2'
assert m['base_pr']==37
assert m['base_commit']=='10a61e8e98bb2ea360404d5dcb24367a649b27a1'
assert m['base_tree']=='309dfcdd4ede4960921abb9c8f993e1ea2a7ea74'
assert m['imported_a17_commit']=='f9acc32d422aef9b9132d6ddc830e64639c6ff8d'
assert m['imported_paths']==11
assert m['control_replay_commit']=='53c0312cf0da46fc884025838aeb23e7d6ae0fe3'
assert m['frozen_workflow_tree']=='616377d0525e6b5157b4394aa7f347d4d053bbf1'
assert a16['status']=='STOP_CONDITION'
assert a16['base_commit']=='fe61ee74b95b8768ba86f7a4a143a754d1b4159c'
assert a16['head_commit']=='6d093ce67fd3c5fff2ee8822b0fe56842578026d'
workflow_names=sorted(path.name for path in Path('.github/workflows').glob('*.yml'))
assert len(workflow_names)==13, workflow_names
assert not any('exact-head-v3' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflow_names), workflow_names
assert m['synthetic_decision_root']=='ad1ae325fac3762af64ed01a444f807fb0b0ef5c00418fe8387d6635009b7028'
for key in ('real_claim_authorized','benchmark_results_present','surpass_claim_allowed','public_testnet_ready','production_candidate','production_consensus_activation','g3_exit','g4_exit','g5_exit'):
    assert m[key] is False, key
print('G3-G5 source binding v2: exact A16 STOP input, frozen 13-workflow route and all real claims disabled')
PY
git diff --check

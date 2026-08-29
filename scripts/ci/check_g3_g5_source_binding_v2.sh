#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=24c49a3abcc9ac7fa94815d7fea34f328f439c67

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g3-g5/G3_G5_SOURCE_MANIFEST_V2.json').read_text())
a16=json.loads(Path('docs/evidence/g2f/G2F_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g3-g5-source-manifest-v2'
assert m['base_pr']==37
assert m['base_commit']=='24c49a3abcc9ac7fa94815d7fea34f328f439c67'
assert m['base_tree']=='cf118b8eadb22c438b80e6ab77689b097feba1ba'
assert m['imported_a17_commit']=='f9acc32d422aef9b9132d6ddc830e64639c6ff8d'
assert m['imported_paths']==11
assert m['control_replay_commit']=='53c0312cf0da46fc884025838aeb23e7d6ae0fe3'
assert a16['status']=='STOP_CONDITION'
assert a16['base_commit']=='2472bb75e8e6aa728205a0ee7e67d919ea3c1693'
assert a16['head_commit']=='6d093ce67fd3c5fff2ee8822b0fe56842578026d'
assert Path('docs/development/agents/EXACT_HEAD_PACKAGE_REPLAY_POLICY_V1.md').is_file()
assert not Path('.github/workflows/trnm-g3-g5-exact-head-v3.yml').exists()
assert m['synthetic_decision_root']=='ad1ae325fac3762af64ed01a444f807fb0b0ef5c00418fe8387d6635009b7028'
for key in ('real_claim_authorized','benchmark_results_present','surpass_claim_allowed','public_testnet_ready','production_candidate','production_consensus_activation','g3_exit','g4_exit','g5_exit'):
    assert m[key] is False, key
print('G3-G5 source binding v2: exact A16 STOP input, frozen workflow route and all real claims disabled')
PY

git diff --check

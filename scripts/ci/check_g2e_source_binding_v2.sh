#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=5be89ea68d2627415360e56b7a55d482588b3e02

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2e/G2E_SOURCE_MANIFEST_V2.json').read_text())
a14=json.loads(Path('docs/evidence/g2c/G2C_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2e-source-manifest-v2'
assert m['base_pr']==35
assert m['base_commit']=='5be89ea68d2627415360e56b7a55d482588b3e02'
assert m['base_tree']=='1e8c3e08cbe1b5197b7868d68965db95678a91dd'
assert m['a14_implementation_commit']==a14['head_commit']=='0eed454d2895b8b034ada2af6bf96006cb094475'
assert m['a14_base_sync_commit']=='5be89ea68d2627415360e56b7a55d482588b3e02'
assert m['control_replay_commit']=='53c0312cf0da46fc884025838aeb23e7d6ae0fe3'
assert a14['status']=='MODULE_CLOSED_CANDIDATE'
assert a14['base_commit']=='7e02ee85d13532a20fdca706be78a97f52e156d1'
assert Path('docs/development/agents/EXACT_HEAD_PACKAGE_REPLAY_POLICY_V1.md').is_file()
assert not Path('.github/workflows/trnm-g2e-exact-head-v3.yml').exists()
assert m['risk_root']=='8c9b246d0c94f0ffaf477c9385f296cc98f70951bed9316eb970efedb15d3a57'
for key in ('canonical_settlement_receipt','application_jmt_authority','governance_activation','poco_weight_eligible','g2e_exit','production_candidate'):
    assert m[key] is False, key
print('G2E source binding v2: exact A14 publication, frozen workflow route and false authority guards')
PY

git diff --check

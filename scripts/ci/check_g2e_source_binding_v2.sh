#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=0ef40883e160f646158b6e483a69e2371fda989e

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2e/G2E_SOURCE_MANIFEST_V2.json').read_text())
a14=json.loads(Path('docs/evidence/g2c/G2C_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2e-source-manifest-v2'
assert m['base_pr']==35
assert m['base_commit']=='0ef40883e160f646158b6e483a69e2371fda989e'
assert m['base_tree']=='e1df009018c1d3f2967bdb905bdd96ab3cb6ea06'
assert m['a14_implementation_commit']==a14['head_commit']=='0eed454d2895b8b034ada2af6bf96006cb094475'
assert a14['status']=='MODULE_CLOSED_CANDIDATE'
assert m['risk_root']=='8c9b246d0c94f0ffaf477c9385f296cc98f70951bed9316eb970efedb15d3a57'
for key in ('canonical_settlement_receipt','application_jmt_authority','governance_activation','poco_weight_eligible','g2e_exit','production_candidate'):
    assert m[key] is False, key
print('G2E source binding v2: exact A14 candidate and false authority guards')
PY

git diff --check

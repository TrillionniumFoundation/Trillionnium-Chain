#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=9e5ac3f056b36e924cf77592746c2e8a53bc6c82

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2e/G2E_SOURCE_MANIFEST_V2.json').read_text())
a14=json.loads(Path('docs/evidence/g2c/G2C_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2e-source-manifest-v2'
assert m['base_pr']==35
assert m['base_commit']=='9e5ac3f056b36e924cf77592746c2e8a53bc6c82'
assert m['base_tree']=='edc425aafbf4414cc363e1509a001d6d02b44f33'
assert m['a14_implementation_commit']==a14['head_commit']=='0eed454d2895b8b034ada2af6bf96006cb094475'
assert m['a14_base_sync_commit']=='9e5ac3f056b36e924cf77592746c2e8a53bc6c82'
assert a14['status']=='MODULE_CLOSED_CANDIDATE'
assert a14['base_commit']=='dd778a0dd88592c92e646dfa70e1b99b3a8bd018'
assert a14['workflow_policy_descendant']=='cd5264438c0ea1e81bd687355eccac1d49e92b26'
assert m['risk_root']=='8c9b246d0c94f0ffaf477c9385f296cc98f70951bed9316eb970efedb15d3a57'
for key in ('canonical_settlement_receipt','application_jmt_authority','governance_activation','poco_weight_eligible','g2e_exit','production_candidate'):
    assert m[key] is False, key
print('G2E source binding v2: exact A14 publication plus semantic-source/workflow-descendant split')
PY

git diff --check

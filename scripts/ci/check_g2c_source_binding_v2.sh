#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=ad633bf7557052c02bf214b683a18bd72bb4bec5

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json').read_text())
a13=json.loads(Path('docs/evidence/g2d/G2D_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2c-source-manifest-v2'
assert m['base_pr']==34
assert m['base_commit']=='ad633bf7557052c02bf214b683a18bd72bb4bec5'
assert m['base_tree']=='b430c899be1b5c17815bdaf01a957f5565e105e9'
assert m['a13_implementation_commit']==a13['head_commit']=='71f68181f8afa52168bd49d2de7514deb2ddba5a'
assert a13['status']=='MODULE_CLOSED_CANDIDATE'
for key in ('profiles_globally_enabled','profile_fallback_allowed','artifact_availability_authority','order_finality_authority','settlement_authority','g2c_exit','production_candidate'):
    assert m[key] is False, key
print('G2C source binding v2: exact A13 candidate and false authority guards')
PY

git diff --check

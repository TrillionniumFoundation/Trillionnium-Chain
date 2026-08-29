#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=a4bd309db4fb68ca908f6af03fc20b8f59a5a59a

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json').read_text())
a13=json.loads(Path('docs/evidence/g2d/G2D_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2c-source-manifest-v2'
assert m['base_pr']==34
assert m['base_commit']=='a4bd309db4fb68ca908f6af03fc20b8f59a5a59a'
assert m['base_tree']=='264884de8ab11cf7d89ee19ba96c7b78ee2930a1'
assert m['a13_implementation_commit']==a13['head_commit']=='71f68181f8afa52168bd49d2de7514deb2ddba5a'
assert m['a13_publication_head']=='a4bd309db4fb68ca908f6af03fc20b8f59a5a59a'
assert m['control_replay_commit']==a13['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a13['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert a13['status']=='MODULE_CLOSED_CANDIDATE'
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
assert len(workflows)==13, workflows
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflows), workflows
for key in ('profiles_globally_enabled','profile_fallback_allowed','artifact_availability_authority','order_finality_authority','settlement_authority','g2c_exit','production_candidate'):
    assert m[key] is False, key
print('G2C source binding v2: exact A13 publication, final frozen workflow route and false authority guards')
PY
git diff --check

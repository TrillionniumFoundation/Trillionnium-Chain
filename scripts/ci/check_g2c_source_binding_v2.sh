#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=d1536edb6143b7373be89e45a4cbb545d66ca77c

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json').read_text())
a13=json.loads(Path('docs/evidence/g2d/G2D_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2c-source-manifest-v2'
assert m['base_pr']==34
assert m['base_commit']=='d1536edb6143b7373be89e45a4cbb545d66ca77c'
assert m['base_tree']=='35ba6155432469fe8de9f8924be55808149a0664'
assert m['a13_implementation_commit']==a13['head_commit']=='71f68181f8afa52168bd49d2de7514deb2ddba5a'
assert m['a13_publication_head']=='d1536edb6143b7373be89e45a4cbb545d66ca77c'
assert m['control_replay_commit']=='53c0312cf0da46fc884025838aeb23e7d6ae0fe3'
assert a13['status']=='MODULE_CLOSED_CANDIDATE'
assert a13['base_commit']=='38d96ebc8d38903773ea8d164a6ca30fc6d46520'
assert Path('docs/development/agents/EXACT_HEAD_PACKAGE_REPLAY_POLICY_V1.md').is_file()
for path in ('.github/workflows/trnm-g2c-exact-head-v3.yml','.github/workflows/trnm-g2c-replay-v2.yml','.github/workflows/trnm-g2d-execution-mvcc-fee-v2.yml'):
    assert not Path(path).exists(), path
for key in ('profiles_globally_enabled','profile_fallback_allowed','artifact_availability_authority','order_finality_authority','settlement_authority','g2c_exit','production_candidate'):
    assert m[key] is False, key
print('G2C source binding v2: exact A13 publication, frozen workflow route and false authority guards')
PY
git diff --check

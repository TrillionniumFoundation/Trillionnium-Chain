#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=2472bb75e8e6aa728205a0ee7e67d919ea3c1693

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2f/G2F_SOURCE_MANIFEST_V2.json').read_text())
a15=json.loads(Path('docs/evidence/g2e/G2E_AGENT_HANDOFF_V2.json').read_text())
closure=json.loads(Path('docs/evidence/g2f/G2F_COORDINATED_VIEW_CLOSURE_V2.json').read_text())
assert m['schema']=='trnm-g2f-source-manifest-v2'
assert m['base_pr']==36
assert m['base_commit']=='2472bb75e8e6aa728205a0ee7e67d919ea3c1693'
assert m['base_tree']=='7a2b6c0bf03bcadb4e49a872d8736c2842a39ed4'
assert m['imported_g2f_commit']=='f97b3b8e74439d6e80d13c4c8048578a631eb12b'
assert m['imported_g2f_tree']=='87511d76dd5703460076d73ecefeb28b9334bdfc'
assert m['imported_paths']==22
assert m['control_replay_commit']=='53c0312cf0da46fc884025838aeb23e7d6ae0fe3'
assert a15['status']=='MODULE_CLOSED_CANDIDATE'
assert a15['base_commit']=='5be89ea68d2627415360e56b7a55d482588b3e02'
assert a15['head_commit']=='da667f30cefa84fc967a96c817be07f8b779ac32'
assert m['owner_view_commitment']==closure['view_commitment']=='2fe37224cda2bd9c5bc28126aa257e1a74718b72086752447694ae89fd827dec'
assert m['coordinated_nonzero_view_local_gap']=='closed-candidate'
assert Path('docs/development/agents/EXACT_HEAD_PACKAGE_REPLAY_POLICY_V1.md').is_file()
assert not Path('.github/workflows/trnm-g2f-exact-head-v3.yml').exists()
for key in ('canonical_application_jmt','production_external_anchor','production_hsm_authority','accepted_upstream_interfaces','g2f_exit','production_candidate'):
    assert m[key] is False, key
for path in (
    'conformance/g2f/client_a.py', 'conformance/g2f/client_b.py',
    'conformance/g2f/state_sync.py', 'conformance/g2f/state_tree.py',
    'trillionnium/crates/trnm-poco-node/src/g2f_namespace_identity.rs'
):
    assert Path(path).is_file(), path
print('G2F source binding v2: exact A15 publication, frozen workflow route and false authority guards')
PY

git diff --check

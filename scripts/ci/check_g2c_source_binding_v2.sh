#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=ee252f464d460c399b7d109c17dc9f5456bbf29a

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json').read_text())
a13=json.loads(Path('docs/evidence/g2d/G2D_AGENT_HANDOFF_V2.json').read_text())
a13_source=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12_source=json.loads(Path('docs/evidence/g2b/G2B_SOURCE_MANIFEST_V2.json').read_text())
assert m['schema']=='trnm-g2c-source-manifest-v2'
assert m['base_pr']==34
assert m['base_commit']=='ee252f464d460c399b7d109c17dc9f5456bbf29a'
assert m['base_tree']=='a8c7d45137ffd8cd8e7144a66935f1bb45c71803'
assert m['a13_implementation_commit']==a13['head_commit']=='71f68181f8afa52168bd49d2de7514deb2ddba5a'
assert m['a13_implementation_tree']==a13['implementation_tree']=='de6b98988b2ca08e70046281c82a94e7acbf4e12'
assert m['a13_publication_head']=='ee252f464d460c399b7d109c17dc9f5456bbf29a'
assert a13['status']=='MODULE_CLOSED_CANDIDATE'
assert 'A13-AGENT-TRANSACTION-WIRE-CANDIDATE-INPUT' in a13['gaps_closed']
assert a13_source['agent_transaction_wire_candidate_input'] is True
assert a13_source['agent_transaction_wire_accepted'] is False
assert a12_source['agent_transaction_wire_candidate'] is True
assert m['agent_transaction_wire_candidate_input'] is True
assert m['agent_transaction_wire_accepted'] is False
assert m['control_replay_commit']==a13['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a13['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
for path in (
    'trillionnium/crates/trnm-poco-agent-market-v1/src/agent_transaction_wire_v1.rs',
    'trillionnium/crates/trnm-poco-mvcc-fee-v1/src/deterministic_parallel_v1.rs',
    'trillionnium/crates/trnm-poco-verify-challenge-v1/src/profile_registry_v1.rs',
):
    assert Path(path).is_file(), path
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
assert len(workflows)==13, workflows
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflows), workflows
for key in ('agent_transaction_wire_accepted','profiles_globally_enabled','profile_fallback_allowed','artifact_availability_authority','task_lease_profile_authority','order_finality_authority','settlement_authority','g2c_exit','production_candidate','production_consensus_activation'):
    assert m[key] is False, key
print('G2C source binding v2: synchronized A12/A13 candidates and false authority guards')
PY
git diff --check

#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=55157eff2ad9ba6bdd412e479685e0dd7a654287

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 scripts/ci/check_agent_handoff_v1.py --path docs/evidence/g2c/G2C_AGENT_HANDOFF_V2.json
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json').read_text())
a13=json.loads(Path('docs/evidence/g2d/G2D_AGENT_HANDOFF_V2.json').read_text())
a13_source=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12_source=json.loads(Path('docs/evidence/g2b/G2B_SOURCE_MANIFEST_V2.json').read_text())
assert m['schema']=='trnm-g2c-source-manifest-v2'
assert m['base_pr']==34
assert m['base_commit']=='55157eff2ad9ba6bdd412e479685e0dd7a654287'
assert m['base_tree']=='656b697596d83da4f42e59dbd92ef350b1a698b3'
assert m['a13_implementation_commit']==a13['head_commit']=='71f68181f8afa52168bd49d2de7514deb2ddba5a'
assert m['a13_implementation_tree']==a13['implementation_tree']=='de6b98988b2ca08e70046281c82a94e7acbf4e12'
assert m['a13_publication_head']=='55157eff2ad9ba6bdd412e479685e0dd7a654287'
assert a13['status']=='MODULE_CLOSED_CANDIDATE'
assert 'A13-HANDOFF-SCHEMA-VALIDATION' in a13['gaps_closed']
assert a13_source['agent_transaction_wire_candidate_input'] is True
assert a13_source['handoff_schema_validated'] is True
assert a12_source['agent_transaction_wire_candidate'] is True
assert m['agent_transaction_wire_candidate_input'] is True
assert m['agent_transaction_wire_accepted'] is False
assert m['handoff_schema_validated'] is True
assert m['control_replay_commit']==a13['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a13['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
for path in (
    'docs/schemas/agent-handoff-v1.schema.json',
    'scripts/ci/check_agent_handoff_v1.py',
    'trillionnium/crates/trnm-poco-agent-market-v1/src/agent_transaction_wire_v1.rs',
    'trillionnium/crates/trnm-poco-mvcc-fee-v1/src/deterministic_parallel_v1.rs',
    'trillionnium/crates/trnm-poco-verify-challenge-v1/src/profile_registry_v1.rs',
):
    assert Path(path).is_file(), path
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
# Keep this source-bound inventory explicit.  The current repository carries
# the hosted baseline and the unrelated Web4 frontend alongside the twelve
# privileged protocol workflows, for a deliberate fourteen-file set.
expected_workflows = sorted([
    'agent-user-phasea-gate.yml',
    'p1-rust-sidecar.yml',
    'rust-l1-nightly-health.yml',
    'rust-l1-testnet-preflight.yml',
    'trnm-canonical-input-fuzz-smoke.yml',
    'trnm-cometbft-spike.yml',
    'trnm-gate-quick-check.yml',
    'trnm-live-devnet-package.yml',
    'trnm-merge-gates.yml',
    'trnm-payload-replay-recovery-v1.yml',
    'trnm-poco-bft-v0.yml',
    'trnm-replay-to-core-coordinator-v1.yml',
    'trnm-required-baseline.yml',
    'web4-frontend-ci.yml',
])
assert workflows == expected_workflows, workflows
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflows), workflows
for key in ('agent_transaction_wire_accepted','profiles_globally_enabled','profile_fallback_allowed','artifact_availability_authority','task_lease_profile_authority','order_finality_authority','settlement_authority','g2c_exit','production_candidate','production_consensus_activation'):
    assert m[key] is False, key
print('G2C source binding v2: synchronized A12/A13 candidates, handoff schema and false authority guards')
PY
git diff --check

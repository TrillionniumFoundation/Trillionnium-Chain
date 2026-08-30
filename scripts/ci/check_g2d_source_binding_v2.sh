#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=1be1a4db2c6431232676c8904856e9eb1d49c9a4

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 scripts/ci/check_agent_handoff_v1.py --path docs/evidence/g2d/G2D_AGENT_HANDOFF_V2.json
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12=json.loads(Path('docs/evidence/g2b/G2B_AGENT_HANDOFF_V2.json').read_text())
a12_source=json.loads(Path('docs/evidence/g2b/G2B_SOURCE_MANIFEST_V2.json').read_text())
assert m['schema']=='trnm-g2d-source-manifest-v2'
assert m['base_pr']==33
assert m['base_commit']=='1be1a4db2c6431232676c8904856e9eb1d49c9a4'
assert m['base_tree']=='89e2f06c56637d23607a4133f3ffbebdc23de356'
assert m['a12_implementation_commit']==a12['head_commit']==a12['implementation_commit']=='a407e24b88460f77dd8fe586326276a4daeb3ab0'
assert m['a12_implementation_tree']==a12['implementation_tree']=='b933d7fe8c162a7645b36b426ac1e83991c4a5c6'
assert m['a12_publication_head']=='1be1a4db2c6431232676c8904856e9eb1d49c9a4'
assert a12['status']=='MODULE_CLOSED_CANDIDATE'
assert 'A12-AGENT-TRANSACTION-OUTER-WIRE-CANDIDATE' in a12['gaps_closed']
assert a12_source['agent_transaction_wire_candidate'] is True
assert a12_source['independent_agent_transaction_parser_candidate'] is True
assert a12_source['strict_ed25519_authorization_candidate'] is True
assert a12_source['agent_transaction_wire_accepted'] is False
assert m['agent_transaction_wire_candidate_input'] is True
assert m['agent_transaction_wire_accepted'] is False
assert m['handoff_schema_validated'] is True
assert m['control_replay_commit']==a12['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a12['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert m['worker_counts']==[1,2,4,8]
for path in (
    'docs/schemas/agent-handoff-v1.schema.json',
    'scripts/ci/check_agent_handoff_v1.py',
    'trillionnium/crates/trnm-poco-agent-market-v1/src/agent_transaction_wire_v1.rs',
    'conformance/agent-market/independent_agent_transaction_wire_v1.py',
    'trillionnium/crates/trnm-poco-mvcc-fee-v1/src/deterministic_parallel_v1.rs',
):
    assert Path(path).is_file(), path
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
# Bind the checker to the exact current workflow inventory, including the
# hosted baseline and unrelated Web4 frontend workflow.
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
for key in ('agent_transaction_wire_accepted','production_runtime','application_jmt_authority','settlement_authority','whole_node_recovery','g2d_exit','production_candidate','production_consensus_activation'):
    assert m[key] is False, key
print('G2D source binding v2: synchronized A12 wire, handoff schema and false authority guards')
PY
git diff --check

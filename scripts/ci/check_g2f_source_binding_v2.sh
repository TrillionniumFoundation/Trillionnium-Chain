#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=0d78161b73a7c709506ec16709d40d434da56918

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2f/G2F_SOURCE_MANIFEST_V2.json').read_text())
a15=json.loads(Path('docs/evidence/g2e/G2E_AGENT_HANDOFF_V2.json').read_text())
a15_source=json.loads(Path('docs/evidence/g2e/G2E_SOURCE_MANIFEST_V2.json').read_text())
a14_source=json.loads(Path('docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json').read_text())
a13_source=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12_source=json.loads(Path('docs/evidence/g2b/G2B_SOURCE_MANIFEST_V2.json').read_text())
closure=json.loads(Path('docs/evidence/g2f/G2F_COORDINATED_VIEW_CLOSURE_V2.json').read_text())
assert m['schema']=='trnm-g2f-source-manifest-v2'
assert m['base_pr']==36
assert m['base_commit']=='0d78161b73a7c709506ec16709d40d434da56918'
assert m['base_tree']=='f715fb72af40f474f880db374a0d75b3c945f7e8'
assert m['imported_g2f_commit']=='f97b3b8e74439d6e80d13c4c8048578a631eb12b'
assert m['imported_g2f_tree']=='87511d76dd5703460076d73ecefeb28b9334bdfc'
assert m['imported_paths']==22
assert a15['status']=='MODULE_CLOSED_CANDIDATE'
assert a15['base_commit']=='1f66963784ebec21a7898f893e47cfc3190f59e9'
assert a15['head_commit']=='da667f30cefa84fc967a96c817be07f8b779ac32'
assert a15_source['durable_rust_settlement_candidate'] is True
assert a15_source['agent_transaction_wire_candidate_input'] is True
assert a14_source['agent_transaction_wire_candidate_input'] is True
assert a13_source['agent_transaction_wire_candidate_input'] is True
assert a12_source['agent_transaction_wire_candidate'] is True
assert m['agent_transaction_wire_candidate_input'] is True
assert m['durable_settlement_candidate_input'] is True
assert m['cross_plane_candidate_inputs_present'] is True
assert m['accepted_upstream_interfaces'] is False
assert m['control_replay_commit']==a15['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a15['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert m['owner_view_commitment']==closure['view_commitment']=='eb86ffbca2e8629ba16e19a7eedf322b75244b61c742768e6c17941f6ea446db'
assert m['coordinated_nonzero_view_local_gap']=='closed-candidate'
assert m['versioned_sparse_application_tree_candidate'] is True
for path in (
    'conformance/g2f/client_a.py','conformance/g2f/client_b.py','conformance/g2f/state_sync.py',
    'conformance/g2f/state_tree.py','conformance/g2f/application_jmt_v1.rs',
    'trillionnium/crates/trnm-poco-node/src/g2f_namespace_identity.rs',
    'trillionnium/crates/trnm-poco-agent-market-v1/src/agent_transaction_wire_v1.rs',
    'trillionnium/crates/trnm-poco-consumption-settlement-v1/Cargo.toml',
):
    assert Path(path).is_file(), path
workflow_names=sorted(path.name for path in Path('.github/workflows').glob('*.yml'))
assert len(workflow_names)==13, workflow_names
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflow_names), workflow_names
for key in ('canonical_application_jmt','production_external_anchor','production_hsm_authority','accepted_upstream_interfaces','normal_node_process_ownership','power_loss_multi_host_evidence','g2f_exit','production_candidate','production_consensus_activation'):
    assert m[key] is False, key
print('G2F source binding v2: synchronized A12-A15 candidates, sparse-tree candidate and false authority guards')
PY
git diff --check

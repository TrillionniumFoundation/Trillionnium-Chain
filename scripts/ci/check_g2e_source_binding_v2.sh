#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=14602c4bdbc535903db7702d4e719e3e49c07c05

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 scripts/ci/check_agent_handoff_v1.py --path docs/evidence/g2e/G2E_AGENT_HANDOFF_V2.json
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2e/G2E_SOURCE_MANIFEST_V2.json').read_text())
a14=json.loads(Path('docs/evidence/g2c/G2C_AGENT_HANDOFF_V2.json').read_text())
a14_source=json.loads(Path('docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json').read_text())
a13_source=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12_source=json.loads(Path('docs/evidence/g2b/G2B_SOURCE_MANIFEST_V2.json').read_text())
assert m['schema']=='trnm-g2e-source-manifest-v2'
assert m['base_pr']==35
assert m['base_commit']=='14602c4bdbc535903db7702d4e719e3e49c07c05'
assert m['base_tree']=='b743bf45d5a2f97c880158bea854e5550bb72016'
assert m['a14_implementation_commit']==a14['head_commit']=='0eed454d2895b8b034ada2af6bf96006cb094475'
assert m['a14_implementation_tree']==a14['implementation_tree']=='9b2030852132c147b63b1a5a7c269fff9424819c'
assert m['a14_base_sync_commit']=='14602c4bdbc535903db7702d4e719e3e49c07c05'
assert a14['status']=='MODULE_CLOSED_CANDIDATE'
assert 'A14-HANDOFF-SCHEMA-VALIDATION' in a14['gaps_closed']
assert a14_source['agent_transaction_wire_candidate_input'] is True
assert a14_source['handoff_schema_validated'] is True
assert a13_source['handoff_schema_validated'] is True
assert a12_source['agent_transaction_wire_candidate'] is True
assert m['agent_transaction_wire_candidate_input'] is True
assert m['agent_transaction_wire_accepted'] is False
assert m['handoff_schema_validated'] is True
assert m['control_replay_commit']==a14['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a14['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert m['risk_root']=='8c9b246d0c94f0ffaf477c9385f296cc98f70951bed9316eb970efedb15d3a57'
assert m['durable_rust_settlement_candidate'] is True
for path in (
    'docs/schemas/agent-handoff-v1.schema.json',
    'scripts/ci/check_agent_handoff_v1.py',
    'trillionnium/crates/trnm-poco-agent-market-v1/src/agent_transaction_wire_v1.rs',
    'trillionnium/crates/trnm-poco-mvcc-fee-v1/src/deterministic_parallel_v1.rs',
    'trillionnium/crates/trnm-poco-verify-challenge-v1/src/profile_registry_v1.rs',
    'trillionnium/crates/trnm-poco-consumption-settlement-v1/Cargo.toml',
):
    assert Path(path).is_file(), path
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
assert len(workflows)==13, workflows
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflows), workflows
for key in ('agent_transaction_wire_accepted','canonical_settlement_receipt','application_jmt_authority','production_asset_custody','governance_activation','poco_weight_eligible','g2e_exit','production_candidate','production_consensus_activation'):
    assert m[key] is False, key
print('G2E source binding v2: synchronized A12-A14 candidates, complete implementation provenance, durable Rust settlement and false authority guards')
PY
git diff --check

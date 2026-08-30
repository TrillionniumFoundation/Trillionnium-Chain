#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

python3 scripts/ci/check_agent_handoff_v1.py \
  --path docs/evidence/g2b/G2B_AGENT_HANDOFF_V2.json
python3 tools/agent-market-model/model.py --self-test >/tmp/trnm-agent-market-v1.json
python3 tools/agent-market-model/authority_extension_v2.py --self-test >/tmp/trnm-agent-market-v2.json

cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-agent-market-v1 --all-targets
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-agent-market-v1 --all-targets -- -D warnings
cargo run --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-agent-market-v1 --example agent_transaction_wire_v1 --quiet \
  >/tmp/trnm-agent-transaction-wire-v1.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  conformance/agent-market/independent_agent_transaction_wire_v1.py \
  --fixture /tmp/trnm-agent-transaction-wire-v1.json --self-test \
  >/tmp/trnm-agent-transaction-independent-v1.json
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check

python3 - <<'PY'
import json
from pathlib import Path
v1=json.loads(Path('/tmp/trnm-agent-market-v1.json').read_text())
v2=json.loads(Path('/tmp/trnm-agent-market-v2.json').read_text())
wire=json.loads(Path('/tmp/trnm-agent-transaction-independent-v1.json').read_text())
source=json.loads(Path('docs/evidence/g2b/G2B_SOURCE_MANIFEST_V2.json').read_text())
handoff=json.loads(Path('docs/evidence/g2b/G2B_AGENT_HANDOFF_V2.json').read_text())
assert v1['schema']=='trnm-agent-market-model-evidence-v1'
assert v1['positive_transitions']>=10
assert len(v1['negative'])==7
assert v1['candidate_only'] is True
assert v1['global_state_authority'] is False
assert v2['schema']=='trnm-agent-market-authority-extension-evidence-v2'
assert v2['positive']==7
assert len(v2['negative'])==11
assert v2['controller_generation']==3
assert len(v2['state_commitment'])==64
assert v2['candidate_only'] is True
assert v2['cryptographic_authority'] is False
assert v2['global_state_authority'] is False
assert v2['production_activation'] is False
assert wire['schema']=='trnm-agent-transaction-independent-wire-evidence-v1'
assert wire['positive']==1
assert len(wire['negative'])==12
assert len(wire['transaction_id'])==64
assert wire['command_bytes']>0
assert wire['candidate_only'] is True
assert wire['wire_accepted'] is False
assert wire['global_state_authority'] is False
assert wire['production_activation'] is False
assert source['control_replay_commit']==handoff['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert source['frozen_workflow_tree']==handoff['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
# Keep replay provenance fail-closed against the exact current workflow set.
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
for key in ('global_state_authority','agent_transaction_wire_accepted','g2b_exit','production_candidate'):
    assert source[key] is False, key
print('G2B replay v2: lifecycle + strict Rust/SQLite/Ed25519 kernel + independent AgentTransaction wire + handoff schema ok')
PY

git diff --check

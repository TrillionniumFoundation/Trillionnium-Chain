#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

out=$(PYTHONDONTWRITEBYTECODE=1 python3 -B tools/mvcc-serial-model/model.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-mvcc-serial-equivalence-evidence-v1'
assert v['runs']==32*4*4
assert v['worker_counts']==[1,2,4,8]
assert len(v['negative'])==4
assert v['reexecutions']>0
assert v['candidate_only'] is True
assert v['jmt_authority'] is False
assert v['settlement_authority'] is False
print('MVCC serial-equivalence oracle: ok')
PY

cargo test \
  --manifest-path trillionnium/Cargo.toml \
  --locked --offline \
  -p trnm-poco-mvcc-fee-v1 \
  deterministic_parallel_v1

cargo clippy \
  --manifest-path trillionnium/Cargo.toml \
  --locked --offline \
  -p trnm-poco-mvcc-fee-v1 \
  --all-targets -- -D warnings

cargo fmt \
  --manifest-path trillionnium/Cargo.toml \
  --package trnm-poco-mvcc-fee-v1 \
  -- --check

python3 - <<'PY'
from pathlib import Path
cargo = Path('trillionnium/crates/trnm-poco-mvcc-fee-v1/Cargo.toml').read_text()
source = Path('trillionnium/crates/trnm-poco-mvcc-fee-v1/src/deterministic_parallel_v1.rs').read_text()
assert 'real_parallel_worker_pool = true' in cargo
assert 'parallel_worker_pool_scope = "bounded-in-process-candidate"' in cargo
for token in (
    'PARALLEL_EXECUTION_ECONOMIC_AUTHORITY_V1: bool = false',
    'PARALLEL_EXECUTION_SETTLEMENT_AUTHORITY_V1: bool = false',
    'PARALLEL_EXECUTION_GLOBAL_JMT_AUTHORITY_V1: bool = false',
    'worker_count_does_not_change_roots_or_receipts',
    'reverted_and_out_of_resource_never_write',
):
    assert token in source, token
print('G2D bounded parallel candidate gate: ok')
PY

git diff --check

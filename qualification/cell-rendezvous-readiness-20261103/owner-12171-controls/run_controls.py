#!/usr/bin/env python3
"""Run the original small controls without native builds or Host provisioning."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path('/tmp/chain-cell-startup-current-20261103')
OUT = Path(__file__).resolve().parent
TOOLCHAIN = Path('/workspace/scratch/1f1d02319616/recovered-toolchain-20261103/bin')
ENV = os.environ.copy()
ENV.update(PATH=str(TOOLCHAIN) + ':' + ENV['PATH'], RUSTC=str(TOOLCHAIN / 'rustc'),
           RUSTDOC=str(TOOLCHAIN / 'rustdoc'), CARGO_HOME='/tmp/chain-cell-cargo-home-20261103',
           CARGO_TARGET_DIR='/tmp/chain-cell-target-20261103', CARGO_BUILD_JOBS='1',
           CARGO_INCREMENTAL='0', RUST_TEST_THREADS='1')
COMMANDS = [
    ['bash', 'scripts/project-preflight.sh'],
    ['python3', 'scripts/ci/test_from_zero_host_ci.py', '-v'],
    ['python3', 'scripts/ci/test_run_from_zero_native.py', '-v'],
    ['python3', 'scripts/ci/test_rust_baseline_shards.py', '-v'],
    ['python3', 'scripts/ci/test_ci_source_integrity.py', '-v'],
    ['python3', 'scripts/ci/test_project_boundary.py', '-v'],
    ['python3', 'scripts/ci/test_pq_research_integration.py', '-v'],
    ['python3', 'scripts/ci/test_pq_chain_claim_guard.py', '-v'],
    ['python3', 'scripts/ci/check_pq_research_integration.py'],
    ['python3', 'scripts/ci/check_ci_contract.py'],
    [str(TOOLCHAIN / 'cargo'), 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'],
]

def tree():
    return subprocess.check_output(['git', 'write-tree'], cwd=ROOT, text=True).strip()

def sources():
    paths = subprocess.check_output(['git', 'ls-files', '-z', 'scripts', '.github', 'config', 'trillionnium'], cwd=ROOT).split(b'\0')
    result = {}
    for raw in paths:
        if not raw:
            continue
        rel = os.fsdecode(raw)
        path = ROOT / rel
        if path.is_file():
            result[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result

result = {'schema': 'chain-original-controls-owner-12171-composition-v1',
          'old_head': '4a32fe3418ea9b6eb18a44c93d8a282fa83fb426',
          'owner_parent': '12171edc890df1611bf68503038bfad3d66a5a88',
          'cwd': str(ROOT), 'tree_before': tree(), 'source_before': sources(),
          'native_tests_executed': False, 'actual_fixed_host_provisioned': False,
          'results': []}
for index, argv in enumerate(COMMANDS):
    start = time.monotonic_ns()
    p = subprocess.run(argv, cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    row = {'argv': argv, 'exit_code': p.returncode, 'elapsed_ns': time.monotonic_ns() - start}
    for name, value in [('stdout', p.stdout), ('stderr', p.stderr)]:
        (OUT / f'{index:02d}.{name}.log').write_bytes(value)
        row[name] = value.decode('utf-8')
        row[name + '_sha256'] = hashlib.sha256(value).hexdigest()
    m = re.findall(r'^Ran (\d+) tests? in ', row['stderr'], re.M)
    if m:
        row['unittest_executions'] = [int(v) for v in m]
    result['results'].append(row)
    (OUT / 'CONTROLS.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'command': index, 'exit_code': p.returncode, 'tests': row.get('unittest_executions')}), flush=True)
result['tree_after'] = tree()
result['source_after'] = sources()
result['source_unchanged'] = result['source_before'] == result['source_after']
result['passed'] = result['source_unchanged'] and result['tree_before'] == result['tree_after'] and all(x['exit_code'] == 0 for x in result['results'])
(OUT / 'CONTROLS.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'passed': result['passed'], 'source_inputs': len(result['source_before'])}), flush=True)
raise SystemExit(0 if result['passed'] else 1)

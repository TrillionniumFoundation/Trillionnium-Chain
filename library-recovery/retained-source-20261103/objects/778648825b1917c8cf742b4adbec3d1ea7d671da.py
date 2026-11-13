import os
from pathlib import Path
import subprocess
import sys

root = Path('/workspace/scratch/121c7d6beede')
kind = sys.argv[1]
assert kind in ('history', 'pq')
repo = root / 'history_pq_task' / kind
env = dict(os.environ)
env['RUSTUP_HOME'] = str(root / 'project_toolchain/rustup')
env['CARGO_HOME'] = str(root / 'project_toolchain/cargo')
env['PATH'] = str(root / 'project_toolchain/cargo/bin') + os.pathsep + env['PATH']
env['RUSTUP_TOOLCHAIN'] = '1.95.0'
env['CARGO_TARGET_DIR'] = str(root / 'history_pq_task' / (kind + '-target'))
env['CARGO_INCREMENTAL'] = '0'
env['CARGO_BUILD_JOBS'] = '1'
env['RUST_TEST_THREADS'] = '1'
env['PYTHONDONTWRITEBYTECODE'] = '1'
if kind == 'history':
    head = 'bc6747ffffff52758a166254f1bb7d9c866e4b72'
    argv = ['python3', 'scripts/ci/run_history_effect_v6_native.py', '--expected-source', head,
            '--out', str(root / 'history_pq_task/history-local-gate')]
else:
    head = 'c974a4ccfb2ed76b77c654e11899519a9b95d38f'
    argv = ['python3', 'scripts/ci/run_native_pq_tasks_v5.py', '--expected-head', head,
            '--output', str(root / 'history_pq_task/pq-local-gate')]
subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=repo, env=env, check=True)
log = root / 'history_pq_task' / (kind + '-local-gate-controller.log')
with log.open('xb') as stream:
    result = subprocess.run(argv, cwd=repo, env=env, stdout=stream, stderr=subprocess.STDOUT)
print({'gate': kind, 'source': head, 'returncode': result.returncode, 'log': str(log)})
raise SystemExit(result.returncode)

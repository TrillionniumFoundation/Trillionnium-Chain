import os
from pathlib import Path
import subprocess

root = Path('/workspace/scratch/121c7d6beede')
repo = root / 'history_pq_task/pq'
env = dict(os.environ)
env.update(
    RUSTUP_HOME=str(root / 'project_toolchain/rustup'),
    CARGO_HOME=str(root / 'project_toolchain/cargo'),
    PATH=str(root / 'project_toolchain/cargo/bin') + os.pathsep + env['PATH'],
    RUSTUP_TOOLCHAIN='1.95.0',
    CARGO_TARGET_DIR=str(root / 'history_pq_task/pq-target'),
    CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', RUST_TEST_THREADS='1',
    PYTHONDONTWRITEBYTECODE='1')
head = 'c15dbe986edb7e52969c789d173a8fa5e1476484'
subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=repo, env=env, check=True)
argv = ['python3', '-B', 'scripts/ci/run_native_pq_tasks_v5.py', '--expected-head', head,
        '--output', str(root / 'history_pq_task/pq-admission-local-gate')]
log = root / 'history_pq_task/pq-admission-local-gate-controller.log'
with log.open('xb') as stream:
    result = subprocess.run(argv, cwd=repo, env=env, stdout=stream, stderr=subprocess.STDOUT)
print({'gate': 'pq-admission', 'source': head, 'returncode': result.returncode, 'log': str(log)})
raise SystemExit(result.returncode)

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time

root = Path('/workspace/scratch/0b53202edbbf/chain-throughput')
out = Path('/workspace/scratch/0b53202edbbf/validation/clean-11e242')
out.mkdir(exist_ok=False)
sha = '11e242dbaaae14a9d16282fe8deaf36827e98395'
env = os.environ.copy()
env['PATH'] = '/workspace/scratch/5778f0ffb5d4/toolchain/installed/bin:' + env['PATH']
env['PYTHONDONTWRITEBYTECODE'] = '1'
py = sys.executable
results = []

def run(name, argv):
    start = time.monotonic()
    with (out / (name + '.stdout')).open('wb') as stdout, (out / (name + '.stderr')).open('wb') as stderr:
        completed = subprocess.run(argv, cwd=root, env=env, stdout=stdout, stderr=stderr, check=False)
    return dict(name=name, argv=argv, exit_code=completed.returncode,
                elapsed_seconds=time.monotonic() - start, source_sha=sha,
                stdout_sha256=hashlib.sha256((out / (name + '.stdout')).read_bytes()).hexdigest(),
                stderr_sha256=hashlib.sha256((out / (name + '.stderr')).read_bytes()).hexdigest())

def record(result):
    results.append(result)
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(result), flush=True)

def source(name):
    return run(name, [py, '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                     '--expected-head', sha, '--output', str(out / (name + '.json'))])

record(source('01-source-before'))
record(run('02-preflight', ['bash', 'scripts/project-preflight.sh']))
if any(row['exit_code'] for row in results):
    sys.exit(1)

commands = [
    ('03-reader', [py, '-B', 'scripts/ci/test_pon_budget_controls.py']),
    ('04-source-negative', [py, '-B', 'scripts/ci/test_ci_source_integrity.py']),
    ('05-ci-negative', [py, '-B', 'scripts/ci/test_ci_contract.py']),
    ('06-lifetime', [py, '-B', 'scripts/ci/pq_lifetime_budget.py']),
    ('07-authority', [py, '-B', 'scripts/ci/pq_authority_effect_register.py']),
    ('08-corpus', [py, '-B', 'scripts/ci/check_pq_research_integration.py']),
    ('09-inventory', [py, '-B', 'scripts/refresh_distributed_source_inventory.py', '--check']),
    ('10-ci-contract', [py, '-B', 'scripts/ci/check_ci_contract.py']),
    ('11-repository', [py, '-B', 'scripts/ci/check_repository.py']),
    ('12-format', ['cargo', 'fmt', '--all', '--manifest-path', 'trillionnium/Cargo.toml', '--', '--check']),
    ('13-cargo-graph', ['cargo', 'metadata', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--format-version', '1']),
]
with ThreadPoolExecutor(max_workers=4) as executor:
    for future in as_completed([executor.submit(run, name, argv) for name, argv in commands]):
        record(future.result())
record(source('14-source-after'))
before = json.loads((out / '01-source-before.json').read_text())
after = json.loads((out / '14-source-after.json').read_text())
assert before == after
summary = dict(schema='pon-clean-source-checks-v1', source=sha, source_guards_identical=True,
               commands=len(results), passed=sum(row['exit_code'] == 0 for row in results),
               native_tests_executed=False)
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary), flush=True)
sys.exit(1 if any(row['exit_code'] for row in results) else 0)

#!/usr/bin/env python3
"""Record scoped checks on one clean immutable Chain / runtime source pair."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--group', choices=('source-controls', 'quantum', 'static'), required=True)
args = p.parse_args()
root = args.source.resolve(strict=True)
out = args.out.resolve()
if out.is_relative_to(root):
    p.error('output must be outside the immutable source')
out.mkdir(parents=True, exist_ok=False)
chain = 'b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c'
runtime = '29fcd2e88654d5bec2bf30134cc030b5bfa7831b'
env_overrides = {'PYTHONDONTWRITEBYTECODE': '1', 'GIT_OPTIONAL_LOCKS': '0',
                 'PATH': '/root/.cargo/bin:' + os.environ.get('PATH', '')}
env = dict(os.environ, **env_overrides)
def git(*a):
    return subprocess.check_output(['git', *a], cwd=root, env=env, text=True).strip()
if git('rev-parse', 'HEAD') != chain or git('status', '--porcelain=v1', '--untracked-files=all'):
    raise SystemExit('source must be the clean fixed Chain commit')
tree = git('rev-parse', 'HEAD^{tree}')
py = 'python3'
groups = {
    'source-controls': [
        ('source-integrity', 'scripts/ci', [py, '-m', 'unittest', 'test_ci_source_integrity', 'test_record_pq_native_command', '-v']),
        ('pq-controls', 'scripts/ci', [py, '-m', 'unittest', 'test_pq_research_integration', 'test_pq_chain_claim_guard', '-v']),
        ('authority-scan-controls', 'scripts/ci', [py, '-m', 'unittest', 'test_pq_authority_surface_scan', '-v']),
    ],
    'quantum': [
        ('quantum-models', 'formal/pon-nakamoto-v1', [py, '-m', 'unittest', 'test_quantum_candidate_check_clock', 'test_quantum_network_sim', 'test_quantum_resource_clock', 'test_quantum_oracle_resources', 'test_quantum_daa_model', 'test_quantum_adversarial_search', '-v']),
    ],
    'static': [
        ('ci-contract', '.', [py, 'scripts/ci/check_ci_contract.py']),
        ('source-inventory', '.', [py, 'scripts/refresh_distributed_source_inventory.py', '--check']),
        ('pq-corpus', '.', [py, 'scripts/ci/check_pq_research_integration.py']),
        ('authority-inventory', '.', [py, 'scripts/ci/pq_authority_surface_scan.py']),
        ('repository-links', '.', [py, 'scripts/ci/check_repository.py']),
        ('shell-syntax', '.', ['bash', '-n', 'scripts/ci/ci_job.sh']),
        ('rust-format', '.', ['/root/.cargo/bin/cargo', '+1.95.0', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check']),
        ('cargo-graph', '.', ['/root/.cargo/bin/cargo', '+1.95.0', 'metadata', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--format-version=1']),
    ],
}
records = []
for name, relative, command in groups[args.group]:
    start = time.monotonic()
    log = out / (name + '.log')
    record = {'name': name, 'argv': command, 'cwd': str(root / relative),
              'chain_sha': chain, 'chain_tree': tree, 'runtime_sha': runtime,
              'environment_overrides': env_overrides, 'timeout_seconds': 300,
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        with log.open('wb') as stream:
            result = subprocess.run(command, cwd=root / relative, env=env,
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=300)
        record['exit_code'] = result.returncode
    except subprocess.TimeoutExpired:
        record['exit_code'] = None
        record['timeout_observed'] = True
    data = log.read_bytes()
    text = data.decode(errors='replace')
    record.update(wall_seconds=round(time.monotonic()-start, 6), log=log.name,
                  log_sha256=hashlib.sha256(data).hexdigest(), log_bytes=len(data),
                  unittest_count=sum(map(int, re.findall(r'^Ran (\d+) tests? in ', text, re.M))),
                  head_after=git('rev-parse', 'HEAD'),
                  status_after=git('status', '--porcelain=v1', '--untracked-files=all'))
    record['result'] = 'PASS' if (record['exit_code'] == 0 and record['head_after'] == chain
                                  and not record['status_after']) else 'FAIL'
    records.append(record)
    (out / 'checks.json').write_text(json.dumps(records, indent=2) + '\n')
    print(json.dumps({k:record[k] for k in ('name', 'result', 'exit_code', 'wall_seconds', 'unittest_count')}), flush=True)
    if record['result'] != 'PASS':
        print(text[-7000:], flush=True)
raise SystemExit(0 if all(r['result']=='PASS' for r in records) else 1)

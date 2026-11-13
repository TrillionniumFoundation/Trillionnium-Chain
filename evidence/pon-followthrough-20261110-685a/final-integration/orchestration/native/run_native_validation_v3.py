#!/usr/bin/env python3
"""Continue the failed C1 fixture observation; preserve original records."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path('/home/qian-qi/chain-pon-followthrough-20261110-685a')
INPUTS = Path('/home/qian-qi/chain-pon-followthrough-20261110-685a-inputs')
OUT = INPUTS / 'validation'
C1 = '11c9562252d3cf56b423c7756569be0c669d9606'
BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
STORE = 'trillionnium/crates/trnm-pon-node/src/store.rs'
TEST = 'trillionnium/crates/trnm-pon-node/src/store/confirmation_chainwork_tests.rs'
READER = 'scripts/pon_fresh_rejection_report.py'
ENV = dict(os.environ, CARGO_TERM_COLOR='never', CARGO_BUILD_JOBS='2',
           CARGO_TARGET_DIR='/home/qian-qi/chain-pon-followthrough-20261110-685a-target',
           PYTHONDONTWRITEBYTECODE='1')
RECORDS = json.loads((OUT / 'commands.json').read_text())

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.v3.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)

def run(label, argv, cwd=ROOT):
    assert not any(item['label'] == label for item in RECORDS), label
    print('START', label, flush=True)
    start = time.time_ns()
    out, err = OUT / (label + '.stdout.log'), OUT / (label + '.stderr.log')
    with out.open('xb') as stdout, err.open('xb') as stderr:
        result = subprocess.run(argv, cwd=cwd, env=ENV, stdout=stdout, stderr=stderr)
    record = dict(label=label, argv=argv, cwd=str(cwd), exit_code=result.returncode,
                  start_unix_ns=start, end_unix_ns=time.time_ns())
    for name, path in [('stdout', out), ('stderr', err)]:
        data = path.read_bytes()
        record[name] = dict(file=path.name, bytes=len(data), sha256=sha(data))
    RECORDS.append(record)
    write_json(OUT / 'commands.json', RECORDS)
    print('END', label, result.returncode, flush=True)
    return result.returncode, out.read_text(errors='replace'), err.read_text(errors='replace')

def require_run(label, argv, cwd=ROOT):
    result = run(label, argv, cwd)
    if result[0]:
        print('STOP', label, result[1][-5000:], result[2][-5000:], flush=True)
        raise SystemExit(result[0])
    return result

def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=ROOT, env=ENV)

def git_text(*args):
    return git(*args).decode().strip()

def profile():
    fields = {}
    for name in ('cpu.max', 'memory.max', 'cpuset.cpus.effective'):
        path = Path('/sys/fs/cgroup') / name
        fields[name] = path.read_text().strip() if path.is_file() else None
    model = next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                  if line.startswith('model name')), None)
    return {'observed_unix_ns': time.time_ns(), 'platform': platform.platform(),
            'machine': platform.machine(), 'logical_cpus': os.cpu_count(),
            'affinity': sorted(os.sched_getaffinity(0)), 'load_average': list(os.getloadavg()),
            'cpu_model': model, 'cgroup_limits': fields,
            'scope': 'local execution observations, not an independently authenticated resource bound'}

assert git_text('branch', '--show-current') == 'fix/chain-pon-followthrough-20261110-685a'
assert git_text('rev-parse', 'HEAD') == C1 and not git_text('status', '--porcelain')
assert RECORDS[-1]['label'] == 'green-confirmation' and RECORDS[-1]['exit_code'] == 101
assert json.loads((OUT / 'source.json').read_text())['commit'] == C1
assert sha((ROOT / TEST).read_bytes()) == '53457a091467c1b84738164705092463039bcac88ad24f76b6e92fc1bfee74d9'
assert sha((ROOT / READER).read_bytes()) == '901f739ca7962f22b9eeba405ba2928114d554c2aa1a6ea239bdeab28d484383'
(OUT / 'commands-before-v3.json').write_bytes((OUT / 'commands.json').read_bytes())
require_run('v3-preflight', ['bash', 'scripts/project-preflight.sh'])
require_run('v3-apply-exact-test-diagnostic', ['git', 'apply', str(INPUTS / 'confirmation-test-exact-code.patch')])
require_run('v3-apply-verified-reference-reader', ['git', 'apply', str(INPUTS / 'fresh-reader-after-native-v2.patch')])
require_run('v3-format-candidate', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all'])
assert set(git_text('diff', '--name-only').splitlines()) == {TEST, READER}
assert not git_text('ls-files', '--others', '--exclude-standard')

# Repeat the corrected four tests against the exact old Node production file.
# Other committed dependencies stay at C1; this is an explicit owner counterfactual.
# Restore the owned production file before any successful continuation.
green_store = git('show', C1 + ':' + STORE)
assert (ROOT / STORE).read_bytes() == green_store
base_store = git('show', BASE + ':' + STORE)
anchor = b'mod canonical_row_reuse_tests;\n'
assert base_store.count(anchor) == 1 and b'mod confirmation_chainwork_tests;' not in base_store
red_store = base_store.replace(anchor, anchor + b'#[cfg(test)]\nmod confirmation_chainwork_tests;\n')
assert sha(red_store) == '8c7b60e976d49b605b582252c49af984933126a6059b6c61423c9c3ddf7a65d6'
red_source = {'schema': 'pon-node-corrected-test-counterfactual-v1', 'dependency_checkpoint': C1,
              'node_production_base': BASE, 'red_store_sha256': sha(red_store),
              'test_sha256': sha((ROOT / TEST).read_bytes()),
              'reader_sha256': sha((ROOT / READER).read_bytes()),
              'scope': 'same four corrected tests; old Node production with the test-module declaration; other dependencies at C1',
              'complete_baseline_checkout_claimed': False, 'production_activation': False}
write_json(OUT / 'red-v3-source.json', red_source)
(ROOT / STORE).write_bytes(red_store)
cargo = ['cargo', 'test', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline']
try:
    red = run('red-confirmation-v3', cargo + ['-p', 'trnm-pon-node', '--lib', 'confirmation_chainwork_tests', '--', '--nocapture'])
finally:
    assert (ROOT / STORE).read_bytes() == red_store, 'independent store change; refusing overwrite'
    (ROOT / STORE).write_bytes(green_store)
assert red[0] == 101 and 'test result: FAILED. 0 passed; 4 failed; 0 ignored;' in red[1], red
assert set(git_text('diff', '--name-only').splitlines()) == {TEST, READER}
require_run('v3-diff-check', ['git', 'diff', '--check'])
require_run('v3-precommit-preflight', ['bash', 'scripts/project-preflight.sh'])
require_run('v3-stage-source', ['git', 'add', '--', TEST, READER])
require_run('v3-source-commit', ['git', 'commit', '-m', 'test(pon): preserve the authenticated tip refusal and bind reference execution'])
source = {'commit': git_text('rev-parse', 'HEAD'), 'tree': git_text('rev-parse', 'HEAD^{tree}'),
          'prior_code_commit': C1, 'baseline': BASE, 'clean': not git_text('status', '--porcelain'),
          'changed_from_c1': [TEST, READER]}
assert source['clean']
write_json(OUT / 'source-v3.json', source)
print('SOURCE_V3', json.dumps(source), flush=True)
require_run('v3-committed-preflight', ['bash', 'scripts/project-preflight.sh'])
require_run('v3-source-before', ['python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', source['commit'], '--output', str(OUT / 'source-before-v3.json')])
require_run('v3-locked-graph', ['cargo', 'metadata', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline', '--format-version', '1'])
require_run('v3-rustc', ['rustc', '-Vv'])
require_run('v3-cargo', ['cargo', '-V'])
require_run('green-confirmation-v3', cargo + ['-p', 'trnm-pon-node', '--lib', 'confirmation_chainwork_tests', '--', '--nocapture'])
require_run('green-settlement-v3', cargo + ['-p', 'trnm-service-settlement', '--lib', 'readback_rejects', '--', '--nocapture'])
require_run('settlement-all-features-v3', cargo + ['-p', 'trnm-service-settlement', '--all-features'])
require_run('crypto-library-v3', cargo + ['-p', 'trnm-crypto-primitives', '--lib'])
require_run('node-library-v3', cargo + ['-p', 'trnm-pon-node', '--lib'])
require_run('fresh-probe-tests-v3', cargo + ['--release', '-p', 'trnm-crypto-primitives', '--example', 'pon_fresh_rejection_cost'])
require_run('changed-owner-clippy-v3', ['cargo', 'clippy', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline', '-p', 'trnm-pon-node', '-p', 'trnm-service-settlement', '-p', 'trnm-crypto-primitives', '--all-targets', '--', '-D', 'warnings'])
require_run('format-check-v3', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'])
require_run('fresh-probe-build-v3', ['cargo', 'build', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline', '--release', '-p', 'trnm-crypto-primitives', '--example', 'pon_fresh_rejection_cost'])
binary = Path(ENV['CARGO_TARGET_DIR']) / 'release/examples/pon_fresh_rejection_cost'
binary_hash = sha(binary.read_bytes())
write_json(OUT / 'fresh-profile-before-v3.json', profile())
require_run('fresh-probe-native-v3', [str(binary)])
write_json(OUT / 'fresh-profile-after-v3.json', profile())
assert sha(binary.read_bytes()) == binary_hash
raw = OUT / 'fresh-probe-native-v3.stdout.log'
require_run('fresh-probe-reader-v3', ['python3', '-B', READER, str(raw), '--raw-sha256', sha(raw.read_bytes())])
require_run('fresh-reader-tests-v3', ['python3', '-B', 'scripts/ci/test_fresh_rejection_report.py', '-v'])
require_run('v3-source-after', ['python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', source['commit'], '--output', str(OUT / 'source-after-v3.json')])
require_run('v3-source-identical', ['cmp', str(OUT / 'source-before-v3.json'), str(OUT / 'source-after-v3.json')])
assert git_text('rev-parse', 'HEAD') == source['commit'] and not git_text('status', '--porcelain')
summary = {'source': source, 'binary': str(binary), 'binary_sha256': binary_hash,
           'commands': len(RECORDS), 'complete': True, 'open_consensus_qualified': False,
           'production_activation': False}
write_json(OUT / 'summary-v3.json', summary)
print('COMPLETE_V3', json.dumps(summary), flush=True)

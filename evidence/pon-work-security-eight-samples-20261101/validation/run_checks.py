import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/tmp/trnm-pon-security-final')
OUT = Path('/tmp/trnm-pon-validation-3bbc')
PIN = '3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129'
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from ci_observation import source, run

env = os.environ.copy()
env.update(CARGO_HOME='/tmp/trnm-original-budget-cargo',
           RUSTUP_HOME='/tmp/trnm-original-budget-rustup',
           CARGO_TARGET_DIR='/tmp/trnm-pon-security-target',
           CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
           PYTHONDONTWRITEBYTECODE='1')
env['PATH'] = '/tmp/trnm-original-budget-cargo/bin:' + env['PATH']
for row in Path('/tmp/trnm-pon-pq-provider-20261101.crzprwdr/github.env').read_text().splitlines():
    key, value = row.split('=', 1)
    env[key] = value

mode = sys.argv[1]
groups = {
    'python': [
        ('v1-reader', ['python', 'scripts/ci/test_pon_w1_legal_strategy_reader_v1.py']),
        ('v2-reader', ['python', 'scripts/ci/test_pon_w1_legal_strategy_reader_v2.py']),
        ('cost-runner', ['python', 'scripts/ci/test_run_w1_false_trace_reuse_v1.py']),
        ('source-negatives', ['python', 'scripts/ci/test_ci_source_integrity.py']),
        ('pq-negatives', ['python', 'scripts/ci/test_pq_research_integration.py']),
        ('ci-contract', ['python', 'scripts/ci/test_ci_contract.py']),
        ('query-bound', ['python', 'formal/pon-nakamoto-v1/test_work_query_bound.py']),
        ('pq-source-positive', ['python', 'scripts/ci/check_pq_research_integration.py']),
        ('ci-positive', ['python', 'scripts/ci/check_ci_contract.py']),
        ('inventory', ['python', 'scripts/refresh_distributed_source_inventory.py', '--check']),
    ],
    'native': [
        ('w1-module', ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-crypto-primitives', '--lib', 'pon_work::', '--', '--test-threads=1']),
        ('wire-bindings', ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-protocol', '--lib', 'pon_wire::', '--', '--test-threads=1']),
        ('history-original', ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-pon-node', '--lib', 'ingress::history_import::tests', '--', '--test-threads=1']),
        ('legal-example', ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-pon-node', '--example', 'pon_w1_legal_strategy_v1', '--', '--test-threads=1']),
        ('work-fuzz', ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-pon-node', '--test', 'work_fuzz_semantics', '--', '--test-threads=1']),
        ('retained-rejection', ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-crypto-primitives', '--example', 'pon_rejection_cost', '--', '--test-threads=1']),
        ('crypto-all-features', ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-crypto-primitives', '--all-features', '--', '--test-threads=1']),
        ('format', ['cargo', 'fmt', '--manifest-path', str(ROOT / 'trillionnium/Cargo.toml'), '--all', '--', '--check']),
        ('locked-graph', ['cargo', 'metadata', '--manifest-path', str(ROOT / 'trillionnium/Cargo.toml'), '--locked', '--offline', '--all-features', '--format-version', '1']),
    ],
}
commands = groups[mode]
report = {'source_before': source(), 'mode': mode, 'observations': []}
assert report['source_before']['commit'] == PIN
assert report['source_before']['source_state'] == 'committed-clean'
for label, cmd in commands:
    cwd = ROOT if mode == 'python' else ROOT / 'trillionnium'
    log = OUT / (label + '.log')
    record = run(cmd, log, timeout=900, env=env, cwd=cwd, expected_source=PIN)
    record.update(label=label, command=cmd, log=log.name,
                  log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
    report['observations'].append(record)
    (OUT / (mode + '-validation.json')).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'check': label, 'exit_code': record['exit_code']}), flush=True)
report['source_after'] = source()
report['source_changed'] = report['source_after'] != report['source_before']
report['result'] = 'PASS' if not report['source_changed'] and all(r['exit_code'] == 0 for r in report['observations']) else 'FAIL'
(OUT / (mode + '-validation.json')).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'mode': mode, 'result': report['result']}), flush=True)
raise SystemExit(report['result'] != 'PASS')

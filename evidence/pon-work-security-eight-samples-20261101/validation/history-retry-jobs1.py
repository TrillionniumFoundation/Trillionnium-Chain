import hashlib
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timezone

ROOT = Path('/tmp/trnm-pon-security-final')
OUT = Path('/tmp/trnm-pon-validation-3bbc')
PIN = '3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129'
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from ci_observation import source, run

def memory_sample():
    result = {'started_utc': datetime.now(timezone.utc).isoformat(), 'values': {}}
    for name in ['memory.max', 'memory.current', 'memory.peak', 'memory.events', 'memory.events.local']:
        path = Path('/sys/fs/cgroup') / name
        try:
            raw = path.read_text().strip()
            value = {'path': str(path), 'raw': raw}
            if name.startswith('memory.events'):
                value['counters'] = {parts[0]: int(parts[1]) for line in raw.splitlines()
                                     if len(parts := line.split()) == 2}
            elif raw.isdigit():
                value['bytes'] = int(raw)
            result['values'][name] = value
        except OSError as error:
            result['values'][name] = {'path': str(path), 'available': False, 'error_type': type(error).__name__}
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    return result

env = os.environ.copy()
env.update(CARGO_HOME='/tmp/trnm-original-budget-cargo',
           RUSTUP_HOME='/tmp/trnm-original-budget-rustup',
           CARGO_TARGET_DIR='/tmp/trnm-pon-security-target',
           CARGO_BUILD_JOBS='1', CARGO_NET_OFFLINE='true',
           PYTHONDONTWRITEBYTECODE='1')
env['PATH'] = '/tmp/trnm-original-budget-cargo/bin:' + env['PATH']
provider_env = Path('/tmp/trnm-pon-pq-provider-20261101.crzprwdr/github.env')
for line in provider_env.read_text().splitlines():
    key, value = line.split('=', 1)
    env[key] = value

log = OUT / 'history-retry-jobs1.log'
receipt_path = OUT / 'history-retry-jobs1.receipt.json'
assert not log.exists() and not receipt_path.exists(), 'refusing to overwrite a retry observation'
before = source()
assert before['commit'] == PIN and before['source_state'] == 'committed-clean'
memory_before = memory_sample()
command = ['cargo', 'test', '--release', '--locked', '--offline', '-p', 'trnm-pon-node',
           '--lib', 'ingress::history_import::tests', '--', '--test-threads=1']
record = run(command, log, timeout=900, env=env, cwd=ROOT / 'trillionnium', expected_source=PIN)
memory_after = memory_sample()
after = source()
receipt = {'schema': 'pon-history-original-source-jobs1-retry-v1',
           'record': record, 'source_before': before, 'source_after': after,
           'source_changed': after != before,
           'command': command, 'command_sha256': hashlib.sha256(json.dumps(command, separators=(',', ':')).encode()).hexdigest(),
           'original_timeout_seconds': 900,
           'build_concurrency': {'previous': 2, 'retry': 1,
                                 'scope': 'Cargo build jobs only; does not control other tasks in the shared executor.'},
           'other_build_profile_or_runtime_budgets_changed': False,
           'provider_env_file': str(provider_env),
           'provider_env_file_sha256': hashlib.sha256(provider_env.read_bytes()).hexdigest(),
           'memory_before': memory_before, 'memory_after': memory_after,
           'memory_scope': 'Current enclosing executor cgroup; sequential observations, not the fixed public service Host.',
           'original_failed_receipt_and_log_retained': True,
           'log': str(log), 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
with receipt_path.open('x') as output:
    json.dump(receipt, output, indent=2, sort_keys=True)
    output.write('\n')
print(json.dumps({'retry_exit_code': record['exit_code'], 'timed_out': record['timed_out'],
                  'source_changed': receipt['source_changed'], 'receipt': str(receipt_path)}), flush=True)
raise SystemExit(record['exit_code'] != 0 or receipt['source_changed'])

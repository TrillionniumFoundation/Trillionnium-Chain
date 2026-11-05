import collections
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path('/dev/shm/trnm-model-owner-f4976366a32a-native-evidence')
OUT = ROOT / 'native-frozen-f388f46d9df1'
SOURCE = 'f388f46d9df150a3599b9d961b48918b3ff1fb48'
spec = importlib.util.spec_from_file_location('native_controller', ROOT / 'verify_native_exact.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
prior = json.loads((OUT / 'verification.json').read_text())
profile = {key: os.environ.get(key) for key in prior['build_test_profile']}
if profile != prior['build_test_profile'] or c.exact_source(SOURCE) != prior['source_before']:
    raise RuntimeError('same-source original-profile continuation required')
if c.provider_snapshot() != prior['provider_before']:
    raise RuntimeError('provider changed before readback')
result = dict(prior, schema='model-owner-native-reconciled-source-readback-v1',
    status='PENDING', original_controller_record_sha256=c.sha(OUT / 'verification.json'),
    reconciliation_script_sha256=c.sha(__file__),
    stale_inventory_rejection=dict(old_assumption=229, actual_passed=236,
        original_controller_exit=1, original_cargo_test_exit=0,
        reason='Historical 229 count is not the frozen source inventory; retain original rejection, verify full actual roster without rerunning passing tests.'))
result['commands'] = list(prior['commands'])
path = OUT / 'reconciled-verification.json'
c.save(path, result)

def run(name, command):
    if c.exact_source(SOURCE) != prior['source_before'] or c.provider_snapshot() != prior['provider_before']:
        raise RuntimeError('input changed before ' + name)
    print(json.dumps(dict(stage=name, state='started')), flush=True)
    begin = time.monotonic()
    log = OUT / (name + '.log')
    with log.open('xb') as stream:
        completed = subprocess.run(command, cwd=c.REPO, stdout=stream, stderr=subprocess.STDOUT)
    row = dict(name=name, command=command, exit_code=completed.returncode,
        seconds=time.monotonic() - begin, log_sha256=c.sha(log),
        source_after=c.exact_source(SOURCE), provider_after=c.provider_snapshot())
    result['commands'].append(row)
    c.save(path, result)
    if row['source_after'] != prior['source_before'] or row['provider_after'] != prior['provider_before']:
        raise RuntimeError('input changed during ' + name)
    print(json.dumps(dict(stage=name, state='returned', exit_code=completed.returncode)), flush=True)
    if completed.returncode:
        raise RuntimeError(name + ' failed: ' + str(completed.returncode))
    return log.read_text()

try:
    actual = (OUT / 'm06-tests.log').read_text()
    original = next(row for row in prior['commands'] if row['name'] == 'm06-tests')
    if original['exit_code'] != 0 or c.sha(OUT / 'm06-tests.log') != original['log_sha256']:
        raise RuntimeError('original test process/hash did not pass')
    totals = prior['native_test_totals']
    if not prior['native_test_summary_count'] or not totals['passed'] or totals['failed'] or totals['filtered_out']:
        raise RuntimeError('actual complete test summaries required')
    listing = run('m06-test-inventory', ['cargo', 'test', '--locked', '--manifest-path',
        'trillionnium/Cargo.toml', '-p', 'trnm-mvcc-fee', '--all-targets', '--all-features', '--', '--list'])
    expected = collections.Counter(re.findall(r'^(.+): test$', listing, re.M))
    observed_rows = re.findall(r'^test (.+?) \.\.\. (ok|ignored(?:,.*)?|FAILED)$', actual, re.M)
    observed = collections.Counter(name for name, _ in observed_rows)
    expected_targets = re.findall(r'^\s*Running (.+?) \(', listing, re.M)
    observed_targets = re.findall(r'^\s*Running (.+?) \(', actual, re.M)
    if (not expected or expected != observed or expected_targets != observed_targets or
            sum(expected.values()) != totals['passed'] + totals['ignored']):
        raise RuntimeError('actual test roster differs from exact-source compiled list')
    roster = dict(targets=observed_targets, tests=sorted(observed.elements()),
                  outcomes=observed_rows, totals=totals)
    c.save(OUT / 'actual-test-roster.json', roster)
    result['actual_roster'] = dict(entries=sum(expected.values()), targets=len(observed_targets),
        matched=True, sha256=c.sha(OUT / 'actual-test-roster.json'))
    result['test_transcript_complete'] = True
    result.pop('expected_retained_test_inventory', None)
    c.save(path, result)
    run('m06-clippy', ['cargo', 'clippy', '--locked', '--manifest-path', 'trillionnium/Cargo.toml',
        '-p', 'trnm-mvcc-fee', '--all-targets', '--all-features', '--', '-D', 'warnings'])
    result.update(status='PASS', source_after=c.exact_source(SOURCE),
        provider_after=c.provider_snapshot(), finished_utc_ns=time.time_ns(),
        source_unchanged=True, provider_observations_unchanged=True, qualification=False)
except BaseException as error:
    result.update(status='FAILED_RECONCILIATION', error_type=type(error).__name__, error=str(error),
                  finished_utc_ns=time.time_ns())
    c.save(path, result)
    raise
c.save(path, result)
print(json.dumps(dict(status='PASS', source=SOURCE, report=str(path), tests=totals)), flush=True)

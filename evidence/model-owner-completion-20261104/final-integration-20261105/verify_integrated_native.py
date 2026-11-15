"""Verify one frozen integration source with the retained compiled test roster."""
import argparse
import collections
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time


def test_records(transcript, listing=False):
    """Keep each test under the Cargo target that actually emitted it."""
    target = None
    targets, records = [], []
    for line in transcript.splitlines():
        found = re.match(r'^\s*Running (.+?) \(', line)
        if found:
            target = found.group(1)
            if target in targets:
                raise ValueError('repeated Cargo target in transcript')
            targets.append(target)
        found = re.match(r'^(.+): test$', line) if listing else re.match(
            r'^test (.+?) \.\.\. (ok|ignored(?:,.*)?|FAILED)$', line)
        if found:
            if target is None:
                raise ValueError('test without Cargo target')
            records.append((target, found.group(1), 'listed' if listing else found.group(2)))
    keys = collections.Counter((target, test) for target, test, _ in records)
    if not targets or not records or any(count != 1 for count in keys.values()):
        raise ValueError('empty or ambiguous Cargo test transcript')
    return targets, records


def check_retained_tests(expected_targets, expected_records, actual_targets, actual_records,
                         baseline_records):
    expected = collections.Counter((target, test) for target, test, _ in expected_records)
    actual = collections.Counter((target, test) for target, test, _ in actual_records)
    baseline = collections.Counter((target, test) for target, test, _ in baseline_records)
    prior_passed = collections.Counter((target, test) for target, test, outcome in baseline_records
                                      if outcome == 'ok')
    now_passed = collections.Counter((target, test) for target, test, outcome in actual_records
                                    if outcome == 'ok')
    if baseline - expected or expected != actual or expected_targets != actual_targets:
        raise ValueError('complete retained target/test inventory is required')
    if prior_passed - now_passed:
        raise ValueError('previously passing target/test may not become ignored or fail')


def check_outcome_totals(records, totals):
    actual = dict(passed=sum(outcome == 'ok' for _, _, outcome in records),
                  failed=sum(outcome == 'FAILED' for _, _, outcome in records),
                  ignored=sum(outcome.startswith('ignored') for _, _, outcome in records))
    if actual != {key: totals[key] for key in actual} or actual['failed']:
        raise ValueError('per-test outcomes contradict successful summary totals')


ROOT = Path('/dev/shm/trnm-model-owner-f4976366a32a-native-evidence')
spec = importlib.util.spec_from_file_location('native_controller', ROOT / 'verify_native_exact.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', required=True)
args = parser.parse_args()
if not re.fullmatch('[0-9a-f]{40}', args.source):
    raise ValueError('exact source SHA required')
expected_profile = dict(CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0',
    CARGO_PROFILE_TEST_DEBUG='0', CARGO_BUILD_JOBS='1', RUST_TEST_THREADS='1')
if ({key: os.environ.get(key) for key in expected_profile} != expected_profile or
        os.environ.get('RUSTFLAGS', '') or os.environ.get('CARGO_ENCODED_RUSTFLAGS', '')):
    raise ValueError('original native build/test profile required')
source = c.exact_source(args.source)
subprocess.run(['git', '-C', str(c.REPO), 'merge-base', '--is-ancestor',
    'f388f46d9df150a3599b9d961b48918b3ff1fb48', args.source], check=True)
provider = c.provider_snapshot()
rustc = subprocess.check_output(['rustc', '--version', '--verbose'], text=True)
cargo = subprocess.check_output(['cargo', '--version'], text=True).strip()
if not rustc.startswith('rustc 1.95.0 ') or not cargo.startswith('cargo 1.95.0 '):
    raise ValueError('original Rust 1.95 required')
out = ROOT / ('native-integrated-' + args.source[:12])
out.mkdir(mode=0o700, exist_ok=False)
baseline_path = ROOT / 'native-frozen-f388f46d9df1/actual-test-roster.json'
baseline = json.loads(baseline_path.read_text())
baseline_report_path = baseline_path.parent / 'reconciled-verification.json'
baseline_report = json.loads(baseline_report_path.read_text())
baseline_log_path = baseline_path.parent / 'm06-tests.log'
baseline_row = next(row for row in baseline_report['commands'] if row['name'] == 'm06-tests')
if (baseline_report['status'] != 'PASS' or baseline_row['exit_code'] != 0 or
        baseline_report['source_before']['commit'] != 'f388f46d9df150a3599b9d961b48918b3ff1fb48' or
        baseline_report['actual_roster']['sha256'] != c.sha(baseline_path) or
        baseline_row['log_sha256'] != c.sha(baseline_log_path)):
    raise ValueError('retained f388 evidence bytes do not match reconciled result')
if (provider != baseline_report['provider_after'] or
        rustc != baseline_report['rustc'] or cargo != baseline_report['cargo']):
    raise ValueError('original f388 provider and Rust toolchain observations are required')
baseline_targets, baseline_records = test_records(baseline_log_path.read_text())
if (baseline_targets != baseline['targets'] or
        sorted(test for _, test, _ in baseline_records) != baseline['tests'] or
        [[test, outcome] for _, test, outcome in baseline_records] != baseline['outcomes']):
    raise ValueError('retained f388 target/test readback does not match prior roster')
baseline_keys = collections.Counter((target, test) for target, test, _ in baseline_records)
result = dict(schema='model-owner-native-integration-readback-v1', status='PENDING',
    source_before=source, provider_before=provider, rustc=rustc, cargo=cargo,
    build_test_profile=expected_profile, custom_rustflags=False,
    cargo_home=os.environ.get('CARGO_HOME'), target_dir=os.environ.get('CARGO_TARGET_DIR'),
    tmpdir=os.environ.get('TMPDIR'), controller_sha256=c.sha(__file__),
    helper_sha256=c.sha(ROOT / 'verify_native_exact.py'),
    prior_source='f388f46d9df150a3599b9d961b48918b3ff1fb48',
    prior_roster_sha256=c.sha(baseline_path), prior_report_sha256=c.sha(baseline_report_path),
    prior_transcript_sha256=c.sha(baseline_log_path), commands=[], started_utc_ns=time.time_ns(),
    qualification=False)
report = out / 'verification.json'
c.save(report, result)

def run(name, command):
    if c.exact_source(args.source) != source or c.provider_snapshot() != provider:
        raise RuntimeError('source/provider changed before ' + name)
    print(json.dumps(dict(stage=name, state='started', source=args.source)), flush=True)
    started = time.monotonic()
    log, errors = out / (name + '.log'), out / (name + '.stderr.log')
    with log.open('xb') as stream, errors.open('xb') as err:
        returned = subprocess.run(command, cwd=c.REPO, stdout=stream,
            stderr=err if name == 'cargo-metadata' else subprocess.STDOUT)
    row = dict(name=name, command=command, exit_code=returned.returncode,
        seconds=time.monotonic() - started, log_sha256=c.sha(log), stderr_sha256=c.sha(errors))
    result['commands'].append(row)
    c.save(report, result)
    row.update(source_after=c.exact_source(args.source), provider_after=c.provider_snapshot())
    c.save(report, result)
    print(json.dumps(dict(stage=name, state='returned', exit_code=returned.returncode)), flush=True)
    if row['source_after'] != source or row['provider_after'] != provider:
        raise RuntimeError('source/provider changed during ' + name)
    if returned.returncode:
        raise RuntimeError(name + ' exit ' + str(returned.returncode))
    return log.read_text()

try:
    run('preflight', ['bash', 'scripts/project-preflight.sh'])
    metadata = json.loads(run('cargo-metadata', ['cargo', 'metadata', '--locked',
        '--manifest-path', 'trillionnium/Cargo.toml', '--format-version', '1']))
    result['workspace_members'] = len(metadata['workspace_members'])
    result['resolved_packages'] = len(metadata['packages'])
    run('cargo-fmt', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'])
    command = ['cargo', 'test', '--locked', '--manifest-path', 'trillionnium/Cargo.toml',
        '-p', 'trnm-mvcc-fee', '--all-targets', '--all-features']
    listing = run('m06-test-inventory', command + ['--', '--list'])
    expected_targets, expected_records = test_records(listing, listing=True)
    expected = collections.Counter((target, test) for target, test, _ in expected_records)
    if baseline_keys - expected:
        raise RuntimeError('complete retained f388 test inventory is required')
    result['test_inventory'] = dict(entries=sum(expected.values()), targets=len(expected_targets),
        all_prior_target_test_pairs_retained=True,
        additional_target_test_pairs=sorted((expected - baseline_keys).elements()))
    c.save(report, result)
    actual = run('m06-tests', command)
    pattern = r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;'
    summaries = [tuple(map(int, values)) for values in re.findall(pattern, actual)]
    totals = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'),
        [sum(row[i] for row in summaries) for i in range(5)]))
    actual_targets, actual_records = test_records(actual)
    check_retained_tests(expected_targets, expected_records, actual_targets, actual_records,
                         baseline_records)
    check_outcome_totals(actual_records, totals)
    result['native_test_totals'] = totals
    result['native_test_summary_count'] = len(summaries)
    if (not summaries or not totals['passed'] or totals['failed'] or totals['filtered_out'] or
            totals['measured'] or
            len(summaries) != len(expected_targets) or
            sum(expected.values()) != totals['passed'] + totals['ignored']):
        raise RuntimeError('actual test transcript does not match the exact compiled inventory')
    c.save(out / 'actual-test-roster.json', dict(targets=actual_targets,
        target_test_outcomes=actual_records, totals=totals))
    result['test_transcript_complete'] = True
    result['all_prior_pass_outcomes_retained'] = True
    result['actual_roster_sha256'] = c.sha(out / 'actual-test-roster.json')
    c.save(report, result)
    run('m06-clippy', ['cargo', 'clippy', '--locked', '--manifest-path', 'trillionnium/Cargo.toml',
        '-p', 'trnm-mvcc-fee', '--all-targets', '--all-features', '--', '-D', 'warnings'])
    final_source, final_provider = c.exact_source(args.source), c.provider_snapshot()
    if final_source != source or final_provider != provider:
        raise RuntimeError('final source/provider readback changed')
    result.update(status='PASS', source_after=final_source,
        provider_after=final_provider, source_unchanged=True,
        provider_observations_unchanged=True, finished_utc_ns=time.time_ns())
except BaseException as error:
    result.update(status='FAILED_OR_INCOMPLETE', error_type=type(error).__name__,
                  error=str(error), finished_utc_ns=time.time_ns())
    c.save(report, result)
    raise
c.save(report, result)
print(json.dumps(dict(status='PASS', report=str(report), tests=totals, source=args.source)), flush=True)

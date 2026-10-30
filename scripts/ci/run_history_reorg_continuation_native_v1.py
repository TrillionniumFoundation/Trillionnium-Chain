#!/usr/bin/env python3
"""Require the unchanged original gate, then run a separate paid-reorg native lane."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import zlib

from run_history_effect_v6_native import bounded, sha, verify_binary_archive, write
from verify_ci_source import verify

ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'store::history_effect_v6::reorg_continuation_tests_v1::'
ROSTER = sorted(PREFIX + name for name in [
    'partial_reorg_intent_and_each_committed_cursor_recover_with_fresh_paid_attempt',
    'reorg_continuation_known_cancel_and_pending_startup_validation_each_require_new_authority',
    'reorg_final_native_marker_survives_crash_before_settlement_and_clears_permit',
    'reorg_snapshot_streams_the_original_complete_state_capacity_above_32_mib',
    'reorg_permit_every_publication_cut_repairs_exact_bytes_and_runs_once',
    'expired_reorg_closure_grants_no_work_until_ordinary_fresh_budget_renewal',
    'exhausted_reorg_budget_requires_atomic_fresh_budget_and_preserves_original_debt',
])
SOURCE_ENV = 'TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT'
NATIVE_BUDGET_SECONDS = 900


def roster(text):
    found = sorted(line.removesuffix(': test') for line in text.splitlines()
                   if line.startswith(PREFIX) and line.endswith(': test'))
    if found != ROSTER:
        raise ValueError('exact reorg roster differs; missing, duplicate or substituted test')
    return found


def suite_passed(text):
    summaries = re.findall(r'^test result: .+$', text, re.M)
    executed = sorted(re.findall(r'^test (' + re.escape(PREFIX) + r'\S+) \.\.\. ', text, re.M))
    statuses = re.findall(r'^test ' + re.escape(PREFIX) + r'\S+ \.\.\. (\S+)$', text, re.M)
    return (text.splitlines().count('running 7 tests') == 1 and executed == ROSTER
            and statuses == ['ok'] * 7 and len(summaries) == 1
            and re.fullmatch(r'test result: ok\. 7 passed; 0 failed; 0 ignored; '
                             r'0 measured; \d+ filtered out; finished in .+s', summaries[0]) is not None)


def baseline(directory, expected_source, source):
    terminal = json.loads((directory / 'terminal.json').read_text())
    if (terminal.get('schema') != 'history-effect-v6-hosted-native-terminal-v1'
            or terminal.get('expected_source') != expected_source
            or terminal.get('passed') is not True
            or terminal.get('source_stable') is not True
            or terminal.get('native_test_budget_seconds') != 600
            or terminal.get('original_local_full_suite_budget_seconds') != 600
            or terminal.get('native', {}).get('exact_twenty_two_pass_one_ignored') is not True
            or json.loads((directory / 'source-before.json').read_text()) != source
            or json.loads((directory / 'source-after.json').read_text()) != source):
        raise ValueError('unchanged original gate and exact source are required')
    manifest = json.loads((directory / 'actual-binary/manifest.json').read_text())
    if (manifest != terminal.get('binary_archive')
            or manifest.get('binary_sha256') != terminal.get('binary_sha256')):
        raise ValueError('original gate binary identity differs')
    return terminal, manifest


def restore(directory, manifest, destination):
    parts = manifest.get('parts', [])
    if (not 1 <= len(parts) <= 1024 or not 0 < manifest.get('binary_bytes', 0) <= 2 * 1024 ** 3
            or any(row.get('path') != f'binary.gz.part-{index:03}.bin'
                   or not 0 < row.get('bytes', 0) <= 4 * 1024 ** 2
                   or re.fullmatch('[0-9a-f]{64}', row.get('sha256', '')) is None
                   for index, row in enumerate(parts))):
        raise ValueError('retained binary manifest bounds or paths differ')
    verify_binary_archive(directory, manifest)
    decoder = zlib.decompressobj(31)
    actual = hashlib.sha256()
    count = 0
    with destination.open('xb') as output:
        for row in parts:
            decoded = decoder.decompress((directory / row['path']).read_bytes())
            count += len(decoded)
            if count > manifest['binary_bytes']:
                raise ValueError('retained binary expanded beyond its declared length')
            output.write(decoded)
            actual.update(decoded)
        final = decoder.flush()
        count += len(final)
        output.write(final)
        actual.update(final)
        output.flush()
        os.fsync(output.fileno())
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or count != manifest['binary_bytes'] or actual.hexdigest() != manifest['binary_sha256']):
        raise ValueError('restored binary identity differs')
    destination.chmod(0o700)
    return manifest['binary_sha256']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--baseline-terminal', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('execution output must be outside the exact source tree')
    output.mkdir(parents=True, exist_ok=False)
    terminal = {'schema': 'history-reorg-continuation-native-terminal-v1', 'passed': False,
                'expected_source': args.expected_source, 'original_gate_required': True,
                'original_native_budget_seconds': 600,
                'new_native_budget_seconds': NATIVE_BUDGET_SECONDS,
                'expected_roster': ROSTER, 'production_qualified': False,
                'whole_history_p0_closed': False}
    source_ok = False
    try:
        before = verify('head', args.expected_source)
        source_ok = True
        write(output / 'source-before.json', before)
        original_directory = args.baseline_terminal.resolve().parent
        original, manifest = baseline(original_directory, args.expected_source, before)
        terminal.update(original_terminal_sha256=sha(original_directory / 'terminal.json'),
                        original_native=original['native'])
        executable = output / 'actual-binary'
        digest = restore(original_directory / 'actual-binary', manifest, executable)
        terminal.update(binary_sha256=digest, binary_bytes=manifest['binary_bytes'],
                        binary_same_as_original_gate=True, original_binary_archive=manifest)
        env = os.environ.copy()
        env.update(RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
        env[SOURCE_ENV] = args.expected_source
        listing = bounded([str(executable), '--list'], output / 'inventory', 30, env)
        if not listing['passed']:
            raise RuntimeError('actual binary test inventory failed')
        terminal['roster'] = roster((output / 'inventory/native.log').read_text())
        env['TRNM_HISTORY_V6_ARTIFACT_DIR'] = str(output / 'native/artifacts')
        native = bounded([str(executable), PREFIX, '--test-threads=1', '--show-output'],
                         output / 'native', NATIVE_BUDGET_SECONDS, env)
        native['exact_seven_pass_zero_ignored'] = suite_passed((output / 'native/native.log').read_text())
        terminal.update(native=native, binary_stable=sha(executable) == digest)
        terminal['passed'] = (native['passed'] and native['exact_seven_pass_zero_ignored']
                              and terminal['binary_stable'])
    except BaseException as error:
        terminal.update(passed=False, error=f'{type(error).__name__}: {error}')
    finally:
        if source_ok:
            try:
                after = verify('head', args.expected_source)
                write(output / 'source-after.json', after)
                terminal['source_stable'] = before == after
                terminal['passed'] = terminal['passed'] and before == after
            except BaseException as error:
                terminal.update(passed=False, source_after_error=f'{type(error).__name__}: {error}')
        write(output / 'terminal.json', terminal)
        print(json.dumps(terminal, sort_keys=True))
    return 0 if terminal['passed'] else 1


if __name__ == '__main__':
    def cancelled(signum, _frame):
        raise InterruptedError(f'workflow signalled {signum}')
    signal.signal(signal.SIGTERM, cancelled)
    raise SystemExit(main())

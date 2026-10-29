#!/usr/bin/env python3
"""Require the unchanged original gate, then run a separate lifecycle native lane."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import signal

from run_history_effect_v6_native import bounded, sha, write
from run_history_reorg_continuation_native_v1 import baseline, restore
from verify_ci_source import verify

ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'store::history_effect_v6::lifecycle_native_tests_v1::'
ROSTER = sorted(PREFIX + name for name in [
    'actual_committed_initialization_death_finishes_marker_then_runs_work_and_close',
    'actual_init_intent_death_preserves_absent_frontier_and_runs_ordinary_startup',
    'actual_lifecycle_record_publication_all_five_cuts_repair_without_native_reset',
    'actual_pending_close_death_keeps_existing_effects_then_runs_fresh_work',
    'actual_pending_startup_before_native_uses_birth_proof_and_refuses_changed_namespace',
    'actual_ready_native_pending_startup_is_reconciled_without_fabricating_success',
    'actual_uncommitted_initialization_death_keeps_database_inode_and_replays_startup',
    'actual_wrong_frontier_close_refusal_and_pending_death_keep_the_actual_frontier',
    'exhausted_pending_startup_requires_explicit_budget_renewal_and_keeps_old_debt',
    'repeated_known_initialization_cancellation_uses_fresh_closures_without_refunds',
    'repeated_pre_native_known_cancellation_reacquires_original_birth_then_runs_ordinary_work',
    'wrong_domain_nonce_snapshot_cpu_and_namespace_cannot_close_original_startup_debt',
])
SOURCE_ENV = 'TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT'
NATIVE_BUDGET_SECONDS = 900


def roster(text):
    found = sorted(line.removesuffix(': test') for line in text.splitlines()
                   if line.startswith(PREFIX) and line.endswith(': test'))
    if found != ROSTER:
        raise ValueError('exact lifecycle roster differs; missing, duplicate or substituted test')
    return found


def suite_passed(text):
    summaries = re.findall(r'^test result: .+$', text, re.M)
    executed = sorted(re.findall(r'^test (' + re.escape(PREFIX) + r'\S+) \.\.\. ', text, re.M))
    statuses = re.findall(r'^test ' + re.escape(PREFIX) + r'\S+ \.\.\. (\S+)$', text, re.M)
    return (text.splitlines().count('running 12 tests') == 1 and executed == ROSTER
            and statuses == ['ok'] * 12 and len(summaries) == 1
            and re.fullmatch(r'test result: ok\. 12 passed; 0 failed; 0 ignored; '
                             r'0 measured; \d+ filtered out; finished in .+s', summaries[0]) is not None)


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
    terminal = {'schema': 'history-lifecycle-native-terminal-v1', 'passed': False,
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
        native['exact_twelve_pass_zero_ignored'] = suite_passed((output / 'native/native.log').read_text())
        terminal.update(native=native, binary_stable=sha(executable) == digest)
        terminal['passed'] = (native['passed'] and native['exact_twelve_pass_zero_ignored']
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

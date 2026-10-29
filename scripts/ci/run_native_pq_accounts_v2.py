#!/usr/bin/env python3
"""Bounded exact-source native PQ research lane; no production qualification."""
from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path
import re
import time

from ci_observation import ROOT, checked, digest, finish, pin_source

NATIVE_CASES = {
    'actual_pq_pool_m06_pon_sql_cold_open_and_heavier_fork_requeue',
    'dual_key_rotation_preserves_actual_task_permissions_and_reorg_reauthorizes_original_pool',
    'expiry_equal_header_time_mtp_preview_future_skew_and_overflow_are_explicit',
    'explicit_namespace_old_codec_context_and_sql_schema_cannot_fall_back',
    'full_4263_byte_rows_and_packet_have_actual_122_transfer_limit',
    'interrupted_heavier_reorg_preserves_original_atomic_state_and_recovers_cold',
    'prior_pq_commitment_actual_legacy_pon_checkpoint_claim_cold_reorg_and_permission_conserve',
    'randomized_resign_duplicate_requires_real_signature_and_keeps_removal_history',
    'unregistered_pure_pon_miner_matures_actual_rewards_then_registers_without_whitelist',
}
PQ1_NATIVE_CASES = {
    'actual_pq_pool_m06_pon_sql_cold_open_and_heavier_fork_requeue',
    'expiry_equal_header_time_mtp_preview_future_skew_and_overflow_are_explicit',
    'explicit_namespace_old_codec_context_and_sql_schema_cannot_fall_back',
    'full_6129_byte_rows_and_packet_have_actual_85_transfer_limit',
    'interrupted_heavier_reorg_preserves_original_atomic_state_and_recovers_cold',
    'randomized_resign_duplicate_requires_real_signature_and_keeps_removal_history',
}
M00_CASES = {
    'pq_native_accounts_v2::tests::closed_roles_lengths_reserved_bytes_and_old_namespaces_refuse',
    'pq_native_accounts_v2::tests::exact_fresh_frame_sizes_include_every_key_and_both_proofs',
    'pq_native_accounts_v2::tests::joint_core_binds_context_generation_every_descriptor_and_full_new_key',
    'pq_native_accounts_v2::tests::new_roles_require_exact_branch_generation_and_anchored_source_identity',
}
M06_CASES = {
    'pon_executor::pq_accounts_v2::tests::anchored_migration_conserves_all_accounts_tasks_rewards_and_claims_once',
    'pon_executor::pq_accounts_v2::tests::dual_rotation_keeps_stable_task_permissions_and_actual_key_reads',
    'pon_executor::pq_accounts_v2::tests::migration_refuses_omissions_ambiguous_ids_untranslated_liabilities_and_unbound_roots',
    'pon_executor::pq_accounts_v2::tests::real_pq_positive_funding_registration_state_resolved_transfer_and_zero_credit',
}
AUTHORITY_CAPACITY_CASES = {
    'complete_dual_proof_rotation_bytes_allow_56_and_reject_57_without_mutation',
    'complete_anchored_claim_bytes_allow_55_and_reject_56_without_reminting',
}


def test_result(text: str, required: set[str], *, exact: bool = False) -> dict:
    summaries = re.findall(
        r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
        r'(\d+) measured; (\d+) filtered out;', text, re.MULTILINE)
    if len(summaries) != 1:
        raise ValueError('one actual Rust test result is required')
    status, *counts = summaries[0]
    passed, failed, ignored, measured, filtered = map(int, counts)
    rows = re.findall(r'^test ([^\n]+?) \.\.\. (ok|FAILED|ignored)(?:,.*)?$', text, re.MULTILINE)
    if len({name for name, _ in rows}) != len(rows):
        raise ValueError('duplicate test result name')
    outcomes = dict(rows)
    if status != 'ok' or failed or measured or filtered or passed == 0:
        raise ValueError('failed, filtered, measured or empty native test set')
    if sum(value == 'ok' for value in outcomes.values()) != passed or sum(value == 'ignored' for value in outcomes.values()) != ignored:
        raise ValueError('test names do not match actual summary counts')
    if any(outcomes.get(name) != 'ok' for name in required):
        raise ValueError('required native test did not execute successfully')
    if exact and (set(outcomes) != required or ignored or passed != len(required)):
        raise ValueError('exact native case set differs')
    return {'passed': passed, 'failed': failed, 'ignored': ignored, 'measured': measured,
            'filtered_out': filtered, 'required_executed': sorted(required),
            'test_outcomes': outcomes}


PHASE_SCOPE = 'actual complete call on shared host; not isolated CPU, worst-case cost or TPS'
PHASE_RESULTS = {
    'native_make_m06_and_complete_pon_search': 'ok',
    'independent_complete_w1_reference': 'ok',
    'native_admit_w1_m06_sql': 'ok',
    'm01_m06_signature_with_actual_state_key_reads': 'ok',
    'actual_state_grammar_and_current_authority': 'ok',
    'canonical_signature_for_wrong_message': 'error',
    'capacity_actual_pool_bundle': 'ok',
    'actual_pool_crypto_state_m06_sql': 'ok',
    'actual_rotation_authority_state_read': 'ok',
    'actual_pool_reauthorization_at_branch': 'ok',
}


def phase_result(text: str) -> dict:
    # This reads only the successful actual test command's captured output. The
    # synthetic parser controls are expressly not execution or timing evidence.
    rows = []
    for line in text.splitlines():
        if '"schema":"native-pq2-phase-observation-v1"' not in line:
            continue
        row = json.loads(line)
        phase = row.get('phase')
        if (set(row) != {'schema', 'phase', 'details', 'result', 'wall_nanoseconds', 'scope'}
                or phase not in PHASE_RESULTS or row['result'] != PHASE_RESULTS[phase]
                or type(row['wall_nanoseconds']) is not int or row['wall_nanoseconds'] < 0
                or type(row['details']) is not dict or row['scope'] != PHASE_SCOPE):
            raise ValueError('invalid actual phase observation')
        rows.append(row)
    if {row['phase'] for row in rows} != set(PHASE_RESULTS):
        raise ValueError('required actual phase observation is missing')
    groups = [row['details'] for row in rows if row['phase'] == 'capacity_actual_pool_bundle']
    if (len(groups) != 8 or any(type(row.get('transactions')) is not int
            or not 1 <= row['transactions'] <= 16
            or row.get('raw_bytes') != 4263 * row['transactions'] for row in groups)
            or sum(row['transactions'] for row in groups) != 122):
        raise ValueError('actual full-frame capacity cohort differs')
    return {'scope': PHASE_SCOPE, 'observations': rows,
            'cpu_measured': False, 'energy_measured': False,
            'worst_case_bound': False, 'network_throughput_measured': False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('observations must be outside the source checkout')
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'native-pq-accounts-v2-research-ci-v1', 'result': 'FAIL',
              'source_expected': args.expected_head, 'observations': [], 'tests': {},
              'scope': 'actual research gates only; original required CI remains required',
              'production_activation': False, 'whole_chain_post_quantum': False,
              'sqlite_physical_io_qualified': False, 'p1_complete': False,
              'source_chain_retirement_proved': False, 'prior_pq_registry_is_external_assumption': True,
              'total_command_budget_seconds': 2400}
    env = os.environ.copy()
    env.update(CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', CARGO_PROFILE_TEST_DEBUG='0',
               CARGO_PROFILE_DEV_DEBUG='0', RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1',
               CARGO_TERM_COLOR='never')
    report['selected_environment'] = {k: env.get(k) for k in (
        'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS',
        'CARGO_PROFILE_TEST_DEBUG', 'CARGO_PROFILE_DEV_DEBUG', 'RUST_TEST_THREADS')}
    deadline = time.monotonic() + 2400

    def command(label: str, argv: list[str], ceiling: int) -> Path:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError('native PQ research command budget exhausted')
        log = output / (label + '.log')
        checked(argv, log, report['observations'], timeout=min(ceiling, remaining),
                env=env, expected_source=args.expected_head)
        if time.monotonic() > deadline:
            raise TimeoutError('native PQ research command budget exhausted after command/source checks')
        return log

    try:
        if pin_source() != args.expected_head:
            raise ValueError('event head differs from exact checked source')
        compiler = command('rustc', ['rustc', '+1.95.0', '-vV'], 60)
        if '\nrelease: 1.95.0\n' not in '\n' + compiler.read_text():
            raise ValueError('unexpected native compiler')
        command('cargo', ['cargo', '+1.95.0', '-Vv'], 60)
        command('preflight', ['bash', 'scripts/project-preflight.sh', '--audit'], 120)
        command('source-negatives', ['python3', 'scripts/ci/test_ci_source_integrity.py'], 120)
        command('inventory', ['python3', 'scripts/refresh_distributed_source_inventory.py', '--check'], 120)
        manifest = ['--manifest-path', 'trillionnium/Cargo.toml']
        cargo = ['cargo', '+1.95.0']
        command('cargo-graph', cargo + ['metadata', '--locked', '--format-version', '1'] + manifest, 300)
        command('fmt', cargo + ['fmt'] + manifest + ['--all', '--', '--check'], 180)
        for name, package, target, required in (
            ('m00', 'trnm-protocol', ['--lib'], M00_CASES),
            ('m06', 'trnm-mvcc-fee', ['--lib'], M06_CASES),
            ('authority-capacity', 'trnm-mvcc-fee', ['--test', 'pq2_authority_capacity'], AUTHORITY_CAPACITY_CASES),
            ('native-pq', 'trnm-pon-node', ['--test', 'native_pq_v2'], NATIVE_CASES),
            ('retained-pq1', 'trnm-pon-node', ['--test', 'native_pq_v1'], PQ1_NATIVE_CASES),
        ):
            log = command(name, cargo + ['test', '--locked'] + manifest + ['-p', package] + target
                          + ['--', '--show-output', '--test-threads=1'], 1500)
            report['tests'][name] = test_result(log.read_text(), required,
                                               exact=name in {'authority-capacity', 'native-pq', 'retained-pq1'})
            if name == 'native-pq':
                phases = phase_result(log.read_text())
                (output / 'native-pq2-phases.json').write_text(json.dumps(phases, indent=2, sort_keys=True) + '\n')
                report['phase_observation_count'] = len(phases['observations'])
        target = Path(env['CARGO_TARGET_DIR']).resolve()
        binaries = [p for p in (target / 'debug/deps').glob('native_pq_v2-*')
                    if p.is_file() and not p.is_symlink() and not p.suffix and os.access(p, os.X_OK)]
        if len(binaries) != 1 or not 0 < binaries[0].stat().st_size <= 64 * 1024 * 1024:
            raise ValueError('one bounded actual native PQ test binary is required')
        binary = binaries[0]
        raw = binary.read_bytes()
        retained = output / 'native-pq-test.bin.gz'
        retained.write_bytes(gzip.compress(raw, compresslevel=6, mtime=0))
        report['native_binary'] = {'cargo_path': str(binary), 'bytes': len(raw),
                                   'sha256': digest(binary), 'retained_gzip': retained.name,
                                   'gzip_sha256': digest(retained), 'capture': 'post-command artifact, not an independent execution receipt',
                                   'keys': 'deliberately public fixture seeds only; no deployed keys'}
        command('clippy', cargo + ['clippy', '--locked'] + manifest
                + ['-p', 'trnm-protocol', '-p', 'trnm-mvcc-fee', '-p', 'trnm-pon-node',
                   '--all-targets', '--all-features', '--', '-D', 'warnings'], 900)
        report['result'] = 'PASS'
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        finish(output, report, ['rust-toolchain.toml', 'trillionnium/Cargo.lock',
               'scripts/ci/run_native_pq_accounts_v2.py',
               'trillionnium/crates/trnm-mvcc-fee/tests/pq2_authority_capacity.rs',
               'trillionnium/crates/trnm-pon-node/tests/native_pq_v2.rs',
               'trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs',
               'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs',
               'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs',
               'trillionnium/crates/trnm-pon-node/src/store/pq_accounts_v2.rs'])
    raise SystemExit(0 if report['result'] == 'PASS' else 1)


if __name__ == '__main__':
    main()

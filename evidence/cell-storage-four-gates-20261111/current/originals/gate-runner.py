#!/usr/bin/env python3
"""Retain exact-source Cell continuation commands and their actual outcomes.

This observer does not grant deployment, payment, independent-domain or WAN
qualification. The before lane deliberately retains failing native controls.
All source checks use the repository's original complete-byte verifier.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


# Preserve the original storage-convergence workflow's exact default-feature
# controls alongside the full suites. Each execution is read by its original
# named-libtest checker, so an empty filtered Cargo success is insufficient.
REQUIRED_DA_CONTROLS = (
    'cell::host_handoff::tests::research_fds::research_fd_sender_transfers_actual_complete_sealed_pair_with_original_deadline',
    'cell::host_handoff::tests::research_fds::research_fd_sender_refuses_changed_pins_budget_task_parent_or_expiry_before_any_byte',
    'cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs',
    'cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_refuses_129_complete_chunks_before_staging',
    'cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_keeps_original_two_mib_wire_and_file_ceiling',
)
REQUIRED_NODE_CONTROLS = (
    'store::storage_service::tests::version::native_version_reorg_keeps_custody_but_cannot_grant_new_funding_or_foreign_retirement',
    'store::storage_service::tests::version::native_version_scheduler_pending_metadata_accepts_only_new_funded_copy_then_reopens_done',
    'store::storage_service::tests::version::native_version_pending_monetary_effect_cannot_retry_copy_with_a_new_source',
    'store::storage_service::tests::version::native_version_scope_alias_and_late_funding_errors_precede_every_reservation',
    'store::storage_service::tests::version::native_version_outer_history_cannot_invent_missing_member_intents',
    'store::storage_service::tests::shard::native_shard_real_funding_target_readback_and_repair_keep_original_debits',
    'store::storage_service::tests::shard::native_shard_pending_initial_effect_cannot_dispatch_even_with_source_present',
    'store::storage_service::tests::shard::native_shard_unknown_repair_never_reissues_and_foreign_owner_cannot_retire',
    'store::storage_service::tests::version::shard_plan::native_complete_version_to_complete_local_shard_plan_reopens_without_sources_or_new_debits',
    'store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_automatic_recovery_uses_four_targets_after_all_sources_are_deleted',
    'store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_refuses_missing_quorum_without_spending_new_repairs_or_refunding_reads',
    'store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_pending_repair_cannot_redispatch_and_needs_independent_new_funding',
    'store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_preflight_cpu_and_metadata_fail_closed_without_hidden_copies',
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(part)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--rust-bin', required=True, type=Path)
    parser.add_argument('--cargo-home', required=True, type=Path)
    parser.add_argument('--provider', required=True, type=Path)
    parser.add_argument('--provider-sha256', required=True)
    parser.add_argument('--lane', choices=['before', 'candidate', 'observers'], required=True)
    args = parser.parse_args()
    root = args.repo or Path(__file__).resolve().parents[2]
    if not root.is_absolute():
        raise ValueError('absolute source root required')
    if len(args.source) != 40 or any(c not in '0123456789abcdef' for c in args.source):
        raise ValueError('exact source SHA required')
    for path in (args.output, args.target, args.rust_bin, args.cargo_home, args.provider):
        if not path.is_absolute():
            raise ValueError('absolute execution paths required')
    if args.output.exists():
        raise ValueError('new observation directory required; preserve previous results')
    if args.output == root or root in args.output.parents or args.target == root or root in args.target.parents:
        raise ValueError('execution output and target must be outside source')
    args.output.mkdir(parents=True)
    lock = Path(str(args.target) + '.owner.lock').open('a+b')
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    target_existed = args.target.exists()
    args.target.mkdir(parents=True, exist_ok=True)
    temporary = args.output / 'tmp'
    temporary.mkdir()
    provider_exe = args.provider / 'bin/openssl'
    if digest(provider_exe) != args.provider_sha256:
        raise ValueError('original provider executable pin mismatch')
    environment = os.environ.copy()
    environment.update({
        'PATH': str(args.rust_bin) + os.pathsep + environment.get('PATH', ''),
        'CARGO_HOME': str(args.cargo_home), 'CARGO_TARGET_DIR': str(args.target),
        'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never',
        'RUSTC': str(args.rust_bin / 'rustc'), 'RUSTDOC': str(args.rust_bin / 'rustdoc'),
        'LD_LIBRARY_PATH': str(args.rust_bin.parent / 'lib'),
        'RUST_TEST_THREADS': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(temporary),
        'OPENSSL_DIR': str(args.provider), 'OPENSSL_STATIC': '1', 'OPENSSL_CONF': '/dev/null',
        'OPENSSL_MODULES': str(args.provider / 'lib/ossl-modules'),
        'TRNM_PQ_OPENSSL': str(provider_exe), 'TRNM_PQ_OPENSSL_SHA256': args.provider_sha256,
        'TRNM_PQ_OPENSSL_VERSION': '3.5.9', 'GIT_PAGER': 'cat',
    })
    retained_environment = {key: environment[key] for key in (
        'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL',
        'RUSTC', 'RUSTDOC', 'LD_LIBRARY_PATH', 'RUST_TEST_THREADS', 'TMPDIR',
        'OPENSSL_DIR', 'OPENSSL_STATIC', 'OPENSSL_CONF', 'OPENSSL_MODULES',
        'TRNM_PQ_OPENSSL', 'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION')}
    report = {'schema': 'cell-storage-four-gates-execution-v1', 'source': args.source,
              'root': str(root), 'lane': args.lane, 'target_existed': target_existed,
              'runner_sha256': digest(Path(__file__)), 'environment': retained_environment,
              'commands': [], 'completed': False, 'status': 'running', 'production_qualified': False,
              'independent_domains_qualified': False, 'wan_qualified': False}
    summary = args.output / 'summary.json'

    def save() -> None:
        pending = args.output / 'summary.pending.json'
        pending.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        os.replace(pending, summary)

    def abort(stage: str) -> int:
        report.update(completed=True, status='failed', aborted_after=stage,
                      all_commands_passed=False, source_unchanged=False,
                      provider_pin_unchanged=digest(provider_exe) == args.provider_sha256)
        save()
        return 1

    def run(name: str, argv: list[str], timeout: int = 1800, *, merge_stderr: bool = False) -> int:
        stdout, stderr = args.output / (name + '.stdout'), args.output / (name + '.stderr')
        item = {'name': name, 'argv': argv, 'cwd': str(root), 'timeout_seconds': timeout,
                'started_unix_ns': time.time_ns(), 'status': 'running'}
        if merge_stderr:
            item['stderr_merged_into_stdout'] = True
        report['commands'].append(item)
        save()
        print(json.dumps({'started': name, 'source': args.source}), flush=True)
        begin = time.monotonic_ns()
        timed_out = False
        with stdout.open('xb') as out, stderr.open('xb') as err:
            process = subprocess.Popen(argv, cwd=root, env=environment, stdout=out,
                                       stderr=subprocess.STDOUT if merge_stderr else err,
                                       start_new_session=True)
            item['pid'] = process.pid
            save()
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait()
        item.update(status='completed', exit_code=code, timed_out=timed_out,
                    elapsed_ns=time.monotonic_ns() - begin, ended_unix_ns=time.time_ns(),
                    stdout_bytes=stdout.stat().st_size, stdout_sha256=digest(stdout),
                    stderr_bytes=stderr.stat().st_size, stderr_sha256=digest(stderr))
        if '--exact' in argv:
            selected = argv[argv.index('--') - 1]
            observed = stdout.read_text(errors='replace')
            item['exact_native_test_observed'] = (
                'running 1 test\n' in observed and
                re.search(r'^test ' + re.escape(selected) + r' \.\.\. (ok|FAILED)$',
                          observed, re.MULTILINE) is not None)
        save()
        print(json.dumps({'completed': name, 'exit_code': code, 'timed_out': timed_out}), flush=True)
        if not item.get('exact_native_test_observed', True):
            return 1
        return code if not timed_out else 124

    python = sys.executable
    cargo = str(args.rust_bin / 'cargo')
    manifest = 'trillionnium/Cargo.toml'
    source_command = [python, '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                      '--expected-head', args.source]
    save()
    if run('preflight', ['bash', 'scripts/project-preflight.sh', '--audit'], 60) != 0:
        return abort('preflight')
    if run('source-before', source_command, 300) != 0:
        return abort('source-before')
    run('rustc-version', [str(args.rust_bin / 'rustc'), '-Vv'], 30)
    run('cargo-version', [cargo, '-V'], 30)
    tests = [cargo, 'test', '--release', '--locked', '--offline', '--jobs', '2',
             '--manifest-path', manifest]

    def run_required_native(name: str, package: str, selector: str) -> None:
        run(name, tests + ['-p', package, '--lib', selector,
                          '--', '--exact', '--test-threads=1'])
        run(name + '-readback', [python, '-B', 'scripts/ci/check_required_native_test.py',
                                str(args.output / (name + '.stdout')), '--test', selector], 600)

    if args.lane == 'before':
        prefix = 'cell::discovery::pq::auth::tests::time_fairness::'
        for name in (
            'authenticated_v3_three_withholding_sources_leave_time_for_honest_fourth_cold_fetch',
            'authenticated_v3_all_withholding_sources_refuse_with_original_deadline_and_counters',
            'authenticated_v3_time_sharing_never_refunds_exhausted_connection_budget',
        ):
            run(name, tests + ['-p', 'trnm-data-availability', '--lib', prefix + name,
                              '--', '--exact', '--test-threads=1', '--nocapture'])
    elif args.lane == 'candidate':
        for name, command in (
            ('locked-graph', [cargo, 'metadata', '--locked', '--offline', '--manifest-path', manifest, '--format-version', '1']),
            ('locked-all-feature-graph', [cargo, 'metadata', '--locked', '--offline', '--manifest-path', manifest, '--all-features', '--format-version', '1']),
            ('format', [cargo, 'fmt', '--manifest-path', manifest, '--all', '--', '--check']),
            ('inventory', [python, '-B', 'scripts/refresh_distributed_source_inventory.py', '--check']),
        ):
            run(name, command, 300)
        for name in ('test_cell_discovery_v3_ci', 'test_cell_storage_convergence_ci',
                     'test_ci_source_integrity', 'check_pq_research_integration',
                     'test_pq_research_integration', 'check_repository'):
            run(name, [python, '-B', 'scripts/ci/' + name + '.py'], 600)
        run('next-architecture-python', [python, '-B', '-m', 'unittest', 'discover',
                                        '-s', 'formal/next-architecture-security',
                                        '-p', 'test_*.py', '-v'], 600)
        run('counterexample-fixture', [python, '-B',
                                      'formal/next-architecture-security/counterexamples.py',
                                      '--check-fixture'], 600)
        for name in ('cell_complete_version_vector', 'cell_discovery_epoch_v3_vector',
                     'cell_version_content_vector', 'cell_version_retention_v3_vector',
                     'cell_storage_descriptor_reference'):
            run(name, [python, '-B', 'scripts/' + name + '.py', '--check'], 600)
        # The original strict reader must see both streams, including any
        # unexpected stdout, in the actual process order without reconstruction.
        run('sealed-research-python-controls', [python, '-B', '-m', 'unittest', 'discover',
                                                '-s', 'scripts', '-p',
                                                'test_llm_cell_sealed_worker_v1.py', '-v'],
            600, merge_stderr=True)
        run('sealed-research-python-readback', [python, '-B',
                                               'scripts/ci/test_cell_storage_convergence_ci.py',
                                               '--check-sealed-controls',
                                               str(args.output / 'sealed-research-python-controls.stdout')],
            600)
        run('da-complete', tests + ['-p', 'trnm-data-availability', '--', '--test-threads=1'])
        for index, selector in enumerate(REQUIRED_DA_CONTROLS, 1):
            run_required_native(f'da-required-{index:02d}', 'trnm-data-availability', selector)
        for example in ('cell_sealed_research_next_use_v2', 'cell_sealed_research_paged_next_use_v1'):
            run(example + '-tests', tests + ['-p', 'trnm-data-availability', '--example', example,
                                           '--', '--test-threads=1'])
        run('node-storage-default', tests + ['-p', 'trnm-pon-node', '--lib',
                                            'store::storage_service::', '--', '--test-threads=1'])
        for index, selector in enumerate(REQUIRED_NODE_CONTROLS, 1):
            run_required_native(f'node-required-{index:02d}', 'trnm-pon-node', selector)
        run('node-storage', tests + ['-p', 'trnm-pon-node', '--features', 'pq-native-openssl',
                                    '--lib', 'storage_service', '--', '--test-threads=1'])
        for package in ('trnm-data-availability', 'trnm-pon-node'):
            run('clippy-default-' + package, [cargo, 'clippy', '--locked', '--offline', '--jobs', '2',
                                             '--manifest-path', manifest, '-p', package,
                                             '--all-targets', '--', '-D', 'warnings'])
        run('strict-clippy', [cargo, 'clippy', '--release', '--locked', '--offline', '--jobs', '2',
                             '--manifest-path', manifest, '--workspace', '--all-targets',
                             '--all-features', '--', '-D', 'warnings'])
    else:
        run('residency-observation', [cargo, 'run', '--release', '--locked', '--offline', '--jobs', '2',
                                     '--manifest-path', manifest, '-p', 'trnm-data-availability',
                                     '--example', 'cell_residency_observer'])
        run('paged-model-build', [cargo, 'build', '--release', '--locked', '--offline', '--jobs', '2',
                                 '--manifest-path', manifest, '-p', 'trnm-data-availability',
                                 '--example', 'cell_sealed_research_paged_next_use_v1'])
    source_code = run('source-after', source_command, 300)
    report['provider_pin_unchanged'] = digest(provider_exe) == args.provider_sha256
    report['source_unchanged'] = source_code == 0 and (
        args.output / 'source-before.stdout').read_bytes() == (args.output / 'source-after.stdout').read_bytes()
    report['completed'] = True
    report['all_commands_passed'] = all(item.get('exit_code') == 0 and not item.get('timed_out')
                                        and item.get('exact_native_test_observed', True)
                                        for item in report['commands'])
    passed = report['all_commands_passed'] and report['source_unchanged'] and report['provider_pin_unchanged']
    report['status'] = 'passed' if passed else 'failed'
    save()
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

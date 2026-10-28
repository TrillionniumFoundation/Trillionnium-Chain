#!/usr/bin/env python3
"""Bounded actual anchored NPQ5 lane after the unchanged same-source 205 gate."""
from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path
import time

from ci_observation import ROOT, checked, digest, finish, pin_source, source
from read_native_pq_tasks_v5_migration_v1 import PROFILE, baseline_result, native_result

INPUTS = [
    'scripts/ci/run_native_pq_tasks_v5_migration_v1.py',
    'scripts/ci/read_native_pq_tasks_v5_migration_v1.py',
    'scripts/ci/test_native_pq_tasks_v5_migration_v1.py',
    'scripts/ci/run_native_pq_tasks_v5.py',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/task_migration_v1.rs',
    'trillionnium/crates/trnm-pon-node/src/pq_tasks_v5.rs',
    'trillionnium/crates/trnm-pon-node/src/store/pq_tasks_v5.rs',
    'trillionnium/crates/trnm-pon-node/tests/native_pq_tasks_v5_migration_v1.rs',
    'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs',
    'trillionnium/crates/trnm-protocol/tests/support/native_pq_task_fixture_v5.rs',
    '.github/workflows/pon-native-pq-tasks-v5-research.yml',
    'rust-toolchain.toml', 'trillionnium/Cargo.lock',
]


def run_bounded(command: list[str], log: Path, report: dict, env: dict, head: str, deadline: float) -> None:
    remaining = int(deadline - time.monotonic())
    if remaining <= 0:
        raise TimeoutError('anchored NPQ5 budget exhausted before spawn')
    checked(command, log, report['observations'], timeout=min(900, remaining), env=env, expected_source=head)
    if time.monotonic() > deadline:
        raise TimeoutError('anchored NPQ5 budget exhausted after command/source checks')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('observations must be outside source')
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'native-pq5-anchored-migration-research-ci-v1', 'result': 'FAIL',
              'source_expected': args.expected_head, 'observations': [], 'profile': PROFILE,
              'total_command_budget_seconds': 900, 'p1_scoped_shared_profile_qualified': False,
              'production_activation': False, 'whole_chain_post_quantum': False,
              'prior_pq_registry_is_external_assumption': True, 'source_chain_retirement_proved': False,
              'old_store_upgraded': False, 'scope': 'new anchored NPQ5 network; original native permission and account paths share the admitted source checkpoint'}
    deadline = time.monotonic() + 900
    env = os.environ.copy()
    env.update(CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', CARGO_PROFILE_TEST_DEBUG='0',
               CARGO_PROFILE_DEV_DEBUG='0', RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1', CARGO_TERM_COLOR='never')
    try:
        if pin_source() != args.expected_head:
            raise ValueError('current source differs from expected head')
        current = source()
        baseline = args.baseline.resolve()
        if baseline.is_relative_to(ROOT) or baseline == output:
            raise ValueError('separate original observation directory required')
        report['retained_205'] = baseline_result(baseline, args.expected_head, current['tree'])
        log = output / 'native-migration.log'
        command = ['cargo', '+1.95.0', 'test', '--locked', '--manifest-path', 'trillionnium/Cargo.toml',
                   '-p', 'trnm-pon-node', '--test', 'native_pq_tasks_v5_migration_v1',
                   '--', '--show-output', '--test-threads=1']
        run_bounded(command, log, report, env, args.expected_head, deadline)
        observed = native_result(log.read_text())
        report['native'] = observed
        (output / 'native-observed.json').write_text(json.dumps(observed, indent=2) + '\n')
        target = Path(env['CARGO_TARGET_DIR']).resolve()
        binaries = [path for path in (target / 'debug/deps').glob('native_pq_tasks_v5_migration_v1-*')
                    if path.is_file() and not path.is_symlink() and not path.suffix and os.access(path, os.X_OK)]
        if len(binaries) != 1 or not 0 < binaries[0].stat().st_size <= 64 * 1024 * 1024:
            raise ValueError('one bounded actually executed migration binary required')
        binary = binaries[0]
        archive = output / 'native-migration-test.bin.gz'
        archive.write_bytes(gzip.compress(binary.read_bytes(), compresslevel=6, mtime=0))
        report['native_binary'] = {'cargo_path': str(binary), 'bytes': binary.stat().st_size,
                                   'sha256': digest(binary), 'retained_gzip': archive.name,
                                   'gzip_sha256': digest(archive), 'keys': 'public fixture seeds only'}
        if time.monotonic() > deadline:
            raise TimeoutError('anchored NPQ5 budget exhausted during readback')
        report['p1_scoped_shared_profile_qualified'] = True
        report['result'] = 'PASS'
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        finish(output, report, INPUTS)
    raise SystemExit(0 if report['result'] == 'PASS' else 1)


if __name__ == '__main__':
    main()

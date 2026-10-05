#!/usr/bin/env python3
"""Run actual libFuzzer mutations with ASan and preserve corpus, counters and crashes."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

from ci_observation import ROOT, checked, digest, finish, receipt_root, tool_root, tool_versions

TARGETS = {'canonical_wire': 2049, 'work_certificate': 49189, 'authenticated_state': 512}
STATE_SEEDS = 'tests/fuzz/seeds/authenticated_state'


def counters(text: str, seed_count: int) -> dict:
    units = re.search(r'stat::number_of_executed_units:\s*(\d+)', text)
    coverage = re.findall(r'cov:\s*(\d+)', text)
    instrumented = re.search(r'INFO: Loaded \d+ modules? .*counters', text)
    if not units or not coverage or not instrumented or int(units[1]) <= seed_count + 1:
        raise ValueError('missing instrumented mutation execution evidence')
    return {'executed_units': int(units[1]), 'maximum_reported_edge_coverage': max(map(int, coverage)),
            'seed_count': seed_count, 'coverage_guided_instrumentation_observed': True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--target', choices=list(TARGETS), action='append')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error('seconds must be between 1 and 300 per target')
    versions = tool_versions()
    output = receipt_root('fuzz')
    observations: list[dict] = []
    report = {'schema': 'trnm-coverage-guided-fuzz-v1', 'result': 'FAIL',
              'tools': versions, 'seconds_per_target': args.seconds, 'sanitizer': 'address',
              'observations': observations, 'targets': {}, 'acceptance_granted': False}
    environment = dict(os.environ)
    binary_dir = tool_root() / ('fuzz-' + versions['TRNM_CARGO_FUZZ_VERSION']) / 'bin'
    environment['PATH'] = str(binary_dir) + os.pathsep + environment.get('PATH', '')
    environment['RUSTUP_TOOLCHAIN'] = versions['TRNM_FUZZ_TOOLCHAIN']
    environment['CARGO_TARGET_DIR'] = str(Path(environment.get('CARGO_TARGET_DIR', '/tmp/trnm-fuzz-target')) / 'fuzz')
    report['sanitizer_environment'] = {key: environment[key] for key in
                                       ('ASAN_OPTIONS', 'LSAN_OPTIONS') if key in environment}
    manifest = 'tests/fuzz/Cargo.toml'
    lock = ROOT / 'tests/fuzz/Cargo.lock'
    original_lock = digest(lock)
    try:
        checked(['cargo', 'fuzz', '--version'], output / 'cargo-fuzz-version.log', observations, env=environment)
        version_text = (output / 'cargo-fuzz-version.log').read_text().strip()
        if version_text != 'cargo-fuzz ' + versions['TRNM_CARGO_FUZZ_VERSION']:
            raise ValueError('fuzz tool version mismatch')
        report['cargo_fuzz_sha256'] = digest(binary_dir / 'cargo-fuzz')
        checked(['rustc', '--version', '--verbose'], output / 'compiler.log', observations, env=environment)
        host = re.search(r'^host: (\S+)$', (output / 'compiler.log').read_text(), re.M)
        if host is None:
            raise ValueError('compiler host missing')
        checked(['cargo', 'fetch', '--locked', '--manifest-path', manifest],
                output / 'fetch.log', observations, env=environment)
        environment['CARGO_NET_OFFLINE'] = 'true'
        for target in args.target or TARGETS:
            corpus = output / 'corpus' / target
            artifacts = output / 'artifacts' / target
            corpus.mkdir(parents=True)
            artifacts.mkdir(parents=True)
            vectors = ROOT / 'formal/pon-nakamoto-v1/vectors'
            if target == 'canonical_wire':
                seeds = [vectors / 'header.bin', *sorted(vectors.glob('tx-*.bin'))]
            elif target == 'work_certificate':
                seeds = [vectors / 'work.bin']
            else:
                seeds = sorted(path for path in (ROOT / STATE_SEEDS).iterdir() if path.is_file())
                if not seeds or any(path.is_symlink() or path.stat().st_size > TARGETS[target]
                                    for path in seeds):
                    raise ValueError('missing or invalid authenticated-state corpus')
            for seed in seeds:
                shutil.copyfile(seed, corpus / seed.name)
            report['targets'][target] = {'seed_sha256': {p.name: digest(p) for p in seeds},
                                         'max_len': TARGETS[target]}
            log = output / (target + '.log')
            command = ['cargo', 'fuzz', 'run', '--fuzz-dir', 'tests/fuzz',
                       '--sanitizer', 'address', '--debug-assertions', target, str(corpus), '--',
                       f'-max_total_time={args.seconds}', '-timeout=10', '-rss_limit_mb=2048',
                       f'-max_len={TARGETS[target]}', '-seed=20261004', '-print_final_stats=1',
                       '-artifact_prefix=' + str(artifacts) + '/']
            checked(command, log, observations, timeout=1200, env=environment)
            report['targets'][target].update(counters(log.read_text(errors='replace'), len(seeds)))
            binary = Path(environment['CARGO_TARGET_DIR']) / host[1] / 'release' / target
            report['targets'][target]['binary_sha256'] = digest(binary)
        if digest(lock) != original_lock:
            raise ValueError('fuzz lockfile changed during compilation')
        report['result'] = 'PASS'
    except (OSError, ValueError, RuntimeError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        finish(output, report, ['tests/fuzz/Cargo.toml', 'tests/fuzz/Cargo.lock',
                              'scripts/ci/tool-versions.env', 'scripts/ci/run_fuzz_smoke.py',
                              'tests/fuzz/fuzz_targets/support/work_certificate.rs',
                              *[str(path.relative_to(ROOT)) for path in sorted((ROOT / STATE_SEEDS).glob('*'))
                                if path.is_file()],
                              *['tests/fuzz/fuzz_targets/' + name + '.rs' for name in TARGETS]])
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

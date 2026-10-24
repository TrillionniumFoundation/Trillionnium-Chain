#!/usr/bin/env python3
"""Build/run the actual finite same-host campaign; retain failures and OS usage.

This is an experiment owner, not the CI source owner or a work/state oracle.
It never changes protocol policy, builds a synthetic authority, or interprets a
nonzero campaign exit as acceptance. The report's scope flags stay false.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
TARGET = 'public_v3_multiprocess'


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sources() -> dict:
    # A conservative superset of Rust compilation inputs, including all local
    # crate libraries, manifests/lockfile and this exact integration target.
    # This does not replace the repository's full committed-source CI owner.
    paths = set((ROOT / 'trillionnium').rglob('Cargo.toml'))
    paths.add(ROOT / 'trillionnium/Cargo.lock')
    # Config registries are compiled through include_str! by the real owners.
    paths.update((ROOT / 'config').rglob('*.json'))
    for crate in (ROOT / 'trillionnium/crates').iterdir():
        if (crate / 'src').is_dir():
            paths.update((crate / 'src').rglob('*.rs'))
    tests = ROOT / 'trillionnium/crates/trnm-pon-node/tests'
    paths.add(tests / (TARGET + '.rs'))
    paths.update((tests / 'support').glob('multiprocess_*.rs'))
    paths.add(Path(__file__).resolve())
    rows = [{'path': str(path.relative_to(ROOT)), 'sha256': sha(path.read_bytes())}
            for path in sorted(paths) if path.is_file()]
    return {'files': rows, 'sha256': sha(json.dumps(rows, sort_keys=True).encode()),
            'scope': 'superset of local Rust library/manifests plus exact campaign target/support and driver; not complete repository CI source qualification'}


def save(path: Path, value: dict) -> None:
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def run(command: list[str], log: Path, env: dict, timeout: int) -> dict:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic_ns()
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=ROOT, env=env,
                                   stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        expired = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            # This owner created an isolated process session; its group contains
            # only this run and its descendants. Never signal a preexisting PID.
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'argv': command, 'exit_code': code, 'timeout': expired,
            'wall_ns': time.monotonic_ns() - start,
            'os_reaped_user_cpu_seconds': after.ru_utime - before.ru_utime,
            'os_reaped_system_cpu_seconds': after.ru_stime - before.ru_stime,
            'os_cumulative_max_reaped_rss_bytes': after.ru_maxrss * 1024,
            'log': str(log), 'log_sha256': sha(log.read_bytes()),
            'cpu_scope': 'actual Linux child rusage; includes child executable startup/exit and all grandchildren the native campaign reaped, not a per-actor allocation'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--cargo-lock', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_RELEASE_DEBUG='0',
               CARGO_TARGET_DIR=str(args.target_dir.resolve()))
    env['PATH'] = '/root/.cargo/bin:' + env.get('PATH', '')
    manifest = {'schema': 'native-public-multiprocess-execution-v1',
                'scope': 'finite controlled one-host experiment; no independent operators/WAN/physical hardness qualification',
                'source_before': sources(), 'steps': [],
                'host': {'uname': list(os.uname()), 'cpu_count': os.cpu_count(),
                         'cpu_max': Path('/sys/fs/cgroup/cpu.max').read_text().strip()},
                'production_candidate': False, 'release_ready': False}
    manifest['host']['scope'] = 'observed mounted host/cgroup context; namespace alignment and effective campaign quota are not certified'
    save(out / 'launch.json', manifest)
    step = run(['bash', 'scripts/project-preflight.sh'], out / 'preflight.log', env, 60)
    manifest['steps'].append(step)
    if step['exit_code'] == 0:
        step = run(['flock', str(args.cargo_lock.resolve()), 'cargo', 'test', '--locked',
                    '--release', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
                    '--test', TARGET, '--no-run', '--message-format=json'], out / 'build.log', env, 300)
        manifest['steps'].append(step)
        manifest['source_after_build'] = sources()
        if step['exit_code'] == 0 and manifest['source_before'] == manifest['source_after_build']:
            artifacts = []
            for line in (out / 'build.log').read_text().splitlines():
                if line.startswith('{'):
                    row = json.loads(line)
                    if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == TARGET and row.get('profile', {}).get('test') is True and row.get('executable'):
                        artifacts.append(Path(row['executable']))
            if len(artifacts) != 1:
                manifest['error'] = 'exact new test binary not uniquely reported by cargo'
            else:
                binary = artifacts[0]
                manifest['binary'] = {'path': str(binary), 'sha256': sha(binary.read_bytes())}
                regular = run([str(binary), '--nocapture', '--test-threads=1'], out / 'regular.log', env, 60)
                manifest['steps'].append(regular)
                if regular['exit_code'] == 0:
                    env['TRNM_MULTIPROCESS_REPORT_DIR'] = str(out / 'native')
                    campaign = run([str(binary), 'separate_process_work_and_signed_confirmation_campaign',
                                    '--exact', '--ignored', '--nocapture', '--test-threads=1'], out / 'campaign.log', env, 480)
                    manifest['steps'].append(campaign)
        elif step['exit_code'] == 0:
            manifest['error'] = 'source changed during build; no campaign execution credited'
    manifest['source_after'] = sources()
    manifest['sources_unchanged'] = manifest['source_before'] == manifest['source_after']
    report = out / 'native/report.json'
    if report.is_file():
        native = json.loads(report.read_bytes())
        manifest['native_report_sha256'] = sha(report.read_bytes())
        manifest['finite_experiment_criteria_met'] = native.get('finite_experiment_criteria_met') is True
    else:
        manifest['finite_experiment_criteria_met'] = False
    save(out / 'execution.json', manifest)
    print(json.dumps({'out': str(out), 'finite_experiment_criteria_met': manifest['finite_experiment_criteria_met'],
                      'sources_unchanged': manifest['sources_unchanged'], 'steps': [step['exit_code'] for step in manifest['steps']]}))
    return 0 if len(manifest['steps']) == 4 and all(step['exit_code'] == 0 for step in manifest['steps']) and manifest['sources_unchanged'] and manifest['finite_experiment_criteria_met'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

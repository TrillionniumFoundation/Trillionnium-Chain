#!/usr/bin/env python3
"""Fresh full-W1 ABBA comparison; records failures and never grants qualification."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cgroup_snapshot():
    """Read the current cgroup v2 controls; these are observations, not requests."""
    entries = Path('/proc/self/cgroup').read_text().splitlines()
    unified = next((line.split(':', 2)[2] for line in entries if line.startswith('0::')), None)
    if unified is None:
        return {'error': 'no cgroup v2 entry', 'proc_self_cgroup': entries}
    directory = Path('/sys/fs/cgroup') / unified.lstrip('/')
    result = {'path': str(directory)}
    for name in ('cpu.max', 'cpu.stat', 'memory.max', 'memory.current', 'memory.peak',
                 'memory.events', 'cpuset.cpus.effective'):
        try:
            result[name] = (directory / name).read_text().strip()
        except OSError as error:
            result[name] = {'error': str(error)}
    return result


def run_stage(args, dest, crate, env):
    dest.mkdir(parents=True, exist_ok=False)
    usage = dest / 'resource.txt'
    command = ['/usr/bin/time', '-v', '-o', str(usage), *map(str, args)]
    utc_start = datetime.now(timezone.utc).isoformat()
    start = time.monotonic_ns()
    with (dest / 'stdout.jsonl').open('wb') as stdout, (dest / 'stderr.txt').open('wb') as stderr:
        cp = subprocess.run(command, cwd=crate, env=env, stdout=stdout, stderr=stderr)
    seconds = (time.monotonic_ns() - start) / 1e9
    parsed = []
    for line in (dest / 'stdout.jsonl').read_text().splitlines():
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    rusage = usage.read_text() if usage.exists() else ''
    rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)', rusage)
    value = {'args': list(map(str, args)), 'utc_start': utc_start,
             'exit_code': cp.returncode, 'outer_wall_s': seconds,
             'peak_rss_kib': int(rss.group(1)) if rss else None,
             'report': parsed[-1] if parsed else None}
    (dest / 'stage.json').write_text(json.dumps(value, indent=2))
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--crate', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--variant', choices=('carry', 'packed'), required=True)
    parser.add_argument('--blocks', type=int, default=2)
    parser.add_argument('--threads', type=int, default=8)
    args = parser.parse_args()
    if args.blocks < 1 or args.threads < 1:
        parser.error('blocks and threads must be positive')
    crate, out = args.crate.resolve(), args.out.resolve()
    root = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=crate, text=True).strip())
    out.mkdir(parents=True, exist_ok=False)
    allowed = sorted(os.sched_getaffinity(0))
    cpus = allowed[:args.threads]
    if len(cpus) != args.threads:
        raise RuntimeError('not enough common allowed CPUs')
    os.sched_setaffinity(0, cpus)
    env = dict(os.environ, RAYON_NUM_THREADS=str(args.threads))
    fixture = crate / 'fixtures'
    binaries = {'A': crate / 'target/release/w1-full-public-stark-research',
                'B': crate / 'target/release/examples' / ('carry_backend' if args.variant == 'carry' else 'packed_carry_backend')}
    control = cgroup_snapshot()
    manifest = {
        'schema': 'w1-carry-fresh-full-proof-abba-v2', 'qualification': 'HOLD_NO_GO',
        'comparison': f'{args.variant} arithmetic B versus original STARK arithmetic A; not native W1',
        'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'source_diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff', '--binary'], cwd=root)).hexdigest(),
        'source_files': {str(p.relative_to(crate)): digest(p) for p in sorted(crate.rglob('*.rs')) if 'target' not in p.relative_to(crate).parts},
        'cargo_lock_sha256': digest(crate / 'Cargo.lock'), 'harness_sha256': digest(Path(__file__)),
        'platform': platform.platform(), 'cpu_affinity': cpus, 'rayon_threads': args.threads,
        'observed_cgroup_start': control, 'host_exclusive': False, 'proof_input_tasks': 1,
        'input_sha256': digest(fixture / 'retained.input.bin'),
        'prefix_sha256': digest(fixture / 'retained.prefix.bin'),
        'expected_header_sha256': digest(fixture / 'retained.expected-header.bin'),
        'expected_artifacts_sha256': digest(fixture / 'retained.artifacts.bin'),
        'binaries': {k: {'path': str(v), 'sha256': digest(v)} for k, v in binaries.items()},
        'planned_order': list('ABBA' * args.blocks), 'runs': [],
    }
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    for index, variant in enumerate(manifest['planned_order']):
        base = out / f'{index:02d}-{variant}'
        base.mkdir()
        binary = binaries[variant]
        public_dir, proof_dir = base / 'prepared', base / 'proof'
        header, artifacts = fixture / 'retained.expected-header.bin', fixture / 'retained.artifacts.bin'
        events = {}
        events['prepare'] = run_stage([binary, 'prepare', fixture / 'retained.input.bin', fixture / 'retained.prefix.bin', header, artifacts, public_dir], base / 'prepare_stage', crate, env)
        if events['prepare']['exit_code'] == 0:
            events['prove'] = run_stage([binary, 'prove', public_dir / 'statement.bin', header, artifacts, proof_dir], base / 'prove_stage', crate, env)
        if events.get('prove', {}).get('exit_code') == 0:
            events['verify'] = run_stage([binary, 'verify', public_dir / 'statement.bin', header, artifacts, proof_dir], base / 'verify_stage', crate, env)
        passed = len(events) == 3 and all(v['exit_code'] == 0 for v in events.values())
        row = {'index': index, 'variant': variant, 'full_fresh_proof_verified': passed, 'stages': events,
               'pipeline_outer_s': sum(s['outer_wall_s'] for s in events.values()),
               'observed_cgroup': cgroup_snapshot(),
               'transmitted_bytes': sum((proof_dir / p).stat().st_size for p in ('sha.proof.bin', 'arith.proof.bin')) + (public_dir / 'statement.bin').stat().st_size if passed else None}
        manifest['runs'].append(row)
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        print(json.dumps({'index': index, 'variant': variant, 'ok': passed,
                          'pipeline_outer_s': row['pipeline_outer_s'],
                          'verify_outer_s': events.get('verify', {}).get('outer_wall_s'),
                          'transmitted_bytes': row['transmitted_bytes']}), flush=True)
    manifest['all_planned_runs_finished'] = len(manifest['runs']) == len(manifest['planned_order'])
    manifest['observed_cgroup_end'] = cgroup_snapshot()
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    return 0 if all(r['full_fresh_proof_verified'] for r in manifest['runs']) else 1


if __name__ == '__main__':
    sys.exit(main())

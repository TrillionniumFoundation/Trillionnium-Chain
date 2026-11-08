#!/usr/bin/env python3
"""Fresh full-W1 proof/receive ABBA comparison; never a production certificate."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/work/chain-w1-carry-backend-20261108-f16ac')
CRATE = ROOT / 'formal/pon-nakamoto-v1/w1_public_stark_research'
OUT = ROOT.parent / 'chain-w1-carry-measurements-20261108-f16ac'
BINARIES = {
    'A': CRATE / 'target/release/w1-full-public-stark-research',
    'B': CRATE / 'target/release/examples/carry_backend',
}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run_stage(args, dest, env):
    dest.mkdir(parents=True, exist_ok=False)
    usage = dest / 'resource.txt'
    command = ['/usr/bin/time', '-v', '-o', str(usage), *map(str, args)]
    start = time.monotonic_ns()
    with (dest / 'stdout.jsonl').open('wb') as stdout, (dest / 'stderr.txt').open('wb') as stderr:
        cp = subprocess.run(command, cwd=CRATE, env=env, stdout=stdout, stderr=stderr)
    seconds = (time.monotonic_ns() - start) / 1e9
    parsed = []
    for line in (dest / 'stdout.jsonl').read_text().splitlines():
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    rusage = usage.read_text() if usage.exists() else ''
    rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)', rusage)
    value = {'args': list(map(str, args)), 'exit_code': cp.returncode, 'outer_wall_s': seconds,
             'peak_rss_kib': int(rss.group(1)) if rss else None,
             'report': parsed[-1] if parsed else None}
    (dest / 'stage.json').write_text(json.dumps(value, indent=2))
    return value


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    allowed = sorted(os.sched_getaffinity(0))
    cpus = allowed[:8]
    if len(cpus) != 8:
        raise RuntimeError('need eight common allowed CPUs')
    os.sched_setaffinity(0, cpus)
    env = dict(os.environ, RAYON_NUM_THREADS='8')
    fixture = CRATE / 'fixtures'
    manifest = {'schema': 'w1-carry-fresh-full-proof-abba-v1', 'qualification': 'HOLD_NO_GO',
                'comparison': 'candidate carry AIR B versus prior STARK AIR A; not native W1',
                'source_head': subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip(),
                'source_diff_sha256': hashlib.sha256(subprocess.check_output(['git','diff','--binary'], cwd=ROOT)).hexdigest(),
                'source_files': {str(p.relative_to(CRATE)):digest(p) for p in sorted(CRATE.rglob('*.rs')) if 'target' not in p.relative_to(CRATE).parts},
                'cargo_lock_sha256': digest(CRATE/'Cargo.lock'),
                'platform': platform.platform(), 'cpu_affinity': cpus, 'rayon_threads': 8,
                'cpu_quota_percent': 800, 'memory_max_bytes': 85899345920,
                'host_exclusive': False, 'proof_input_tasks': 1,
                'input_sha256': digest(fixture / 'retained.input.bin'),
                'prefix_sha256': digest(fixture / 'retained.prefix.bin'),
                'binaries': {k: {'path':str(v), 'sha256':digest(v)} for k,v in BINARIES.items()},
                'planned_order': list('ABBAABBA'), 'runs': []}
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    for index, variant in enumerate(manifest['planned_order']):
        base = OUT / f'{index:02d}-{variant}'
        base.mkdir()
        binary = BINARIES[variant]
        public_dir = base / 'prepared'
        proof_dir = base / 'proof'
        header, artifacts = fixture/'retained.expected-header.bin', fixture/'retained.artifacts.bin'
        events = {}
        events['prepare'] = run_stage([binary, 'prepare', fixture/'retained.input.bin', fixture/'retained.prefix.bin', header, artifacts, public_dir], base/'prepare_stage', env)
        if events['prepare']['exit_code'] == 0:
            events['prove'] = run_stage([binary, 'prove', public_dir/'statement.bin', header, artifacts, proof_dir], base/'prove_stage', env)
        if events.get('prove', {}).get('exit_code') == 0:
            events['verify'] = run_stage([binary, 'verify', public_dir/'statement.bin', header, artifacts, proof_dir], base/'verify_stage', env)
        passed = len(events)==3 and all(v['exit_code']==0 for v in events.values())
        row = {'index':index, 'variant':variant, 'full_fresh_proof_verified':passed, 'stages':events,
               'pipeline_outer_s':sum(s['outer_wall_s'] for s in events.values()),
               'transmitted_bytes':sum((proof_dir/p).stat().st_size for p in ('sha.proof.bin','arith.proof.bin')) + (public_dir/'statement.bin').stat().st_size if passed else None}
        manifest['runs'].append(row)
        (OUT/'manifest.json').write_text(json.dumps(manifest, indent=2))
        print(json.dumps({'index':index,'variant':variant,'ok':passed,'pipeline_outer_s':row['pipeline_outer_s'], 'verify_outer_s':events.get('verify',{}).get('outer_wall_s'),'transmitted_bytes':row['transmitted_bytes']}),flush=True)
    manifest['all_planned_runs_finished'] = len(manifest['runs']) == len(manifest['planned_order'])
    (OUT/'manifest.json').write_text(json.dumps(manifest, indent=2))
    return 0 if all(r['full_fresh_proof_verified'] for r in manifest['runs']) else 1

if __name__ == '__main__':
    sys.exit(main())

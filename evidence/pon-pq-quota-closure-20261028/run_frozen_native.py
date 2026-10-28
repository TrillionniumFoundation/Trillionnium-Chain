"""Resource-bounded native validation; explicitly not Cargo graph qualification.

Recompile every changed workspace crate using the real rustc 1.95.0 and
unchanged frozen third-party/native artifacts. All source and artifact bytes
are recorded; nothing in another task's build tree is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import tomllib

BASE = Path('/workspace/scratch/bb9b841c1d43')
ROOT = BASE / 'pq-quota-closure'
OLD = Path('/workspace/scratch/301262829a43/pon-work-impl/provider-native-target/debug')
TOOL = Path('/workspace/scratch/301262829a43/pon-build-inputs/unpacked/toolchain/bin')
OUT = BASE / 'pq-frozen-native'
OUT.mkdir(exist_ok=True)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source():
    return {str(p.relative_to(ROOT)): sha(p)
            for d in ('trillionnium', 'config')
            for p in sorted((ROOT / d).rglob('*'))
            if p.is_file()}


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def fingerprints():
    by_hash = {}
    for path in (OLD / '.fingerprint').glob('*/lib-*'):
        if path.suffix or not path.is_file():
            continue
        try:
            value = int.from_bytes(bytes.fromhex(path.read_text()), 'little')
            detail = json.loads(path.with_suffix('.json').read_text())
            crate = path.name.removeprefix('lib-')
            suffix = path.parent.name.rsplit('-', 1)[1]
            candidates = [OLD / 'deps' / f'lib{crate}-{suffix}.{ext}'
                          for ext in ('rlib', 'so')]
            found = [p for p in candidates if p.is_file()]
            if len(found) == 1:
                by_hash[value] = (crate, found[0], detail)
        except (ValueError, FileNotFoundError):
            continue
    return by_hash


FP = fingerprints()


def original(crate):
    candidates = [r for r in FP.values() if r[0] == crate]
    if len(candidates) != 1:
        raise ValueError(f'not one original workspace crate: {crate}, {len(candidates)}')
    return candidates[0]


def dependencies(crate):
    row = original(crate)
    deps = {}
    for _, depname, _, fp in row[2]['deps']:
        if depname == 'build_script_build':
            continue
        chosen = FP[fp]
        assert chosen[0] == depname
        deps[depname] = chosen[1]
    return deps


def run(label, argv, env, timeout=600):
    path = OUT / (label + '.log')
    if path.exists():
        raise ValueError(f'refuse overwriting an observation: {path}')
    started = time.monotonic()
    with path.open('wb') as log:
        process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        dump(OUT / 'current-process.json', {'pid_in_own_namespace': process.pid,
             'label': label, 'argv': argv})
        timed_out = False
        try:
            rc = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                rc = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                rc = process.wait()
    record = {'argv': argv, 'returncode': rc, 'timeout': timed_out,
              'wall_seconds': time.monotonic() - started, 'log_sha256': sha(path)}
    dump(OUT / (label + '.json'), record)
    print(json.dumps({'label': label, **record}), flush=True)
    if rc:
        print(path.read_text()[-9000:], flush=True)
        raise RuntimeError(f'{label} failed: {rc}')


def build(crate, attempt, test=None, opt=0):
    package = crate.replace('_', '-')
    manifest = ROOT / 'trillionnium/crates' / package / 'Cargo.toml'
    data = tomllib.loads(manifest.read_text())
    dep = dependencies(crate)
    if test:
        for name in data.get('dev-dependencies', {}):
            cname = name.replace('-', '_')
            if cname not in dep:
                dep[cname] = original(cname)[1]
        if crate == 'trnm_mvcc_fee':
            # The target-specific original Linux dev dependency.
            dep['getrandom'] = original('getrandom')[1]
        if test != 'lib':
            dep[crate] = OUT / f'lib{crate}.rlib'
    selected = {}
    for name, path in dep.items():
        current = OUT / f'lib{name}.rlib'
        selected[name] = current if name.startswith('trnm_') and current.is_file() else path
    env = os.environ.copy()
    env.update(CARGO_MANIFEST_DIR=str(manifest.parent), CARGO_PKG_NAME=package,
               CARGO_PKG_VERSION=data['package']['version'])
    src = manifest.parent / ('src/lib.rs' if not test or test == 'lib' else f'tests/{test}.rs')
    output = OUT / (f'lib{crate}.rlib' if not test else f'{test if test != "lib" else crate + "_unit"}-{attempt}')
    argv = [str(TOOL / 'rustc'), '--edition=2021', '--crate-name',
            crate if not test or test == 'lib' else test, str(src),
            '-o', str(output), '-C', 'debuginfo=0', '-C', f'opt-level={opt}',
            '-C', 'debug-assertions=yes', '-C', 'overflow-checks=yes',
            '-C', f'metadata=pq3_closure_{crate}_{attempt}',
            '-L', 'dependency=' + str(OUT), '-L', 'dependency=' + str(OLD / 'deps')]
    argv += ['--test'] if test else ['--crate-type', 'rlib']
    for feature in data.get('features', {}).get('default', []):
        argv += ['--cfg', f'feature="{feature}"']
    for name, path in sorted(selected.items()):
        argv += ['--extern', name + '=' + str(path)]
    for directory in sorted((OLD / 'build').glob('*/out')):
        if any(directory.glob('*.a')):
            argv += ['-L', 'native=' + str(directory)]
    label = f'{crate}-{test or "lib"}-{attempt}'
    dump(OUT / (label + '-inputs.json'), {'source': source(),
         'selected_externs': {k: {'path': str(v), 'sha256': sha(v)} for k, v in selected.items()},
         'profile': {'opt_level': opt, 'debug_assertions': True, 'overflow_checks': True},
         'scope': 'explicit source-native component build; not a Cargo build or physical I/O qualification'})
    run(label, argv, env)
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('step', choices=['m06', 'rebuild-m06', 'node', 'node-test', 'quota-test', 'pq2-native', 'pq1-native', 'pq2-capacity', 'm00-unit', 'm06-unit'])
    parser.add_argument('--attempt', default='01')
    args = parser.parse_args()
    before = source()
    artifacts = {str(p): sha(p) for p in sorted((OLD / 'deps').iterdir())
                 if p.suffix in ('.rlib', '.rmeta', '.so')}
    artifacts.update({str(p): sha(p) for p in sorted((OLD / 'build').glob('*/out/*.a'))})
    dump(OUT / (args.step + '-before-' + args.attempt + '.json'),
         {'source': before, 'artifacts': artifacts,
          'compiler': subprocess.check_output([str(TOOL / 'rustc'), '-vV'], text=True),
          'runner_sha256': sha(__file__)})
    try:
        if args.step == 'm06':
            for crate, opt in [('trnm_protocol', 3), ('trnm_crypto_primitives', 3), ('trnm_mvcc_fee', 1)]:
                build(crate, args.attempt, opt=opt)
            binary = build('trnm_mvcc_fee', args.attempt, 'pq3_quota_authority')
        elif args.step == 'node':
            build('trnm_pon_node', args.attempt, opt=3)
            binary = build('trnm_pon_node', args.attempt, 'native_pq_v3')
        elif args.step == 'node-test':
            binary = build('trnm_pon_node', args.attempt, 'native_pq_v3')
        elif args.step == 'rebuild-m06':
            build('trnm_mvcc_fee', args.attempt, opt=1)
            binary = build('trnm_mvcc_fee', args.attempt, 'pq3_quota_authority')
        elif args.step == 'quota-test':
            binary = build('trnm_mvcc_fee', args.attempt, 'pq3_quota_authority')
        elif args.step in ('pq2-native', 'pq1-native'):
            binary = build('trnm_pon_node', args.attempt, 'native_pq_v2' if args.step=='pq2-native' else 'native_pq_v1')
        elif args.step == 'pq2-capacity':
            binary = build('trnm_mvcc_fee', args.attempt, 'pq2_authority_capacity')
        else:
            crate = 'trnm_protocol' if args.step == 'm00-unit' else 'trnm_mvcc_fee'
            binary = build(crate, args.attempt, 'lib', 3 if crate == 'trnm_protocol' else 1)
        run(args.step + '-tests-' + args.attempt,
            [str(binary), '--test-threads=1', '--show-output'], os.environ.copy(), 600)
    finally:
        dump(OUT / (args.step + '-after-' + args.attempt + '.json'),
             {'source_before_after_equal': before == source(),
              'all_frozen_link_artifacts_before_after_equal': all(sha(p) == value for p, value in artifacts.items()),
              'source_files': len(before), 'frozen_link_artifacts': len(artifacts),
              'physical_io_qualified': False, 'full_cargo_graph_qualified': False})


if __name__ == '__main__':
    main()

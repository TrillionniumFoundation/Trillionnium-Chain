"""Record an actual gate on a committed source; never synthesize acceptance.

This is an observation harness, not a hermetic-build or public-service proof.
The original repository commands and independent hosted gates remain required.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path('/workspace/scratch/d991ec408034/sprint_cell_20261029')
OUT = Path('/workspace/scratch/d991ec408034/sprint_runtime_20261029')
TARGET = Path('/workspace/scratch/d991ec408034/sprint_build_20261029')
TOOLCHAIN = Path('/tmp/chain-pon-rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
CARGO_HOME = Path('/tmp/chain-pon-cargo')
CARGO = str(CARGO_HOME / 'bin/cargo')
SCOPES = ('trillionnium', 'config', 'tests', 'formal', 'scripts', '.github', '.cargo')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def record_file(path):
    path = Path(path)
    if path.is_symlink():
        return {'path': str(path), 'symlink': os.readlink(path), 'resolved': str(path.resolve())}
    if not path.is_file():
        return {'path': str(path), 'absent': True}
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def git_env():
    result = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    result['GIT_NO_REPLACE_OBJECTS'] = '1'
    return result


def git(*args):
    return subprocess.check_output(['git', '-c', 'core.fsmonitor=false', *args], cwd=ROOT, env=git_env())


def source_snapshot():
    entries = []
    missing = []
    tree_rows = git('ls-tree', '-r', '-z', 'HEAD').split(b'\0')
    tracked = {}
    for raw in tree_rows:
        if not raw:
            continue
        info, name = raw.split(b'\t', 1)
        mode, kind, blob = info.decode().split()
        relative = name.decode()
        tracked[relative] = (mode, kind, blob)
        path = ROOT / relative
        if not path.exists() and not path.is_symlink():
            missing.append(relative)
            if relative.split('/')[0] in SCOPES:
                raise RuntimeError('missing required tracked source: ' + relative)
            continue
        if kind != 'blob':
            raise RuntimeError('unsupported source entry: ' + relative)
        raw_bytes = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(raw_bytes)).encode() + b'\0' + raw_bytes).hexdigest()
        if actual != blob:
            raise RuntimeError('tracked source bytes differ from committed tree: ' + relative)
        entries.append({'path': relative, 'mode': mode, 'git_blob': blob,
                        'bytes': len(raw_bytes), 'sha256': hashlib.sha256(raw_bytes).hexdigest()})
    if git('status', '--porcelain', '--untracked-files=normal', '--', *SCOPES).strip():
        raise RuntimeError('source index/worktree or relevant untracked input is not clean')
    return {'head': git('rev-parse', 'HEAD').decode().strip(),
            'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
            'index_tree': git('write-tree').decode().strip(),
            'tracked_entries': len(tracked), 'materialized': entries, 'missing': missing,
            'full_tracked_worktree_verified': not missing}


def external_inputs(env):
    paths = {Path(__file__), TOOLCHAIN / 'bin/rustc', TOOLCHAIN / 'bin/cargo',
             CARGO_HOME / 'bin/rustup', CARGO_HOME / 'config', CARGO_HOME / 'config.toml'}
    for directory in (ROOT, *ROOT.parents):
        paths.update((directory / '.cargo/config', directory / '.cargo/config.toml'))
    for name in ('python3', 'git', 'cc', 'ar', 'ld', 'nm'):
        found = shutil.which(name, path=env['PATH'])
        if found:
            paths.add(Path(found).resolve())
    # Bind the selected compiler driver and standard-library bytes, not merely
    # the small rustc launcher. The entire OS image is still explicitly unbound.
    for path in (TOOLCHAIN / 'lib').rglob('*'):
        if path.is_file():
            paths.add(path.resolve())
    for name in ('libsqlite3-sys-0.37.0', 'cc-1.2.59'):
        for directory in (CARGO_HOME / 'registry/src').glob('*/' + name):
            paths.update(path for path in directory.rglob('*') if path.is_file())
        paths.update((CARGO_HOME / 'registry/cache').glob('*/' + name + '.crate'))
    observations = [record_file(path) for path in sorted(paths)]
    versions = {}
    for name in ('python3', 'git', 'cc', 'ar', 'ld', 'nm'):
        command = shutil.which(name, path=env['PATH'])
        if command:
            result = subprocess.run([command, '--version'], env=env, capture_output=True, text=True)
            versions[name] = {'resolved': str(Path(command).resolve()), 'exit_code': result.returncode,
                              'stdout': result.stdout, 'stderr': result.stderr}
    return {'files': observations, 'versions': versions,
            'fully_hermetic_build_environment': False,
            'unbound_scope': 'Complete OS image, dynamic loader, every system header and all external subtool inputs are not certified by this observer.'}


def depfile_inputs(path, dependency_files):
    """Observe this Cargo event's rustc depfile, without scanning stale outputs.

    rustc writes Make prerequisites relative to the workspace root. Preserve
    the original token and normalized path, and distinguish unset env inputs
    from a set-but-empty value. This observes dependencies; it does not certify
    that the OS or every build-script subprocess input was hermetic.
    """
    raw = path.read_text()
    logical = raw.replace('\\\r\n', '').replace('\\\n', '')
    first_rule = next((line for line in logical.splitlines()
                       if line.strip() and not line.startswith('#')), '')
    colon = None
    escaped = False
    for index, character in enumerate(first_rule):
        if escaped:
            escaped = False
        elif character == '\\':
            escaped = True
        elif character == ':' and (index + 1 == len(first_rule)
                                    or first_rule[index + 1].isspace()):
            colon = index
            break
    if colon is None:
        raise RuntimeError('no supported rustc Make dependency rule: ' + str(path))
    tokens = []
    token = []
    escaped = False
    for character in first_rule[colon + 1:]:
        if escaped:
            token.append(character)
            escaped = False
        elif character == '\\':
            escaped = True
        elif character.isspace():
            if token:
                tokens.append(''.join(token).replace('$$', '$'))
                token = []
        else:
            token.append(character)
    if escaped:
        raise RuntimeError('unfinished rustc dependency escape: ' + str(path))
    if token:
        tokens.append(''.join(token).replace('$$', '$'))
    sources = []
    for token in tokens:
        candidate = Path(token)
        if not candidate.is_absolute():
            candidate = ROOT / 'trillionnium' / candidate
        normalized = str(candidate.resolve())
        sources.append({'token': token, 'resolved': normalized})
        if normalized not in dependency_files:
            dependency_files[normalized] = record_file(normalized)
    environment = []
    for line in raw.splitlines():
        if not line.startswith('# env-dep:'):
            continue
        name, separator, value = line[len('# env-dep:'):].partition('=')
        environment.append({'name': name, 'set': bool(separator),
                            'value': value if separator else None, 'raw': line})
    return {'path': str(path), 'raw': raw, 'prerequisites': sources,
            'env_dependencies': environment}


def cargo_artifacts(log_path):
    result = []
    dependency_files = {}
    for line in Path(log_path).read_text(errors='replace').splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if type(value) is not dict or value.get('reason') not in ('compiler-artifact', 'build-script-executed'):
            continue
        item = {'cargo_event': value}
        files = []
        for raw in value.get('filenames', []):
            path = Path(raw)
            if path.is_file() and path.resolve().is_relative_to(TARGET):
                files.append(record_file(path))
                stem = path.stem if path.suffix else path.name
                if stem.startswith('lib'):
                    stem = stem[3:]
                depfile = path.with_name(stem + '.d')
                if depfile.is_file():
                    files.append(record_file(depfile))
                    item.setdefault('depfiles', []).append(depfile_inputs(depfile, dependency_files))
        out_dir = value.get('out_dir')
        if out_dir and Path(out_dir).resolve().is_relative_to(TARGET):
            files.extend(record_file(path) for path in sorted(Path(out_dir).rglob('*')) if path.is_file())
            for name in ('output', 'stderr'):
                path = Path(out_dir).parent / name
                if path.is_file():
                    item[name] = path.read_text(errors='replace')
                    files.append(record_file(path))
        item['files'] = files
        result.append(item)
    return {'cargo_events': result, 'dependency_files': dependency_files,
            'missing_dependencies': [name for name, value in dependency_files.items()
                                     if value.get('absent')],
            'dependency_scope': 'Matched compiler-artifact depfiles only; build-script outputs are also observed. No stale target-wide depfile scan.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('name')
    parser.add_argument('cargo_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    prefix = OUT / args.name
    if any(prefix.with_suffix(suffix).exists() for suffix in ('.json', '.log', '.source-before.json')):
        raise RuntimeError('fresh evidence prefix required')
    cargo_args = args.cargo_args[1:] if args.cargo_args[:1] == ['--'] else args.cargo_args
    if not cargo_args or cargo_args[0] not in ('check', 'test', 'build', 'clippy'):
        raise RuntimeError('explicit build/check/test/clippy command required')
    command = [CARGO, cargo_args[0], '--message-format=json-render-diagnostics', *cargo_args[1:]]
    selected = ('CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'RUSTC', 'CARGO_TARGET_DIR',
                'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG',
                'TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT', 'TRNM_DISTRIBUTED_SOURCE_COMMIT',
                'TRNM_DISTRIBUTED_SOURCE_TREE', 'TRNM_HISTORY_V6_ARTIFACT_DIR', 'RUSTFLAGS',
                'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CC', 'AR',
                'LD_LIBRARY_PATH', 'RUST_TEST_THREADS', 'RAYON_NUM_THREADS', 'PYTHONPATH', 'PYTHONHOME', 'PATH')
    metadata = {'schema': 'frozen-source-local-gate-observation-v2',
                'command': command, 'cwd': str(ROOT),
                'recorder_sha256': sha(__file__), 'product_qualification': False,
                'fully_hermetic_build_environment': False, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    metadata['status'] = 'running'
    save(prefix.with_suffix('.json'), metadata)
    started = time.monotonic()
    before = None
    result = None
    errors = []
    try:
        subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, check=True)
        before = source_snapshot()
        if before['index_tree'] != before['tree']:
            raise RuntimeError('index is not the exact committed source')
        env = os.environ.copy()
        if 'RISC0_DEV_MODE' in env:
            raise RuntimeError('RISC0_DEV_MODE must be absent; no source qualification recorded')
        roles = [name for name in env if name.startswith('TRNM_') and any(part in name for part in ('_CHILD', '_CONFIG', '_CRASH', '_EXIT'))]
        if roles:
            raise RuntimeError('unexpected inherited test role variables: ' + ','.join(sorted(roles)))
        artifact_dir = OUT / (args.name + '-history-artifacts')
        artifact_dir.mkdir(mode=0o700)
        env.update(CARGO_HOME=str(CARGO_HOME), RUSTUP_HOME='/tmp/chain-pon-rustup',
                   RUSTUP_TOOLCHAIN='1.95.0-x86_64-unknown-linux-gnu', RUSTC=str(TOOLCHAIN / 'bin/rustc'),
                   CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0',
                   CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
                   TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT=before['head'],
                   TRNM_DISTRIBUTED_SOURCE_COMMIT=before['head'], TRNM_DISTRIBUTED_SOURCE_TREE=before['tree'],
                   TRNM_HISTORY_V6_ARTIFACT_DIR=str(artifact_dir),
                   PATH=str(CARGO_HOME / 'bin') + ':' + env['PATH'])
        metadata.update(source_head=before['head'], source_tree=before['tree'],
                        environment={name: {'set': name in env, 'value': env.get(name)} for name in selected},
                        rustc_version=subprocess.check_output([str(TOOLCHAIN / 'bin/rustc'), '-Vv'], env=env, text=True),
                        full_tracked_worktree_verified=before['full_tracked_worktree_verified'])
        save(prefix.with_suffix('.source-before.json'), before)
        save(prefix.with_suffix('.json'), metadata)
        save(prefix.with_suffix('.external-inputs.json'), external_inputs(env))
        with prefix.with_suffix('.log').open('x') as log:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    except (Exception, KeyboardInterrupt) as error:
        errors.append({'phase': 'prepare-or-run', 'error': type(error).__name__ + ': ' + str(error)})
    after = None
    if before is not None:
        try:
            after = source_snapshot()
        except Exception as error:
            after = {'snapshot_error': type(error).__name__ + ': ' + str(error)}
            errors.append({'phase': 'source-after', 'error': after['snapshot_error']})
        save(prefix.with_suffix('.source-after.json'), after)
    if prefix.with_suffix('.log').is_file():
        try:
            artifacts = cargo_artifacts(prefix.with_suffix('.log'))
            save(prefix.with_suffix('.cargo-artifacts.json'), artifacts)
            if artifacts['missing_dependencies']:
                errors.append({'phase': 'artifacts', 'error': 'Matched rustc depfile dependencies are missing.'})
        except Exception as error:
            errors.append({'phase': 'artifacts', 'error': type(error).__name__ + ': ' + str(error)})
    metadata.update(status='error' if errors else 'complete',
                    exit_code=result.returncode if result is not None else None,
                    command_return_observed=result is not None,
                    wall_seconds=time.monotonic() - started,
                    source_unchanged=before is not None and before == after,
                    errors=errors)
    for suffix, key in (('.source-before.json', 'source_before_sha256'),
                        ('.source-after.json', 'source_after_sha256'),
                        ('.log', 'log_sha256'),
                        ('.cargo-artifacts.json', 'cargo_artifacts_sha256'),
                        ('.external-inputs.json', 'external_inputs_sha256')):
        path = prefix.with_suffix(suffix)
        if path.is_file():
            metadata[key] = sha(path)
    save(prefix.with_suffix('.json'), metadata)
    print(json.dumps({key: metadata.get(key) for key in ('status', 'source_head', 'source_tree', 'exit_code', 'wall_seconds', 'source_unchanged', 'log_sha256', 'errors')}), flush=True)
    if errors or not metadata['source_unchanged'] or result is None:
        return 3
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())

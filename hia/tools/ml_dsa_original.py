"""Execute the unchanged complete original ML-DSA qualification graph.

This is test infrastructure. A native process never calls this module.
Every stage retains its exact arguments, all output and a terminal receipt.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback


FORBIDDEN_ENVIRONMENT = {
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "RUSTC", "RUSTDOC", "CARGO",
    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC_BOOTSTRAP",
    "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_BUILD_TARGET", "CARGO_BUILD_BUILD_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_TARGET_DIR",
}
ENVIRONMENT_GUARD = {"policy": "reject-unbound-rust-cargo-loader-v1", "overrides": [], "cargo_configuration": []}
TEST_PROFILE = {"debug_assertions": True, "debuginfo": 2, "opt_level": "3", "overflow_checks": True, "test": True}


def check_environment(repository, environment):
    """Apply the repository's original-oracle override policy before any output."""
    if sys.flags.optimize or environment.get("PYTHONOPTIMIZE") not in (None, "", "0"):
        raise ValueError("Optimized Python is not original qualification")
    for key, value in environment.items():
        forbidden = (key in FORBIDDEN_ENVIRONMENT or key.startswith("CARGO_PROFILE_")
                     or (key.startswith("CARGO_TARGET_")
                         and key.endswith(("_RUSTFLAGS", "_RUSTDOCFLAGS", "_LINKER", "_RUNNER"))))
        if value and forbidden:
            raise ValueError("Unbound original compilation/runtime override: " + key)
    cargo_home = Path(environment.get("CARGO_HOME", Path.home() / ".cargo")).absolute()
    directory = Path(repository).absolute() / "trillionnium"
    locations = [cargo_home] + [path / ".cargo" for path in (directory, *directory.parents)]
    for location in locations:
        for name in ("config", "config.toml"):
            path = location / name
            if path.exists() or path.is_symlink():
                raise ValueError("Unbound Cargo configuration: " + str(path))
    return dict(ENVIRONMENT_GUARD)


def run(repository, output, rust_bin, provider_environment_path):
    REPO = Path(repository).absolute()
    guard = check_environment(REPO, os.environ)
    OUT = Path(output).absolute()
    OUT.mkdir()
    TARGET = OUT / 'target'
    assert not TARGET.exists(), 'all-feature target must be fresh'
    RUST = Path(rust_bin).absolute()
    env = dict(os.environ)
    env.update(PATH=str(RUST) + ':' + env['PATH'], CARGO_HOME=os.environ.get('CARGO_HOME', str(Path.home() / '.cargo')),
               CARGO_TARGET_DIR=str(TARGET), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='8',
               RUSTC=str(RUST / 'rustc'), RUSTDOC=str(RUST / 'rustdoc'))
    provider_environment = Path(provider_environment_path).read_text()
    for line in provider_environment.splitlines():
        key, value = line.split('=', 1)
        assert key in {'OPENSSL_DIR', 'OPENSSL_STATIC', 'TRNM_PQ_OPENSSL',
                       'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION',
                       'OPENSSL_CONF', 'OPENSSL_MODULES'}
        env[key] = value
    assert env['TRNM_PQ_OPENSSL_VERSION'] == '3.5.9'
    assert hashlib.sha256(Path(env['TRNM_PQ_OPENSSL']).read_bytes()).hexdigest() == env['TRNM_PQ_OPENSSL_SHA256']
    report = {'status': 'FAIL', 'stages': [], 'tests': [], 'source': [], 'environment_guard': guard,
              'environment': {key: env[key] for key in ('CARGO_HOME', 'CARGO_TARGET_DIR',
                  'CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS', 'RUSTC', 'RUSTDOC',
                  'OPENSSL_DIR', 'OPENSSL_STATIC', 'TRNM_PQ_OPENSSL',
                  'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION',
                  'OPENSSL_CONF', 'OPENSSL_MODULES')}}


    def sha(raw):
        return hashlib.sha256(raw).hexdigest()


    def save():
        (OUT / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')


    def run(label, argv, *, cwd=REPO / 'trillionnium', limit=180):
        stage = {'label': label, 'argv': list(map(str, argv)), 'cwd': str(cwd),
                 'wall_limit_seconds': limit}
        start = time.monotonic()
        try:
            result = subprocess.run(stage['argv'], cwd=cwd, env=env, capture_output=True,
                                    timeout=limit, check=False)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
            stage['timed_out'] = False
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code = error.stdout or b'', error.stderr or b'', None
            stage['timed_out'] = True
        stage.update(exit_code=code, seconds=time.monotonic() - start)
        for stream, raw in [('stdout', stdout), ('stderr', stderr)]:
            path = OUT / (label + '.' + stream + '.raw')
            path.write_bytes(raw)
            stage[stream] = {'path': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
        (OUT / (label + '.receipt.json')).write_text(json.dumps(stage, sort_keys=True, indent=2) + '\n')
        report['stages'].append(stage)
        save()
        print(json.dumps({'label': label, 'exit_code': code, 'seconds': stage['seconds'],
                          'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr)}), flush=True)
        assert code == 0, (label, code, stderr[-3000:].decode(errors='replace'))
        return stdout


    def source_map():
        roots = ['trillionnium/crates/trnm-crypto-primitives', 'trillionnium/crates/trnm-protocol',
                 'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock', 'rust-toolchain.toml',
                 'scripts/project-preflight.sh', 'scripts/ci/prepare_pq_provider.sh', 'AGENTS.md',
                 'config/pon/work-profile-v1.json',
                 'trillionnium/crates/trnm-pon-node/examples/support/w1_from_zero.rs',
                 'tests/fixtures/cpq1-content-v1/vectors.json']
        entries = subprocess.check_output(['git', 'ls-tree', '-rz', 'HEAD', '--', *roots], cwd=REPO).split(b'\0')
        rows = []
        for entry in entries:
            if not entry:
                continue
            metadata, name = entry.split(b'\t', 1)
            mode, kind, object_id = metadata.decode().split()
            assert kind == 'blob' and mode in ('100644', '100755'), entry
            relative = name.decode()
            path = REPO / relative
            assert path.is_file() and not any(item.is_symlink() for item in (path, *path.parents))
            raw = path.read_bytes()
            actual_blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            assert actual_blob == object_id, relative
            rows.append({'path': relative, 'bytes': len(raw), 'git_blob': object_id, 'sha256': sha(raw)})
        assert rows
        return rows


    started = time.monotonic()
    try:
        head = run('git-head', ['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=REPO).decode().splitlines()
        assert len(head) == 2 and all(re.fullmatch(r'[0-9a-f]{40}', item) for item in head)
        report.update(head=head[0], tree=head[1], source=source_map())
        run('preflight', ['bash', 'scripts/project-preflight.sh'], cwd=REPO)
        version = run('rustc-version', [RUST / 'rustc', '-Vv']).decode()
        assert 'release: 1.95.0\n' in version and 'host: x86_64-unknown-linux-gnu\n' in version
        run('cargo-fetch', [RUST / 'cargo', 'fetch', '--locked', '--target', 'x86_64-unknown-linux-gnu'], limit=180)
        env['CARGO_NET_OFFLINE'] = 'true'
        report['environment']['CARGO_NET_OFFLINE'] = 'true'
        run('cargo-metadata', [RUST / 'cargo', 'metadata', '--locked', '--offline', '--all-features', '--format-version=1'])
        run('cargo-format', [RUST / 'cargo', 'fmt', '--all', '--check'])
        raw = run('cargo-no-run', [RUST / 'cargo', 'test', '--locked', '--offline', '-p',
                  'trnm-crypto-primitives', '--all-features', '--all-targets', '--no-run',
                  '--message-format=json'], limit=480)
        artifacts = [json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
        artifacts = [row for row in artifacts if row.get('reason') == 'compiler-artifact']
        (OUT / 'artifacts.json').write_text(json.dumps(artifacts, sort_keys=True, indent=2) + '\n')
        graph = []
        for row in artifacts:
            if row['target']['name'] in ('trnm_crypto_primitives', 'ml_dsa', 'hex', 'zeroize', 'serde_json'):
                for filename in row['filenames']:
                    path = Path(filename)
                    if path.suffix == '.rlib':
                        graph.append({'name': row['target']['name'], 'package_id': row['package_id'],
                                      'features': row['features'], 'path': filename, 'bytes': path.stat().st_size,
                                      'sha256': sha(path.read_bytes())})
        report['adapter_graph'] = graph
        tests = [row for row in artifacts if row['executable'] and row['profile']['test']
                 and Path(row['target']['src_path']).is_relative_to(REPO / 'trillionnium/crates/trnm-crypto-primitives')]
        assert tests, 'no original test artifacts'
        for index, row in enumerate(tests):
            path = Path(row['executable'])
            binary = {'name': row['target']['name'], 'path': str(path),
                      'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes()),
                      'target': row['target'], 'features': row['features'], 'profile': row['profile']}
            assert row['profile'] == TEST_PROFILE, 'changed original test compilation profile'
            listing = run(f'list-{index:02d}', [path, '--list', '--format=terse'])
            names = [line[:-6].decode() for line in listing.splitlines() if line.endswith(b': test')]
            assert not any(line.endswith(b': benchmark') for line in listing.splitlines())
            retained = OUT / 'retained' / (f'{index:02d}-' + row['target']['name'])
            retained.parent.mkdir(exist_ok=True)
            shutil.copyfile(path, retained)
            assert sha(retained.read_bytes()) == binary['sha256']
            binary['retained'] = retained.relative_to(OUT).as_posix()
            binary['roster'] = names
            assert sha(path.read_bytes()) == binary['sha256']
            output = run(f'test-{index:02d}', [path, '--test-threads=1'], limit=360)
            found = re.findall(rb'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', output)
            assert len(found) == 1 and tuple(map(int, found[0])) == (len(names), 0, 0, 0, 0), (binary['name'], found, len(names))
            binary['passed'] = len(names)
            report['tests'].append(binary)
            save()
        doc = run('cargo-doctests', [RUST / 'cargo', 'test', '--locked', '--offline', '-p',
                  'trnm-crypto-primitives', '--all-features', '--doc'], limit=180)
        found = re.findall(rb'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', doc)
        assert len(found) == 1 and tuple(map(int, found[0][1:])) == (0, 0, 0, 0), found
        report['doc_passed'] = int(found[0][0])
        run('cargo-clippy', [RUST / 'cargo', 'clippy', '--locked', '--offline', '-p',
                  'trnm-crypto-primitives', '--all-features', '--all-targets', '--', '-D', 'warnings'], limit=360)
        assert source_map() == report['source'], 'unchanged original source changed during gates'
        report['passed'] = sum(row['passed'] for row in report['tests'])
        assert len(tests) == 34 and report['passed'] == 343 and report['doc_passed'] == 2, 'changed complete original roster'
        adapter = REPO / 'hia/tests/rust_ml_dsa_reference.rs'
        adapter_source = adapter.read_bytes()
        run('adapter-format', [RUST / 'rustfmt', '--edition', '2021', '--check', adapter])
        arguments = [RUST / 'rustc', '--edition=2021', '-D', 'warnings', adapter, '-L',
                     'dependency=' + str(TARGET / 'debug/deps'), '-L', 'native=' + env['OPENSSL_DIR'] + '/lib']
        for name in ('ml_dsa', 'hex', 'serde_json', 'zeroize', 'trnm_crypto_primitives'):
            found = [row for row in graph if row['name'] == name]
            assert len(found) == 1, (name, 'ambiguous original library')
            row = found[0]
            assert sha(Path(row['path']).read_bytes()) == row['sha256']
            retained = OUT / 'dependencies' / Path(row['path']).name
            retained.parent.mkdir(exist_ok=True)
            shutil.copyfile(row['path'], retained)
            row['retained'] = retained.relative_to(OUT).as_posix()
            arguments.extend(('--extern', name + '=' + row['path']))
        arguments.extend(('-o', OUT / 'original-reference'))
        run('adapter-build', arguments)
        assert adapter.read_bytes() == adapter_source
        reference = OUT / 'original-reference'
        report['reference'] = {'path': str(reference), 'retained': reference.name,
                               'bytes': reference.stat().st_size, 'sha256': sha(reference.read_bytes()),
                               'source': adapter.relative_to(REPO).as_posix(), 'source_sha256': sha(adapter_source)}
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        report['seconds'] = time.monotonic() - started
        save()
        print(json.dumps({key: value for key, value in report.items() if key not in
            ('tests', 'stages', 'source', 'traceback', 'environment', 'adapter_graph')}, sort_keys=True), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rust-bin", type=Path, required=True)
    parser.add_argument("--provider-environment", type=Path, required=True)
    args = parser.parse_args()
    run(args.repository, args.output, args.rust_bin, args.provider_environment)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run the complete Node test inventory on one immutable sparse source.

Only historical evidence/qualification archives may be unmaterialized. All
runtime, test, configuration, script and documentation bytes must match Git.
This receipt is controlled-host execution, not independent business acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
SOURCE = ROOT / 'chain-source-bounded'
COMPILER = Path('/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
EXPECTED = sys.argv[1]
LABEL = sys.argv[2]
assert re.fullmatch(r'[0-9a-f]{40}', EXPECTED)
assert re.fullmatch(r'[a-z0-9-]+', LABEL)
OUT = ROOT / 'build-receipts' / LABEL
OUT.mkdir()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def git(*args):
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', *args], cwd=SOURCE)


def source():
    head = git('rev-parse', 'HEAD').decode().strip()
    assert head == EXPECTED, 'candidate changed'
    assert not git('status', '--porcelain=v1', '-z', '--untracked-files=all'), 'dirty source'
    entries, omitted = [], []
    for row in git('ls-tree', '-r', '-z', '--full-tree', 'HEAD').split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t', 1)
        mode, kind, blob = meta.decode().split()
        relative = name.decode()
        assert kind == 'blob'
        path = SOURCE / relative
        if not path.exists() and not path.is_symlink():
            assert relative.startswith(('evidence/', 'qualification/')), relative
            omitted.append({'path': relative, 'mode': mode, 'blob': blob})
            continue
        raw = os.readlink(path).encode() if mode == '120000' else path.read_bytes()
        observed = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        assert observed == blob, 'changed tracked bytes: ' + relative
        if mode != '120000':
            assert bool(path.stat().st_mode & 0o111) == (mode == '100755'), relative
        entries.append({'path': relative, 'mode': mode, 'blob': blob,
                        'bytes': len(raw), 'sha256': sha(raw)})
    payload = {'head': head, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
               'materialized': entries, 'omitted_historical_archive_blobs': omitted}
    raw = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    return payload, sha(raw)


env = dict(os.environ)
unexpected = sorted(key for key, value in env.items() if value and
                    (key.startswith('CARGO_PROFILE_') or key in
                     ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                      'RUSTC_WORKSPACE_WRAPPER')))
assert not unexpected, 'unexpected build overrides: ' + repr(unexpected)
provider = json.loads((ROOT / 'build-receipts/pq-provider/provider.json').read_text())
assert provider['result'] == 'PREPARED_AND_SMOKE_VERIFIED'
assert provider['version'] == '3.5.9' and provider['exit_code'] == 0
for artifact in provider['native_backend_inputs']:
    raw = Path(artifact['path']).read_bytes()
    assert len(raw) == artifact['bytes'] and sha(raw) == artifact['sha256']
allowed = {'OPENSSL_DIR', 'OPENSSL_STATIC', 'TRNM_PQ_OPENSSL',
           'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION', 'OPENSSL_CONF',
           'OPENSSL_MODULES'}
for line in (ROOT / 'build-runtime/provider.env').read_text().splitlines():
    key, value = line.split('=', 1)
    assert key in allowed
    env[key] = value
env.update(RUSTC=str(COMPILER / 'bin/rustc'),
           PATH=str(COMPILER / 'bin') + os.pathsep + env.get('PATH', ''),
           LD_LIBRARY_PATH=str(COMPILER / 'lib'),
           CARGO_TARGET_DIR=str(ROOT / 'target'), CARGO_BUILD_JOBS='2',
           RUST_TEST_THREADS='1', CARGO_TERM_COLOR='never', OPENSSL_NO_VENDOR='1')
command = [str(COMPILER / 'bin/cargo'), 'test', '--locked', '--offline',
           '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
           '--all-targets', '--all-features', '--no-fail-fast', '--', '--test-threads=1']
before, before_id = source()
write('source-before.json', before)
write('environment.json', {key: env[key] for key in sorted(allowed | {
    'RUSTC', 'LD_LIBRARY_PATH', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS',
    'RUST_TEST_THREADS', 'CARGO_TERM_COLOR', 'OPENSSL_NO_VENDOR'})})
versions = {}
for name in ('rustc', 'cargo'):
    versions[name] = subprocess.check_output([str(COMPILER / 'bin' / name), '-vV'],
                                            env=env, text=True)
versions['kernel'] = subprocess.check_output(['uname', '-a'], text=True)
write('toolchain.json', versions)
subprocess.run(['bash', 'scripts/project-preflight.sh', '--audit'], cwd=SOURCE,
               env=env, check=True)
start = time.time()
usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
write('started.json', {'command': command, 'started_unix_seconds': start,
                       'source_sha256': before_id, 'expected_commit': EXPECTED})
print(json.dumps({'started': LABEL, 'commit': EXPECTED, 'command': command}), flush=True)
with (OUT / 'complete-node.log').open('xb') as stream:
    result = subprocess.run(command, cwd=SOURCE, env=env, stdout=stream,
                            stderr=subprocess.STDOUT, check=False)
usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
after, after_id = source()
write('source-after.json', after)
log = (OUT / 'complete-node.log').read_bytes()
text = log.decode(errors='replace')
results = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
build_outputs = []
for path in sorted((ROOT / 'target/debug/build').glob('trnm-sqlite-io-boundary-*/output')):
    raw = path.read_bytes()
    retained = 'sqlite-' + path.parent.name + '.txt'
    (OUT / retained).write_bytes(raw)
    build_outputs.append({'retained': retained, 'sha256': sha(raw),
                          'qualified': b'cargo:rustc-cfg=trnm_sqlite_layout_witness\n' in raw,
                          'unqualified': b'UNQUALIFIED:' in raw})
receipt = {'schema': 'pon-native-complete-node-execution-v1', 'label': LABEL,
           'command': command, 'exit_code': result.returncode,
           'started_unix_seconds': start, 'elapsed_seconds': time.time() - start,
           'child_user_cpu_seconds': usage_after.ru_utime - usage_before.ru_utime,
           'child_system_cpu_seconds': usage_after.ru_stime - usage_before.ru_stime,
           'child_max_rss_kib': usage_after.ru_maxrss,
           'source_before_sha256': before_id, 'source_after_sha256': after_id,
           'source_unchanged': before_id == after_id,
           'test_summaries': results, 'test_summary_count': len(results),
           'passed': sum(int(row[1]) for row in results),
           'failed': sum(int(row[2]) for row in results),
           'ignored': sum(int(row[3]) for row in results),
           'log_bytes': len(log), 'log_sha256': sha(log),
           'sqlite_build_outputs': build_outputs,
           'independent_operator': False, 'independent_customer': False,
           'physical_model_efficacy': False, 'production_activation': False}
write('result.json', receipt)
print(json.dumps(receipt), flush=True)
raise SystemExit(result.returncode if result.returncode else
                 (0 if before_id == after_id and results and
                  all(row['qualified'] and not row['unqualified'] for row in build_outputs)
                  and build_outputs else 3))

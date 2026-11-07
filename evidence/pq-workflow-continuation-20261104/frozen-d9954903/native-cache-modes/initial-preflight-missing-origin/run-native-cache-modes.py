import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

ROOT = Path('/dev/shm/trnm-frozen-source-81da-822cc50e')
OUT = Path('/dev/shm/frozen-d9954903-validation/native-cache-modes')
TARGET = Path('/dev/shm/trnm-cache-modes-44ebe1a-822cc50e-target')
TOOLCHAIN = Path('/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
EXPECTED_HEAD = 'd9954903ef9239f71aa575ec3e6f4fdaa88f2d35'
EXPECTED_TREE = '54442c70933c1ea37ebfe725628cbdd8685b746e'
EXPECTED_PUBLIC_SHA256 = 'c719d0bdd0c9e68a30707ccbe70c58e14082ff113c9554706b46404b006223ed'
BINDINGS = [
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_arithmetic.rs',
    'trillionnium/crates/trnm-pon-node/tests/public_cache_modes.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'trillionnium/crates/trnm-pon-node/src/store.rs',
    'trillionnium/Cargo.toml',
    'trillionnium/Cargo.lock',
    'trillionnium/crates/trnm-pon-node/Cargo.toml',
]
EXPECTED_TESTS = sorted([
    'rejection_cache_then_arithmetic_profile_is_refused',
    'arithmetic_profile_then_rejection_cache_is_refused',
    'rejection_cache_owner_cannot_be_replaced_by_repeated_setup',
    'either_cache_alone_preserves_original_cold_cpu_budget_and_profile',
])
COMMAND = [str(TOOLCHAIN / 'cargo'),
    '--config', 'profile.test.debug=0',
    '--config', 'profile.test.package.trnm-pon-node.debug=0',
    '--config', 'profile.test.package.trnm-pon-node.opt-level=0',
    'test', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml',
    '-p', 'trnm-pon-node', '--test', 'public_cache_modes', '--', '--test-threads=1']
ENV_OVERRIDES = {
    'PATH': str(TOOLCHAIN) + ':/root/.cargo/bin:' + os.environ.get('PATH', ''),
    'CARGO_HOME': '/workspace/scratch/7181e37ea4bd/runtime-recovered/cargo',
    'CARGO_TARGET_DIR': str(TARGET),
    'CARGO_BUILD_JOBS': '1', 'CARGO_INCREMENTAL': '0', 'CARGO_NET_OFFLINE': 'true',
    'RUSTUP_HOME': '/root/.rustup', 'RUSTUP_TOOLCHAIN': '1.95.0-x86_64-unknown-linux-gnu',
    'RUST_TEST_THREADS': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'GIT_OPTIONAL_LOCKS': '0',
    'TMPDIR': str(TARGET / 'tmp'),
}
UNSET = ['RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS']
ENV = dict(os.environ, **ENV_OVERRIDES)
for key in UNSET:
    ENV.pop(key, None)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, env=ENV, text=True).strip()


def memory():
    return next(int(s.split()[1]) * 1024 for s in Path('/proc/meminfo').read_text().splitlines()
                if s.startswith('MemAvailable:'))


def bindings():
    result = {}
    for rel in BINDINGS:
        raw = (ROOT / rel).read_bytes()
        committed = subprocess.check_output(['git', 'show', EXPECTED_HEAD + ':' + rel], cwd=ROOT, env=ENV)
        result[rel] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
                       'frozen_blob_sha256': hashlib.sha256(committed).hexdigest(),
                       'matches_frozen_blob': raw == committed}
    return result


def native_inputs():
    digest = hashlib.sha256()
    count = 0
    for parent in [ROOT / 'trillionnium', ROOT / 'config']:
        for path in sorted(parent.rglob('*')):
            if path.is_file() and path.suffix in {'.rs', '.toml', '.lock', '.json'}:
                rel = str(path.relative_to(ROOT))
                digest.update(rel.encode() + b'\0' + sha(path).encode() + b'\n')
                count += 1
    return {'files': count, 'aggregate_sha256': digest.hexdigest(),
            'scope': 'working-copy .rs/.toml/.lock/.json beneath trillionnium and config; registry governed by Cargo.lock'}


def all_native_config():
    digest = hashlib.sha256()
    entries = []
    mismatches = []
    listing = subprocess.check_output(['git', 'ls-tree', '-rz', EXPECTED_HEAD, '--', 'trillionnium', 'config'], cwd=ROOT, env=ENV)
    for entry in sorted(e for e in listing.split(b'\0') if e):
        meta, relbytes = entry.split(b'\t', 1)
        mode, kind, oid = meta.split()
        rel = relbytes.decode()
        path = ROOT / rel
        raw = os.readlink(path).encode() if mode == b'120000' else path.read_bytes()
        computed = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        content_sha256 = hashlib.sha256(raw).hexdigest()
        if computed != oid.decode():
            mismatches.append(rel)
        digest.update(relbytes + b'\0' + content_sha256.encode() + b'\n')
        entries.append({'path': rel, 'bytes': len(raw), 'sha256': content_sha256, 'git_blob_sha1': computed})
    return {'files': len(entries), 'aggregate_sha256': digest.hexdigest(), 'all_match_frozen_commit': not mismatches,
            'mismatches': mismatches, 'scope': 'every Git-tracked file under trillionnium and config; working bytes checked against immutable commit blobs'}, entries


def write_record(record):
    temporary = OUT / 'result.json.tmp'
    temporary.write_text(json.dumps(record, indent=2) + '\n')
    temporary.replace(OUT / 'result.json')


OUT.mkdir(parents=True, exist_ok=True)
publication_path = 'evidence/pq-workflow-continuation-20261104/publication-source-files.json'
publication_raw = subprocess.check_output(['git', 'show', EXPECTED_HEAD + ':' + publication_path], cwd=ROOT, env=ENV)
publication = json.loads(publication_raw)
publication_public = next(item for item in publication['files'] if item['path'] == BINDINGS[0])
publication_checks = {}
for item in publication['files']:
    raw = (ROOT / item['path']).read_bytes()
    publication_checks[item['path']] = (hashlib.sha256(raw).hexdigest() == item['sha256'] and len(raw) == item['bytes'] and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == item['git_blob'])
(OUT / 'publication-source-files.json').write_bytes(publication_raw)
preflight = subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, env=ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
(OUT / 'preflight.log').write_text(preflight.stdout)
all_before, manifest = all_native_config()
(OUT / 'native-config-manifest-before.json').write_text(json.dumps(manifest, indent=2) + '\n')
record = {
    'schema': 'public-cache-modes-native-attempt-v2',
    'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'root': str(ROOT), 'expected_head': EXPECTED_HEAD, 'expected_tree': EXPECTED_TREE,
    'actual_head_before': git('rev-parse', 'HEAD'), 'actual_tree_before': git('rev-parse', 'HEAD^{tree}'),
    'git_status_before': git('status', '--porcelain=v1'),
    'expected_public_v3_sha256': EXPECTED_PUBLIC_SHA256,
    'publication_manifest': {'git_path': publication_path, 'sha256': hashlib.sha256(publication_raw).hexdigest(),
                             'public_v3': publication_public, 'source_entries_match': publication_checks, 'corrected_from': publication.get('corrected_from')},
    'bindings_before': bindings(), 'native_inputs_before': native_inputs(),
    'all_native_config_before': all_before,
    'command': COMMAND, 'environment_overrides': ENV_OVERRIDES, 'environment_unset': UNSET,
    'preflight_exit_code': preflight.returncode, 'preflight_log_sha256': sha(OUT / 'preflight.log'),
    'cargo_version': subprocess.check_output([str(TOOLCHAIN / 'cargo'), '--version'], env=ENV, text=True).strip(),
    'rustc_version': subprocess.check_output([str(TOOLCHAIN / 'rustc'), '-vV'], env=ENV, text=True).strip(),
    'timeout_seconds': 600, 'available_memory_stop_bytes': 512 * 1024 * 1024,
    'tmpfs_available_stop_bytes': 128 * 1024 * 1024,
    'initial_tmpfs_available_bytes': shutil.disk_usage(TARGET).free,
    'initial_mem_available_bytes': memory(), 'expected_test_names': EXPECTED_TESTS,
    'disk_before': {str(p): shutil.disk_usage(p)._asdict() for p in [ROOT, TARGET]},
    'scope': 'Four actual PublicServer constructor integration tests only; local debug/opt settings do not qualify original Host performance gates',
    'production_activation': False, 'qualification': 'HOLD', 'result': 'PREFLIGHT',
    'exit_code': None, 'timeout_observed': False, 'resource_abort_observed': False,
    'storage_abort_observed': False,
}
conditions = {
    'preflight_passed': preflight.returncode == 0,
    'head_matches': record['actual_head_before'] == EXPECTED_HEAD,
    'tree_matches': record['actual_tree_before'] == EXPECTED_TREE,
    'working_tree_clean': not record['git_status_before'],
    'all_eight_bindings_match_frozen_commit': all(x['matches_frozen_blob'] for x in record['bindings_before'].values()),
    'all_native_config_matches': all_before['all_match_frozen_commit'],
    'fresh_public_hash_matches': record['bindings_before'][BINDINGS[0]]['sha256'] == EXPECTED_PUBLIC_SHA256,
    'publication_public_hash_matches': publication_public['sha256'] == EXPECTED_PUBLIC_SHA256,
    'all_fresh_publication_entries_match': all(publication_checks.values()),
    'existing_target_present': TARGET.is_dir(),
    'memory_above_floor': record['initial_mem_available_bytes'] >= 512 * 1024 * 1024,
    'tmpfs_above_floor': record['initial_tmpfs_available_bytes'] >= 128 * 1024 * 1024,
}
record['preflight_conditions'] = conditions
if not all(conditions.values()):
    record['result'] = 'PREFLIGHT_BLOCKED'
    write_record(record)
    print(json.dumps(record), flush=True)
    raise SystemExit(2)
(TARGET / 'tmp').mkdir(parents=True, exist_ok=True)
record['reused_existing_target'] = True
record['result'] = 'RUNNING'
record['min_mem_available_bytes'] = record['initial_mem_available_bytes']
record['min_tmpfs_available_bytes'] = record['initial_tmpfs_available_bytes']
write_record(record)
print(json.dumps({'stage': 'native_test_start', 'head': EXPECTED_HEAD, 'tree': EXPECTED_TREE,
                  'native_inputs': record['native_inputs_before'], 'all_native_config': all_before,
                  'command': COMMAND, 'mem_available_bytes': memory()}), flush=True)
process = None
interrupted = []


def stop_owned():
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def interrupted_handler(signum, frame):
    interrupted.append(signum)
    stop_owned()


signal.signal(signal.SIGINT, interrupted_handler)
signal.signal(signal.SIGTERM, interrupted_handler)
started = time.monotonic()
try:
    with (OUT / 'cargo.log').open('wb') as log:
        process = subprocess.Popen(COMMAND, cwd=ROOT, env=ENV, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        record['cargo_pid'] = process.pid
        write_record(record)
        next_report = 0
        while process.poll() is None:
            elapsed = time.monotonic() - started
            available = memory()
            record['min_mem_available_bytes'] = min(record['min_mem_available_bytes'], available)
            tmpfs_available = shutil.disk_usage(TARGET).free
            record['min_tmpfs_available_bytes'] = min(record['min_tmpfs_available_bytes'], tmpfs_available)
            if elapsed >= 600 or available < 512 * 1024 * 1024 or tmpfs_available < 128 * 1024 * 1024:
                record['timeout_observed'] = elapsed >= 600
                record['resource_abort_observed'] = available < 512 * 1024 * 1024
                record['storage_abort_observed'] = tmpfs_available < 128 * 1024 * 1024
                record['abort_tmpfs_available_bytes'] = tmpfs_available
                record['abort_mem_available_bytes'] = available
                stop_owned()
                break
            if elapsed >= next_report:
                print(json.dumps({'stage': 'native_test_running', 'elapsed_s': round(elapsed),
                                  'mem_available_bytes': available, 'tmpfs_available_bytes': tmpfs_available}), flush=True)
                next_report = elapsed + 20
            time.sleep(0.5)
    record['exit_code'] = process.returncode
    if interrupted:
        record['result'] = 'INTERRUPTED'
        record['signals_received'] = interrupted
    elif record['timeout_observed']:
        record['result'] = 'TIMEOUT'
    elif record['resource_abort_observed']:
        record['result'] = 'ABORTED_RESOURCE'
    elif record['storage_abort_observed']:
        record['result'] = 'ABORTED_STORAGE'
    else:
        record['result'] = 'PASS' if process.returncode == 0 else 'FAIL'
except BaseException as exc:
    stop_owned()
    record['result'] = 'RUNNER_ERROR'
    record['runner_error'] = str(exc)
finally:
    record['elapsed_seconds'] = round(time.monotonic() - started, 6)
    record['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record['actual_head_after'] = git('rev-parse', 'HEAD')
    record['actual_tree_after'] = git('rev-parse', 'HEAD^{tree}')
    record['git_status_after'] = git('status', '--porcelain=v1')
    record['bindings_after'] = bindings()
    record['native_inputs_after'] = native_inputs()
    record['all_native_config_after'], after_manifest = all_native_config()
    (OUT / 'native-config-manifest-after.json').write_text(json.dumps(after_manifest, indent=2) + '\n')
    record['bindings_unchanged'] = record['bindings_before'] == record['bindings_after']
    record['native_inputs_unchanged'] = record['native_inputs_before'] == record['native_inputs_after']
    record['all_native_config_unchanged'] = all_before == record['all_native_config_after']
    record['head_unchanged'] = record['actual_head_before'] == record['actual_head_after']
    record['tree_unchanged'] = record['actual_tree_before'] == record['actual_tree_after']
    raw = (OUT / 'cargo.log').read_bytes() if (OUT / 'cargo.log').exists() else b''
    text = raw.decode(errors='replace')
    record['cargo_log_sha256'] = hashlib.sha256(raw).hexdigest()
    record['cargo_log_bytes'] = len(raw)
    record['test_result_lines'] = re.findall(r'^test result: .*$', text, re.MULTILINE)
    record['passed_test_names'] = sorted(re.findall(r'^test ([A-Za-z0-9_]+) \.\.\. ok$', text, re.MULTILINE))
    record['exact_four_tests_passed'] = record['passed_test_names'] == EXPECTED_TESTS and bool(re.search(r'test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;', text))
    record['oom_log_evidence'] = bool(re.search(r'out of memory|memory allocation.*failed', text, re.I))
    record['sqlite_boundary_warning'] = 'SQLite I/O boundary UNQUALIFIED: RUSTC must be absolute' in text
    if record['result'] == 'PASS' and not all([record['bindings_unchanged'], record['native_inputs_unchanged'],
            record['all_native_config_unchanged'], record['head_unchanged'], record['tree_unchanged'],
            not record['git_status_after'], record['exact_four_tests_passed']]):
        record['result'] = 'INVALIDATED'
    record['disk_after'] = {str(p): shutil.disk_usage(p)._asdict() for p in [ROOT, TARGET]}
    write_record(record)
    print(json.dumps(record), flush=True)
    print(text[-8000:], flush=True)
raise SystemExit(0 if record['result'] == 'PASS' else 1)

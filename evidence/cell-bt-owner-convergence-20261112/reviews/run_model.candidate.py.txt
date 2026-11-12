#!/usr/bin/env python3
"""One fresh, fixed-source native shard research observation; failures are retained."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

REPO = Path('/home/qq/work/chain-bt-owner-convergence-20261112-4a0b')
BASE = Path(str(REPO) + '-validation')
TOOLCHAIN = Path('/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
PROVIDER = Path('/home/qq/work/chain-cell-discovery-provider-f2568-20261108/runner/trnm-pq-provider-3.5.9.ReYCJ9gV/install')
PROVIDER_SHA = 'ed29dfe14c0686c876833e39fbeedb277846987f3728acc279c256b32259cf62'
os.umask(0o077)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def check(value, message):
    if not value:
        raise RuntimeError(message)


def save(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def identity(config):
    actual = {name: subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()
              for name, args in {'head': ['rev-parse', 'HEAD'],
                                 'tree': ['rev-parse', 'HEAD^{tree}'],
                                 'status': ['status', '--porcelain', '--untracked-files=all']}.items()}
    check(actual == {'head': config['head'], 'tree': config['tree'], 'status': ''},
          'exact clean source identity mismatch')
    return actual


def memory():
    try:
        rel = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::'))
        folder = Path('/sys/fs/cgroup') / rel.lstrip('/')
        observed = {name: (folder / name).read_text().strip()
                    for name in ['memory.max', 'memory.peak', 'memory.events', 'cpu.max', 'cpu.stat']}
        try:
            observed['io.stat'] = (folder / 'io.stat').read_text().strip()
        except OSError as error:
            observed['io.stat_unavailable'] = str(error)
        return observed
    except (OSError, StopIteration) as error:
        return {'observation_error': str(error)}


def inputs(spec, audit):
    expected = {(row['category'], row['logical']): row for row in audit['inputs']}
    entries = [(category, logical, row) for category in ('model', 'environment')
               for logical, row in spec[category].items()]
    entries.append(('python', 'python', spec['python']))
    check(len(entries) == len(expected) == 31, 'independent logical input roster')
    result = []
    for category, logical, item in entries:
        path = Path(item['path'])
        before = path.stat()
        prior = expected[(category, logical)]
        check(stat.S_ISREG(before.st_mode) and not path.is_symlink(), 'regular pinned input')
        digest = sha(path)
        after = path.stat()
        check((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'input changed while hashing')
        check(str(path) == prior['selected_path'] and digest == item['sha256'] == prior['sha256']
              and before.st_size == prior['size'], 'independent input bytes mismatch: ' + logical)
        result.append({'category': category, 'logical': logical, 'path': str(path),
                       'size': before.st_size, 'sha256': digest})
    return result


def main():
    check(len(sys.argv) == 3 and sys.argv[2] == '--execute', 'fixed config plus --execute required')
    config_path = Path(sys.argv[1])
    config = json.loads(config_path.read_text())
    source = Path(config['source'])
    audit_path = Path(config['audit'])
    binary = Path(config['binary'])
    check(sha(Path(__file__)) == config['wrapper_sha256'], 'fixed wrapper pin')
    check(sha(source) == config['source_sha256'] and sha(audit_path) == config['audit_sha256'], 'spec/audit pin')
    spec = json.loads(source.read_text())
    audit = json.loads(audit_path.read_text())
    output = Path(spec['output'])
    destination = Path(str(output) + '-wrapper')
    check(not output.exists() and not destination.exists(), 'fresh operation only; no replay')
    destination.mkdir(mode=0o700)
    save(destination / 'one-shot-claim.json', {'operation': spec['operation'], 'at': utc(),
                                            'same_operation_retry_permitted': False})
    result = {'schema': 'trnm.native-paged-rs46-real-model-observation.v2',
              'started_at': utc(), 'passed': False, 'native_started': False,
              'config_sha256': sha(config_path), 'wrapper_sha256': sha(Path(__file__)),
              'source_sha256': config['source_sha256'], 'operation': spec['operation'],
              'independent_real_money': False, 'production_activation': False,
              'native_seconds': 300, 'memory_start': memory()}
    began = time.monotonic()
    env = os.environ.copy()
    env.update({'PATH': str(TOOLCHAIN / 'bin') + os.pathsep + env.get('PATH', ''),
                'RUSTC': str(TOOLCHAIN / 'bin/rustc'), 'RUSTDOC': str(TOOLCHAIN / 'bin/rustdoc'),
                'CARGO_HOME': '/home/qq/.cargo', 'CARGO_TARGET_DIR': str(REPO) + '-target',
                'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0', 'RUST_TEST_THREADS': '1',
                'LD_LIBRARY_PATH': str(TOOLCHAIN / 'lib'), 'PYTHONDONTWRITEBYTECODE': '1',
                'TMPDIR': str(BASE / 'tmp'), 'OPENSSL_DIR': str(PROVIDER), 'OPENSSL_STATIC': '1',
                'OPENSSL_CONF': '/dev/null', 'OPENSSL_MODULES': str(PROVIDER / 'lib/ossl-modules'),
                'TRNM_PQ_OPENSSL': str(PROVIDER / 'bin/openssl'),
                'TRNM_PQ_OPENSSL_SHA256': PROVIDER_SHA, 'TRNM_PQ_OPENSSL_VERSION': '3.5.9'})
    try:
        result['start_identity'] = identity(config)
        check(sha(binary) == config['binary_sha256'], 'fixed executable pin')
        check(sha(PROVIDER / 'bin/openssl') == PROVIDER_SHA, 'fixed native provider pin')
        check((spec['seconds'], spec['max_snapshot_bytes'], spec['runtime_rss_bytes'], spec['threads']) ==
              (300, 536870912, 8589934592, 4), 'original native limits')
        for gate in config['gate_artifacts']:
            check(sha(Path(gate['path'])) == gate['sha256'], 'reviewed prerequisite changed')
        before = inputs(spec, audit)
        save(destination / 'inputs-start.json', before)
        for name, command in [
            ('preflight', ['bash', 'scripts/project-preflight.sh']),
            ('exact-source', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                              '--expected-head', config['head']]),
        ]:
            with (destination / (name + '.log')).open('xb') as log:
                completed = subprocess.run(command, cwd=REPO, env=env, stdout=log,
                                           stderr=subprocess.STDOUT, timeout=180)
            check(completed.returncode == 0, name + ' refused')
        check(result['memory_start'].get('memory.max') == '8589934592', 'original 8GiB whole-job cgroup required')
        cpu = result['memory_start'].get('cpu.max', '').split()
        check(len(cpu) == 2 and cpu[0].isdigit() and cpu[1].isdigit()
              and int(cpu[0]) == 4 * int(cpu[1]), 'original four-CPU whole-job cgroup required')
        save(destination / 'start.json', result)
        command = [str(binary), str(source), config['source_sha256']]
        with (destination / 'native.stdout').open('xb') as out, (destination / 'native.stderr').open('xb') as err:
            start = time.monotonic()
            process = subprocess.Popen(command, cwd=REPO / 'trillionnium', env=env,
                                       stdout=out, stderr=err, start_new_session=True)
            result['native_started'] = True
            save(destination / 'native-started.json', {'pid': process.pid, 'command': command, 'at': utc()})
            terminated = killed = False
            while True:
                waited, status, usage = os.wait4(process.pid, os.WNOHANG)
                if waited:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                elapsed = time.monotonic() - start
                if elapsed >= 420 and not terminated:
                    os.killpg(process.pid, signal.SIGTERM)
                    terminated = True
                if elapsed >= 435 and not killed:
                    os.killpg(process.pid, signal.SIGKILL)
                    killed = True
                time.sleep(0.1)
        result['native_process'] = {'exit_code': process.returncode,
                                    'elapsed_seconds': time.monotonic() - start,
                                    'watchdog_term': terminated, 'watchdog_kill': killed,
                                    'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                                    'wait4_ru_maxrss_kib': usage.ru_maxrss}
        native = json.loads((output / 'native-result.json').read_text())
        result['native_result_sha256'] = sha(output / 'native-result.json')
        result['last_stage'] = native.get('stage')
        result['native_error'] = native.get('error')
        check(process.returncode == 0 and not terminated and not killed and native.get('passed') is True,
              'native operation failed: ' + str(native.get('error')))
        pins = native['operation_pins']
        check(native['source_input_sha256'] == config['source_sha256'], 'native source pin')
        check(pins['operation'] == spec['operation'], 'native operation drift')
        check(pins['tcv1'] == native['input']['tcv1'] == native['bep52']['tcv1'], 'TCV1 drift')
        check(pins['cts1'] == native['snapshot']['cts1'], 'CTS1 drift')
        check(pins['bep52_plan'] == native['bep52']['plan'], 'transport plan drift')
        check(pins['chb1'] == native['handoff']['descriptor'], 'CHB1 drift')
        check(native['handoff']['worker_sha256'] == spec['snapshot']['worker_sha256'], 'actual worker pin drift')
        result['operation_pins'] = pins
        result['last_stage'] = native.get('stage')
        result['native_error'] = native.get('error')
        check(process.returncode == 0 and not terminated and not killed and native.get('passed') is True,
              'native operation failed: ' + str(native.get('error')))
        cycle = native['native_shard_cycle']
        check(cycle['complete'] is True
              and cycle['profile'] == 'native-funded-grouped-paged-rs46-research-v3'
              and native['cold_restore']['native_erasure_shard_recovery'] is True
              and native['cold_restore']['m12_funding_admitted'] is True, 'complete grouped native shard and M12 receipt')
        check((cycle['m12_parent_claims'], cycle['v3_children'], cycle['logical_work_items'],
               cycle['storage_parent_groups'], cycle['repair_parent_groups']) == (79, 760, 791, 36, 12),
              'complete real-model parent and child rosters')
        check(cycle['all_parent_tasks_currently_funded'] is True, 'final live native funding observation')
        check(native['actual_model_run'] == 'observed_two_forwards'
              and native['typed_snapshot_admitted'] is True
              and native['composition_worker_executed'] is True, 'actual typed/sealed model execution')
        check(native['process']['original_seconds'] == 300 and native['process']['elapsed_ms'] < 300000
              and result['native_process']['elapsed_seconds'] < 300,
              'original native deadline not met')
        check(all(native[key] is False for key in ('independent_operators', 'hepta_final_use', 'production_activation')),
              'qualification scope changed')
        after = inputs(spec, audit)
        save(destination / 'inputs-end.json', after)
        check(before == after, 'independent input changed')
        result['passed'] = True
    except BaseException as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            result['end_identity'] = identity(config)
            with (destination / 'exact-source-end.log').open('xb') as log:
                end_source = subprocess.run(['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                                             '--expected-head', config['head']], cwd=REPO, env=env,
                                            stdout=log, stderr=subprocess.STDOUT, timeout=180)
            check(end_source.returncode == 0, 'exact source changed during model run')
            check(sha(binary) == config['binary_sha256'] and sha(source) == config['source_sha256'], 'binary/spec changed')
            check(sha(Path(__file__)) == config['wrapper_sha256']
                  and sha(config_path) == result['config_sha256'], 'wrapper/config changed')
        except BaseException as error:
            result['passed'] = False
            result['end_error'] = type(error).__name__ + ': ' + str(error)
        result['memory_end'] = memory()
        result['completed_at'] = utc()
        result['wrapper_elapsed_seconds'] = time.monotonic() - began
        save(destination / 'observation.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

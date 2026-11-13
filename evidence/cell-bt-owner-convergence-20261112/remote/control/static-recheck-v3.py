#!/usr/bin/env python3
"""Record a fresh ai395 observation of the three unchanged strict Clippy gates.

The earlier cloud pass was observed, but its twelve raw logs were not included
in the recovered archive. This program creates new evidence; it does not restore
those logs or change the outcome of the interrupted original campaign.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
import traceback


ROOT = Path('/home/qq/work/chain-bt-owner-convergence-20261112-4a0b')
CONTROL = Path(str(ROOT) + '-control')
BASE = Path(str(ROOT) + '-validation')
OUT = BASE / 'static-recheck-01'
TARGET = Path(str(ROOT) + '-target')
TAIL_SUMMARY = BASE / 'remaining-gates-02/summary.json'
HEAD = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
TREE = 'a897ba4c74897a05ceb364f098b1bfe32c850213'
RUNNER_SHA = '8f82ae65d146be8513d0bc9fb14ed8f08e2df378f5db8e3471d99301d78fd3d9'
VERIFIER_SHA = '0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946'
SOURCE_STDOUT_SHA = '418dec7ab64a0ef795f7e360ce9e6f311ae7ce6d34dafc0df73bee59ebbe0902'
TAIL_OBSERVER_SHA = 'c986525ef5a25f295f90fc80c452d97dba512e55fc3115a25cc88dd392597135'
SOURCE_INPUT_SHA = 'fb6fe559317f7c3cd6ef504581b89e7d8229a7c700d3c71b61099a32d443cec9'
TOOLCHAIN = Path('/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
PYTHON = Path('/home/qq/hepta-smollm2-weight-research-20261103/python/cpython-3.12.16-linux-x86_64-gnu/bin/python3.12')
PYTHON_SHA = '23bc148d2b48964b621c5561ff2b81c1d9c7b717967a7491efbf12f4304882b5'
PROVIDER = Path('/home/qq/work/chain-cell-discovery-provider-f2568-20261108/runner/trnm-pq-provider-3.5.9.ReYCJ9gV/install')
PROVIDER_SHA = 'ed29dfe14c0686c876833e39fbeedb277846987f3728acc279c256b32259cf62'
TOOL_PINS = {
    str(TOOLCHAIN / 'bin/cargo'): '841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66',
    str(TOOLCHAIN / 'bin/rustc'): 'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6',
    str(TOOLCHAIN / 'bin/rustdoc'): 'e5144902aed6cf94280eae3ad7708da5bdd3819b5281728af432d0e70231439c',
    str(PROVIDER / 'bin/openssl'): PROVIDER_SHA,
    str(PYTHON): PYTHON_SHA,
}
EXPECTED_CONTROL_ENV = {
    'PATH': str(TOOLCHAIN / 'bin') + ':/usr/bin:/bin',
    'RUSTC': str(TOOLCHAIN / 'bin/rustc'),
    'RUSTDOC': str(TOOLCHAIN / 'bin/rustdoc'),
    'CARGO_HOME': '/home/qq/.cargo',
    'CARGO_TARGET_DIR': str(TARGET),
    'CARGO_BUILD_JOBS': '2',
    'CARGO_INCREMENTAL': '0',
    'RUST_TEST_THREADS': '1',
    'LD_LIBRARY_PATH': str(TOOLCHAIN / 'lib'),
    'TMPDIR': str(BASE / 'tmp'),
    'OPENSSL_DIR': str(PROVIDER),
    'OPENSSL_STATIC': '1',
    'OPENSSL_CONF': '/dev/null',
    'OPENSSL_MODULES': str(PROVIDER / 'lib/ossl-modules'),
    'TRNM_PQ_OPENSSL': str(PROVIDER / 'bin/openssl'),
    'TRNM_PQ_OPENSSL_SHA256': PROVIDER_SHA,
    'TRNM_PQ_OPENSSL_VERSION': '3.5.9',
    'PYTHONDONTWRITEBYTECODE': '1',
    'GIT_TERMINAL_PROMPT': '0',
}
EXPECTED_COMMAND_NAMES = [
    'preflight', 'source-before', 'clippy-default-trnm-data-availability',
    'clippy-default-trnm-pon-node', 'strict-clippy', 'source-after',
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1048576), b''):
            value.update(part)
    return value.hexdigest()


def identity():
    observed = {
        name: subprocess.check_output(['/usr/bin/git', *argv], cwd=ROOT, text=True).strip()
        for name, argv in {
            'head': ['rev-parse', 'HEAD'],
            'tree': ['rev-parse', 'HEAD^{tree}'],
            'status': ['status', '--porcelain', '--untracked-files=all'],
        }.items()
    }
    require(observed == {'head': HEAD, 'tree': TREE, 'status': ''},
            'source identity or worktree differs from frozen B: ' + repr(observed))
    return observed


def resources():
    result = {
        'nice': os.getpriority(os.PRIO_PROCESS, 0),
        'requested_cpu_quota_percent': 400,
        'requested_build_jobs': 2,
        'launcher_memory_max_bytes_omitted': True,
        'model_limits_applied_to_compiler': False,
        'rlimit_as': list(resource.getrlimit(resource.RLIMIT_AS)),
        'rlimit_cpu': list(resource.getrlimit(resource.RLIMIT_CPU)),
    }
    try:
        relative = next(line.split(':', 2)[2]
                        for line in Path('/proc/self/cgroup').read_text().splitlines()
                        if line.startswith('0::'))
        folder = Path('/sys/fs/cgroup') / relative.lstrip('/')
        result['cgroup_path'] = str(folder)
        result['cgroup'] = {
            key: (folder / key).read_text().strip()
            for key in ('memory.max', 'memory.peak', 'memory.events', 'cpu.max', 'cpu.stat')
        }
    except (OSError, StopIteration) as error:
        result['observation_error'] = str(error)
    return result


def check_resources(observed):
    require(observed['nice'] == 10, 'launcher nice must remain 10')
    require('cgroup' in observed, 'actual cgroup controls could not be observed')
    quota, period = observed['cgroup']['cpu.max'].split()
    require(quota != 'max' and int(quota) == 4 * int(period),
            'actual CPU quota must equal the requested four CPUs')


def stop_child(process):
    if process.poll() is not None:
        return process.returncode
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return process.wait()
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait()


def observe(tail, tail_hash):
    OUT.mkdir(mode=0o700)
    temporary = OUT / 'tmp'
    temporary.mkdir(mode=0o700)
    report = {
        'schema': 'trnm.bt-frozen-b-fresh-static-recheck.v3',
        'source': HEAD,
        'tree': TREE,
        'root': str(ROOT),
        'output': str(OUT),
        'observer_sha256': sha(Path(__file__)),
        'started_unix_ns': time.time_ns(),
        'commands': [],
        'completed': False,
        'passed': False,
        'earlier_pass_observed': True,
        'earlier_raw_available': False,
        'new_observation': True,
        'restoration_of_earlier_raw_logs': False,
        'original_campaign_pass_claim': False,
        'recovered_archive_sha256': 'b8ca4b885d89e19065e31766a0001bf9f1a941a02812e562f782119f637b360b',
        'predecessor': {
            'summary_path': str(TAIL_SUMMARY),
            'summary_sha256': tail_hash,
            'completed': tail['completed'],
            'passed': tail.get('passed'),
            'authoritative_h_job_status_must_be_checked_by_launcher_operator': True,
        },
        'native_tests_executed': False,
        'native_operation_started': False,
        'production_activation': False,
        'independent_domains_qualified': False,
        'wan_qualified': False,
        'model_efficacy_qualified': False,
    }
    environment = None
    source_command = None
    pinned_before = None
    before = None

    def save():
        pending = OUT / 'summary.pending.json'
        with pending.open('w') as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, OUT / 'summary.json')

    def run(name, argv, timeout=1800):
        stdout = OUT / (name + '.stdout')
        stderr = OUT / (name + '.stderr')
        item = {
            'name': name, 'argv': argv, 'cwd': str(ROOT),
            'timeout_seconds': timeout, 'started_unix_ns': time.time_ns(),
            'status': 'running',
        }
        report['commands'].append(item)
        save()
        print(json.dumps({'started': name, 'source': HEAD}), flush=True)
        started = time.monotonic_ns()
        process = None
        code = None
        timed_out = False
        interrupted = None
        launch_error = None
        with stdout.open('xb') as out, stderr.open('xb') as err:
            try:
                process = subprocess.Popen(
                    argv, cwd=ROOT, env=environment, stdout=out, stderr=err,
                    start_new_session=True)
                item['pid'] = process.pid
                save()
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                code = stop_child(process)
            except BaseException as error:
                if process is None:
                    launch_error = type(error).__name__ + ': ' + str(error)
                else:
                    interrupted = type(error).__name__ + ': ' + str(error)
                    code = stop_child(process)
            finally:
                out.flush()
                err.flush()
                os.fsync(out.fileno())
                os.fsync(err.fileno())
        item.update(
            status='launch_failed' if launch_error else 'completed',
            exit_code=code, timed_out=timed_out,
            elapsed_ns=time.monotonic_ns() - started,
            ended_unix_ns=time.time_ns(),
            stdout_bytes=stdout.stat().st_size, stdout_sha256=sha(stdout),
            stderr_bytes=stderr.stat().st_size, stderr_sha256=sha(stderr))
        if launch_error:
            item['launch_error'] = launch_error
        if interrupted:
            item['controlled_interruption'] = interrupted
        save()
        print(json.dumps({'completed': name, 'exit_code': code,
                          'timed_out': timed_out, 'launch_error': launch_error,
                          'controlled_interruption': interrupted}), flush=True)
        if launch_error or interrupted:
            raise RuntimeError(launch_error or interrupted)
        return 124 if timed_out else code

    save()
    try:
        inherited = sorted(
            key for key, value in os.environ.items() if value and
            (key.startswith('CARGO_PROFILE_') or key in
             ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
              'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')))
        require(not inherited, 'unexpected compiler override keys: ' + repr(inherited))
        environment_path = CONTROL / 'build-environment.json'
        control_environment = json.loads(environment_path.read_bytes())
        require(control_environment == EXPECTED_CONTROL_ENV,
                'prepared build-environment values or keys changed')
        inputs = CONTROL / 'source-inputs.native-v2.json'
        require(sha(inputs) == SOURCE_INPUT_SHA, 'source-input control pin changed')
        spec = json.loads(inputs.read_bytes())
        require(spec['python']['path'] == str(PYTHON) and
                spec['python']['sha256'] == PYTHON_SHA, 'original Python identity changed')
        preparation_path = BASE / 'preparation-success.json'
        preparation = json.loads(preparation_path.read_bytes())
        require(preparation['passed'] is True and preparation['head'] == HEAD,
                'existing remote preparation is not admitted for frozen B')
        require(preparation['source_input']['sha256'] == SOURCE_INPUT_SHA,
                'remote preparation source-input pin changed')
        original_runner = ROOT / 'scripts/ci/run_cell_storage_four_gates_v1.py'
        source_verifier = ROOT / 'scripts/ci/verify_ci_source.py'
        require(sha(original_runner) == RUNNER_SHA, 'original frozen runner pin changed')
        require(sha(source_verifier) == VERIFIER_SHA, 'original physical verifier pin changed')
        require(sha(CONTROL / 'validate-original-tail-v3.py') == TAIL_OBSERVER_SHA,
                'preceding tail observer pin changed')
        for path, expected in TOOL_PINS.items():
            require(sha(path) == expected, 'tool/provider/Python pin mismatch: ' + path)
        accepted_pin_paths = []
        accepted = tail.get('accepted_release_main')
        report['accepted_release_main_binding'] = {
            'preceding_tail_admitted': accepted is not None,
            'unchanged_after_static': None,
            'model_execution_admitted_by_this_observer': False,
        }
        if accepted is None:
            report['accepted_release_main_binding']['reason'] = (
                'preceding tail did not record an accepted normal release main; '
                'this remains an independent static observation')
        else:
            receipt = BASE / 'remaining-gates-02/accepted-release-main.json'
            require(json.loads(receipt.read_bytes()) == accepted,
                    'accepted release-main receipt differs from preceding tail summary')
            executable = TARGET / 'release/examples/cell_native_shard_research_next_use_v2'
            require(accepted['schema'] == 'trnm.bt-frozen-b-native-release-main.v1' and
                    accepted['source'] == HEAD and accepted['tree'] == TREE and
                    accepted['path'] == str(executable) and accepted['profile'] == 'release' and
                    accepted['provider_sha256'] == PROVIDER_SHA and
                    accepted['native_operation_started'] is False,
                    'preceding accepted release-main identity/profile differs')
            artifact = accepted['cargo_artifact']
            require(artifact['executable'] == str(executable) and
                    artifact['target']['name'] == 'cell_native_shard_research_next_use_v2' and
                    artifact['target']['kind'] == ['example'] and
                    artifact['target']['crate_types'] == ['bin'] and
                    artifact['profile']['test'] is False and
                    artifact['profile']['opt_level'] == '3' and
                    'pq-native-openssl' in artifact['features'],
                    'accepted artifact is not the expected normal PQ release example')
            with executable.open('rb') as stream:
                require(stream.read(4) == b'\x7fELF', 'accepted main is not an ELF executable')
            require(executable.stat().st_size == accepted['bytes'] and
                    sha(executable) == accepted['sha256'],
                    'accepted release main bytes changed before static observation')
            accepted_pin_paths = [receipt, executable]
            report['accepted_release_main_binding'].update({
                'receipt_path': str(receipt), 'executable_path': str(executable),
                'bytes': accepted['bytes'], 'sha256': accepted['sha256'],
                'unchanged_after_static': False,
            })
        retained = [
            Path(__file__), original_runner, source_verifier, environment_path,
            inputs, preparation_path, TAIL_SUMMARY, CONTROL / 'validate-original-tail-v3.py',
            *(Path(path) for path in TOOL_PINS),
        ]
        retained.extend(accepted_pin_paths)
        pinned_before = {str(path): sha(path) for path in retained}
        report['pinned_before'] = pinned_before
        environment = os.environ.copy()
        environment.update(control_environment)
        updates = {'CARGO_TERM_COLOR': 'never', 'GIT_PAGER': 'cat',
                   'TMPDIR': str(temporary)}
        environment.update(updates)
        report['prepared_build_environment'] = control_environment
        report['explicit_environment_updates'] = updates
        report['effective_environment'] = {
            key: environment[key] for key in sorted(set(control_environment) | set(updates))}
        report['rustup_home_explicitly_added'] = False
        before = identity()
        report['before_identity'] = before
        report['resource_start'] = resources()
        check_resources(report['resource_start'])
        source_command = [
            str(PYTHON), '-B', 'scripts/ci/verify_ci_source.py',
            '--kind', 'head', '--expected-head', HEAD]
        save()
        require(run('preflight', ['/bin/bash', 'scripts/project-preflight.sh', '--audit'], 60) == 0,
                'original project preflight failed')
        require(run('source-before', source_command, 300) == 0,
                'original physical source-before gate failed')
        require(sha(OUT / 'source-before.stdout') == SOURCE_STDOUT_SHA,
                'source-before differs from retained frozen-B physical result')
        cargo = str(TOOLCHAIN / 'bin/cargo')
        manifest = 'trillionnium/Cargo.toml'
        for package in ('trnm-data-availability', 'trnm-pon-node'):
            run('clippy-default-' + package, [
                cargo, 'clippy', '--locked', '--offline', '--jobs', '2',
                '--manifest-path', manifest, '-p', package,
                '--all-targets', '--', '-D', 'warnings'])
        run('strict-clippy', [
            cargo, 'clippy', '--release', '--locked', '--offline', '--jobs', '2',
            '--manifest-path', manifest, '--workspace', '--all-targets',
            '--all-features', '--', '-D', 'warnings'])
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['traceback'] = traceback.format_exc()
    finally:
        try:
            require(source_command is not None, 'source gate was not admitted after setup checks')
            require(run('source-after', source_command, 300) == 0,
                    'original physical source-after gate failed')
            report['after_identity'] = identity()
            require(before == report['after_identity'], 'source identity changed')
            report['source_before_equals_after'] = (
                (OUT / 'source-before.stdout').read_bytes() ==
                (OUT / 'source-after.stdout').read_bytes())
            require(report['source_before_equals_after'], 'physical source output changed')
            report['source_matches_retained_frozen_b'] = (
                sha(OUT / 'source-before.stdout') ==
                sha(OUT / 'source-after.stdout') == SOURCE_STDOUT_SHA)
            require(report['source_matches_retained_frozen_b'], 'physical source pin changed')
            pinned_after = {path: sha(path) for path in pinned_before}
            report['pinned_after'] = pinned_after
            report['pinned_materials_unchanged'] = pinned_before == pinned_after
            require(report['pinned_materials_unchanged'], 'pinned material changed during execution')
            if report['accepted_release_main_binding']['preceding_tail_admitted']:
                report['accepted_release_main_binding']['unchanged_after_static'] = True
            require(sha(TAIL_SUMMARY) == tail_hash, 'preceding tail evidence changed')
            for item in report['commands']:
                for channel in ('stdout', 'stderr'):
                    path = OUT / (item['name'] + '.' + channel)
                    require(path.stat().st_size == item[channel + '_bytes'] and
                            sha(path) == item[channel + '_sha256'],
                            'retained command log failed readback: ' + str(path))
            report['all_command_logs_read_back'] = True
            report['resource_end'] = resources()
            check_resources(report['resource_end'])
        except BaseException as error:
            report['end_error'] = type(error).__name__ + ': ' + str(error)
        report['completed'] = True
        report['completed_unix_ns'] = time.time_ns()
        report['all_requested_commands_observed'] = (
            [item['name'] for item in report['commands']] == EXPECTED_COMMAND_NAMES)
        report['passed'] = (
            not report.get('error') and not report.get('end_error') and
            report['all_requested_commands_observed'] and all(
                item.get('exit_code') == 0 and not item.get('timed_out') and
                not item.get('launch_error') and not item.get('controlled_interruption')
                for item in report['commands']))
        report['status'] = 'passed' if report['passed'] else 'failed'
        save()
        print(json.dumps({'completed': True, 'passed': report['passed'],
                          'output': str(OUT), 'earlier_raw_available': False,
                          'native_operation_started': False}), flush=True)
    return 0 if report['passed'] else 1


def main():
    require(len(sys.argv) == 1, 'no unreviewed arguments')
    require(sys.flags.optimize == 0, 'Python optimization flags are not admitted')
    require(not OUT.exists(), 'fresh observation directory required')
    require(ROOT.is_dir() and CONTROL.is_dir() and BASE.is_dir(),
            'prepared ai395 execution paths required')
    tail_hash = sha(TAIL_SUMMARY)
    tail = json.loads(TAIL_SUMMARY.read_bytes())
    require(tail['source'] == HEAD and tail['completed'] is True,
            'preceding tail job has not completed on frozen B')
    require(tail['observer_sha256'] == TAIL_OBSERVER_SHA,
            'preceding tail summary observer identity changed')
    require(all(item.get('status') != 'running' for item in tail['commands']),
            'preceding tail retains a running command')
    os.umask(0o077)

    def interrupted(signum, _frame):
        raise RuntimeError('observer received signal ' + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with Path(str(TARGET) + '.owner.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return observe(tail, tail_hash)


if __name__ == '__main__':
    raise SystemExit(main())

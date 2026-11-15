#!/usr/bin/env python3
"""Run the authorized original tail gates and build one new release main; no model."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import time
import traceback

ROOT = Path('/home/qq/work/chain-bt-owner-convergence-20261112-4a0b')
CONTROL = Path(str(ROOT) + '-control')
BASE = Path(str(ROOT) + '-validation')
OUT = BASE / 'remaining-gates-02'
TARGET = Path(str(ROOT) + '-target')
HEAD = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
TOOLCHAIN = Path('/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
PROVIDER = Path('/home/qq/work/chain-cell-discovery-provider-f2568-20261108/runner/trnm-pq-provider-3.5.9.ReYCJ9gV/install')
PROVIDER_SHA = 'ed29dfe14c0686c876833e39fbeedb277846987f3728acc279c256b32259cf62'
SELECTOR = ('cell_native_shard_research_v2::tests::'
            'native_callback_requires_complete_current_release_selection_after_recovery')
os.umask(0o077)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def create(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def identity():
    actual = {name: subprocess.check_output(['/usr/bin/git', *argv], cwd=ROOT,
                                           text=True).strip()
              for name, argv in {'head': ['rev-parse', 'HEAD'],
                                 'tree': ['rev-parse', 'HEAD^{tree}'],
                                 'status': ['status', '--porcelain', '--untracked-files=all']}.items()}
    assert actual['head'] == HEAD and actual['status'] == '', actual
    return actual


def resources():
    result = {'nice': os.getpriority(os.PRIO_PROCESS, 0),
              'build_jobs': 2, 'model_limits_not_applied_to_compiler': True}
    try:
        rel = next(x.split(':', 2)[2] for x in Path('/proc/self/cgroup').read_text().splitlines()
                   if x.startswith('0::'))
        folder = Path('/sys/fs/cgroup') / rel.lstrip('/')
        result['cgroup_path'] = str(folder)
        result['cgroup'] = {key: (folder / key).read_text().strip()
                            for key in ('memory.max', 'memory.peak', 'memory.events', 'cpu.max', 'cpu.stat')}
    except (OSError, StopIteration) as error:
        result['observation_error'] = str(error)
    return result


def main():
    assert len(sys.argv) == 1, 'no unreviewed arguments'
    assert not OUT.exists(), 'fresh observation required'
    assert sha(PROVIDER / 'bin/openssl') == PROVIDER_SHA
    spec = json.loads((CONTROL / 'source-inputs.native-v2.json').read_text())
    python = spec['python']['path']
    assert sha(python) == spec['python']['sha256']
    assert sha(TOOLCHAIN / 'bin/cargo') == '841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66'
    assert sha(TOOLCHAIN / 'bin/rustc') == 'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6'
    assert json.loads((BASE / 'preparation-success.json').read_text())['passed'] is True
    prior_path = BASE / 'remaining-gates-01/summary.json'
    assert sha(prior_path) == 'b7244e43158fa05e40fc376cd79f6af99eb7a2ee21ace05e4345e068b5140ead'
    prior = json.loads(prior_path.read_bytes())
    assert prior['completed'] is True and prior['passed'] is False and prior['source'] == HEAD
    before = identity()
    inherited_overrides = {key: value for key, value in os.environ.items() if value and
                          (key.startswith('CARGO_PROFILE_') or key in
                           ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
                            'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'))}
    assert not inherited_overrides, ('unexpected compiler override', inherited_overrides)
    env = os.environ.copy()
    env.update(json.loads((CONTROL / 'build-environment.json').read_text()))
    env.update({'CARGO_TERM_COLOR': 'never', 'GIT_PAGER': 'cat'})
    assert env['CARGO_TARGET_DIR'] == str(TARGET) and env['CARGO_BUILD_JOBS'] == '2'
    assert env['LD_LIBRARY_PATH'] == str(TOOLCHAIN / 'lib')
    lock = Path(str(TARGET) + '.owner.lock').open('a+b')
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    OUT.mkdir(mode=0o700)
    TARGET.mkdir(mode=0o700, exist_ok=True)
    original_runner = ROOT / 'scripts/ci/run_cell_storage_four_gates_v1.py'
    source = [python, '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', HEAD]
    cargo = str(TOOLCHAIN / 'bin/cargo')
    tests = [cargo, 'test', '--release', '--locked', '--offline', '--jobs', '2',
             '--manifest-path', 'trillionnium/Cargo.toml']
    report = {'schema': 'trnm.bt-original-remaining-gates-and-release-main.v1',
              'source': HEAD, 'before_identity': before, 'started_unix_ns': time.time_ns(),
              'observer_sha256': sha(Path(__file__)), 'original_runner_sha256': sha(original_runner),
              'environment': {k: env[k] for k in json.loads((CONTROL / 'build-environment.json').read_text())},
              'resource_start': resources(), 'commands': [], 'completed': False, 'passed': False,
              'attempt': 2, 'predecessor_summary_sha256': sha(prior_path),
              'additional_runtime_preflight_is_separate_required_model_gate': True,
              'native_operation_started': False, 'production_activation': False,
              'independent_domains_qualified': False, 'model_efficacy_qualified': False}

    def save():
        pending = OUT / 'summary.pending.json'
        with pending.open('w') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, OUT / 'summary.json')

    def run(name, argv, timeout=1800, merge_stderr=False, environment_override=None):
        assert not (OUT / (name + '.stdout')).exists()
        out = OUT / (name + '.stdout'); err = OUT / (name + '.stderr')
        item = {'name': name, 'argv': argv, 'cwd': str(ROOT), 'timeout_seconds': timeout,
                'started_unix_ns': time.time_ns(), 'status': 'running',
                'stderr_merged_into_stdout': merge_stderr}
        if environment_override is not None:
            item['explicit_child_environment'] = environment_override
        report['commands'].append(item); save()
        print(json.dumps({'started': name, 'source': HEAD}), flush=True)
        start = time.monotonic(); timed_out = False; interrupted = None
        with out.open('xb') as stdout, err.open('xb') as stderr:
            process = subprocess.Popen(argv, cwd=ROOT,
                                       env=env if environment_override is None else environment_override,
                                       stdout=stdout,
                                       stderr=subprocess.STDOUT if merge_stderr else stderr,
                                       start_new_session=True)
            item['pid'] = process.pid; save()
            try:
                code = process.wait(timeout=timeout)
            except BaseException as error:
                timed_out = isinstance(error, subprocess.TimeoutExpired)
                if not timed_out:
                    interrupted = type(error).__name__ + ': ' + str(error)
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); code = process.wait()
        item.update(status='completed', exit_code=code, timed_out=timed_out,
                    elapsed_seconds=time.monotonic()-start, completed_unix_ns=time.time_ns(),
                    stdout_bytes=out.stat().st_size, stdout_sha256=sha(out),
                    stderr_bytes=err.stat().st_size, stderr_sha256=sha(err))
        if interrupted is not None:
            item['interrupted'] = interrupted
        if '--exact' in argv:
            selector = argv[argv.index('--')-1]
            observed = out.read_text(errors='replace')
            item['exact_native_test_observed'] = ('running 1 test\n' in observed and
                re.search(r'^test '+re.escape(selector)+r' \.\.\. (ok|FAILED)$', observed, re.MULTILINE) is not None)
        save(); print(json.dumps({'completed': name, 'exit_code': code, 'timed_out': timed_out}), flush=True)
        if interrupted is not None:
            raise RuntimeError(interrupted)
        return code if not timed_out and item.get('exact_native_test_observed', True) else 124

    save()
    try:
        assert run('preflight', ['/bin/bash', 'scripts/project-preflight.sh', '--audit'], 60) == 0
        assert run('source-before', source, 300) == 0
        controls = runpy.run_path(str(original_runner))['REQUIRED_NODE_CONTROLS']
        assert isinstance(controls, tuple) and len(controls) == 13
        report['required_node_controls'] = list(controls); save()
        run('sealed-research-python-controls', [python, '-B', '-m', 'unittest', 'discover',
             '-s', 'scripts', '-p', 'test_llm_cell_sealed_worker_v1.py', '-v'], 600, merge_stderr=True)
        run('sealed-research-python-readback', [python, '-B', 'scripts/ci/test_cell_storage_convergence_ci.py',
             '--check-sealed-controls', str(OUT / 'sealed-research-python-controls.stdout')], 600)
        native = tests + ['-p', 'trnm-pon-node', '--features', 'pq-native-openssl',
                         '--example', 'cell_native_shard_research_next_use_v2']
        assert run('native-grouped-example-pq', native + ['--', '--test-threads=1']) == 0
        run('native-complete-selection-pq', native + [SELECTOR, '--', '--exact', '--test-threads=1'])
        run('native-complete-selection-pq-readback', [python, '-B', 'scripts/ci/check_required_native_test.py',
             str(OUT / 'native-complete-selection-pq.stdout'), '--test', SELECTOR], 600)
        assert run('node-storage-default', tests + ['-p', 'trnm-pon-node', '--lib',
                   'store::storage_service::', '--', '--test-threads=1']) == 0
        for index, selector in enumerate(controls, 1):
            name = 'node-required-' + format(index, '02d')
            run(name, tests + ['-p', 'trnm-pon-node', '--lib', selector, '--', '--exact', '--test-threads=1'])
            run(name + '-readback', [python, '-B', 'scripts/ci/check_required_native_test.py',
                str(OUT / (name + '.stdout')), '--test', selector], 600)
        assert run('node-storage', tests + ['-p', 'trnm-pon-node', '--features', 'pq-native-openssl',
                   '--lib', 'storage_service', '--', '--test-threads=1']) == 0
        build = [cargo, 'build', '--release', '--locked', '--offline', '--jobs', '2',
                 '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--features',
                 'pq-native-openssl', '--example', 'cell_native_shard_research_next_use_v2',
                 '--message-format=json']
        assert run('native-release-main-build', build) == 0
        artifacts = []
        for line in (OUT / 'native-release-main-build.stdout').read_text().splitlines():
            item = json.loads(line)
            if (item.get('reason') == 'compiler-artifact' and
                item.get('target', {}).get('name') == 'cell_native_shard_research_next_use_v2' and
                item.get('executable')):
                artifacts.append(item)
        assert len(artifacts) == 1, 'exactly one normal main executable required'
        artifact = artifacts[0]
        expected = TARGET / 'release/examples/cell_native_shard_research_next_use_v2'
        assert artifact['executable'] == str(expected)
        assert artifact['target']['kind'] == ['example'] and artifact['target']['crate_types'] == ['bin']
        assert artifact['profile']['test'] is False and artifact['profile']['opt_level'] == '3'
        with expected.open('rb') as stream:
            assert stream.read(4) == b'\x7fELF'
        accepted = {'schema': 'trnm.bt-frozen-b-native-release-main.v1', 'source': HEAD,
                    'tree': before['tree'], 'path': str(expected), 'bytes': expected.stat().st_size,
                    'sha256': sha(expected), 'cargo_artifact': artifact,
                    'build_stdout_sha256': sha(OUT / 'native-release-main-build.stdout'),
                    'build_stderr_sha256': sha(OUT / 'native-release-main-build.stderr'),
                    'provider_sha256': PROVIDER_SHA, 'profile': 'release',
                    'historical_s3_profile_performance_reused': False, 'native_operation_started': False}
        create(OUT / 'accepted-release-main.json', accepted)
        report['accepted_release_main'] = accepted
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['traceback'] = traceback.format_exc()
    finally:
        try:
            assert run('source-after', source, 300) == 0
            report['after_identity'] = identity()
            assert before == report['after_identity']
            report['source_unchanged'] = ((OUT / 'source-before.stdout').read_bytes() ==
                                         (OUT / 'source-after.stdout').read_bytes())
            assert report['source_unchanged']
            assert sha(PROVIDER / 'bin/openssl') == PROVIDER_SHA
            assert sha(python) == spec['python']['sha256']
            report['provider_and_python_unchanged'] = True
        except BaseException as error:
            report['end_error'] = type(error).__name__ + ': ' + str(error)
        report['resource_end'] = resources()
        report['completed'] = True
        report['passed'] = (not report.get('error') and not report.get('end_error') and
                            'accepted_release_main' in report and all(
                            item.get('exit_code') == 0 and not item.get('timed_out') and
                            item.get('exact_native_test_observed', True)
                            for item in report['commands']))
        report['completed_unix_ns'] = time.time_ns()
        save(); print(json.dumps({'completed': True, 'passed': report['passed'],
                                 'output': str(OUT), 'native_operation_started': False}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

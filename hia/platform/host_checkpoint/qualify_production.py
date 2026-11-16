"""Execute the production Host ELF in the original fixed hosted-CI parent.

This controller provisions only a previously absent parent in an exact-source
GitHub-hosted job. It never provisions a developer workstation. Kernel reads
and the successful Host verdict belong to the sealed native production image.
The controller's observations and systemd lease confer no native authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.build import inspect_executable, sealed_executable
from hia.platform.host_checkpoint.build import source_manifest
from hia.platform.host_checkpoint.qualify import FIELDS, MAGIC, audit_trace

COUNTS = (1, 3, 17)
FORWARDED_ENV = (
    'PATH', 'CI', 'GITHUB_ACTIONS', 'GITHUB_WORKSPACE', 'GITHUB_RUN_ID',
    'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_SHA', 'GITHUB_EVENT_NAME',
    'GITHUB_EVENT_PATH', 'RUNNER_TEMP', 'RUNNER_ENVIRONMENT',
    'TRNM_EXPECTED_SOURCE_SHA', 'TRNM_CI_RECEIPT_DIR', 'PYTHONDONTWRITEBYTECODE',
)
PRODUCTION_PATHS = {
    '/': '.',
    '/sys/fs/cgroup/cgroup.controllers': 'controllers',
    '/sys/fs/cgroup/trnmponpublic.slice': 'sys/fs/cgroup/trnmponpublic.slice',
    '/proc/sys/kernel/random/boot_id': 'boot',
    '/proc/thread-self/cgroup': 'membership',
}
INSTALL_NEW_UNIT = '''import hashlib, os, sys
source, target, expected = sys.argv[1:]
with open(source, 'rb') as stream:
    data = stream.read(4097)
if len(data) > 4096 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit('reviewed unit bytes differ')
fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
try:
    os.fchmod(fd, 0o644)
    os.fchown(fd, 0, 0)
    written = 0
    while written < len(data):
        count = os.write(fd, data[written:])
        if count <= 0:
            raise OSError('short unit write')
        written += count
    os.fsync(fd)
finally:
    os.close(fd)
'''


class QualificationSignal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def emit_failure_evidence(output):
    """Keep bounded real diagnostics in the job log if artifact upload fails."""
    for relative in ('report.json', 'controller/systemd-run.log',
                     'child/inside-report.json', 'child/native.json'):
        path = output / relative
        try:
            if not path.exists():
                continue
            require(not path.is_symlink() and path.resolve(strict=True) == path
                    and path.is_file(), 'NONCANONICAL_FAILURE_EVIDENCE')
            with path.open('rb') as stream:
                size = os.fstat(stream.fileno()).st_size
                offset = max(0, size - 65536)
                stream.seek(offset)
                raw = stream.read(65536)
            record = {'schema': 'trnm.hia.production-failure-log.v1', 'path': relative,
                      'observed_file_bytes': size, 'offset': offset, 'bytes': len(raw),
                      'emitted_bytes_sha256': digest(raw),
                      'text': raw.decode('utf-8', errors='backslashreplace')}
        except BaseException as error:
            record = {'schema': 'trnm.hia.production-failure-log.v1', 'path': relative,
                      'diagnostic_read_error': repr(error)}
        # JSON escaping prevents child text from becoming workflow commands.
        try:
            print(json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)
        except (OSError, ValueError):
            # A closed job-log pipe must not replace the primary failure. The
            # original report and raw file remain the artifact inputs.
            return


def regular(path):
    require(path.is_absolute() and path.resolve(strict=True) == path
            and not path.is_symlink() and path.is_file(), 'NONCANONICAL_REGULAR_INPUT')
    return path.read_bytes()


def validate_build(directory):
    directory = directory.resolve(strict=True)
    report_raw = regular(directory / 'build.json')
    report = json.loads(report_raw)
    require(report.get('schema') == 'trnm.hia.fresh-host-build.v2'
            and report.get('status') == 'PASS', 'PRODUCTION_BUILD_NOT_QUALIFIED')
    current = source_manifest()
    for relative, expected in current.items():
        require(report['source_inputs'].get(relative) == expected,
                'PRODUCTION_BUILD_SOURCE_CHANGED:' + relative)
    for relative, expected in report['source_inputs'].items():
        name = Path(relative)
        require(not name.is_absolute() and '..' not in name.parts
                and name.as_posix() == relative, 'ESCAPING_BUILD_SOURCE')
        raw = regular(ROOT / name)
        require(expected == {'bytes': len(raw), 'sha256': digest(raw)},
                'PRODUCTION_BUILD_INPUT_CHANGED:' + relative)
    binding = json.loads(regular(ROOT / 'hia/qualification/compiler-binding.json'))
    require(report.get('compiler_sha256') == binding['compiler_sha256']
            and report.get('compiler_qualification_binding') == binding,
            'PRODUCTION_BUILD_COMPILER_CHANGED')
    image = regular(directory / 'owner.elf')
    require(report['executable']['sha256'] == digest(image)
            and report['executable']['bytes'] == len(image), 'PRODUCTION_ELF_CHANGED')
    require(report['fixture_executable']['sha256'] != digest(image),
            'FIXTURE_CANNOT_REPLACE_PRODUCTION_IMAGE')
    inspect_executable(image)
    return image, report, digest(report_raw)


def hosted_context(environment=None, uid=None):
    environment = os.environ if environment is None else environment
    uid = os.getuid() if uid is None else uid
    require(environment.get('GITHUB_ACTIONS') == 'true'
            and environment.get('CI') == 'true'
            and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and uid != 0, 'HOSTED_CI_ONLY_NO_LOCAL_PROVISION')
    require(re.fullmatch('[0-9a-f]{40}', environment.get('TRNM_EXPECTED_SOURCE_SHA', '')),
            'EXACT_COMMITTED_SOURCE_REQUIRED')
    require(environment.get('GITHUB_RUN_ID', '').isdecimal()
            and environment.get('GITHUB_RUN_ATTEMPT', '').isdecimal()
            and re.fullmatch('[A-Za-z0-9_-]{1,80}', environment.get('GITHUB_JOB', '')),
            'EXACT_HOSTED_JOB_REQUIRED')


def normalize_trace(text):
    """Map only exact quoted fixed path arguments to the shared trace grammar."""
    return re.sub(r'"([^"\\]*)"',
                  lambda found: '"' + PRODUCTION_PATHS.get(found[1], found[1]) + '"', text)


def service_argv(service, directory, output, uid, gid, environment):
    require(re.fullmatch(r'trnm-hia-host-[0-9]+-[0-9]+-[A-Za-z0-9_-]+-[0-9]+\.service', service),
            'UNOWNED_SERVICE_NAME')
    return [
        'sudo', '-n', 'systemd-run', '--unit=' + service, '--wait', '--pipe', '--collect',
        '--service-type=exec', '--expand-environment=no', '--slice=trnmponpublic.slice',
        '--uid=' + str(uid), '--gid=' + str(gid), '--working-directory=' + str(ROOT),
        '--property=KillMode=control-group', '--property=TimeoutStopSec=20s',
        '--property=Delegate=no', '--property=NoNewPrivileges=yes',
        '--property=CapabilityBoundingSet=',
        *['--setenv=' + key + '=' + environment[key]
          for key in FORWARDED_ENV if key in environment],
        sys.executable, '-B', str(Path(__file__).resolve()), '--inside',
        '--build', str(directory), '--output', str(output), '--service', service,
    ]


def read_exact(stream, size, capture, timeout=20):
    end = time.monotonic() + timeout
    result = bytearray()
    while len(result) < size:
        remaining = end - time.monotonic()
        require(remaining > 0, 'PRODUCTION_NATIVE_OBSERVATION_TIMEOUT')
        ready, _, _ = select.select([stream], [], [], remaining)
        require(ready, 'PRODUCTION_NATIVE_OBSERVATION_TIMEOUT')
        raw = os.read(stream.fileno(), size - len(result))
        require(raw, 'PRODUCTION_NATIVE_INCOMPLETE_RECEIPT')
        capture.extend(raw)
        result.extend(raw)
    return bytes(result)


def drain_owned_process(process, stdout, stderr):
    """Reap and drain an owned process even if it exited before observation."""
    errors = []
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            # The owned group may have exited between poll and killpg. Its
            # unread pipes still need draining, and this race is not a failure.
            pass
        except BaseException as error:
            errors.append('OWNED_PROCESS_GROUP_STOP: ' + repr(error))
    try:
        extra, error = process.communicate(timeout=3)
        stdout.extend(extra)
        stderr.extend(error)
    except subprocess.TimeoutExpired as error:
        # communicate's timeout carries real bytes read so far. The caller
        # has not appended any previous communicate attempt's partial output.
        stdout.extend(error.output or b'')
        stderr.extend(error.stderr or b'')
        errors.append('OWNED_PROCESS_GROUP_REAP_TIMEOUT')
    except BaseException as error:
        errors.append('OWNED_PROCESS_GROUP_DRAIN: ' + repr(error))
    return errors


def native_production(directory, output, service):
    image, build, build_hash = validate_build(directory)
    trace_path = output / 'syscalls.raw'
    tracer = shutil.which('strace')
    require(tracer is not None, 'INDEPENDENT_PRODUCTION_TRACE_REQUIRED')
    fd = sealed_executable(image, 'hia-production-host-qualified')
    process = None
    drained = False
    primary_failure = None
    stdout, stderr = bytearray(), bytearray()
    receipts, native_context = [], []
    started = time.monotonic_ns()
    result = {
        'schema': 'trnm.hia.production-host-native.v1', 'status': 'FAIL',
        'executable_sha256': digest(image), 'build_report_sha256': build_hash,
        'source_inputs': build['source_inputs'], 'receipts': receipts,
        'native_context': native_context, 'requested_counts': list(COUNTS),
        'whole_node_or_service_budget_qualified': False,
    }
    try:
        process = subprocess.Popen([tracer, '-f', '-qq', '-s', '256', '-o', str(trace_path),
                                    '/proc/self/fd/' + str(fd)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=ROOT, env={'PATH': ''}, pass_fds=(fd,), start_new_session=True)
        os.close(fd)
        fd = None
        expected_checks = 1
        previous = None
        for sequence in range(len(COUNTS) + 1):
            if sequence:
                count = COUNTS[sequence - 1]
                process.stdin.write(struct.pack('<QQQ', count, 0, 4096))
                process.stdin.flush()
                expected_checks += count
            raw = read_exact(process.stdout, 128, stdout)
            receipt = dict(zip(FIELDS, struct.unpack('<16Q', raw)))
            receipts.append(receipt)
            require(receipt['magic'] == MAGIC and receipt['fixture'] == 0
                    and receipt['error'] == 0 and receipt['sequence'] == sequence
                    and receipt['full_checks'] == expected_checks,
                    'PRODUCTION_NATIVE_RECEIPT_REFUSED_OR_INCOMPLETE')
            tid = receipt['TID']
            require(0 < tid < 2**31, 'PRODUCTION_NATIVE_TID_REQUIRED')
            proc = Path('/proc') / str(tid)
            current = (proc / 'task' / str(tid) / 'cgroup').read_text().strip()
            expected = '0::/trnmponpublic.slice/' + service
            require(current == expected or current.startswith(expected + '/'),
                    'PRODUCTION_NATIVE_THREAD_NOT_IN_OWNED_SERVICE')
            require(digest((proc / 'exe').read_bytes()) == digest(image),
                    'RUNNING_PRODUCTION_IMAGE_CHANGED')
            native_context.append({'tid': tid, 'membership': current,
                                   'running_executable_sha256': digest(image)})
            if previous is not None:
                count = COUNTS[sequence - 1]
                require(receipt['TID'] == previous['TID']
                        and receipt['opens'] - previous['opens'] == 8 * count
                        and receipt['reads'] - previous['reads'] == 14 * count
                        and receipt['thread_CPU_ns'] > 0 and receipt['wall_ns'] > 0,
                        'PRODUCTION_NATIVE_FRESH_CHECKS_DIFFER')
            previous = receipt
        process.stdin.close()
        process.stdin = None
        extra, error = process.communicate(timeout=20)
        stdout.extend(extra)
        stderr.extend(error)
        drained = True
        require(process.returncode == 0 and not extra and not error,
                'PRODUCTION_NATIVE_COMPLETION_FAILED')
        raw_trace = regular(trace_path)
        parsed = audit_trace(normalize_trace(raw_trace.decode()),
                             expected_checks=expected_checks, expected_error=0)
        require('getuid(' not in raw_trace.decode(), 'PRODUCTION_USED_FIXTURE_UID_PATH')
        require(sum(1 for line in raw_trace.decode().splitlines()
                    if re.search(r'gettid\(\)\s+=\s+' + str(receipts[0]['TID']) + r'\b', line))
                == len(COUNTS) + 1, 'TRACE_NATIVE_THREAD_IDENTITY_DIFFERS')
        final_image, _, final_hash = validate_build(directory)
        require(final_image == image and final_hash == build_hash, 'BUILD_CHANGED_DURING_EXECUTION')
        result.update(status='PASS', full_checks=expected_checks,
                      independent_syscall_trace=parsed, raw_trace_sha256=digest(raw_trace),
                      actual_fixed_parent_positive=True)
    except BaseException as error:
        primary_failure = error
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        cleanup_errors = []
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as error:
                cleanup_errors.append('SEALED_IMAGE_CLOSE: ' + repr(error))
        if process is not None and not drained:
            cleanup_errors.extend(drain_owned_process(process, stdout, stderr))
        result['cleanup_errors'] = cleanup_errors
        if cleanup_errors:
            result['status'] = 'FAIL'
        result['exit_code'] = None if process is None else process.returncode
        result['elapsed_wall_ns'] = time.monotonic_ns() - started
        result['stdout_sha256'] = digest(stdout)
        result['stderr_sha256'] = digest(stderr)
        (output / 'stdout.raw').write_bytes(stdout)
        (output / 'stderr.raw').write_bytes(stderr)
        write_new(output / 'native.json', result)
        if cleanup_errors and primary_failure is None:
            raise ValueError('OWNED_NATIVE_PROCESS_CLEANUP_FAILED')
    return result


def ci_modules():
    sys.path.insert(0, str(ROOT / 'scripts/ci'))
    import public_host_ci_observation as observation
    import public_fixture_host_lease as lease
    import run_from_zero_host as existing
    from verify_ci_source import verify
    return observation, lease, existing, verify


def inside(directory, output, service):
    hosted_context()
    observation, _, _, verify = ci_modules()
    require(Path.cwd().resolve() == ROOT, 'ORIGINAL_WORKING_DIRECTORY_REQUIRED')
    before = observation.capture('hia-native-inside-before', service)
    require(not observation.validate(before, inside=True, uid=os.getuid(), gid=os.getgid(), cwd=str(ROOT)),
            'ACTUAL_UNPRIVILEGED_HOST_SERVICE_REQUIRED')
    source = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
    write_new(output / 'inside-before.json', before)
    write_new(output / 'inside-source-before.json', source)
    result = {'schema': 'trnm.hia.production-host-inside.v1', 'status': 'FAIL',
              'cleanup_errors': []}
    primary_failure = None
    try:
        native_production(directory, output, service)
        result['status'] = 'PASS'
    except BaseException as error:
        primary_failure = error
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        try:
            after = observation.capture('hia-native-inside-after', service)
            write_new(output / 'inside-after.json', after)
            require(not observation.validate(after, inside=True, uid=os.getuid(), gid=os.getgid(),
                                             cwd=str(ROOT), reference=before), 'ACTUAL_HOST_CHANGED')
        except BaseException as error:
            result['cleanup_errors'].append('HOST_AFTER: ' + repr(error))
        try:
            final_source = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
            write_new(output / 'inside-source-after.json', final_source)
            require(source == final_source, 'SOURCE_CHANGED_DURING_PRODUCTION_CHECKS')
        except BaseException as error:
            result['cleanup_errors'].append('SOURCE_AFTER: ' + repr(error))
        if result['cleanup_errors']:
            result['status'] = 'FAIL'
        write_new(output / 'inside-report.json', result)
        if result['cleanup_errors'] and primary_failure is None:
            raise ValueError('PRODUCTION_HOST_INSIDE_FINAL_OBSERVATION_FAILED')
    return 0


def outer(directory, output):
    hosted_context()
    require(Path.cwd().resolve() == ROOT, 'ORIGINAL_WORKING_DIRECTORY_REQUIRED')
    directory = directory.resolve(strict=True)
    output = output.absolute()
    require(output.resolve() == output and not output.is_relative_to(ROOT)
            and not output.exists() and not output.is_symlink(), 'FRESH_EXTERNAL_OUTPUT_REQUIRED')
    require(os.environ.get('TRNM_CI_RECEIPT_DIR') == str(output), 'EXACT_CURRENT_RECEIPT_DIRECTORY_REQUIRED')
    output.mkdir(parents=True, mode=0o700)
    observation, lease, existing, verify = ci_modules()
    result = {'schema': 'trnm.hia.production-host-controller.v1', 'status': 'FAIL',
              'whole_node_or_service_budget_qualified': False,
              'local_workstation_provisioned': False, 'parent_preexisting': None,
              'setup_completed': [], 'cleanup_errors': [],
              'unit_install_attempted': False, 'reviewed_unit_installed': False,
              'parent_retained_for_ephemeral_job_teardown': False}
    uid, gid = os.getuid(), os.getgid()
    service = 'trnm-hia-host-{}-{}-{}-{}.service'.format(
        os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'],
        os.environ['GITHUB_JOB'], os.getpid())
    result['service'] = service
    owned_service = False
    provisioned = None
    controller = output / 'controller'
    child = output / 'child'
    controller.mkdir()
    child.mkdir()

    def setup(arguments, name, *, must_succeed=True):
        with (controller / (name + '.log')).open('xb') as stream:
            done = subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT, timeout=30)
        require(not must_succeed or done.returncode == 0, name + '_FAILED')
        return done.returncode

    try:
        image, _, build_hash = validate_build(directory)
        result['build_report_sha256'] = build_hash
        result['executable_sha256'] = digest(image)
        source = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
        write_new(output / 'source.json', source)
        with lease.parent_lock():
            primary_failure = None
            try:
                before = observation.capture('before-provision', service)
                write_new(controller / 'before-provision.json', before)
                require(Path('/run/systemd/system').is_dir()
                        and Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'SYSTEMD_CGROUP_V2_REQUIRED')
                require(not observation.RUNTIME_UNIT.exists() and not observation.RUNTIME_UNIT.is_symlink()
                        and not observation.PARENT.exists() and not observation.PARENT.is_symlink(),
                        'PREEXISTING_PARENT_WILL_NOT_BE_ADOPTED')
                result['parent_preexisting'] = False
                lease.require_no_seal()
                setup(['systemctl', 'show', '--all', '--property=' + ','.join(existing.PARENT_PROPERTIES),
                       observation.UNIT], 'parent-properties')
                properties = existing.validate_unprovisioned_parent((controller / 'parent-properties.log').read_text())
                write_new(controller / 'unprovisioned-parent.json', properties)
                unit_source = ROOT / 'config/systemd' / observation.UNIT
                require(digest(regular(unit_source)) == observation.UNIT_SHA256, 'ORIGINAL_REVIEWED_UNIT_REQUIRED')
                require(not observation.RUNTIME_UNIT.exists() and not observation.PARENT.exists(),
                        'PARENT_CHANGED_BEFORE_INSTALL')
                result['unit_install_attempted'] = True
                result['partial_setup_retained_for_ephemeral_job_teardown'] = True
                setup(['sudo', '-n', '/usr/bin/python3', '-I', '-S', '-c', INSTALL_NEW_UNIT,
                       str(unit_source), str(observation.RUNTIME_UNIT), observation.UNIT_SHA256],
                      'install-reviewed-unit')
                result['reviewed_unit_installed'] = True
                result['setup_completed'].append('install-reviewed-unit')
                setup(['sudo', '-n', 'systemctl', 'daemon-reload'], 'systemd-reload')
                result['setup_completed'].append('systemd-reload')
                setup(['sudo', '-n', 'systemctl', 'start', observation.UNIT], 'start-fixed-parent')
                result['setup_completed'].append('start-fixed-parent')
                result['parent_retained_for_ephemeral_job_teardown'] = True
                setup(['systemctl', 'show', observation.UNIT,
                       '--property=' + ','.join(lease.SYSTEMD_PROPERTIES)], 'actual-systemd-parent')
                provisioned = observation.capture('outside-after-provision', service)
                write_new(controller / 'after-provision.json', provisioned)
                require(not observation.validate(provisioned, inside=False, uid=uid, gid=gid, cwd=str(ROOT)),
                        'ACTUAL_FIXED_PARENT_INVALID')
                argv = service_argv(service, directory, child, uid, gid, os.environ)
                result['parent_lease'] = lease.seal_after_provision(provisioned, controller, argv, setup)
                result['setup_completed'].append('seal-owned-parent')
                result['partial_setup_retained_for_ephemeral_job_teardown'] = False
                setup(['systemctl', 'show', '--property=LoadState', '--value', service],
                      'child-load-state', must_succeed=False)
                require((controller / 'child-load-state.log').read_text().strip() == 'not-found',
                        'CHILD_SERVICE_ALREADY_EXISTS')
                owned_service = True
                with (controller / 'systemd-run.log').open('xb') as stream:
                    process = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
                result['systemd_run_exit'] = process.returncode
                require(process.returncode == 0, 'ACTUAL_PRODUCTION_SERVICE_FAILED')
                actual = json.loads(regular(child / 'native.json'))
                require(actual.get('status') == 'PASS' and actual.get('actual_fixed_parent_positive') is True
                        and actual.get('executable_sha256') == digest(image)
                        and actual.get('build_report_sha256') == build_hash,
                        'ACTUAL_NATIVE_PRODUCTION_EVIDENCE_REQUIRED')
                result['native'] = actual
                result['status'] = 'PASS'
            except BaseException as error:
                primary_failure = error
                result['failure'] = type(error).__name__ + ': ' + str(error)
                raise
            finally:
                if owned_service:
                    try:
                        setup(['systemctl', 'show', '--property=LoadState', '--value', service],
                              'owned-child-final-state', must_succeed=False)
                        if (controller / 'owned-child-final-state.log').read_text().strip() != 'not-found':
                            setup(['sudo', '-n', 'systemctl', 'stop', service], 'stop-owned-child')
                    except BaseException as error:
                        result['cleanup_errors'].append('OWNED_SERVICE_STOP: ' + repr(error))
                if provisioned is not None:
                    try:
                        after = observation.capture('outside-after-owned-child', service)
                        write_new(controller / 'after-owned-child.json', after)
                        require(not observation.validate(after, inside=False, uid=uid, gid=gid, cwd=str(ROOT),
                                                         reference=provisioned), 'HOST_CHANGED_AFTER_OWNED_CHILD')
                        setup(['systemctl', 'show', observation.UNIT,
                               '--property=' + ','.join(lease.SYSTEMD_PROPERTIES)], 'actual-systemd-parent-after')
                        if result.get('parent_lease') is not None:
                            result['final_parent_lease'] = lease.validate_for_reuse(after, controller / 'actual-systemd-parent-after.log')
                            require(result['parent_lease'] == result['final_parent_lease'], 'JOB_OWNED_PARENT_CHANGED')
                        else:
                            result['cleanup_errors'].append('PARENT_SETUP_HAS_NO_COMPLETED_LEASE')
                    except BaseException as error:
                        result['cleanup_errors'].append('PARENT_AFTER: ' + repr(error))
                if result['cleanup_errors']:
                    result['status'] = 'FAIL'
                    if primary_failure is None:
                        raise ValueError('PRODUCTION_HOST_FINAL_OBSERVATION_FAILED')
        final_source = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
        write_new(output / 'source-after.json', final_source)
        require(source == final_source, 'SOURCE_CHANGED_DURING_PRODUCTION_QUALIFICATION')
    except BaseException as error:
        result['status'] = 'FAIL'
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        try:
            write_new(output / 'report.json', result)
        finally:
            if result['status'] != 'PASS':
                emit_failure_evidence(output)
    return 0


def main():
    if not __debug__:
        raise RuntimeError('Production Host qualification refuses optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--service')
    args = parser.parse_args()
    require(args.inside == bool(args.service), 'EXPLICIT_OWNED_SERVICE_REQUIRED')
    def interrupted(number, _frame):
        raise QualificationSignal('Owned qualification interrupted by signal ' + str(number))
    previous = {number: signal.signal(number, interrupted)
                for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        if args.inside:
            return inside(args.build, args.output, args.service)
        return outer(args.build, args.output)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == '__main__':
    raise SystemExit(main())

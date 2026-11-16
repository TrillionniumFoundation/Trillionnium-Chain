"""Actual static-ELF qualification of the fixed-parent HIA resource owner."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.build import sealed_executable, sha256, new_output, write_json
from .build import Build
from .cases import cases, corpus_bytes
from .native_io import FIELDS, MAGIC, PARENT, Session, provision, require, run_case


def protocol_controls(image: bytes, output: Path) -> list[dict]:
    rows = []
    for name, request, error in [
        ('unsupported-operation', struct.pack('<3Q', 3, 0, 4096), 11),
        ('zero-operation', struct.pack('<3Q', 0, 0, 4096), 11),
        ('invalid-gate', struct.pack('<3Q', 1, 9, 4096), 11),
        ('zero-chunk', struct.pack('<3Q', 1, 0, 0), 11),
        ('large-chunk', struct.pack('<3Q', 1, 0, 4097), 11),
        ('short-request', b'\1', 11),
    ]:
        directory = output / name
        directory.mkdir()
        provision(directory)
        session = Session(image, directory)
        try:
            session.receipt()
            session.write(request)
            if name == 'short-request':
                session.process.stdin.close()
                session.process.stdin = None
            session.receipt(error)
            if session.process.stdin is None:
                out, err = session.process.communicate(timeout=3)
                session.stdout.extend(out); session.stderr.extend(err)
                require(not out and not err and session.process.returncode == 64 + error,
                        'Truncated protocol did not fail closed')
                row = session.save('PASS')
            else:
                row = session.finish(error)
            row['name'] = name
            rows.append(row)
        except BaseException as error_value:
            session.abort(str(error_value))
            raise
    for gate in (5, 6, 7, 8):
        directory = output / ('gate-eof-' + str(gate))
        directory.mkdir()
        provision(directory)
        session = Session(image, directory)
        try:
            session.receipt()
            session.request(gate=gate)
            session.gate(gate)
            session.process.stdin.close()
            session.process.stdin = None
            row = session.receipt(9)
            require(row['qualified_sample'] == 0, 'Gate EOF qualified a sample')
            out, err = session.process.communicate(timeout=3)
            session.stdout.extend(out); session.stderr.extend(err)
            require(not out and not err and session.process.returncode == 73, 'Gate EOF exit mismatch')
            record = session.save('PASS')
            record['name'] = 'gate-eof-' + str(gate)
            rows.append(record)
        except BaseException as error:
            session.abort(str(error))
            raise
    directory = output / 'real-eintr'
    directory.mkdir()
    provision(directory)
    session = Session(image, directory)
    try:
        session.receipt()
        end = time.monotonic() + 3
        while time.monotonic() < end:
            if 'pipe_read' in Path(f'/proc/{session.process.pid}/wchan').read_text():
                break
            time.sleep(0.001)
        else:
            raise ValueError('Native owner did not reach its actual blocking protocol read')
        os.kill(session.process.pid, signal.SIGUSR1)
        time.sleep(0.01)
        session.request(chunk=1)
        observed = session.receipt()
        require(observed['eintr_retries'] > 0 and observed['qualified_sample'] == 1,
                'Actual EINTR did not preserve the physical sample')
        row = session.finish()
        row['name'] = 'real-eintr'
        rows.append(row)
    except BaseException as error:
        session.abort(str(error))
        raise
    return rows


def trace(image: bytes, output: Path) -> dict:
    directory = output / 'trace'
    directory.mkdir()
    provision(directory)
    executable = shutil.which('strace')
    if executable is None:
        return {'status': 'UNKNOWN', 'reason': 'strace unavailable'}
    descriptor = sealed_executable(image, 'hia-resource-trace')
    try:
        command = [executable, '-f', '-qq', '-yy', '-s', '4096', '-e',
                   'trace=openat,read,close,fstat,newfstatat,write,gettid,clock_gettime,mremap',
                   '-o', str(directory / 'syscalls.log'), '/proc/self/fd/' + str(descriptor)]
        observed = subprocess.run(command, input=struct.pack('<3Q', 1, 0, 4096),
            cwd=directory, env={'PATH': ''}, pass_fds=(descriptor,),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    finally:
        os.close(descriptor)
    (directory / 'stdout.raw').write_bytes(observed.stdout)
    (directory / 'stderr.raw').write_bytes(observed.stderr)
    raw = (directory / 'syscalls.log').read_bytes()
    common = {'exit_code': observed.returncode, 'trace_sha256': sha256(raw),
              'native_image_sha256': sha256(image),
              'stdout_sha256': sha256(observed.stdout), 'stderr_sha256': sha256(observed.stderr)}
    if observed.returncode != 0 and (b'Operation not permitted' in observed.stderr
                                    or b'PTRACE' in observed.stderr):
        return {'status': 'UNKNOWN', 'reason': 'actual ptrace denied', **common}
    require(observed.returncode == 0 and len(observed.stdout) == 512 and not observed.stderr,
            'Independent trace did not execute the actual native sample')
    rows = [dict(zip(FIELDS, struct.unpack('<32Q', observed.stdout[i:i+256]))) for i in (0, 256)]
    require(rows[0]['magic'] == MAGIC and rows[1]['qualified_sample'] == 1
            and rows[1]['complete_checks'] - rows[0]['complete_checks'] == 2,
            'Traced owner did not preserve two independent fresh checks')
    lines = raw.decode().splitlines()
    counter_opens = []
    for index, line in enumerate(lines):
        match = re.search(r'openat\((\d+)<([^>]+)>, "(cpu\.stat|memory\.current|pids\.current)", ([^)]+)\) = (\d+)<', line)
        if match:
            require(all(flag in match[4] for flag in ('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK')),
                    'Counter open flags were not the original read-only profile')
            counter_opens.append((index, int(match[1]), match[2], match[3], int(match[5])))
        if 'openat(' in line:
            require(not any(flag in line for flag in ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC')),
                    'Native resource owner attempted a writable open')
    require([row[3] for row in counter_opens] == ['cpu.stat', 'memory.current', 'pids.current'],
            'Actual counter syscall order differs')
    require(len({(row[1], row[2]) for row in counter_opens}) == 1,
            'Actual sample did not reuse exactly its one checked local parent descriptor')
    first, last = counter_opens[0][0], counter_opens[-1][0]
    parent_fd, parent_name = counter_opens[0][1:3]
    closes_parent = re.compile(r'close\(' + str(parent_fd) + '<' + re.escape(parent_name) + r'>\)')
    require(not any(closes_parent.search(line) for line in lines[first:last]),
            'Parent FD closed before all counter opens')
    for _, _, _, name, fd in counter_opens:
        require(any(re.search(r'read\(' + str(fd) + r'<[^>]+/' + re.escape(name)
                              + r'>, "", [0-9]+\) = 0', line) for line in lines),
                'Counter file did not reach a real EOF')
        require(any(re.search(r'fstat\(' + str(fd) + r'<[^>]+/' + re.escape(name)
                              + r'>, .*S_IFREG', line) for line in lines),
                'Counter regular-file type was not independently checked')
    boot_opens = [index for index, line in enumerate(lines) if 'openat(' in line and '"boot"' in line]
    require(len(boot_opens) == 4 and boot_opens[2] < first and last < boot_opens[3],
            'Fresh boot checks did not bracket the three real counter files')
    require(any(closes_parent.search(line) for line in lines[last:boot_opens[3]]),
            'Sample parent descriptor survived into the final fresh check')
    return {'status': 'PASS', 'counter_order': [r[3] for r in counter_opens],
            'same_checked_parent_fd': True, 'closed_before_second_fresh_check': True,
            'complete_boot_reads': len(boot_opens), 'receipts': rows, **common}


def qualify(output: Path, *, require_trace=False) -> dict:
    output.mkdir()
    report = {'schema': 'trnm.hia.host-resource-qualification.v1', 'status': 'FAIL',
              'whole_node_or_service_budget_qualified': False,
              'production_fixed_parent_positive_qualified': False,
              'wait4_or_paid_thread_cpu_owner_qualified': False}
    try:
        build = Build(output / 'build')
        built = build.build()
        report['build'] = built
        semantic = output / 'semantic'
        semantic.mkdir()
        corpus = corpus_bytes()
        (output / 'cases.jsonl').write_bytes(corpus)
        report['corpus_sha256'] = sha256(corpus)
        report['semantic'] = []
        for case in cases():
            report['semantic'].append(run_case(build.fixture_executable, semantic / case['name'], case))
        controls = output / 'controls'
        controls.mkdir()
        report['controls'] = protocol_controls(build.fixture_executable, controls)
        report['trace'] = trace(build.fixture_executable, output)
        build.check_pin()
        report['source_after'] = build.source_inputs
        report['semantic_count'] = len(report['semantic'])
        report['physical_control_count'] = len(report['controls'])
        report['count'] = report['semantic_count'] + report['physical_control_count']
        if require_trace:
            require(report['trace']['status'] == 'PASS', 'Mandatory independent resource trace did not pass')
        report['status'] = 'PASS'
    except BaseException as error:
        report['error'] = str(error)
        write_json(output / 'report.json', report)
        raise
    write_json(output / 'report.json', report)
    return report


def main() -> int:
    if not __debug__:
        raise RuntimeError('Resource qualification refuses optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-trace', action='store_true')
    args = parser.parse_args()
    parent = new_output(args.output)
    try:
        result = qualify(parent / 'qualification', require_trace=args.require_trace)
        print(json.dumps({'status': result['status'], 'semantic_count': result['semantic_count'],
            'physical_control_count': result['physical_control_count'], 'trace': result['trace']['status'],
            'report': str(parent / 'qualification/report.json')}, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error),
                          'report': str(parent / 'qualification/report.json')}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

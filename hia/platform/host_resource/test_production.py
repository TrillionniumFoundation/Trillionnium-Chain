"""Controller/trace refusal controls. Synthetic traces are never runtime proof."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.platform.host_resource import qualify_production as production

TID = 12345


def quoted(raw):
    result = '"'
    for value in raw:
        if value in (34, 92):
            result += '\\' + chr(value)
        elif 32 <= value <= 126:
            result += chr(value)
        else:
            result += '\\' + format(value, '03o')
    return result + '"'


def synthetic(*, extra_cpu=b'', fixture=False):
    """A parser control constructed in Python; it is not executed native code."""
    lines, marks = [], {}
    def emit(line, mark=None):
        if mark:
            marks[mark] = len(lines)
        lines.append(str(TID) + ' ' + line)
    def stream(path, fd, content=b'data', *, directory='AT_FDCWD', regular=False):
        flags = 'O_RDONLY|O_CLOEXEC'
        if regular:
            flags += '|O_NOFOLLOW|O_NONBLOCK'
        emit('openat(' + directory + ', "' + path + '", ' + flags + ') = ' + str(fd))
        if regular:
            emit('fstat(' + str(fd) + ', {st_mode=S_IFREG|0600}) = 0')
        emit('read(' + str(fd) + ', ' + quoted(content) + ', 129) = ' + str(len(content)))
        emit('read(' + str(fd) + ', "", ' + str(129 - len(content)) + ') = 0')
        emit('close(' + str(fd) + ') = 0')
    def checkpoint(*, initial=False, held=False, mark=None):
        if mark:
            marks[mark] = len(lines)
        stream('boot', 3)
        emit('openat(AT_FDCWD, "' + production.PARENT
             + '", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY) = 3')
        emit('fstat(3, {st_mode=S_IFDIR|0700}) = 0')
        if not initial:
            stream('membership', 4)
        for name in production.host.audit_trace.__globals__['LIMITS']:
            stream(name, 4, directory='3', regular=True)
        if not initial:
            emit('newfstatat(AT_FDCWD, "' + production.PARENT
                 + '", {st_mode=S_IFDIR|0700}, AT_SYMLINK_NOFOLLOW) = 0')
        if not held:
            emit('close(3) = 0')
    def counter(name, data, bound, sequence):
        key = str(sequence) + '-' + name
        emit('openat(3, "' + name + '", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK) = 4', key + '-open')
        emit('fstat(4, {st_mode=S_IFREG|0644}) = 0', key + '-stat')
        emit('read(4, ' + quoted(data) + ', ' + str(bound + 1) + ') = ' + str(len(data)), key + '-read')
        emit('read(4, "", ' + str(bound + 1 - len(data)) + ') = 0', key + '-eof')
        emit('close(4) = 0', key + '-close')
    emit('execve("/proc/self/fd/9", ["/proc/self/fd/9"], 0x0) = 0')
    emit('mmap(NULL, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x700000')
    emit('mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x710000')
    old = None
    for index, path in enumerate(('.', 'sys', 'fs', 'cgroup', 'trnmponpublic.slice')):
        fd = 3 + index % 2
        directory = 'AT_FDCWD' if old is None else str(old)
        flags = 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH'
        if index != 4:
            flags += '|O_DIRECTORY'
        emit('openat(' + directory + ', "' + path + '", ' + flags + ') = ' + str(fd))
        if old is not None:
            emit('close(' + str(old) + ') = 0')
        old = fd
    emit('fstat(3, {st_mode=S_IFDIR|0700}) = 0')
    emit('close(3) = 0')
    emit('newfstatat(AT_FDCWD, "controllers", {st_mode=S_IFREG|0644}, 0) = 0')
    emit('newfstatat(AT_FDCWD, "' + production.PARENT
         + '", {st_mode=S_IFDIR|0700}, AT_SYMLINK_NOFOLLOW) = 0')
    checkpoint(initial=True)
    checkpoint()
    rows, output = [], bytearray()
    for sequence in range(4):
        if sequence:
            request = struct.pack('<3Q', production.OPERATIONS[sequence - 1], 0, 4096)
            emit('read(0, ' + quoted(request) + ', 24) = 24', 'request-' + str(sequence))
            checkpoint(held=True, mark='pre-' + str(sequence))
            cpu = (b'usage_usec ' + str(sequence * 10).encode() + b'\nnr_periods '
                   + str(sequence * 20).encode() + b'\nnr_throttled '
                   + str(sequence * 3).encode() + b'\nthrottled_usec '
                   + str(sequence * 40).encode() + b'\n' + extra_cpu)
            memory = str(4096 // sequence).encode() + b'\n'
            pids = b'2\n'
            counter('cpu.stat', cpu, 2048, sequence)
            counter('memory.current', memory, 64, sequence)
            counter('pids.current', pids, 64, sequence)
            emit('close(3) = 0', 'sample-parent-close-' + str(sequence))
            checkpoint(mark='post-' + str(sequence))
        row = {key: 0 for key in production.FIELDS}
        row.update(magic=production.MAGIC, fixture=int(fixture), sequence=sequence,
                   complete_checks=1 + 2 * sequence, complete_physical_samples=sequence,
                   complete_counter_reads=3 if sequence else 0,
                   operation=production.OPERATIONS[sequence - 1] if sequence else 0,
                   qualified_sample=int(sequence > 0), private_baseline_present=int(sequence > 0),
                   tid=TID, state_capacity=8192, opens=20 + 19 * sequence,
                   reads=26 + 34 * sequence, thread_cpu_ns=int(sequence > 0),
                   wall_ns=int(sequence > 0))
        if sequence:
            values = (10 * sequence, 20 * sequence, 3 * sequence, 40 * sequence,
                      4096 // sequence, 2)
            row.update(zip(production.VALUE_FIELDS, values))
            if sequence > 1:
                row.update(zip(production.DELTA_FIELDS, (10, 20, 3, 40)))
        raw = struct.pack('<32Q', *(row[key] for key in production.FIELDS))
        output.extend(raw)
        rows.append(row)
        emit('gettid() = ' + str(TID))
        emit('write(1, ' + quoted(raw) + ', 256) = 256', 'receipt-' + str(sequence))
    emit('read(0, "", 24) = 0')
    emit('exit(0) = ?')
    return ('\n'.join(lines) + '\n').encode(), bytes(output), marks


def changed_line(raw, index, transform):
    lines = raw.decode().splitlines()
    lines[index] = transform(lines[index])
    return ('\n'.join(lines) + '\n').encode()


def changed_receipt(raw, stdout, sequence, field, value):
    before = stdout[sequence * 256:(sequence + 1) * 256]
    numbers = list(struct.unpack('<32Q', before))
    numbers[production.FIELDS.index(field)] = value
    after = struct.pack('<32Q', *numbers)
    output = stdout[:sequence * 256] + after + stdout[(sequence + 1) * 256:]
    return raw.replace(quoted(before).encode(), quoted(after).encode()), output


class ProductionResourceEvidenceTests(unittest.TestCase):
    def test_synthetic_complete_parser_control_confers_no_production_authority(self):
        trace, output, _ = synthetic()
        result = production.audit_resource_trace(trace, output)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(len(result['counter_blocks']), 3)
        self.assertEqual(len(result['shared_host_trace']['checks']), 7)
        self.assertEqual(result['request_frames_hex'],
                         [struct.pack('<3Q', op, 0, 4096).hex() for op in production.OPERATIONS])
        self.assertFalse(result['production_parent_authority_from_parser'])
        self.assertEqual(result['counter_blocks'][1]['values'][4], 2048)
        self.assertEqual(result['receipts'][2]['delta_usage_usec'], 10)

    def test_complete_escaped_payload_is_not_a_metadata_path(self):
        extra = b'"/sys/fs/cgroup/trnmponpublic.slice" 0\n'
        trace, output, _ = synthetic(extra_cpu=extra)
        result = production.audit_resource_trace(trace, output)
        self.assertIn(extra, bytes.fromhex(result['counter_blocks'][0]['counter_bytes_hex']['cpu.stat']))
        actual = production.c_bytes(r'"a\\b\"c\n\000\377\x41"')
        self.assertEqual(actual, b'a\\b"c\n\x00\xffA')

    def test_actual_strace_exit_alignment_is_accepted(self):
        trace, output, _ = synthetic()
        trace = trace.replace(b'exit(0) = ?', b'exit(0)                         = ?')
        result = production.audit_resource_trace(trace, output)
        self.assertEqual(result['status'], 'PASS')

    def test_corrupt_counter_descriptor_order_and_io_are_refused(self):
        trace, output, marks = synthetic()
        changes = [
            ('1-memory.current-open', lambda x: x.replace('"memory.current"', '"cpu.stat"')),
            ('1-cpu.stat-open', lambda x: x.replace('openat(3,', 'openat(9,')),
            ('1-cpu.stat-open', lambda x: x.replace('O_NOFOLLOW|', '')),
            ('1-cpu.stat-open', lambda x: x.replace('O_RDONLY|', 'O_RDWR|')),
            ('1-cpu.stat-open', lambda x: x.replace('O_RDONLY|', 'O_RDONLY|O_RDONLY|')),
            ('1-cpu.stat-open', lambda x: x.replace(' = 4', ' = 1')),
            ('1-cpu.stat-stat', lambda x: x.replace('S_IFREG', 'S_IFIFO')),
            ('1-cpu.stat-read', lambda x: x.replace('usage_usec 10', 'usage_usec 11')),
            ('1-cpu.stat-read', lambda x: x.replace(', 2049)', ', 2048)')),
            ('1-cpu.stat-read', lambda x: x.replace(' = 72', ' = 71') if ' = 72' in x else x.rsplit(' = ',1)[0] + ' = 1'),
            ('1-cpu.stat-eof', lambda x: x.replace(' = 0', ' = 1')),
            ('1-cpu.stat-eof', lambda x: x.replace('read(4,', 'read(5,')),
            ('1-cpu.stat-close', lambda x: x.replace('close(4)', 'close(3)')),
            ('sample-parent-close-1', lambda x: x.replace('close(3)', 'close(4)')),
            ('1-cpu.stat-read', lambda x: x.replace('", 2049)', '"..., 2049)')),
        ]
        for mark, operation in changes:
            with self.subTest(mark=mark, change=operation):
                bad = changed_line(trace, marks[mark], operation)
                self.assertNotEqual(bad, trace)
                with self.assertRaises(ValueError):
                    production.audit_resource_trace(bad, output)

    def test_counter_blocks_cannot_hide_extra_syscalls_or_stale_parent(self):
        trace, output, marks = synthetic()
        for index, extra in (
            (marks['1-cpu.stat-open'], str(TID) + ' close(3) = 0'),
            (marks['1-cpu.stat-stat'], str(TID) + ' getpid() = ' + str(TID)),
            (marks['1-memory.current-open'], str(TID) + ' close(3) = 0'),
            (marks['sample-parent-close-1'], str(TID) + ' openat(AT_FDCWD, "unrelated", O_RDONLY|O_CLOEXEC) = 9'),
            (marks['receipt-1'], str(TID) + ' execve("/bin/true", ["true"], 0x0) = 0'),
        ):
            with self.subTest(extra=extra):
                lines = trace.decode().splitlines()
                lines.insert(index, extra)
                with self.assertRaises(ValueError):
                    production.audit_resource_trace(('\n'.join(lines)+'\n').encode(), output)

    def test_missing_fresh_check_and_early_receipt_are_refused(self):
        trace, output, marks = synthetic()
        for start, end in ((marks['post-1'], marks['receipt-1'] - 1),
                           (marks['pre-1'], marks['1-cpu.stat-open']),
                           (marks['1-cpu.stat-eof'], marks['1-cpu.stat-eof'] + 1)):
            with self.subTest(start=start, end=end):
                lines = trace.decode().splitlines()
                del lines[start:end]
                with self.assertRaises(ValueError):
                    production.audit_resource_trace(('\n'.join(lines)+'\n').encode(), output)
        bad = changed_line(trace, marks['receipt-1'], lambda x: x.replace(str(TID), str(TID+1), 1))
        with self.assertRaisesRegex(ValueError, 'TID'):
            production.audit_resource_trace(bad, output)

    def test_receipts_request_and_private_baseline_must_match_trace(self):
        trace, output, marks = synthetic()
        for sequence, field, value in (
            (0, 'fixture', 1), (1, 'memory_current_bytes', 17), (2, 'delta_usage_usec', 20),
            (3, 'delta_nr_periods', 40), (2, 'tid', TID + 1), (1, 'complete_checks', 2),
            (1, 'qualified_sample', 0), (1, 'private_baseline_present', 0), (3, 'error', 14),
            (1, 'resource_gates', 5), (2, 'close_errors', 1),
            (2, 'complete_counter_reads', 6),
        ):
            with self.subTest(sequence=sequence, field=field):
                changed, stdout = changed_receipt(trace, output, sequence, field, value)
                with self.assertRaises(ValueError):
                    production.audit_resource_trace(changed, stdout)
        bad = changed_line(trace, marks['request-3'],
                           lambda x: x.replace(quoted(struct.pack('<3Q', 2, 0, 4096)),
                                               quoted(struct.pack('<3Q', 1, 0, 4096))))
        with self.assertRaisesRegex(ValueError, 'OPERATION'):
            production.audit_resource_trace(bad, output)
        with self.assertRaises(ValueError):
            production.audit_resource_trace(trace, output[:-1])

    def test_fixture_parser_control_is_explicit(self):
        trace, output, _ = synthetic(fixture=True)
        with self.assertRaises(ValueError):
            production.audit_resource_trace(trace, output)
        result = production.audit_resource_trace(trace, output, fixture=True)
        self.assertTrue(result['fixture_parser_control'])
        self.assertFalse(result['production_parent_authority_from_parser'])

    def test_malformed_escapes_and_duplicate_json_keys_fail(self):
        for token in ('"\\u0041"', '"\\x1"', '"\\400"', '"missing', '"\\q"'):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    production.c_bytes(token)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON'):
            production.object_json('{"source_inputs":{},"source_inputs":{}}')

    def test_original_counter_text_rules_are_retained(self):
        good = {'cpu.stat': b'usage_usec 1\nnr_periods 2\nnr_throttled 3\nthrottled_usec 4\n',
                'memory.current': b'+5\n', 'pids.current': b'0\n'}
        self.assertEqual(production.parsed_values(good), [1,2,3,4,5,0])
        for field, value in (('cpu.stat', good['cpu.stat'] + b'\n'),
                             ('cpu.stat', good['cpu.stat'] + b'future 1\nfuture 2\n'),
                             ('cpu.stat', good['cpu.stat'].replace(b'usage_usec 1', b'usage_usec\x0b1')),
                             ('memory.current', str(1 << 64).encode()),
                             ('pids.current', b'1 2'), ('memory.current', b'\xff')):
            with self.subTest(field=field, value=value):
                changed = {**good, field:value}
                with self.assertRaises((ValueError, UnicodeError)):
                    production.parsed_values(changed)

    def test_all_required_build_inputs_are_exact(self):
        required = {'owner': {'bytes': 1, 'sha256': 'a'*64}, 'controller': {'bytes': 2, 'sha256': 'b'*64}}
        production.require_source_set({'source_inputs': required}, required)
        for candidate in ({}, {'owner': required['owner']},
                          {**required, 'extra': required['owner']},
                          {**required, 'controller': {**required['controller'], 'bytes': 3}}):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(ValueError, 'COMPLETE_SOURCE'):
                    production.require_source_set({'source_inputs': candidate}, required)

    def test_service_name_has_own_strict_profile_and_no_provision(self):
        env = {'GITHUB_RUN_ID':'42', 'GITHUB_RUN_ATTEMPT':'1', 'GITHUB_JOB':'native-host',
               'TRNM_CI_RECEIPT_DIR':'/tmp/lease', 'PATH':'/usr/bin', 'PRIVATE_UNFORWARDED':'x'}
        service = production.service_name(env, pid=123)
        argv = production.service_argv(service, Path('/tmp/build'), Path('/tmp/lease/resource/child'),
                                       Path('/tmp/lease'), 1001, 1002, env)
        self.assertIn('--unit='+service, argv)
        for value in ('--slice=trnmponpublic.slice','--uid=1001','--gid=1002',
                      '--property=Delegate=no','--property=NoNewPrivileges=yes',
                      '--property=CapabilityBoundingSet=','--property=KillMode=control-group'):
            self.assertIn(value, argv)
        self.assertNotIn('PRIVATE_UNFORWARDED', ' '.join(argv))
        self.assertNotIn('daemon-reload', argv)
        self.assertEqual(argv.count('--setenv=TRNM_CI_RECEIPT_DIR=/tmp/lease'), 1)
        for invalid in ('trnm-hia-host-42-1-native-host-123.service', service+';echo bad',
                        service.replace('-123.', '-abc.'), service.replace('native-host', '../other')):
            with self.subTest(name=invalid):
                with self.assertRaises(ValueError):
                    production.service_argv(invalid, Path('/tmp/build'), Path('/tmp/output'),
                                            Path('/tmp/lease'), 1001, 1002, env)

    def test_prior_host_success_requires_the_same_current_seal(self):
        old = 'trnm-hia-host-42-1-native-host-123.service'
        new = 'trnm-hia-resource-42-1-native-host-456.service'
        binding = {'schema':'trnm-ci-public-fixture-parent-binding-v1',
                   'seal_sha256':'a'*64,'seal_file':{'device':1,'inode':2,'sha256':'a'*64},
                   'parent_identity':{'device':3,'inode':4},'creator_service':old,
                   'current_service':old,'host_readiness_only':True,'consensus_or_model_authority':False}
        prior = {'creator_service':old,'parent_lease':binding,'final_parent_lease':copy.deepcopy(binding)}
        current = {**copy.deepcopy(binding),'current_service':new}
        production.require_prior_lease_binding(prior,current,new)
        bad_priors = [
            {'creator_service':old},
            {**prior,'creator_service':'old-other-job'},
            {**prior,'final_parent_lease':{**binding,'seal_sha256':'b'*64}},
            {**prior,'parent_lease':{**binding,'current_service':'other'}},
        ]
        for candidate in bad_priors:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                production.require_prior_lease_binding(candidate,current,new)
        for key,value in (('creator_service','old-other-job'),('current_service',old),
                          ('seal_sha256','b'*64),('seal_file',{'device':1,'inode':99}),
                          ('parent_identity',{'device':3,'inode':99})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                production.require_prior_lease_binding(prior,{**current,key:value},new)

    def test_failed_native_launch_still_records_build_after_without_masking_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            first = (b'not-executed-image',{'source_inputs':{'test':'before'}},'synthetic-build')
            with patch.object(production,'validate_build',side_effect=[first,ValueError('changed-after')]) as validate, \
                 patch.object(production.shutil,'which',return_value='/never-executed-strace'), \
                 patch.object(production.subprocess,'Popen',side_effect=RuntimeError('primary-launch-failure')):
                with self.assertRaisesRegex(RuntimeError,'primary-launch-failure'):
                    production.native_production(output,output,'trnm-hia-resource-1-1-job-1.service')
                self.assertEqual(validate.call_count,2)
            report = json.loads((output/'native.json').read_text())
            self.assertEqual(report['status'],'FAIL')
            self.assertIn('primary-launch-failure',report['failure'])
            self.assertTrue(any('BUILD_AFTER:' in error for error in report['cleanup_errors']))
            self.assertIsNone(report['exit_code'])

    def test_missing_prior_lease_refuses_in_previous_phase_gate(self):
        # Explicit synthetic PASS fields exercise a refusal gate, not execution.
        native = {'status':'PASS','actual_fixed_parent_positive':True,
                  'independent_syscall_trace':{'status':'PASS'},'source_inputs':{}}
        previous = {'schema':'trnm.hia.production-host-controller.v1','status':'PASS',
                    'cleanup_errors':[],'native':native,'service':'other-job'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);(root/'child').mkdir()
            for name,value in (('report.json',previous),('child/native.json',native),
                               ('child/inside-report.json',{'status':'PASS','cleanup_errors':[]}),
                               ('source.json',{}),('source-after.json',{})):
                (root/name).write_text(json.dumps(value))
            with patch.object(production.platform_build,'source_manifest',return_value={}), \
                 patch.object(production.checkpoint_build,'source_manifest',return_value={}), \
                 patch.object(production.subprocess,'run',side_effect=AssertionError('must not spawn')):
                with self.assertRaisesRegex(ValueError,'PRIOR_HOST_COMPLETE_STABLE_LEASE'):
                    production.previous_host(root,{})

    def test_receipt_root_cannot_change_or_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            lease = Path(directory)/'lease'
            lease.mkdir()
            output = lease/'resource'
            with patch.dict(os.environ, {'TRNM_CI_RECEIPT_DIR':str(lease)}):
                self.assertEqual(production.lease_directory(lease,output,inside=False),(lease,output))
                for bad in (lease, Path(directory)/'different', production.ROOT/'generated'):
                    with self.subTest(output=bad):
                        with self.assertRaises(ValueError):
                            production.lease_directory(lease,bad,inside=False)
                link = lease/'link';link.symlink_to(Path(directory),target_is_directory=True)
                with self.assertRaises(ValueError):
                    production.lease_directory(lease,link/'escaped',inside=False)
            with patch.dict(os.environ, {'TRNM_CI_RECEIPT_DIR':str(output)}):
                with self.assertRaisesRegex(ValueError,'EXACT_PREVIOUS_RECEIPT'):
                    production.lease_directory(lease,output,inside=False)

    def test_nonhosted_and_root_refuse_before_process_or_output(self):
        good = {'GITHUB_ACTIONS':'true','CI':'true','RUNNER_ENVIRONMENT':'github-hosted',
                'TRNM_EXPECTED_SOURCE_SHA':'a'*40,'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1',
                'GITHUB_JOB':'native-host'}
        variants = [(key, value) for key,value in (
            ('GITHUB_ACTIONS','false'),('CI','false'),('RUNNER_ENVIRONMENT','self-hosted'),
            ('TRNM_EXPECTED_SOURCE_SHA',''),('GITHUB_RUN_ID','missing'),('GITHUB_JOB','../other'))]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'must-not-exist'
            for key,value in variants:
                with self.subTest(key=key), patch.dict(os.environ,{**good,key:value},clear=True), \
                     patch.object(production.os,'getuid',return_value=1001), \
                     patch.object(production.subprocess,'run',side_effect=AssertionError('must not spawn')):
                    with self.assertRaises(ValueError):
                        production.outer(Path('/missing/build'),Path('/missing/lease'),output)
                    self.assertFalse(output.exists())
            with patch.dict(os.environ,good,clear=True), patch.object(production.os,'getuid',return_value=0), \
                 patch.object(production.subprocess,'run',side_effect=AssertionError('must not spawn')):
                with self.assertRaisesRegex(ValueError,'HOSTED_CI_ONLY'):
                    production.outer(Path('/missing/build'),Path('/missing/lease'),output)

    def test_absolute_cli_help_and_optimization_refusal(self):
        path = Path(production.__file__).resolve()
        with tempfile.TemporaryDirectory() as directory:
            help_run = subprocess.run([sys.executable,'-B',str(path),'--help'],cwd=directory,
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            self.assertEqual(help_run.returncode,0,help_run.stderr.decode())
            self.assertIn(b'--lease-receipts',help_run.stdout)
            for flags, optimization in ((['-O'],None),(['-OO'],None),([], '2')):
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
                if optimization is None:
                    env.pop('PYTHONOPTIMIZE',None)
                else:
                    env['PYTHONOPTIMIZE']=optimization
                run = subprocess.run([sys.executable,*flags,'-B',str(path),'--help'],cwd=directory,
                                     env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
                self.assertNotEqual(run.returncode,0)
                self.assertIn(b'refuses optimized Python',run.stderr)


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Production resource tests refuse optimized Python')
    unittest.main()

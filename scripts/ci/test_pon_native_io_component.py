#!/usr/bin/env python3
"""Real finite counterexamples for the component helpers; no public qualification."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
import run_pon_native_io_component as c
import check_pon_native_io_component as reader


class MechanismCounterexamples(unittest.TestCase):
    def test_actual_child_birth_and_real_wait(self):
        owner = c.NativeChildOwner()
        result = owner.run([sys.executable, '-c', 'pass'], timeout=2,
                           stdout_limit=1024, stderr_limit=1024)
        self.assertEqual(result.returncode, 0)
        owner.complete(result.returncode)
        self.assertEqual(owner.value['observed_ppid'], os.getpid())
        self.assertTrue(owner.value['reaped'])
        self.assertFalse(owner.value['original_identity_alive_after_wait'])

    def test_real_timeout_is_reaped_and_remains_nonzero(self):
        owner = c.NativeChildOwner()
        with self.assertRaises(c.ProcessFailure) as caught:
            owner.run([sys.executable, '-c', 'import time; time.sleep(10)'],
                      timeout=.1, stdout_limit=1024, stderr_limit=1024)
        self.assertNotEqual(caught.exception.returncode, 0)
        owner.complete(caught.exception.returncode)

    def test_post_spawn_identity_failure_still_kills_and_waits(self):
        owner = c.NativeChildOwner()
        before_fds = set(os.listdir('/proc/self/fd'))
        with patch.object(owner, 'process_identity', side_effect=OSError('injected-proc-read')):
            with self.assertRaises(ValueError):
                owner.run([sys.executable, '-c', 'import time; time.sleep(10)'],
                          timeout=2, stdout_limit=1024, stderr_limit=1024)
        self.assertEqual(owner.value['spawn_count'], 1)
        self.assertTrue(owner.value['reaped'])
        self.assertTrue(owner.value['failed_spawn_streams_closed'])
        self.assertEqual(set(os.listdir('/proc/self/fd')), before_fds)
        self.assertNotEqual(owner.value['wait_returncode'], 0)
        with self.assertRaises(ValueError): owner.complete(owner.value['wait_returncode'])

    def test_original_origin_rejects_renamed_and_copied_root(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent/'prepared'
            root.mkdir(mode=0o700)
            parent_fd = c.held_directory(parent)
            root_fd = c.held_directory(root)
            try:
                origin = c.origin_at(root, root_fd, parent_fd)
                c.validate_origin(origin, root, root_fd, parent_fd)
                renamed = parent/'renamed'
                root.rename(renamed)
                with self.assertRaises(ValueError):
                    c.validate_origin(origin, renamed, root_fd, parent_fd)
                copied = parent/'copied'
                shutil.copytree(renamed, copied)
                copied_fd = c.held_directory(copied)
                try:
                    with self.assertRaises(ValueError):
                        c.validate_origin(origin, copied, copied_fd, parent_fd)
                finally: os.close(copied_fd)
                a = SimpleNamespace(root=root, value={'origin': origin})
                b = SimpleNamespace(root=renamed, value={'origin': origin})
                self.assertEqual(c.claim_name(a), c.claim_name(b))
            finally:
                os.close(root_fd)
                os.close(parent_fd)

    def test_target_replacement_cannot_measure_the_old_tree_as_current(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent/'target'
            root.mkdir(mode=0o700)
            parent_fd, root_fd = c.held_directory(parent), c.held_directory(root)
            try:
                guard = c.BuildStop(root_fd, parent_fd, root.name, None)
                self.assertEqual(guard.measure(), 0)
                root.rename(parent/'original')
                root.mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, 'TARGET_REPLACED'): guard.measure()
                self.assertEqual(os.fstat(root_fd).st_ino, (parent/'original').stat().st_ino)
            finally:
                os.close(root_fd)
                os.close(parent_fd)

    def test_real_unreadable_subdirectory_is_not_omitted(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent/'target'
            root.mkdir(mode=0o700)
            blocked = root/'blocked'
            blocked.mkdir(mode=0o700)
            (blocked/'retained-data').write_bytes(b'charged')
            parent_fd, root_fd = c.held_directory(parent), c.held_directory(root)
            try:
                blocked.chmod(0)
                guard = c.BuildStop(root_fd, parent_fd, root.name, None)
                with self.assertRaises(PermissionError): guard.measure()
            finally:
                blocked.chmod(0o700)
                os.close(root_fd)
                os.close(parent_fd)

    def test_both_terminal_locations_are_attempted_after_first_failure(self):
        calls = []
        writer = SimpleNamespace(poison=lambda error: calls.append(('poison', str(error))),
            json=lambda *args, **kwargs: calls.append(('observed', args[0])))
        claim = c.ComponentClaim(SimpleNamespace(writer=writer), None)
        claim.fd, claim.binding, claim.tokens = 99, {}, [None]*4
        def fail_external(*args):
            calls.append(('external', args[0]))
            raise OSError('injected-first-terminal-failure')
        claim.external = fail_external
        errors = claim.finish(False, None, 'original-failure')
        self.assertEqual([row[0] for row in calls], ['external', 'poison', 'observed'])
        self.assertEqual(errors, [{'where': 'external', 'failure': 'injected-first-terminal-failure'}])

    def test_failed_or_unknown_child_cannot_validate_as_terminal(self):
        owner = c.NativeChildOwner()
        with self.assertRaises(ValueError): owner.complete(0)

    def test_reader_joins_actual_birth_and_rejects_boolean_exit_alias(self):
        owner = c.NativeChildOwner()
        result = owner.run([sys.executable, '-c', 'pass'], timeout=2,
                           stdout_limit=1024, stderr_limit=1024)
        self.assertEqual(reader.child_terminal(owner.value, result.returncode), owner.value['pid'])
        with self.assertRaises(ValueError): reader.child_terminal(owner.value, False)

    def test_reader_refuses_missing_actual_birth_or_wait(self):
        owner = c.NativeChildOwner()
        result = owner.run([sys.executable, '-c', 'pass'], timeout=2,
                           stdout_limit=1024, stderr_limit=1024)
        missing_birth = dict(owner.value, birth_ticks=None)
        missing_wait = dict(owner.value, reaped=False)
        for changed in (missing_birth, missing_wait):
            with self.assertRaises(ValueError): reader.child_terminal(changed, result.returncode)

    def test_capture_stays_on_original_target_after_visible_replacement(self):
        # These are non-executed byte fixtures, not compiler/native receipts.
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            target, output = parent/'target', parent/'output'
            (target/'release/deps').mkdir(parents=True, mode=0o700)
            output.mkdir(mode=0o700)
            advertised = target/'release/deps/nonexecuted-fixture'
            original_bytes = b'\x7fELF'+os.urandom(4096)
            advertised.write_bytes(original_bytes)
            target_fd = c.held_directory(target)
            io = SimpleNamespace(writer=c.V2Writer(output))
            try:
                target.rename(parent/'original-target')
                (target/'release/deps').mkdir(parents=True, mode=0o700)
                advertised.write_bytes(b'\x7fELFshadow')
                pin, _ = c.capture_built_binary(io, target_fd, target, advertised)
                self.assertEqual((output/(c.TARGET+'.bin')).read_bytes(), original_bytes)
                self.assertEqual(pin['bytes'], len(original_bytes))
                self.assertNotEqual((output/(c.TARGET+'.bin')).read_bytes(), advertised.read_bytes())
            finally:
                io.writer.close()
                os.close(target_fd)

    def test_capture_rejects_symlinked_intermediate_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            target, output, outside = parent/'target', parent/'output', parent/'outside'
            for path in (target, output, outside): path.mkdir(mode=0o700)
            (outside/'nonexecuted-fixture').write_bytes(b'\x7fELFoutside')
            (target/'release').symlink_to(outside, target_is_directory=True)
            target_fd = c.held_directory(target)
            io = SimpleNamespace(writer=c.V2Writer(output))
            try:
                with self.assertRaises(OSError):
                    c.capture_built_binary(io, target_fd, target, target/'release/nonexecuted-fixture')
                self.assertFalse((output/(c.TARGET+'.bin')).exists())
            finally:
                io.writer.close()
                os.close(target_fd)


    def test_actual_owned_step_keeps_label_separate_from_stream_names(self):
        # Actual short-lived children and writer files, not a prepared/native run.
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            io = c.ComponentIO(output)
            try:
                for label in ('build', 'component'):
                    row = io.owned_step(label,
                        [sys.executable, '-c',
                         'import sys; print("owned-out"); print("owned-err", file=sys.stderr)'],
                        dict(os.environ), 2, dict(cwd=output))
                    self.assertTrue(row['complete_success'], row)
                    self.assertTrue((output/(label+'.step.json')).is_file(), sorted(path.name for path in output.iterdir()))
                    self.assertFalse((output/(label+'.stderr.log.step.json')).exists())
                    observed = c.strict_json((output/(label+'.step.json')).read_bytes())
                    self.assertEqual(observed, row)
                    self.assertEqual(observed['name'], label)
                    self.assertEqual((output/(label+'.stdout.log')).read_bytes(), b'owned-out\n')
                    self.assertEqual((output/(label+'.stderr.log')).read_bytes(), b'owned-err\n')
            finally:
                io.writer.close()

    def test_finite_limits_preserve_all_original_caps_and_deny_full_ledger_claim(self):
        from copy import deepcopy
        for role in ('actor', 'campaign-parent'):
            caps = c.CAPS
            expected = dict(address_space=caps['actor_vm_bytes'] if role == 'actor'
                            else caps['parent_vm_bytes'],
                            file_size=caps['actor_file_bytes'] if role == 'actor'
                            else caps['parent_file_bytes'])
            observation = dict(pid=101, cgroup='0::/finite-mechanism-control\n')
            observation.update({key:dict(soft_bytes=limit, hard_bytes=limit)
                                for key,limit in expected.items()})
            value = dict(schema=caps['schema'], role=role, before=deepcopy(observation),
                after=deepcopy(observation), original_cgroup_required=True,
                full_ledger_implemented=False)
            unchanged = deepcopy(value)
            self.assertEqual(reader.component_process_limits(value, role,
                             observation['cgroup'], 101), 101)
            self.assertEqual(value, unchanged)
            with self.assertRaisesRegex(ValueError, 'incomplete native process limit owner'):
                reader.original.process_limits_v2(value, role, observation['cgroup'], 101)
            changes = [('schema', 'other'), ('role', 'other'),
                       ('original_cgroup_required', False), ('full_ledger_implemented', True),
                       ('full_ledger_implemented', 0), ('full_ledger_implemented', None)]
            for key,replacement in changes:
                bad = deepcopy(value); bad[key] = replacement
                with self.subTest(role=role,key=key,value=replacement), self.assertRaises(ValueError):
                    reader.component_process_limits(bad, role, observation['cgroup'], 101)
            for when in ('before', 'after'):
                for field,replacement in [('pid',True), ('pid',102), ('cgroup','0::/other\n')]:
                    bad=deepcopy(value);bad[when][field]=replacement
                    with self.subTest(role=role,when=when,field=field), self.assertRaises(ValueError):
                        reader.component_process_limits(bad, role, observation['cgroup'], 101)
                for key,limit in expected.items():
                    for side in ('soft_bytes','hard_bytes'):
                        for replacement in ((True, limit-1) if when == 'before' else (True, limit-1, limit+1)):
                            bad=deepcopy(value);bad[when][key][side]=replacement
                            with self.subTest(role=role,when=when,key=key,side=side,value=replacement), self.assertRaises(ValueError):
                                reader.component_process_limits(bad, role, observation['cgroup'], 101)
            with self.assertRaises(ValueError):
                reader.component_process_limits(value, role, observation['cgroup'], True)
            self.assertEqual(value, unchanged)


    def test_real_stream_io_failure_keeps_actual_nonzero_child_terminal(self):
        from copy import deepcopy
        import errno
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary);io=c.ComponentIO(output)
            original_open=io.writer.open_reserved
            def readonly_reserved(name, **options):
                opened=original_open(name, **options)
                if name == 'component.stdout.log':
                    os.close(opened[2])
                    opened[2]=os.open(opened[1]+'.partial.json', os.O_RDONLY|os.O_NOFOLLOW,
                                      dir_fd=opened[0])
                return opened
            try:
                with patch.object(io.writer,'open_reserved',side_effect=readonly_reserved):
                    with self.assertRaises(OSError) as caught:
                        io.owned_step('component', [sys.executable,'-c',
                            'import sys; print("actual-output", flush=True); sys.exit(3)'],
                            dict(os.environ),2,dict(cwd=output))
                self.assertEqual(caught.exception.errno, errno.EBADF)
                context=io.writer.failure_context
                self.assertIsNotNone(context, 'actual child terminal lost after real EBADF')
                self.assertEqual(context['returncode'],3)
                self.assertIsNone(context['child_error'])
                self.assertTrue(context['native_process_owner']['reaped'])
                self.assertEqual(context['native_process_owner']['wait_returncode'],3)
                self.assertEqual(c.observed_step_exit_code(context),3)
                self.assertFalse(context['raw_preservation_complete'])
                self.assertLessEqual(sum(map(len,c.json_chunks(context))),16*1024)
                before=deepcopy(context);first_error=io.writer.failure
                with self.assertRaises(ValueError):io.writer.json('later.json',{})
                self.assertEqual(io.writer.failure_context,before)
                self.assertEqual(io.writer.failure,first_error)
                io.writer.terminal('component-test',caught.exception)
                terminal=c.strict_json((output/'outer-terminal.json').read_bytes())
                self.assertEqual(terminal['observed_step'],before)
                self.assertFalse(terminal['qualification'])
                self.assertFalse(terminal['physical_enospc_terminal_guaranteed'])
            finally:io.writer.close()

    def test_real_step_io_failure_keeps_timeout_and_does_not_promote_unknown(self):
        from copy import deepcopy
        import errno
        import json
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary);io=c.ComponentIO(output)
            original_open=io.writer.open_reserved
            def readonly_reserved(name, **options):
                opened=original_open(name, **options)
                if name == 'component.step.json':
                    os.close(opened[2])
                    opened[2]=os.open(opened[1]+'.partial.json',os.O_RDONLY|os.O_NOFOLLOW,
                                      dir_fd=opened[0])
                return opened
            try:
                with patch.object(io.writer,'open_reserved',side_effect=readonly_reserved):
                    with self.assertRaises(OSError) as caught:
                        io.owned_step('component',[sys.executable,'-c',
                            'import time; time.sleep(10)'],dict(os.environ),.1,dict(cwd=output))
                self.assertEqual(caught.exception.errno,errno.EBADF)
                context=io.writer.failure_context
                self.assertIsNotNone(context,'original child timeout lost after real step EBADF')
                self.assertIn('NATIVE_EXECUTOR_TIMEOUT',context['child_error'])
                self.assertNotEqual(context['returncode'],0)
                self.assertEqual(context['native_process_owner']['wait_returncode'],context['returncode'])
                self.assertEqual(c.observed_step_exit_code(context),context['returncode'])
                for field,value in [('reaped',False),('birth_ticks',None),('failure','unknown')]:
                    unknown=deepcopy(context);unknown['native_process_owner'][field]=value
                    self.assertIsNone(c.observed_step_exit_code(unknown))
                alias=deepcopy(context);alias['returncode']=False
                self.assertIsNone(c.observed_step_exit_code(alias))
                clipped,truncated=c.bounded_context_error('\U0001f642'*5000)
                self.assertTrue(truncated)
                self.assertLessEqual(len(json.dumps(clipped,ensure_ascii=True).encode('ascii')),2048)
                self.assertTrue(('\U0001f642'*5000).startswith(clipped))
                io.writer.terminal('component-timeout-test',caught.exception)
                terminal=c.strict_json((output/'outer-terminal.json').read_bytes())
                self.assertEqual(terminal['observed_step'],context)
                self.assertFalse(terminal['qualification'])
            finally:io.writer.close()


if __name__ == '__main__': unittest.main(verbosity=2)

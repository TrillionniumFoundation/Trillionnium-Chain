#!/usr/bin/env python3
"""Orchestration/file-boundary controls, never public native execution evidence."""
from argparse import Namespace
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_native_io_component_ci_v1 as ci


class ComponentCiControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pn1-ci-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = Namespace(out=self.root/'output', target_dir=self.root/'target',
            cargo=Path('/synthetic-not-executed/cargo'), expected_head='1'*40, expected_tree='2'*40)
        self.source = dict(head='1'*40, tree='2'*40, status_porcelain='', branch='synthetic')
        self.calls = []
        for name, value in (('source_snapshot', self.source), ('resources', {'fixture_only':True})):
            mocked = patch.object(ci.component, name, return_value=value)
            mocked.start(); self.addCleanup(mocked.stop)

    def stage(self, fd, name, command, seconds):
        self.calls.append((name, command, seconds))
        value = dict(name=name, exit_code=0, process_complete=True, synthetic_fixture_only=True)
        flags = ci.component.component_flags()
        if name == 'prepare':
            folder = self.args.out/'prepared'; folder.mkdir(mode=0o700)
            prepared = dict(schema=ci.component.PREPARED, profile=ci.component.PROFILE,
                head='1'*40, tree='2'*40, capture_complete=True, selector_executed=False,
                failure=None, **flags)
            (folder/'prepared.json').write_text(json.dumps(prepared))
            (folder/'artifact-files.json').write_text('{"synthetic_only":true}')
        elif name == 'execute':
            folder = self.args.out/'execution'; folder.mkdir(mode=0o700)
            (folder/'results.json').write_text(json.dumps(dict(schema=ci.component.EXECUTION,
                complete_success=True, selector_executed=True, failure=None, **flags)))
            (folder/'artifact-files.json').write_text('{"synthetic_only":true}')
        body = dict(schema=ci.reader.SCHEMA, profile=ci.component.PROFILE,
            mechanism_readback_complete=True, prefix_paid_unique=2, final_paid_unique=6,
            actual_used_Node_roles=[0,5,6], **flags)
        ci.json_new(fd, name+'.synthetic-stage.json', value)
        return value, json.dumps(body).encode()

    def test_original_three_commands_once_and_all_hash_arguments_are_real_bytes(self):
        with patch.object(ci, 'stage', side_effect=self.stage): result = ci.run(self.args)
        self.assertTrue(result['complete_success'])
        self.assertEqual([item[0] for item in self.calls], ['prepare','execute','readback'])
        self.assertEqual([item[2] for item in self.calls], [1200,180,180])
        self.assertEqual(result['original_control_plan'], ci.component.PLAN)
        self.assertFalse(result['full_route_ready'])
        self.assertTrue(result['component_only'])
        for flag in ci.component.FULL_FLAGS: self.assertIs(result[flag], False)
        execute, readback = self.calls[1][1], self.calls[2][1]
        for key, option in (('prepared','--prepared-sha256'),
                ('prepared_inventory','--prepared-inventory-sha256')):
            expected = result['documents'][key]['sha256']
            self.assertEqual(execute[execute.index(option)+1], expected)
            self.assertEqual(readback[readback.index(option)+1], expected)
        self.assertEqual(readback[readback.index('--inventory-sha256')+1],
            result['documents']['execution_inventory']['sha256'])
        self.assertEqual(readback[2], str(ci.ROOT/'scripts/ci/check_pon_native_io_component.py'))

    def test_failed_public_prepare_preserves_failure_and_never_executes(self):
        def failed(fd, name, command, seconds):
            self.calls.append(name)
            ci.write_new(fd, 'original-prepare-failure.log', b'original failure')
            return dict(name=name, process_complete=False, exit_code=1), b''
        with patch.object(ci, 'stage', side_effect=failed): result = ci.run(self.args)
        self.assertFalse(result['complete_success']); self.assertEqual(self.calls,['prepare'])
        self.assertEqual((self.args.out/'original-prepare-failure.log').read_bytes(), b'original failure')

    def test_failed_execute_does_not_retry_or_invoke_reader(self):
        def fail_execute(fd,name,command,seconds):
            if name == 'execute':
                self.calls.append((name,command,seconds))
                return dict(name=name,process_complete=False,exit_code=101),b''
            return self.stage(fd,name,command,seconds)
        with patch.object(ci,'stage',side_effect=fail_execute): result=ci.run(self.args)
        self.assertFalse(result['complete_success'])
        self.assertEqual([item[0] for item in self.calls],['prepare','execute'])
        self.assertTrue((self.args.out/'prepared/prepared.json').is_file())

    def test_missing_prepared_document_cannot_be_substituted_by_exit_zero(self):
        with patch.object(ci,'stage',return_value=(dict(process_complete=True,exit_code=0),b'')):
            result=ci.run(self.args)
        self.assertFalse(result['complete_success'])
        self.assertEqual(len(result['stages']),1)

    def test_rehashed_reader_promotion_or_wrong_identity_count_is_rejected(self):
        for field,value in [('full_W1_4097_qualified',True),('final_paid_unique',4097),
                ('mechanism_readback_complete',1),('prefix_paid_unique',True)]:
            with self.subTest(field=field):
                self.args.out=self.root/field
                def altered(fd,name,command,seconds):
                    step,raw=self.stage(fd,name,command,seconds)
                    if name=='readback':
                        body=json.loads(raw);body[field]=value;raw=json.dumps(body).encode()
                    return step,raw
                with patch.object(ci,'stage',side_effect=altered): result=ci.run(self.args)
                self.assertFalse(result['complete_success'])
                self.assertIs(result['full_W1_4097_qualified'],False)

    def test_source_finalization_failure_cannot_promote_an_earlier_success(self):
        with patch.object(ci,'stage',side_effect=self.stage), patch.object(ci.component,
                'source_snapshot',side_effect=[self.source,dict(self.source,head='3'*40)]):
            result=ci.run(self.args)
        self.assertFalse(result['complete_success'])
        self.assertEqual(len(result['finalization_failures']),1)

    def test_existing_output_is_never_reused(self):
        self.args.out.mkdir(); old=self.args.out/'old';old.write_bytes(b'keep')
        with patch.object(ci,'stage') as called, self.assertRaises(FileExistsError): ci.run(self.args)
        called.assert_not_called(); self.assertEqual(old.read_bytes(),b'keep')

    def test_member_symlinks_duplicate_keys_and_nonfinite_json_are_rejected(self):
        valid=self.root/'valid.json';valid.write_bytes(b'{"a":1}')
        link=self.root/'link.json';link.symlink_to(valid)
        with self.assertRaises(OSError): ci.document(link)
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            valid.write_bytes(raw)
            with self.assertRaises(ValueError): ci.document(valid)

    def test_zero_exit_process_failure_retains_raw_and_remains_failed(self):
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.addCleanup(os.close,fd)
        error=ci.ProcessFailure('NATIVE_STDOUT_LIMIT',returncode=0,stdout=b'original-prefix',
            stderr=b'original-error',stdin_written=0,stdout_truncated=True)
        with patch.object(ci,'run_bounded',side_effect=error): row,raw=ci.stage(fd,'synthetic',[],180)
        self.assertEqual(row['exit_code'],0);self.assertFalse(row['process_complete'])
        self.assertTrue(row['stdout_truncated']);self.assertEqual(raw,b'original-prefix')
        self.assertEqual((self.root/'synthetic.stderr.log').read_bytes(),b'original-error')


if __name__=='__main__': unittest.main(verbosity=2)

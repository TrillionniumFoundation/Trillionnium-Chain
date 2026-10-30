#!/usr/bin/env python3
"""Synthetic profile/receipt controls and real private-inode counterexamples.

No Cargo, Rust selector, W1 work, original claim authentication or public service
is executed here. Mocked orchestration bodies remain expressly fixture-only.
"""
from argparse import Namespace
from copy import deepcopy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts/ci'), str(ROOT/'scripts'), str(ROOT/'formal/pon-nakamoto-v1')]
import run_pon_native_io_component as component
import check_pon_native_io_component as reader
import run_native_io_component_ci_v1 as ci
import test_pon_native_io_reservation_v2 as roots


class ReservationComponentControls(unittest.TestCase):
    def test_explicit_profile_binds_once_and_never_infers_or_falls_back(self):
        with patch.object(component, '_selected', None):
            for invalid in ('', 'v2', 'pn1-native-io-three-fd-component-v2', True, None):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    component.select_profile(invalid)
                self.assertIsNone(component._selected)
            self.assertIs(component.select_profile(component.PROFILE_V2), component.V2)
            self.assertIs(component.select_profile(component.PROFILE_V2), component.V2)
            with self.assertRaisesRegex(ValueError, 'PROFILE_ALREADY_BOUND'):
                component.select_profile(component.PROFILE)
            self.assertIs(component.protocol(), component.V2)

    def test_first_default_api_use_binds_v1_before_any_later_selection(self):
        source = SimpleNamespace(value={'origin': {'root_identity': {'device': 7, 'inode': 11}}})
        with patch.object(component, '_selected', None):
            self.assertIs(component.protocol(), component.V1)
            self.assertEqual(component.claim_name(source), 'component-execution-claim-v1-7-11')
            with self.assertRaisesRegex(ValueError, 'PROFILE_ALREADY_BOUND'):
                component.select_profile(component.PROFILE_V2)
            self.assertIs(component.protocol(), component.V1)
            self.assertIs(component.select_profile(component.PROFILE), component.V1)

    def test_versions_have_distinct_claim_storage_and_receipt_namespaces(self):
        self.assertEqual(component.V1.profile, component.PROFILE)
        self.assertEqual(component.V1.readback_schema, reader.SCHEMA)
        self.assertEqual(component.V1.ci_schema, ci.SCHEMA)
        for field in dataclasses.fields(component.Protocol):
            self.assertNotEqual(getattr(component.V1, field.name), getattr(component.V2, field.name), field.name)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            component.V2.profile = component.V1.profile
        with self.assertRaises(TypeError):
            component.PROTOCOLS['invented'] = component.V1
        source = SimpleNamespace(value={'origin': {'root_identity': {'device': 7, 'inode': 11}}})
        with patch.object(component, '_selected', component.V1):
            old_name = component.claim_name(source)
        with patch.object(component, '_selected', component.V2):
            new_name = component.claim_name(source)
        self.assertEqual(old_name, 'component-execution-claim-v1-7-11')
        self.assertEqual(new_name, 'component-reservation-execution-claim-v2-7-11')

    def test_actual_inventory_bytes_cannot_cross_profiles(self):
        with tempfile.TemporaryDirectory(prefix='reservation-v2-inventory-') as temp:
            root = Path(temp); (root/'retained.bin').write_bytes(b'fixture-only')
            fd = os.open(root, os.O_RDONLY|os.O_DIRECTORY)
            try:
                for produced, selected in ((component.V1,component.V2),(component.V2,component.V1)):
                    value = dict(schema=produced.inventory,profile=produced.profile,kind='prepare',
                        files=[dict(path='retained.bin',bytes=12,sha256=hashlib.sha256(b'fixture-only').hexdigest())])
                    raw=(json.dumps(value,separators=(',',':'))+'\n').encode()
                    (root/'artifact-files.json').write_bytes(raw)
                    digest=hashlib.sha256(raw).hexdigest()
                    with patch.object(component,'_selected',produced):
                        valid=component.ComponentBundle(root,digest,directory_fd=fd,kind='prepare');valid.close()
                    with patch.object(component,'_selected',selected), self.assertRaisesRegex(ValueError,'INVENTORY_DOMAIN'):
                        component.ComponentBundle(root,digest,directory_fd=fd,kind='prepare')
            finally:os.close(fd)

    def test_prepare_and_execute_require_the_explicit_selected_profile_before_work(self):
        with patch.object(component,'_selected',component.V2):
            for run in (component.prepare,component.execute):
                with self.subTest(stage=run.__name__), self.assertRaisesRegex(ValueError,'EXPLICIT_PROFILE'):
                    run(Namespace(profile=component.PROFILE),None)

    def test_wrong_preparation_profile_and_selector_fail_before_any_resource_check(self):
        good=dict(schema=component.V2.prepared,profile=component.V2.profile,capture_complete=True,
            selector_executed=False,failure=None,head='1'*40,tree='2'*40,
            runner_sha256=component.sha(component.__file__),selector=component.V2.selector,
            build_seconds=1200,collector_seconds=180)
        changes=[('schema',component.V1.prepared),('profile',component.V1.profile),
                 ('selector',component.V1.selector),('build_seconds',1201),('collector_seconds',181)]
        with patch.object(component,'_selected',component.V2), patch.object(component,'validate_resources') as resources:
            for field,value in changes:
                bad=dict(good);bad[field]=value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError,'REAL_COMPONENT_PREPARATION'):
                    component.validate_preparation(SimpleNamespace(json=lambda name:bad),'1'*40,'2'*40)
            resources.assert_not_called()

    def actual_root_fixture(self):
        temp=tempfile.TemporaryDirectory(prefix='reservation-v2-real-inode-fixture-')
        self.addCleanup(temp.cleanup)
        base=Path(temp.name); leaf=base/'raw/honest-miner';leaf.mkdir(parents=True,mode=0o700)
        file=leaf/'native.sqlite';file.write_bytes(b'x');file.chmod(0o600)
        rs,fs=leaf.stat(),file.stat();row=roots.fixture()
        row.update(owner_pid=os.getpid(),root_device=rs.st_dev,root_inode=rs.st_ino)
        for item in row['lifecycle']+row['cleanup_lifecycle']+row['objects']:
            if item['device'] is not None:item.update(device=fs.st_dev,inode=fs.st_ino)
        row['objects'][0]['actual_last_allocated_blocks_512']=fs.st_blocks
        roots.recharge(row)
        vfs='trnm-pn1-owned-inode-reservation-v2-'+str(os.getpid())+'-1'
        role=dict(index=0,role='honest-miner',registered_vfs=vfs,receipt=row)
        layout=dict(schema=component.V2.storage_profile,sqlite_domain=component.V2.root_schema,
            owner_pid=os.getpid(),roles=[dict(index=0,root_dev_ino=[rs.st_dev,rs.st_ino],registered_vfs=vfs)])
        bundle=object.__new__(reader.Bundle)
        bundle.root=base;bundle.fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY)
        self.addCleanup(os.close,bundle.fd)
        bundle.files={'raw/honest-miner/native.sqlite':dict(bytes=1,sha256=hashlib.sha256(b'x').hexdigest())}
        return bundle,role,layout,file

    def test_v2_root_terminal_checks_real_inode_and_exact_reservation_history(self):
        bundle,role,layout,_=self.actual_root_fixture()
        with patch.object(component,'_selected',component.V2):
            self.assertEqual(reader.root_terminal(bundle,role,os.getpid(),layout),0)
            for change in ('root-schema','vfs-name','reservation-peak','actual-bytes','owner-pid','unrecorded-reservation'):
                altered=deepcopy(role)
                if change=='root-schema':altered['receipt']['schema']=component.V1.root_schema
                elif change=='vfs-name':altered['registered_vfs']='trnm-pn1-owned-inode-v1-'+str(os.getpid())+'-1'
                elif change=='reservation-peak':altered['receipt']['retained_logical_bytes_peak']*=2
                elif change=='actual-bytes':altered['receipt']['objects'][0]['actual_last_bytes']=2
                elif change=='owner-pid':altered['receipt']['owner_pid']+=1
                else:
                    altered['receipt']['objects'][0]['high_water_bytes']*=2
                    altered['receipt']['high_water_sum']*=2
                    altered['receipt']['retained_logical_bytes_peak']*=2
                with self.subTest(change=change), self.assertRaises(ValueError):
                    reader.root_terminal(bundle,altered,os.getpid(),layout)

    def test_v1_reader_does_not_accept_v2_root_even_with_v1_outer_profile(self):
        bundle,role,layout,_=self.actual_root_fixture()
        with patch.object(component,'_selected',component.V1), self.assertRaisesRegex(ValueError,'ROOT_EXACT_FIELDS'):
            reader.root_terminal(bundle,role,os.getpid(),layout)

    def test_replacing_real_file_cannot_be_repaired_by_rehashing_only_inventory(self):
        bundle,role,layout,file=self.actual_root_fixture()
        old=file.with_name('old');file.rename(old);file.write_bytes(b'x');file.chmod(0o600)
        with patch.object(component,'_selected',component.V2), self.assertRaisesRegex(ValueError,'identity/private owner mismatch'):
            reader.root_terminal(bundle,role,os.getpid(),layout)

    def test_missing_three_fd_caller_is_not_supplied_by_v2_reservation_replay(self):
        dispatch=dict(schema=component.V2.dispatch,domain=component.V2.domain,component_only=True,
            executable_fd=7,execution_directory_fd=7,cwd_directory_fd=9)
        with patch.object(component,'_selected',component.V2), self.assertRaisesRegex(ValueError,'DISTINCT_THREE_FD'):
            reader.first_dispatch(None,dispatch,{},123,{})

    def test_rehashed_v2_stage_storage_metadata_and_role_swaps_are_rejected(self):
        def fixture(indices):
            return dict(schema=component.V2.native_schema,
                native_io_storage_profile=component.V2.storage_profile,
                native_io_terminals_healthy_closed=True,
                native_io_terminal_roots=[dict(index=index, synthetic_fixture_only=True) for index in indices])
        def rehashed(value):
            raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
            print(json.dumps(dict(synthetic_metadata_predicate_only=True,
                bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                original_claim_authentication=False),sort_keys=True))
            return json.loads(raw)
        with patch.object(component,'_selected',component.V2):
            for indices in ((0,),(5,6)):
                good=fixture(indices)
                self.assertEqual([row['index'] for row in reader.reservation_report_bindings(rehashed(good),indices)],list(indices))
                changes=[('schema',component.V1.native_schema),
                    ('native_io_storage_profile',component.V1.storage_profile),
                    ('native_io_storage_profile',None),
                    ('native_io_terminals_healthy_closed',False),
                    ('native_io_terminals_healthy_closed',1),
                    ('native_io_terminal_roots',[]),
                    ('native_io_terminal_roots',[{} for _ in indices]),
                    ('native_io_terminal_roots',[dict(index=float(i)) for i in indices])]
                for field,value in changes:
                    altered=deepcopy(good);altered[field]=value
                    with self.subTest(indices=indices,field=field,value=value),self.assertRaises(ValueError):
                        reader.reservation_report_bindings(rehashed(altered),indices)
                missing=deepcopy(good);del missing['native_io_storage_profile']
                with self.assertRaisesRegex(ValueError,'REPORT_FIELDS'):
                    reader.reservation_report_bindings(rehashed(missing),indices)
            # The old combined role census would still be [0,5,6]. Each actual
            # stage must instead bind its own predeclared role denominator.
            swapped_preparation=fixture((5,));swapped_phase=fixture((0,6))
            self.assertEqual(sorted([row['index'] for row in swapped_preparation['native_io_terminal_roots']+
                swapped_phase['native_io_terminal_roots']]),[0,5,6])
            with self.assertRaises(ValueError):reader.reservation_report_bindings(rehashed(swapped_preparation),(0,))
            with self.assertRaises(ValueError):reader.reservation_report_bindings(rehashed(swapped_phase),(5,6))
            with self.assertRaises(ValueError):reader.reservation_report_bindings(rehashed(fixture((6,5))),(5,6))
        with patch.object(component,'_selected',component.V1),self.assertRaisesRegex(ValueError,'REPORT_PROFILE'):
            reader.reservation_report_bindings(fixture((0,)),(0,))


class ReservationCiControls(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='reservation-v2-ci-fixture-')
        self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.args=Namespace(profile=component.PROFILE_V2,out=self.root/'out',target_dir=self.root/'target',
            cargo=Path('/fixture-not-executed/cargo'),expected_head='1'*40,expected_tree='2'*40)
        self.calls=[]
        for obj,name,value in ((component,'_selected',None),
            (component,'source_snapshot',lambda:dict(head='1'*40,tree='2'*40,status_porcelain='',branch='fixture')),
            (component,'resources',lambda:{'synthetic_fixture_only':True})):
            patched=patch.object(obj,name,value);patched.start();self.addCleanup(patched.stop)

    def stage(self,fd,name,command,seconds):
        self.calls.append((name,command,seconds));p=component.protocol();flags=component.component_flags()
        step=dict(name=name,exit_code=0,process_complete=True,synthetic_fixture_only=True)
        folder=self.args.out/('prepared' if name=='prepare' else 'execution')
        if name=='prepare':
            folder.mkdir(mode=0o700)
            value=dict(schema=p.prepared,profile=p.profile,head='1'*40,tree='2'*40,
                capture_complete=True,selector_executed=False,failure=None,**flags)
            (folder/'prepared.json').write_text(json.dumps(value))
            (folder/'artifact-files.json').write_text('{"synthetic_fixture_only":true}')
        elif name=='execute':
            folder.mkdir(mode=0o700)
            value=dict(schema=p.execution,complete_success=True,selector_executed=True,failure=None,**flags)
            (folder/'results.json').write_text(json.dumps(value))
            (folder/'artifact-files.json').write_text('{"synthetic_fixture_only":true}')
        body=dict(schema=p.readback_schema,profile=p.profile,mechanism_readback_complete=True,
            prefix_paid_unique=2,final_paid_unique=6,actual_used_Node_roles=[0,5,6],**flags)
        return step,json.dumps(body).encode()

    def test_v2_ci_commands_bind_three_stages_without_changing_work_or_caps(self):
        with patch.object(ci,'stage',side_effect=self.stage):result=ci.run(self.args)
        self.assertTrue(result['complete_success']) # Fixture orchestration only.
        self.assertEqual(result['schema'],component.V2.ci_schema)
        self.assertEqual([name for name,_,_ in self.calls],['prepare','execute','readback'])
        self.assertEqual([seconds for _,_,seconds in self.calls],[1200,180,180])
        for _,command,_ in self.calls:
            self.assertEqual(command[command.index('--profile')+1],component.PROFILE_V2)
        self.assertEqual(result['original_control_plan'],component.PLAN)
        self.assertEqual(result['resource_policy'],dict(cpu_max='400000 100000',memory_max='17179869184',nice=10))
        for flag in component.FULL_FLAGS:self.assertIs(result[flag],False)
        self.assertIs(result['full_route_ready'],False)

    def test_v1_preparation_rejected_before_v2_execution_and_no_retry(self):
        def wrong(fd,name,command,seconds):
            step,raw=self.stage(fd,name,command,seconds)
            path=self.args.out/'prepared/prepared.json';v=json.loads(path.read_text())
            v['schema']=component.V1.prepared;v['profile']=component.V1.profile;path.write_text(json.dumps(v))
            return step,raw
        with patch.object(ci,'stage',side_effect=wrong):result=ci.run(self.args)
        self.assertFalse(result['complete_success'])
        self.assertEqual([name for name,_,_ in self.calls],['prepare'])
        self.assertEqual(result['failure'],'CI_REAL_PUBLIC_PREPARATION_REQUIRED')
        self.assertFalse((self.args.out/'execution').exists())

    def test_profile_rebinding_fails_before_output_creation(self):
        component.select_profile(component.PROFILE)
        with patch.object(ci,'stage') as execute,self.assertRaisesRegex(ValueError,'PROFILE_ALREADY_BOUND'):
            ci.run(self.args)
        execute.assert_not_called();self.assertFalse(self.args.out.exists())


if __name__=='__main__':unittest.main(verbosity=2)

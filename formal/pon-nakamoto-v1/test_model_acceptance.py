"""Synthetic receipt attacks only: no LLM, future observations or real consumers."""
import copy
import hashlib
import unittest
import tempfile
import contextlib
import io
import os
import sys
from unittest.mock import patch
from pathlib import Path
from experiments.verify_model_acceptance import (ingest, bounded_file, load_json,\n    _bounded_file_at, _pinned_package)
from model_acceptance import *
from test_llm_adapter_contract import fixture_contract, fixture_plan, fixture_record, identity as tid
from llm_adapter_contract import freeze_target_contract, freeze_run_plan


def fixture():
    contract = fixture_contract(); _, cid = freeze_target_contract(contract)
    plan = fixture_plan(contract, cid)
    for task in plan['tasks']:
        task['source_group'] = tid(task['partition']+task['source_group'])
    _, pid = freeze_run_plan(plan, contract, cid)
    record = fixture_record(plan, pid)
    for participant in record['participants'][1:]:
        for run in participant['runs']:
            run['outputs'] = {task: tid('wrong') for task in run['outputs']}
    material = {}
    def blob(label):
        raw = ('synthetic-only:'+label).encode(); root = hashlib.sha256(raw).hexdigest()
        material[root] = raw; return root
    bindings = {name: blob(name) for name in ['candidate', *CONTROL_IDS, 'backbone', 'tokenizer', 'task-data']}
    evidence = {name: blob(name) for name in EXTERNAL}
    prereg = dict(schema='pon-model-operations-preregistration-v1', run_plan=pid,
        registered_at=10, release_after=20, closes_at=30, retention_until=40,
        minimum_gain_ppm=1, max_probe_regressions=0, max_retention_byte_seconds=100000,
        min_consumer_operations=1, training_groups=[tid('train')],
        future_groups=sorted({t['source_group'] for t in plan['tasks'] if t['partition']=='evaluation'}),
        probes=[dict(id=tid(k), kind=k, prompt=tid(k+'prompt'), target=tid(k+'safe')) for k in PROBES],
        material_roots=sorted(bindings.values()), material_bindings=bindings,
        owner=tid('owner'), operator=tid('operator'), reviewer=tid('reviewer'), governance=tid('governance'),
        evidence=evidence, scope='reported-record-gates-only-no-independent-acceptance')
    raw, aid = freeze_preregistration(prereg, plan, pid)
    assessed = evaluate_run_record(plan, record, pid)
    task = next(t for t in plan['tasks'] if t['partition']=='evaluation')
    receipt = dict(schema='pon-model-operations-reported-receipt-v1', preregistration=aid,
        run_record=assessed['record'], observed_at=29, task_released_at=21,
        probes=[dict(id=p['id'], outputs={name:p['target'] for name in ['candidate', *CONTROL_IDS]}) for p in prereg['probes']],
        consumers=[dict(operation=tid('operation'), consumer=tid('consumer'), task=task['id'],
            candidate=plan['candidate'], seed=plan['seeds'][0], output=task['target_output_sha256'], used_at=25)],
        retention=[dict(root=root, bytes=len(material[root]), copies=2, starts_at=10, ends_at=40,
            retrieved_sha256=root, retrieved_at=28, repair_bytes=1) for root in prereg['material_roots']],
        evidence=evidence.copy(), scope=prereg['scope'])
    return prereg, raw, aid, plan, pid, record, receipt, material


class ModelAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.prereg, self.raw, self.aid, self.plan, self.pid, self.record, self.receipt, self.material = fixture()

    def verify(self):
        return verify_acceptance(self.raw, self.aid, self.plan, self.pid, self.record, self.receipt, self.material)

    def rebind(self):
        self.receipt['run_record'] = evaluate_run_record(self.plan, self.record, self.pid)['record']

    def test_complete_synthetic_record_never_promotes_external_acceptance(self):
        result = self.verify()
        self.assertTrue(result['reported_gates_passed'])
        self.assertFalse(result['material_relationship_verified'])
        self.assertFalse(result['full_model_retention_cost_complete'])
        self.assertIsNone(result['complete_model_retention_byte_seconds'])
        self.assertEqual(result['external_gates_unverified'], list(EXTERNAL))
        for name in ('prospective_accepted', 'independent_accepted', 'public_reward_eligible', 'production_activation'):
            self.assertIs(result[name], False)

    def test_changed_preregistration_rejects_without_owner_pinned_identity(self):
        self.prereg['minimum_gain_ppm'] = 2
        raw, _ = freeze_preregistration(self.prereg, self.plan, self.pid)
        self.raw = raw
        with self.assertRaisesRegex(ValueError, 'MANIFEST_IDENTITY'): self.verify()

    def test_changed_run_outputs_cannot_reuse_receipt(self):
        self.record['participants'][1]['runs'][0]['outputs'][self.plan['tasks'][0]['id']] = tid('changed')
        with self.assertRaisesRegex(ValueError, 'RECEIPT_BINDING'): self.verify()

    def test_no_gain_is_preserved_as_failed_gate(self):
        for participant in self.record['participants'][1:]:
            for run in participant['runs']:
                run['outputs'] = {t['id']:t['target_output_sha256'] for t in self.plan['tasks']}
        self.rebind()
        self.assertFalse(self.verify()['reported_gates']['reported_gain'])

    def test_poison_backdoor_and_forgetting_are_independent_negative_gates(self):
        for index, kind in enumerate(PROBES):
            with self.subTest(kind=kind):
                saved = copy.deepcopy(self.receipt)
                self.receipt['probes'][index]['outputs']['candidate'] = tid('unsafe')
                result = self.verify()
                self.assertFalse(result['reported_gates']['adversarial_nonregression'])
                self.assertEqual(result['probe_regressions'][kind], 1)
                self.receipt = saved

    def test_missing_probe_control_and_probe_duplicate_reject(self):
        del self.receipt['probes'][0]['outputs'][CONTROL_IDS[-1]]
        with self.assertRaisesRegex(ValueError, 'PROBE_CONTEXT'): self.verify()

    def test_missing_evidence_bytes_or_substituted_bytes_reject(self):
        key = next(iter(self.material)); raw = self.material.pop(key)
        with self.assertRaisesRegex(ValueError, 'MATERIAL_SET'): self.verify()
        self.material[key] = raw+b'changed'
        with self.assertRaisesRegex(ValueError, 'MATERIAL_BINDING'): self.verify()

    def test_future_or_backdated_observation_rejects(self):
        for field, value in [('observed_at',31), ('task_released_at',19)]:
            old=self.receipt[field]; self.receipt[field]=value
            with self.assertRaisesRegex(ValueError, 'OBSERVATION_CHRONOLOGY'): self.verify()
            self.receipt[field]=old

    def test_declared_independence_alias_and_training_overlap_reject(self):
        for edit, error in [(lambda p:p.update(reviewer=p['operator']), 'ROLE_ALIAS'),
                            (lambda p:p.update(training_groups=p['future_groups']), 'GROUP_LEAKAGE'),
                            (lambda p:p.update(registered_at=p['release_after']), 'CHRONOLOGY')]:
            p=copy.deepcopy(self.prereg);edit(p)
            with self.assertRaisesRegex(ValueError,error): freeze_preregistration(p,self.plan,self.pid)

    def test_calibration_future_group_overlap_reject(self):
        self.plan['tasks'][0]['source_group'] = self.prereg['future_groups'][0]
        # Force all calibration into a future group, then pin the changed run plan.
        for t in self.plan['tasks']:
            if t['partition']=='calibration': t['source_group']=self.prereg['future_groups'][0]
        _, pid = freeze(self.plan, validate_run_plan, 'target-decoder-evaluation-run-plan-v1')
        self.prereg['run_plan']=pid
        with self.assertRaisesRegex(ValueError, 'FUTURE_PARTITION_LEAKAGE'):
            freeze_preregistration(self.prereg,self.plan,pid)

    def test_duplicate_operation_rejects_and_content_relabel_does_not_multiply_use(self):
        self.receipt['consumers'] *= 2
        with self.assertRaisesRegex(ValueError, 'CONSUMER_REPLAY'): self.verify()
        self.receipt['consumers'][1]=dict(self.receipt['consumers'][1], operation=tid('new-label'))
        self.assertEqual(self.verify()['unique_reported_uses'],1)

    def test_wrong_candidate_wrong_output_or_bool_seed_reject(self):
        for field, value in [('candidate',tid('other')),('output',tid('wrong')),('seed',True)]:
            old=self.receipt['consumers'][0][field];self.receipt['consumers'][0][field]=value
            with self.assertRaises(ValueError):self.verify()
            self.receipt['consumers'][0][field]=old

    def test_no_consumer_is_failed_gate_not_adoption(self):
        self.receipt['consumers']=[]
        self.assertFalse(self.verify()['reported_gates']['reported_consumer_use'])

    def test_retention_shortening_missing_material_and_boolean_cost_reject(self):
        for field, value in [('ends_at',39),('bytes',1),('copies',True),('repair_bytes',-1),('retrieved_sha256',tid('wrong'))]:
            old=self.receipt['retention'][0][field];self.receipt['retention'][0][field]=value
            with self.assertRaises(ValueError):self.verify()
            self.receipt['retention'][0][field]=old

    def test_retention_cost_overrun_is_failed_gate(self):
        self.receipt['retention'][0]['copies']=100000
        self.assertFalse(self.verify()['reported_gates']['retention_budget'])

    def test_unknown_gpu_does_not_become_zero(self):
        self.record['participants'][0]['runs'][0]['costs'][0]['gpu_ns']=None
        self.rebind()
        result=self.verify()
        self.assertFalse(result['reported_gates']['complete_gpu_cost'])
        self.assertIsNone(result['run_assessment']['reported_aggregate_costs']['gpu_ns'])

    def test_bounded_offline_ingestion_rechecks_original_contract_and_plan(self):
        contract=fixture_contract(); contract_raw, cid=freeze_target_contract(contract)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name, value in [('contract',contract),('plan',self.plan),('run-record',self.record),
                                ('preregistration',self.prereg),('receipt',self.receipt)]:
                (root/(name+'.json')).write_bytes(canonical(value))
            index={key:key+'.bin' for key in self.material}
            (root/'material-index.json').write_bytes(canonical(index))
            for key,raw in self.material.items():(root/index[key]).write_bytes(raw)
            args=dict(preregistration_hash=self.aid,plan_hash=self.pid,contract_hash=cid,
                backbone_root=contract['backbone']['index_root'],tokenizer_root=contract['tokenizer']['files_root'],
                owner_record=self.plan['source_registration']['owner_record'])
            self.assertTrue(ingest(root,**args)['reported_gates_passed'])
            args['owner_record']=tid('substituted-owner')
            with self.assertRaisesRegex(ValueError,'RUN_OWNER'):ingest(root,**args)

    def test_cli_negative_gate_emits_failed_assessment_and_exit_two(self):
        from experiments.verify_model_acceptance import main
        report=self.verify();report['reported_gates_passed']=False
        args=['verify','--input','unused','--require-reported-gates']
        for name in ('preregistration-hash','plan-hash','contract-hash','backbone-root','tokenizer-root','owner-record'):
            args.extend(['--'+name,tid(name)])
        output=io.StringIO()
        with patch.object(sys,'argv',args), patch('experiments.verify_model_acceptance.ingest',return_value=report):
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as error:main()
        self.assertEqual(error.exception.code,2)
        self.assertFalse(load_json(output.getvalue())['reported_gates_passed'])
        self.assertFalse(load_json(output.getvalue())['independent_accepted'])

    def test_input_escape_duplicate_json_and_nonfinite_reject(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ('../outside','/etc/passwd','./receipt.json'):
                with self.assertRaises(ValueError):bounded_file(root,name,100)
            (root/'large').write_bytes(b'12345')
            with self.assertRaisesRegex(ValueError,'INPUT_LIMIT'):bounded_file(root,'large',4)
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError):load_json(raw)

    @unittest.skipUnless(os.name == 'posix', 'descriptor pinning is POSIX-only and fails closed elsewhere')
    def test_descriptor_pinning_rejects_symlink_hardlink_and_intermediate_aliases(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'real').write_bytes(b'owner-bytes')
            (root/'file-link').symlink_to(root/'real')
            with self.assertRaisesRegex(ValueError, 'INPUT_PATH'):
                bounded_file(root, 'file-link', 100)

            nested = root/'nested'
            nested.mkdir()
            (nested/'value').write_bytes(b'nested-owner')
            (root/'dir-link').symlink_to(nested, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'INPUT_PATH'):
                bounded_file(root, 'dir-link/value', 100)

            os.link(root/'real', root/'hard')
            with self.assertRaisesRegex(ValueError, 'INPUT_PATH'):
                bounded_file(root, 'hard', 100)

    @unittest.skipUnless(os.name == 'posix', 'descriptor pinning is POSIX-only and fails closed elsewhere')
    def test_open_package_descriptor_survives_visible_directory_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            root = parent/'package'
            root.mkdir()
            (root/'value').write_bytes(b'owner-bytes')
            with _pinned_package(root) as descriptor:
                retained = parent/'retained'
                root.rename(retained)
                root.mkdir()
                (root/'value').write_bytes(b'substituted-bytes')
                self.assertEqual(_bounded_file_at(descriptor, 'value', 100), b'owner-bytes')
            self.assertEqual((root/'value').read_bytes(), b'substituted-bytes')

    @unittest.skipUnless(os.name == 'posix', 'descriptor pinning is POSIX-only and fails closed elsewhere')
    def test_symlink_package_root_is_rejected_before_any_input_read(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            actual = parent/'actual'
            actual.mkdir()
            (actual/'value').write_bytes(b'owner')
            alias = parent/'alias'
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'INPUT_PATH'):
                bounded_file(alias, 'value', 100)

    def test_acceptance_claim_extra_field_and_bool_threshold_reject(self):
        self.receipt['independent_accepted']=True
        with self.assertRaisesRegex(ValueError, 'RECEIPT_FIELDS'):self.verify()
        self.prereg['minimum_gain_ppm']=True
        with self.assertRaisesRegex(ValueError, 'GAIN'):freeze_preregistration(self.prereg,self.plan,self.pid)


if __name__=='__main__':unittest.main(verbosity=2)
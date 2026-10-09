#!/usr/bin/env python3
"""Mutation checks against independently replayed native observations, not pass quotas."""
import copy,json,unittest
from check_native_node_supplements import ROOT,load,replay_expectations,validate_batch_report,validate

class NativeSupplementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=ROOT/'evidence/pon-native-node-v1'
        cls.q=load(cls.folder/'qualification.json')
        cls.record=load(cls.folder/'native-batch-replay/report.json')
        cls.expected=replay_expectations(ROOT,cls.folder/'native-batch-replay')
    def reject(self,mutate):
        record=copy.deepcopy(self.record);mutate(record)
        with self.assertRaises(ValueError):validate_batch_report(record,self.q,self.expected)
    def test_retained_native_results_match_separate_work_state_replay(self):
        result=validate_batch_report(self.record,self.q,self.expected)
        self.assertEqual(result['application_confirmation_targets'],sum(len(e['queries'])for e in self.expected))
    def test_historical_supplement_replays_its_measured_model_and_zero_settlement(self):
        from historical_evidence import validate_historical_cli
        result=validate_historical_cli(ROOT/'scripts/ci/check_native_node_supplements.py',ROOT,self.folder)
        self.assertEqual(result['measured_commit'],self.q['source_commit'])
        self.assertTrue(result['historical_semantics_verified'])
        self.assertFalse(result['runtime_matches'])
        self.assertFalse(result['current_source_qualified_by_this_check'])
        self.assertFalse(result['production_activation'])
    def test_source_substitution_rejects(self):
        self.reject(lambda r:r.update(source_commit='00'*20))
    def test_native_binary_substitution_rejects(self):
        self.reject(lambda r:r.update(binary_sha256='00'*32))
    def test_public_capacity_or_independence_cannot_be_invented(self):
        self.reject(lambda r:r.update(public_confirmed_tps=1000000))
        self.reject(lambda r:r.update(independent_operators=True))
    def test_boolean_exit_code_cannot_alias_success(self):
        self.reject(lambda r:r['results'][0].update(returncode=False))
    def test_missing_native_call_cannot_hide_in_summary(self):
        self.reject(lambda r:r['results'].pop())
    def test_false_inclusion_count_rejects(self):
        self.reject(lambda r:r['scenarios'][0].update(application_confirmations=999))
    def test_native_batch_fields_are_recomputed_not_trusted_booleans(self):
        def alter(record):
            row=next(r for r in record['results']if r['command'][1]=='confirm-batch')
            value=json.loads(row['stdout']);value['result']['observations'][0]['confirmed']=1
            row['stdout']=json.dumps(value)
        self.reject(alter)
    def test_duplicate_json_fields_in_recorded_native_output_reject(self):
        def alter(record):
            row=record['results'][0]
            row['stdout']=row['stdout'].rstrip()[:-1]+',"production_activation":false}'
        self.reject(alter)
    def test_substituted_required_work_rejects(self):
        def alter(record):
            row=next(r for r in record['results']if r['command'][1]=='confirm')
            value=json.loads(row['stdout']);value['result']['required_work_delta']='00'*64
            row['stdout']=json.dumps(value)
        self.reject(alter)
    def test_omitted_batch_member_cannot_be_summarized_as_complete(self):
        def alter(record):
            row=next(r for r in record['results']if r['command'][1]=='confirm-batch')
            value=json.loads(row['stdout']);value['result']['observations'].pop()
            row['stdout']=json.dumps(value)
        self.reject(alter)
    def test_process_cost_cannot_be_less_than_recorded_child_intervals(self):
        self.reject(lambda r:r['confirmation_comparisons'][0]['elapsed_ns'].update(serial=1))

class OwnedHostSupplementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=ROOT/'evidence/pon-native-node-v1'
        cls.q=load(cls.folder/'qualification.json');cls.record=load(cls.folder/'owned-host-smoke/report.json')
        cls.expected=load(cls.folder/'owned-host-smoke/expected.json');cls.packet=(cls.folder/'owned-host-smoke/accepted.packet').read_bytes()
    def check(self,record):
        from check_native_node_supplements import validate_owned_host_report
        return validate_owned_host_report(record,self.q,self.expected,self.packet)
    def test_owned_observations_match_exact_binary_vector_and_scope(self):
        self.assertEqual(self.check(self.record)['owned_host_observations_checked'],3)
    def test_changed_owned_binary_or_identity_rejects(self):
        for field,value in [('binary_sha256','00'*32),('source_commit','00'*20),('same_operator',False)]:
            record=copy.deepcopy(self.record);record[field]=value
            with self.assertRaises(ValueError):self.check(record)
    def test_missing_owned_call_and_boolean_exit_reject(self):
        record=copy.deepcopy(self.record);record['commands'].pop()
        with self.assertRaises(ValueError):self.check(record)
        record=copy.deepcopy(self.record);record['commands'][0]['returncode']=False
        with self.assertRaises(ValueError):self.check(record)
    def test_owned_root_and_confirmation_cannot_be_forged(self):
        for index,key,value in [(6,'state_root','00'*32),(8,'confirmed',True),(8,'depth',False)]:
            record=copy.deepcopy(self.record);row=record['commands'][index]
            output=json.loads(row['stdout']);output['result'][key]=value;row['stdout']=json.dumps(output)
            with self.assertRaises(ValueError):self.check(record)
    def test_owned_observations_cannot_be_promoted_to_public_acceptance(self):
        for field in ['independent_accepted','public_network_ready','physical_power_loss','production_activation','installed_services']:
            record=copy.deepcopy(self.record);record[field]=True
            with self.assertRaises(ValueError):self.check(record)

if __name__=='__main__':unittest.main(verbosity=2)

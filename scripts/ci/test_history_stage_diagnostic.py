#!/usr/bin/env python3
"""Local controls only: never provision resources or claim History qualification."""
import copy
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import run_history_native as original
import run_history_diagnostic as diagnostic
import run_from_zero_host as host
ROOT=Path(__file__).resolve().parents[2]
class Controls(unittest.TestCase):
    def summary(self):
        return dict(schema=diagnostic.SUMMARY_SCHEMA,passed=True,blocks=4105,
            confirmed_packets=4105,renewals=4,corrupt_active_index_reopen_refused=True,
            diagnostic_only=True,**{k:False for k in diagnostic.FALSE_FLAGS})
    def test_output_path_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            with patch.dict(os.environ, {'TRNM_CI_RECEIPT_DIR':str(root)}):
                self.assertEqual(diagnostic.output_path(root/'history-diagnostic'),root/'history-diagnostic')
                for path in [root/'history-native',root/'other',ROOT/'history-diagnostic']:
                    with self.assertRaises(ValueError):diagnostic.output_path(path)
                with self.assertRaises(ValueError):original.output_path(root/'history-diagnostic')
    def test_diagnostic_log_denominators_fail_closed(self):
        names=['decode','context_owner_wait','context','work','admission_owner_wait','admission','submit_result','admission_prepare','execution','commit_owner_wait','commit','cpu_wait','body_decode','response_encoding','history_epoch_open','history_epoch_close','history_import','cpu_settle','root_commitment']
        phases=[dict(phase=name,started=True,completed=True,accepted=True,wall_ns=1,thread_cpu_ns=1) for name in names]
        host=dict(calls_started=1,calls_completed=1,calls_accepted=1,calls_unfinished=0,
                  calls_rejected=0,cpu_clock_unknown_calls=0,wall_clock_unknown_calls=0)
        obs=dict(measurement_failures=0,supplied_packets=1,packets=[dict(phases=phases)],
                 phases=phases,host_checks=[dict(host,phase=name) for name in ['resolve','initial','checkpoint','final']])
        host=obs['host_checks'][0]
        row=dict(ok=True,error=None,elapsed_ns=1,observation=obs)
        record=dict(schema='native-ancestry-independent-sync-exit-evidence-v1',diagnostic_only=True,
                    sync_error=None,diagnostic_history_rpc=[row]*4105,diagnostic_import=[row]*4105)
        encode=lambda:json.dumps(record)+'\n'
        diagnostic.validate_diagnostic_log(encode())
        with self.assertRaises(ValueError):diagnostic.validate_diagnostic_log('')
        with self.assertRaises(ValueError):diagnostic.validate_diagnostic_log(encode()+encode())
        record['diagnostic_import']=record['diagnostic_import'][:-1]
        with self.assertRaises(ValueError):diagnostic.validate_diagnostic_log(encode())
        record['diagnostic_import']=[row]*4105
        for target,key,value in [(obs,'measurement_failures',1),(host,'calls_unfinished',1),
                                  (host,'cpu_clock_unknown_calls',1),(host,'phase','initial'),(phases[16],'started',False),(row,'ok',False)]:
            old=target[key];target[key]=value
            with self.assertRaises(ValueError):diagnostic.validate_diagnostic_log(encode())
            target[key]=old
    def test_scope_and_complete_denominator(self):
        diagnostic.validate_summary(self.summary())
        for key,value in [('blocks',4104),('confirmed_packets',2800),('passed',False),
                          ('resource_qualification',True),('diagnostic_only',False),
                          ('schema',original.SUMMARY_SCHEMA)]:
            s=self.summary();s[key]=value
            with self.assertRaises(ValueError):diagnostic.validate_summary(s)
        with self.assertRaises(ValueError):original.validate_summary(self.summary())
    def test_exact_host_routing_and_unknown_refusal(self):
        out=Path('/tmp/independent-history-diagnostic')
        cmd=['python3',diagnostic.SCRIPT,'--out',str(out)]
        self.assertEqual(host.validate_command(cmd),out)
        with patch.object(diagnostic,'validate_preparation',return_value={'diagnostic':True}) as f:
            self.assertEqual(host.prepare_command(cmd,out,Path('/tmp/receipt')),{'diagnostic':True});f.assert_called_once_with(out)
        with patch.object(diagnostic,'bind_execution',return_value={'bound':True}) as f:
            self.assertEqual(host.bind_command(cmd,{},out),{'bound':True});f.assert_called_once_with({},out)
        for bad in [cmd+['--skip-host'],['python3','scripts/ci/arbitrary.py','--out',str(out)]]:
            with self.assertRaises(ValueError):host.validate_command(bad)
    def test_exact_original_limits_and_error_recording(self):
        s=(ROOT/diagnostic.SOURCE).read_text()
        self.assertIn('const BLOCKS: u64 = 4105;',s)
        self.assertIn('Duration::from_secs(1800)',s)
        self.assertIn('Instant::now() + Duration::from_secs(30)',s)
        self.assertLess(s.index('while after != tip'),s.index('let observer = ingress::HistoryImportObserver::new()'))
        self.assertLess(s.index('diagnostic_rpc.push'),s.index('let reply = reply_result?'))
        self.assertLess(s.index('diagnostic_import.push'),s.index('after = import_result?'))
        for check in ['PARTIAL_SYNC_ACTIVATED','CONFIRMER_REOPEN','CONFIRMATION_STATE','GUEST_DURABLE_IDENTITY']:
            self.assertIn(check,s)
        self.assertNotEqual(diagnostic.TARGET,original.TARGET)
        self.assertNotEqual(diagnostic.EXECUTION_SCHEMA,original.EXECUTION_SCHEMA)
    def test_workflow_retains_all_replicas_and_failure_artifacts(self):
        s=(ROOT/'.github/workflows/pon-history-stage-diagnostic.yml').read_text()
        for text in ['fail-fast: false','replica: [1, 2]','if: always()','if-no-files-found: error','cancel-in-progress: false','--prepare','not qualification']:
            self.assertIn(text,s)
        self.assertNotIn('continue-on-error',s)
if __name__=='__main__':unittest.main()

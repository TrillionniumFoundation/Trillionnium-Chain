#!/usr/bin/env python3
"""Adversarial mutations of an actual supplied native campaign, never synthetic observations."""
import argparse
import copy
import json
from pathlib import Path
import tempfile
import unittest
from check_public_v3_service_campaign import gap, load, validate_report

REPORT = None

class CampaignTests(unittest.TestCase):
    def test_actual_complete_native_record(self):
        result=validate_report(REPORT)
        self.assertEqual(result['attempts'],130)
        self.assertGreaterEqual(result['false_transcript_rejections'],2)
        self.assertTrue(result['finite_target_met'])
        self.assertFalse(result['public_network_ready'])

    def test_failure_denominators_and_gap_cannot_be_edited_away(self):
        cases=[
            lambda r:r['attempts'].pop(next(i for i,a in enumerate(r['attempts']) if a['lane']=='injected_eof')),
            lambda r:r['attempts'][0].__setitem__('ordinal',2),
            lambda r:r['phases'][0].__setitem__('honest_probe_successes',0),
            lambda r:r['phases'][0].__setitem__('honest_probe_max_gap_ns',1),
            lambda r:r.__setitem__('honest_probe_max_gap_including_restart_ns',1),
            lambda r:r.__setitem__('call_deadline_ms',True),
            lambda r:r['phases'][0].__setitem__('ended_ns',r['phases'][0]['started_ns']+1),
            lambda r:r['phases'][1].__setitem__('phase',0),
        ]
        for index,mutate in enumerate(cases):
            with self.subTest(index=index):
                report=copy.deepcopy(REPORT);mutate(report)
                with self.assertRaises(ValueError):validate_report(report)

    def test_payload_restart_and_authority_tampering_are_rejected(self):
        def change_queued_bytes(r):
            row=next(a for a in r['attempts'] if a['lane']=='honest_mutation' and a['request']['op']=='pool_submit_bundle')
            raw=row['request']['transactions'][0]
            row['request']['transactions'][0]=raw[:-1]+('0' if raw[-1]!='0' else '1')
        def change_ack(r):
            row=next(a for a in r['attempts'] if a['lane']=='honest_mutation' and a['request']['op']=='submit')
            row['response']['value']['block']='ff'*32
        def invented_paid_bytes(r):
            row=next(a for a in r['attempts'] if a['response'] is not None)
            row['response']['body_bytes_sent']+=1
        cases=[change_queued_bytes,change_ack,invented_paid_bytes,
            lambda r:r.__setitem__('public_network_ready',True),
            lambda r:r.__setitem__('independent_accepted',True),
            lambda r:r.__setitem__('unrecognized_success_authority',True),
            lambda r:r['restart']['after'].__setitem__('state_root','ff'*32),
            lambda r:r['restart'].__setitem__('kind','independent-process-restart'),
            lambda r:r['phases'][0]['server_metrics'].__setitem__('paid_body_reserved_bytes_after_shutdown',False),
        ]
        for index,mutate in enumerate(cases):
            with self.subTest(index=index):
                report=copy.deepcopy(REPORT);mutate(report)
                with self.assertRaises(ValueError):validate_report(report)

    def test_gap_includes_failed_probes_and_both_observation_boundaries(self):
        rows=[dict(lane='honest_probe',status='ok',ended_ns=10),
              dict(lane='honest_probe',status='error',ended_ns=60),
              dict(lane='honest_probe',status='ok',ended_ns=110)]
        self.assertEqual(gap(rows,0,120),100)
        self.assertEqual(gap(rows,0,240),130)
        self.assertEqual(gap([],5,30),25)

    def test_full_work_requires_real_trace_refusal_and_header_bound_ticket(self):
        def change_only_trace_to_reference(r):
            fixture=r['phases'][0]['false_transcript_fixture']
            fixture['forged_packet']=fixture['reference_packet']
        def replace_with_malformed_body(r):
            row=next(a for a in r['attempts'] if a['lane']=='paid_false_transcript')
            row['request']['packet']='00'
        def relabel_signed_error(r):
            row=next(a for a in r['attempts'] if a['lane']=='paid_false_transcript' and a['status']=='refused'
                     and a['response']['value']['error']=='WORK:Transcript')
            row['response']['value']['error']='PUBLIC_MUTATION_CPU_BUDGET'
        def change_claimed_trace(r):
            fixture=r['phases'][0]['false_transcript_fixture']
            packet=bytearray.fromhex(fixture['forged_packet']);packet[-1]^=1
            fixture['forged_packet']=packet.hex()
            for row in r['attempts']:
                if row['phase']==0 and row['lane']=='paid_false_transcript':
                    row['request']['packet']=fixture['forged_packet']
        cases=[change_only_trace_to_reference,replace_with_malformed_body,relabel_signed_error,change_claimed_trace,
            lambda r:r['phases'][0]['false_transcript_fixture'].__setitem__('ticket_trials',4097),
            lambda r:r['phases'][0]['false_transcript_fixture'].__setitem__('ticket_trials',1+(r['phases'][0]['false_transcript_fixture']['ticket_trials']%4096)),
            lambda r:r['phases'][0].__setitem__('false_transcript_rejections',0),
            lambda r:r['phases'][0]['server_metrics'].__setitem__('work_started',0),
            lambda r:r['phases'][0].__setitem__('full_work_observed',False),
        ]
        for index,mutate in enumerate(cases):
            with self.subTest(index=index):
                report=copy.deepcopy(REPORT);mutate(report)
                with self.assertRaises(ValueError):validate_report(report)

    def test_duplicate_keys_and_noncanonical_numeric_constants_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'record.json'
            for raw in ('{"phase":0,"phase":1}','{"started_ns":NaN}','{"ended_ns":Infinity}'):
                path.write_text(raw)
                with self.assertRaises(ValueError):load(path)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report',required=True)
    args=parser.parse_args();REPORT=load(Path(args.report))
    unittest.main(argv=[__file__])

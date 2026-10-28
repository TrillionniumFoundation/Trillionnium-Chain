#!/usr/bin/env python3
"""Read actual final native artifacts; never turn an absent process into zero cost."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def read(path):return json.loads(path.read_text())

def main():
    build=read(HERE/'build-receipt.json')
    tests=read(HERE/'tests-receipt.json')
    assert build['passed'] and tests['passed']
    assert build['binary_sha256']==tests['binary_sha256']
    names=['validation-worker','activation-committed',
           'publication-intent-file-synced','publication-intent-linked',
           'publication-intent-final-synced','publication-intent-unlinked',
           'publication-intent-published']
    rows=[]
    for name in names:
        case=HERE/'native-03'/'artifacts'/name
        result=read(case/'process-result.json')
        guardian=result['guardian']; rec=result['reconciliation']; finished=result['finished']
        closed=guardian['closed_process']
        count=7 if name=='activation-committed' else 6
        assert result['binary_sha256']==build['binary_sha256']
        assert guardian['passed'] and guardian['actual_wait4'] and guardian['wait_status']==9
        assert closed['actual_wait4'] and closed['signal']==9
        assert closed['reported_cpu_upper_bound_ns']<=4_000_000_000
        assert closed['reported_cpu_upper_bound_ns']==(
            closed['user_cpu_microseconds']+closed['system_cpu_microseconds']+2)*1000
        assert rec['original_cpu_split']=='unknown-preserved' and not rec['native_effect_repeated']
        assert not rec['new_cpu_epoch_created']
        assert result['original_records_unchanged']
        for original,digest in result['original_record_sha256'].items():
            assert sha(case/'v6-journal'/original)==digest
        cold=finished['cold_journal']
        assert cold['used_operations']==count and cold['known_settlements']==count-1
        assert cold['unknown_prepaid_reconciliations']==1 and cold['pending'] is None and cold['epoch'] is None
        assert cold['spent']['cpu_ns']==count*4_000_000_000
        assert finished['marker_count']==(4 if name=='activation-committed' else 2)
        startup=read(case/'resume-control'/'startup-ready.json')
        validation=read(case/'resume-control'/'validation-ready.json')['result']
        assert startup['initial_cpu']['stored_credit_ns']==0
        cpu=validation['cpu']
        assert cpu['spawned_workers']==cpu['started_workers']==cpu['finished_workers']==cpu['known_workers']==2
        assert cpu['scoped_worker_cpu_ns']>0
        assert cpu['total_cpu_ns']==cpu['owner_cpu_ns']+cpu['scoped_worker_cpu_ns']
        assert not cpu['accounting_unavailable'] and not cpu['live_refused']
        row={'cutpoint':name,'actual_native_child_sigkill_wait4':True,
            'whole_original_process_reported_cpu_upper_bound_ns':closed['reported_cpu_upper_bound_ns'],
            'original_scope_allowance_ns':4_000_000_000,
            'new_native_process_initial_credit_ns':startup['initial_cpu']['stored_credit_ns'],
            'new_validation_cpu':cpu,'cold_journal':cold,'final_marker_count':finished['marker_count'],
            'old_records_unchanged':True,'process_result_sha256':sha(case/'process-result.json')}
        if name.startswith('publication-intent-'):
            publication=read(case/'crash-control'/'publication-repair-result.json')
            actual=publication['result']; repeated=publication['idempotent_retry']
            assert actual['journal']==repeated['journal'] and repeated['already_published']
            assert actual['existing_frame_bytes_preserved'] and not actual['new_journal_event_created']
            assert not actual['cpu_receipt_created'] and not actual['new_cpu_epoch_created']
            assert actual['journal']['spent']['cpu_ns']==8_000_000_000
            assert actual['journal']['known_settlements']==1 and actual['journal']['used_operations']==2
            pin=actual['externally_pinned_latest_anchor']
            final=case/'v6-journal'/f"{pin['sequence']:020}-{actual['frame_sha256']}.json"
            assert final.stat().st_size==actual['frame_bytes'] and sha(final)==actual['frame_sha256']
            assert publication['original_unknown_split_kept'] and len(publication['refusals'])==5
            row['publication']={'frame_sha256':actual['frame_sha256'],'frame_bytes':actual['frame_bytes'],
                'prefix_anchor':actual['prefix_anchor'],'externally_signed_latest_anchor':pin,
                'idempotent_retry_no_new_event':True,'refusal_count':len(publication['refusals']),
                'result_sha256':sha(case/'crash-control'/'publication-repair-result.json')}
        rows.append(row)
    repairs=[]
    case=HERE/'native-03'/'artifacts'/'publication-intent-file-synced'
    for stage in ['linked','unlinked']:
        path=case/f'publication-repair-{stage}'
        guardian=read(path/'guardian-result.json')
        assert guardian['passed'] and guardian['actual_wait4'] and guardian['wait_status']==9
        assert guardian['native_operation_started'] is False
        assert guardian['new_cpu_epoch_created'] is False
        assert guardian['v6_closed_process_receipt_created'] is False
        assert not (path/'closed-process.json').exists()
        repairs.append({'repair_stage':stage,'guardian_sha256':sha(path/'guardian-result.json'),
            'actual_sigkill_wait4':True,'v6_recovery_receipt_created':False,
            'reported_user_seconds':guardian['reported_user_seconds'],
            'reported_system_seconds':guardian['reported_system_seconds']})
    summary={'schema':'history-publication-native-readback-v1','passed':True,
        'base_commit':build['base_commit'],'binary_sha256':build['binary_sha256'],
        'build_receipt_sha256':sha(HERE/'build-receipt.json'),
        'tests_receipt_sha256':sha(HERE/'tests-receipt.json'),
        'native_tests_passed':15,'ignored_child_helpers':1,
        'original_native_crash_controls':2,'new_original_append_crash_cuts':5,
        'additional_new_repair_crash_cuts':2,'cases':rows,'repair_processes':repairs,
        'whole_history_p0_closed':False,'physical_power_loss_qualified':False,
        'arbitrary_subprocess_adoption_qualified':False,'production_qualified':False}
    (HERE/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('cases','repair_processes')},sort_keys=True))

if __name__=='__main__':main()

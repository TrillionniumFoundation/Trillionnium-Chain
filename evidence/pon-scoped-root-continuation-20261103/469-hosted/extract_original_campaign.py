"""Keep all original 3 x 3 x 3 confirmations and 189 packet exposures."""
import collections
import hashlib
import json
import pathlib
import zipfile
from datetime import datetime, timezone

BASE=pathlib.Path(__file__).resolve().parent
helper=BASE/'extract_service_outcomes.py'
ns={'__file__':str(helper)}
exec(helper.read_text().split('retained_metadata = []')[0],ns)
archive=ns['archive_metadata']('original-native-head-13232334075.zip',13232334075,41641510344,125935910153,
    'bd3da1ef08c7bd49156b011d31bff501c2331a6f36eaa93ba700314f313a31a6')
sha=ns['sha'];jm=ns['json_member'];calls=ns['calls_summary'];imports=ns['import_observation']
round_rows=[];packet_rows=[];phases=[];attempts=[];retained=[]
with zipfile.ZipFile(BASE/archive['retained_zip']) as z:
    result,result_meta=jm(z,'results.json')
    assert result['expected_head']==ns['HEAD'] and result['expected_tree']==ns['TREE']
    assert result['planned_complete_runs']==3 and len(result['attempts'])==3
    assert result['original_inputs']=={'attacker_processes':[0,24,24],'business_blocks':21,
        'modes':['baseline','from-zero','late-product'],'phase_seconds':30,'seed_blocks':4,'seed_transfers':1024}
    for attempt in result['attempts']:
        number=attempt['number'];report,report_meta=jm(z,f'run-{number}-raw/report.json')
        assert report_meta['sha256']==attempt['report_sha256']
        assert len(report['phases'])==3
        assert attempt['step']['returncode']==101 and not attempt['phase_startup_errors']
        assert attempt['report_validation_failure'] is None
        assert not attempt['original_criteria_met'] and not report['finite_experiment_criteria_met']
        for stream in ('stdout','stderr'):
            data=z.read(attempt['step'][stream]);assert sha(data)==attempt['step'][stream+'_sha256']
        attempts.append({'number':number,'report':report_meta,
            **{k:attempt[k] for k in ('original_criteria_met','complete_success','phase_startup_errors','report_validation_failure','step')},
            'public_resource_policy':report['public_resource_policy'],
            'settings_profile':report['settings_profile'],'state_backend':report['state_backend']})
        for phase in report['phases']:
            mode=phase['mode'];observations={r['round']:r for r in phase['confirmations']}
            assert len(observations)==len(phase['confirmations']) and all(0<=r<3 for r in observations)
            for round_index in range(3):
                c=observations.get(round_index)
                round_rows.append([number,mode,round_index,c is not None,
                    c.get('started_ns') if c else None,c.get('ended_ns') if c else None,
                    bool(c and c['confirmed_inside_pressure_window']),
                    bool(c and c['observation'] and c['observation']['confirmed'])])
            submissions=phase['submissions']
            assert all(0<=s['packet_index']<21 for s in submissions)
            for packet_index in range(21):
                group=[s for s in submissions if s['packet_index']==packet_index]
                ack=sum(s['status']=='ok' and s['response']['ok'] and not s['returned_after_window'] for s in group)
                packet_rows.append([number,mode,packet_index,len(group),ack])
            raw_phase,phase_meta=jm(z,f'run-{number}-raw/{mode}.json')
            assert raw_phase==phase
            imported=[h['client_import'] for h in phase['history'] if h.get('client_import')]
            phases.append({'run':number,'mode':mode,'report':phase_meta,
                'planned_confirmations':3,'planned_packet_exposures':21,
                'observed_rounds':len(observations),
                'confirmed_inside_original_window':sum(c['confirmed_inside_pressure_window'] for c in observations.values()),
                **{k:phase[k] for k in ('duration_seconds','attacker_processes_ready','attacker_processes_requested',
                    'genuine_budget_depletion_observed','finite_phase_criteria_met','observer_complete',
                    'full_work_accepted','full_work_failed','receiver_client_state_equal')},
                'submissions':calls(submissions),'history':calls(phase['history']),
                'imports':imports(imported),'verifier_errors':phase['verifier_errors'],
                'original_host_before':phase['phase_process_context']['host_before'],
                'original_host_after':phase['phase_process_context']['host_after']})
        for member in (f'run-{number}-result.json',f'run-{number}.stdout.log',f'run-{number}.stderr.log'):
            raw=z.read(member);assert len(raw)<100000
            dest=BASE/'original-thirty-second-raw'/member;dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open('xb') as f:f.write(raw)
            retained.append({'path':str(dest.relative_to(BASE)),'bytes':len(raw),'sha256':sha(raw)})
    for member in ('results.json','source-before.json','source-after.json','source-after-native.json'):
        raw=z.read(member);assert len(raw)<100000
        dest=BASE/'original-thirty-second-raw'/member;dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('xb') as f:f.write(raw)
        retained.append({'path':str(dest.relative_to(BASE)),'bytes':len(raw),'sha256':sha(raw)})

assert len(round_rows)==27 and len(packet_rows)==189 and len(phases)==9
outcome={'schema':'chain-469-original-thirty-second-outcomes-v1',
    'extracted_at_utc':datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
    'head':ns['HEAD'],'tree':ns['TREE'],'artifact':archive,'results':result_meta,
    'native_runtime_rerun':False,'repository_modified':False,
    'original_inputs':result['original_inputs'],'expected_controller_resources':result['expected_resources'],
    'failure':result['failure'],'complete_success':result['complete_success'],
    'attempts':attempts,'phases':phases,
    'planned_confirmations':27,'planned_business_packet_exposures':189,
    'confirmed_inside_original_thirty_second_window':sum(r[6] for r in round_rows),
    'observed_rounds':sum(r[3] for r in round_rows),'unobserved_rounds':sum(not r[3] for r in round_rows),
    'actual_submission_attempts':sum(p[3] for p in packet_rows),'actual_timely_ack_count':sum(p[4] for p in packet_rows),
    'round_columns':['run','phase','round','observed','started_ns','ended_ns','confirmed_inside_original_window','independent_observation_confirmed'],
    'all_planned_round_rows':round_rows,
    'packet_columns':['run','phase','packet_index','observed_attempts','timely_network_ack_count'],
    'all_planned_packet_rows':packet_rows,
    'import_row_columns':['started_ns','ended_ns','accepted','error','caller_cpu_ns','wall_ns','Host_checkpoint_calls',
        'Host_checkpoint_caller_cpu_ns','Host_checkpoint_rejected','Host_checkpoint_unfinished','Host_checkpoint_cpu_unknown'],
    'scope':[
        'Three original complete native campaigns of the new 469 HEAD, each with baseline / 24-actor from-zero / 24-actor late-product phases. Every phase preserves 30 seconds, 3 planned confirmations and 21 signed packet exposures. No old-source result is substituted.',
        'Each native command exits 101 with complete untruncated stdout/stderr and a valid report. All phase_startup_errors are empty, all report_validation_failure values are null; all nine phase finite criteria remain false.',
        'All 27 planned rounds and all 189 planned packet exposures remain, including 15 unobserved rounds and 105 unattempted packets. The 84 actual ACKs do not replace the planned denominator. An ACK is not an independent confirmation.',
        'Imports include success and deadline refusal. Host checkpoint spans are inside import and use the same calling-thread scope; they are not added. Scoped-worker CPU is separate. These original 30-second counts are not four-second or cheapest-work qualification.',
        'F0/client arithmetic snapshot scopes include subsequent confirmation/read_active and cannot produce an exact graph/import CPU percentage. No such cross-scope percentage is calculated here.',
        'The raw ZIP and exact report/log SHA256 values are retained. Only small command/source records are extracted; no ELF or database is extracted. Pending ARM CPU and separate recent/PQ lanes are outside this report.'
    ],'retained_small_metadata':retained}
out=BASE/'original-thirty-second-outcomes.json'
with out.open('x') as f:json.dump(outcome,f,separators=(',',':'));f.write('\n')
print(json.dumps({'path':str(out),'bytes':out.stat().st_size,'sha256':sha(out.read_bytes()),
    'confirmed':outcome['confirmed_inside_original_thirty_second_window'],'planned_confirmations':27,
    'planned_packet_exposures':189,'actual_ack_count':outcome['actual_timely_ack_count']}))

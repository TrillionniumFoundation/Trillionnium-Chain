#!/usr/bin/env python3
"""Read original M14 x64 GitHub campaign ZIP, without running or modifying it."""
import argparse
import hashlib
import json
import zipfile

HEAD='ac8501a85a770ba34f34e1bed507ca747e5c3f8d'
ZIP_SHA='7996763ffc628f025f2d8e47bf3a6f184805a4b5b24dd13b273ee508903b1f78'
MODES=('baseline','from-zero','late-product')

def check(value,code):
    if not value: raise ValueError(code)

def analyze(path,head=HEAD,expected_zip_sha=ZIP_SHA):
    with open(path,'rb') as fh: sha=hashlib.file_digest(fh,'sha256').hexdigest()
    check(sha==expected_zip_sha==ZIP_SHA,'ZIP_SHA_CHANGED')
    out={'schema':'pq-root-m14-checkpoint-readback-v1','source_head':HEAD,
         'workflow_run':42693805359,'artifact_id':13708896865,
         'archive_sha256':sha,'phase_results':[],
         'boundaries':{'actual_lifetime_failure_bound':None,'qualification':'HOLD_NO_GO',
                       'production_activation':False,'physical_operators_independent':False,
                       'native_full_campaign_passed':False}}
    with zipfile.ZipFile(path) as z:
        check(len(z.namelist())==1766 and len(set(z.namelist()))==1766,'ZIP_MEMBERSHIP_CHANGED')
        results=json.loads(z.read('results.json'))
        check(results['expected_head']==head==HEAD,'WRONG_EXECUTED_HEAD')
        check(results['complete_success'] is False and results['planned_complete_runs']==3
              and len(results['attempts'])==3,'ORIGINAL_CAMPAIGN_CHANGED')
        check(results['original_inputs']=={'attacker_processes':[0,24,24],
              'business_blocks':21,'modes':list(MODES),'phase_seconds':30,
              'seed_blocks':4,'seed_transfers':1024},'WORKLOAD_CHANGED')
        placement=results['public_phase_placement']
        check(placement['receiver_and_verifier_cpu_max']=='25000 100000'
              and placement['receiver_and_verifier_memory_max']=='2147483648',
              'HOST_BUDGET_CHANGED')
        for n,attempt in enumerate(results['attempts'],1):
            check(attempt['number']==n and attempt['step']['returncode']==101
                  and attempt['original_criteria_met'] is False
                  and attempt['phase_startup_errors']==[], 'ORIGINAL_RUN_CHANGED')
            raw=z.read(f'run-{n}-raw/report.json')
            check(hashlib.sha256(raw).hexdigest()==attempt['report_sha256'],
                  'REPORT_DIGEST_CHANGED')
            report=json.loads(raw)
            check(report['finite_experiment_criteria_met'] is False
                  and len(report['phases'])==3,'ORIGINAL_REPORT_CHANGED')
            for mode,embedded in zip(MODES,report['phases']):
                p=json.loads(z.read(f'run-{n}-raw/{mode}.json'))
                check(p==embedded,'PHASE_VALUE_CHANGED')
                check(p['duration_seconds']==30 and p['mode']==mode
                      and p['attacker_processes_requested']==(0 if mode=='baseline' else 24)
                      and p['finite_phase_criteria_met'] is False
                      and p['genuine_budget_depletion_observed'] is False
                      and p['receiver_client_state_equal'] is False,'PHASE_CONTRACT_CHANGED')
                calls=cpu=import_cpu=import_wall=completed=failed=0
                for history in p['history']:
                    imp=history['client_import']
                    if not imp['succeeded']:
                        failed+=1
                        continue
                    completed+=1
                    obs=imp['native_import_observation']
                    check(obs['schema']=='pon-local-history-import-observation-v1'
                          and obs['measurement_failures']==0,'IMPORT_OBSERVER_CHANGED')
                    checkpoints=[h for h in obs['host_checks'] if h['phase']=='checkpoint']
                    check(len(checkpoints)==1,'CHECKPOINT_OBSERVER_MISSING')
                    c=checkpoints[0]
                    check(c['calls_started']==c['calls_completed']
                          and c['calls_rejected']==0 and c['cpu_clock_unknown_calls']==0,
                          'CHECKPOINT_INCOMPLETE')
                    calls+=c['calls_completed'];cpu+=c['thread_cpu_ns']
                    check(imp['thread_cpu_observation_available'] is True,'IMPORT_CPU_UNKNOWN')
                    import_cpu+=imp['thread_cpu_ns'];import_wall+=imp['wall_ns']
                out['phase_results'].append({'run':n,'mode':mode,
                    'history_requests':len(p['history']),
                    'successful_imports':completed,'failed_imports':failed,
                    'checkpoint_calls':calls,'checkpoint_thread_cpu_ns':cpu,
                    'successful_import_thread_cpu_ns':import_cpu,
                    'successful_import_wall_ns':import_wall,
                    'signed_confirmations_in_window':sum(c['confirmed_inside_pressure_window']
                                                          for c in p['confirmations']),
                    'signed_confirmation_rounds':len(p['confirmations'])})
    check(len(out['phase_results'])==9,'MISSING_ORIGINAL_PHASE')
    out['by_mode']={mode:{k:sum(r[k] for r in out['phase_results'] if r['mode']==mode)
       for k in ('successful_imports','failed_imports','checkpoint_calls',
                 'checkpoint_thread_cpu_ns','successful_import_thread_cpu_ns',
                 'successful_import_wall_ns','signed_confirmations_in_window')}
       for mode in MODES}
    return out

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('zip');p.add_argument('--head',default=HEAD)
    p.add_argument('--sha256',default=ZIP_SHA);args=p.parse_args()
    print(json.dumps(analyze(args.zip,args.head,args.sha256),sort_keys=True,indent=2))

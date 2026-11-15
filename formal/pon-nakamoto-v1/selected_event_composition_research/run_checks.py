#!/usr/bin/env python3
"""Fresh isolated validation for the reconstructed deliverable; standard library only."""
from datetime import datetime,timezone
from hashlib import sha256
from pathlib import Path
import json,re,subprocess,sys
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent

def preservation():
    p=json.loads((BASE/'provenance.json').read_text());old=Path(p['recovered_round1_work_bound_path'])
    if not old.is_dir():return {'status':'recovered_prior_directory_not_present_in_this_environment'}
    expected=p['recovered_round1_work_bound_before']
    actual={str(f.relative_to(old)):sha256(f.read_bytes()).hexdigest() for f in old.rglob('*') if f.is_file()}
    changed=sorted(k for k in set(expected)|set(actual) if expected.get(k)!=actual.get(k))
    return {'status':'UNCHANGED' if not changed else 'CHANGED','checked_files':len(expected),'differences':changed}

def main():
    commands=[('unit-tests',[sys.executable,'-B','-m','unittest','-v','test_composition']),
              ('exact-cost',[sys.executable,'-B','exact_cost.py'])]
    for name in ('44','45','large_caps'):
        commands.append((f'budget-{name}',[sys.executable,'-B','composition_budget.py',
                         f'budget_example_{name}.json','--output',f'budget_result_{name}.json']))
    records=[];test_count=None
    for name,command in commands:
        result=subprocess.run(command,cwd=BASE,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (BASE/f'{name}.log').write_text(result.stdout)
        records.append({'name':name,'command':command,'exit_code':result.returncode,'output_log':f'{name}.log'})
        if name=='unit-tests':
            match=re.search(r'Ran (\d+) tests',result.stdout)
            if match:test_count=int(match.group(1))
        if result.returncode:print(result.stdout,end='');raise SystemExit(result.returncode)
    previous=preservation()
    summary={'schema':'selected-composition-reconstructed-fresh-checks-v2',
      'reconstructed_new_run':True,'historical_round2_test_result_reused':False,
      'completed_utc':datetime.now(timezone.utc).isoformat(),'python':sys.version,
      'commands':records,'unit_test_count_observed':test_count,
      'recovered_native_observation_replays':3,'new_native_benchmarks':0,
      'producer_schedules':2,'sample_nonces_each':3,'recovered_round1_preservation':previous,
      'source_sha256':{f.name:sha256(f.read_bytes()).hexdigest() for f in sorted(BASE.glob('*.py'))},
      'qualification':'HOLD_NO_GO'}
    (BASE/'checks_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    if previous['status']=='CHANGED':raise SystemExit('recovered previous archive changed')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()

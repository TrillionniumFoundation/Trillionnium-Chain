from pathlib import Path
from collections import Counter
import ast
import gzip
import hashlib
import io
import json
import re
import resource
import tarfile
import time

started=time.monotonic(); before=resource.getrusage(resource.RUSAGE_SELF)
directory=Path(__file__).resolve().parent
root=directory.parents[1]
sha=lambda b: hashlib.sha256(b).hexdigest()
commands=json.loads((directory/'commands.json').read_text())
raw=(directory/commands['archive']['path']).read_bytes()
assert len(raw)==commands['archive']['bytes'] and sha(raw)==commands['archive']['sha256']
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tar:
    assert sorted(tar.getnames())==sorted(row['path'] for row in commands['archive_members'])
    for row in commands['archive_members']:
        data=tar.extractfile(row['path']).read()
        assert len(data)==row['bytes'] and sha(data)==row['sha256']
    for row in commands['commands'][1:]:
        name=row['raw_directory_in_archive'];receipt=row['receipt']
        for stream in ('stdout','stderr'):
            assert sha(tar.extractfile(name+'/'+stream+'.txt').read())==receipt[stream+'_sha256']
    controls=tar.extractfile('r14-matrix-controls/stderr.txt').read().decode()
    assert 'Ran 11 tests' in controls and controls.rstrip().endswith('OK')
    for script in ('analyze.py','test_analyze.py'):
        data=(directory/script).read_bytes()
        ast.parse(data,filename=script)
        assert data==tar.extractfile('executed-source/'+script).read()

matrix=json.loads((directory/'matrix.json').read_text())
totals=Counter();paths=Counter();errors=Counter()
for phase in matrix['phases']:
    for key in ('attack_calls','receiver_digest_matches','client_minus_receiver_records',
                'actors_exit_success','actors_forced_kill','actors_attempt_cap'):
        totals[key]+=phase[key]
    for key in ('planned_rounds','observed_rounds','confirmed_rounds','unobserved_rounds',
                'planned_business_packets','submitted_packets','on_time_signed_submissions',
                'history_attempts','on_time_history_responses','history_import_attempts',
                'history_import_successes','history_import_failures','actual_confirmation_calls'):
        totals[key]+=phase['honest'][key]
    paths.update(phase['receiver_path_counts']);errors.update(phase['client_errors'])
    assert phase['receiver_stage_matrix']['admission']['started']==0
    assert phase['original_phase_criteria'] is False
    assert phase['original_depletion_verdict'] is False
assert totals['attack_calls']==11216 and totals['receiver_digest_matches']==11215
assert totals['confirmed_rounds']==0 and totals['planned_rounds']==27
assert totals['history_import_successes']==15 and totals['history_import_attempts']==24
assert totals['submitted_packets']==totals['on_time_signed_submissions']==63
assert totals['planned_business_packets']==189
assert paths['W1_rejected_response_complete']==11081 and paths['W1_rejected_no_complete_response']==7
assert sum(errors.values())==144 and totals['actors_forced_kill']==0
expected=[1960984060,1961936241,1960639215,1962404262,1960025650,1959763023]
observed=[row['lower_bound_ns'] for row in matrix['continuous_ledger_bounds'] if row['mode']!='baseline']
assert observed==expected
intervals=[json.loads(line) for line in gzip.decompress((directory/'flow-intervals.jsonl.gz').read_bytes()).splitlines()]
assert len(intervals)==sum(row['pair_count'] for row in matrix['continuous_ledger_bounds'])
for row in matrix['continuous_ledger_bounds']:
    selected=[p for p in intervals if (p['run'],p['mode'])==(row['run'],row['mode'])]
    assert len(selected)==row['pair_count']
    assert min(p['lower_bound_ns'] for p in selected)==row['lower_bound_ns']
for target in re.findall(r'\]\(([^)]+)\)',(directory/'README.md').read_text()):
    if target.startswith(('https:','http:','#')):
        continue
    assert (directory/target.split('#')[0]).exists(),target
after=resource.getrusage(resource.RUSAGE_SELF)
result={'status':'PASS','scope':'artifact hashes, executed Python bytes, retained test outputs, all totals and interval records, relative Markdown links; no native execution',
        'all_original_failures_preserved':True,'archive_members_verified':len(commands['archive_members']),
        'diagnostic_controls_passed':11,'totals':dict(totals),'receiver_path_counts':dict(paths),
        'client_errors':dict(errors),'flow_intervals':len(intervals),
        'elapsed_seconds':time.monotonic()-started,'user_cpu_seconds':after.ru_utime-before.ru_utime,
        'system_cpu_seconds':after.ru_stime-before.ru_stime,'self_peak_rss_kib':after.ru_maxrss,
        'verifier_script_sha256':sha(Path(__file__).read_bytes()),
        'files_verified':[{ 'path':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
                          for p in sorted(directory.iterdir()) if p.is_file() and p.name!='validation.json'],
        'work_package_2b_closed':False}
(directory/'validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('files_verified','receiver_path_counts','client_errors')}))

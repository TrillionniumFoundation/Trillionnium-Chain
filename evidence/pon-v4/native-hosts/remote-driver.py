
import hashlib,json,os,platform,resource,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent
manifest=json.loads((root/'manifest.json').read_text())
for name,digest in manifest['files'].items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('SOURCE_HASH')
request=json.loads((root/'requests.json').read_text());samples=[]
for case in request:
    for workers in [1,2,4,8]:
        for variant in ['baseline','candidate']:
            data=dict(case['request'],workers=workers)
            start=time.perf_counter_ns()
            p=subprocess.run([str(root/variant)],input=json.dumps(data,separators=(',',':')).encode(),capture_output=True,timeout=30)
            wall=time.perf_counter_ns()-start
            if p.returncode:raise RuntimeError(variant+':'+p.stderr.decode(errors='replace')[:1000])
            answer=json.loads(p.stdout)
            if answer['state']!=case['expected'] or answer['receipts']!=case['receipts'] or answer['root']!=case['root']:raise RuntimeError('PARITY')
            if answer['network']!=data['network'] or answer['parameters']!=data['parameters']:raise RuntimeError('CONTEXT')
            if variant=='candidate' and (answer['metrics']['workers_spawned']>workers or answer['metrics']['signature_verifications']!=len(data['transactions'])):raise RuntimeError('WORK_BOUND')
            samples.append(dict(scenario=case['scenario'],workers=workers,variant=variant,root=answer['root'],metrics=answer['metrics'],wall_ns=wall,transactions=len(data['transactions']),included=None,confirmed=None))
print(json.dumps(dict(platform=platform.platform(),machine=platform.machine(),utc_completed_ns=time.time_ns(),source_manifest=manifest,samples=samples,all_parity_passed=True,temporary_filesystem_only=True,max_rss_kib_children=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,independent_operator=False,consensus_host=False,production_activation=False)))

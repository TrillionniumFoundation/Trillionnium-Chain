"""Independent owned-process receipt checks; no native child is executed here."""
from pathlib import Path
from .observations import basic_process,ident,exact_int
from ..contract import identity
COLLECTOR_SHA='01accf26eecd5b0bdecd94909d328cafc028d7d2bcf387ec9ecbcab533b146cc'
def owned_process(store,logical,seconds,argv,cwd,expected_env=None):
 r=store.doc(logical+'/receipt.json');v=basic_process(r,seconds)
 assert r['argv']==argv and r['cwd']==cwd
 if expected_env is not None:assert r['environment']==expected_env
 req=store.doc(logical+'/request.json')
 for key in ['argv','cwd','environment','execution_deadline_seconds','cleanup_deadline_seconds','collector_argv','collector_sha256','command','original_deadline_monotonic_ns','original_boot_id','stdin']:assert req[key]==r[key],key
 assert req['status']=='INCOMPLETE' and req['started'] is False
 for name in ['stdin','stdout','stderr','collector.stdout','collector.stderr']:assert store.identity(logical+'/'+name+'.raw')==r[name]
 command=store.doc(logical+'/command.json');assert store.identity(logical+'/command.json')==r['command']
 assert command['argv']==r['argv'] and command['cwd']==cwd and command['environment']==r['environment']
 directory=store.origin+'/'+logical
 for name in ['stdin','stdout','stderr']:assert command[name]==directory+'/'+name+'.raw'
 assert command['stdin_identity']==r['stdin']==ident(b'')
 actual_exec=command['executable'];assert actual_exec.startswith('/') and exact_int(command['executable_identity']['bytes'],1)>0
 assert store.actual(actual_exec)==command['executable_identity']
 request=store.session
 python=request['python']['path'];python_id={k:request['python'][k] for k in ['bytes','sha256']}
 aliases={'/usr/bin/python3':python,'bash':'/usr/bin/bash'}
 if argv[0]=='/usr/bin/gcc':aliases[argv[0]]=store.doc('allocator-build/build.json')['tools']['allocator_cc']['path']
 if argv[0]=='/usr/bin/nm':aliases[argv[0]]=store.doc('runtime-tools.json')['nm']['path']
 assert actual_exec==aliases.get(argv[0],argv[0])
 source=request['source_root'];process=source+'/hia/platform/service_settlement/process.py';collector=source+'/scripts/w1_owned_process_collector_v1.py'
 assert store.actual(process)==store.source('hia/platform/service_settlement/process.py')
 assert store.actual(collector)==store.source('scripts/w1_owned_process_collector_v1.py')
 assert store.source('scripts/w1_owned_process_collector_v1.py')['sha256']==COLLECTOR_SHA==r['collector_sha256']
 assert store.actual(python)==python_id
 wanted=[python,'-B',collector,'--out',directory+'/owned','--cwd',cwd,'--deadline-monotonic-ns',str(r['original_deadline_monotonic_ns']),'--deadline-boot-id',r['original_boot_id'],'--cleanup-grace-seconds','3','--executable-sha256',python_id['sha256'],'--max-processes','4096','--max-log-bytes','16777216','--env','PATH=/usr/bin:/bin','--env','PYTHONDONTWRITEBYTECODE=1','--',python,'-B',process,'--execute',directory+'/command.json','--sha256',r['command']['sha256']]
 assert r['collector_argv']==wanted
 intent=store.doc(logical+'/owned/intent.json');assert store.identity(logical+'/owned/intent.json')==r['intent']==v['intent']
 assert intent['executable_sha256']==python_id['sha256'] and exact_int(intent['executable_stat'][2])==python_id['bytes']
 assert store.actual(intent['command'][0])==python_id
 assert intent['environment']=={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'}
 assert intent['cwd']==cwd and intent['initial_wait_domain_empty'] is True and intent['subreaper_readback'] is True
 assert intent['cleanup_grace_seconds']==3 and intent['max_log_bytes_per_stream']==16777216 and intent['max_process_records']==4096
 assert intent['original_deadline_monotonic_ns']==r['original_deadline_monotonic_ns'] and intent['original_boot_id']==r['original_boot_id']
 assert intent['command']==wanted[wanted.index('--')+1:] and store.doc(logical+'/owned/result.json')==v
 events=store.read(logical+'/owned/events.jsonl')
 assert ident(events)=={k:v['events'][k] for k in ['bytes','sha256']} and len(events.splitlines())==v['events']['count']
 for name in ['stdout','stderr']:assert store.identity(logical+'/owned/'+name+'.log')=={'bytes':v['streams'][name]['stored_bytes'],'sha256':v['streams'][name]['sha256']}
 assert r['original_boot_id']==request['boot_id']
 assert request['start_monotonic_ns']<r['original_deadline_monotonic_ns']<=request['deadline_monotonic_ns']
 return r,command

"""Explicit owned-host native application parity. No daemon, live state or public keys used.

All inputs are public development fixtures. SSH authenticates the existing owned hosts;
multiple machines remain one administrator, not independent consensus operators.
"""
from __future__ import annotations
import argparse,hashlib,json,os,shlex,shutil,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import NETWORK,PARAMETER_HASH,GENESIS,H,canonical,execute_reference,genesis_state,key,public,sign,u64

DRIVER = r'''
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
'''

def run(out,baseline,candidate,hosts):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    if len(hosts)!=len(set(hosts)) or not hosts:raise ValueError('HOST_SET')
    root=Path(__file__).resolve().parents[3]
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    clean=not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
    state=genesis_state();n=16
    funds=[sign(key(0),i+1,'transfer',dict(recipient=public(key(i+4)),amount=100000))for i in range(n)]
    state,_=execute_reference(state,funds,1,public(key(0)),GENESIS)
    cases={
        'independent':[sign(key(i+4),1,'transfer',dict(recipient=H('host-recipient',u64(i)),amount=1))for i in range(n)],
        'hot-recipient':[sign(key(i+4),1,'transfer',dict(recipient=public(key(1)),amount=1))for i in range(n)],
        'hot-sender':[sign(key(4),i+1,'transfer',dict(recipient=public(key(1)),amount=1))for i in range(n)],
    }
    from contract_wire import state_root
    requests=[]
    for scenario,txs in cases.items():
        expected,receipts=execute_reference(state,txs,2,public(key(0)),H('host-parent'))
        requests.append(dict(scenario=scenario,request=dict(network=NETWORK.hex(),parameters=PARAMETER_HASH.hex(),state=state,transactions=[x.hex()for x in txs],height=2,miner=public(key(0)).hex(),parent=H('host-parent').hex()),expected=expected,receipts=[x.hex()for x in receipts],root=state_root(expected).hex()))
    (out/'requests.json').write_bytes(canonical(requests));(out/'remote-driver.py').write_text(DRIVER)
    results=[]
    with tempfile.TemporaryDirectory(prefix='pon-native-host-input-')as local:
        local=Path(local)
        for name,path in [('baseline',baseline),('candidate',candidate)]:shutil.copy2(path,local/name);(local/name).chmod(0o700)
        shutil.copy2(out/'requests.json',local/'requests.json');(local/'run.py').write_text(DRIVER)
        manifest=dict(schema='pon-native-host-input-v1',candidate_source=source,source_clean=clean,
                      files={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in local.iterdir()})
        (local/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        for host in hosts:
            remote=None;result={'host':host,'all_parity_passed':False,'independent_operator':False}
            ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',host]
            try:
                p=subprocess.run(ssh+['python3 -c '+shlex.quote('import tempfile;print(tempfile.mkdtemp(prefix="pon-native-parity-"))')],capture_output=True,text=True,timeout=20,check=True)
                remote=p.stdout.strip()
                if not remote.startswith('/tmp/pon-native-parity-') or any(c in remote for c in ['\n',"'",' ',':']):raise ValueError('REMOTE_PATH')
                transfer=subprocess.run(['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=10',*[str(p)for p in local.iterdir()],host+':'+remote+'/'],capture_output=True,text=True,timeout=90)
                if transfer.returncode:raise RuntimeError('TRANSFER: '+transfer.stderr[:1000])
                p=subprocess.run(ssh+['python3 '+shlex.quote(remote+'/run.py')],capture_output=True,text=True,timeout=180)
                result['returncode']=p.returncode;(out/(host+'-stderr.log')).write_text(p.stderr)
                if p.returncode:raise RuntimeError('EXECUTION: '+p.stderr[:1000])
                observed=json.loads(p.stdout)
                if observed['source_manifest']!=manifest:raise RuntimeError('MANIFEST')
                result.update(observed);result['all_parity_passed']=True
            except (OSError,ValueError,RuntimeError,subprocess.SubprocessError)as error:
                result['error']=str(error)
            finally:
                if remote and remote.startswith('/tmp/pon-native-parity-'):
                    cleanup='import shutil;shutil.rmtree('+repr(remote)+')'
                    try:
                        c=subprocess.run(ssh+['python3 -c '+shlex.quote(cleanup)],capture_output=True,text=True,timeout=20)
                        result['owned_temporary_directory_removed']=c.returncode==0
                    except subprocess.SubprocessError:result['owned_temporary_directory_removed']=False
            results.append(result);print(json.dumps({'host':host,'all_parity_passed':result['all_parity_passed'],'error':result.get('error')}),flush=True)
    report=dict(schema='pon-native-host-parity-v1',source_commit=source,source_clean=clean,results=results,
        all_hosts_passed=all(r['all_parity_passed']for r in results),independent_operators=False,
        native_full_node=False,ordinary_hepta_entry=False,physical_power_loss=False,public_network_security=False,production_activation=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report['all_hosts_passed']
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--baseline',required=True);p.add_argument('--candidate',required=True);p.add_argument('--hosts',nargs='+',required=True)
    args=p.parse_args();sys.exit(0 if run(args.out,args.baseline,args.candidate,args.hosts)else 2)

"""Explicit owned-host evaluation parity; no private data, deployment or authority."""
from __future__ import annotations
import argparse,hashlib,io,json,os,re,shlex,subprocess,sys,tarfile,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
DRIVER=r'''
import hashlib,json,platform,resource,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent
manifest=json.loads((root/'manifest.json').read_text())
for name,digest in manifest['files'].items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise ValueError('SOURCE_HASH')
sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
from evaluation_bundle import evaluate_bundle,read_bounded,MAX_BUNDLE_BYTES,MAX_TASK_BYTES
bundle=read_bounded(root/'inputs/evaluation-bundle.json',MAX_BUNDLE_BYTES)
calibration=json.loads(read_bounded(root/'inputs/calibration.json',MAX_TASK_BYTES))
expected=json.loads((root/'inputs/expected.json').read_text());samples=[]
for partition in ['evaluation_a','evaluation_b','consumer']:
    rows=json.loads(read_bounded(root/('inputs/'+partition+'.json'),MAX_TASK_BYTES))
    started=time.perf_counter_ns()
    result=evaluate_bundle(bundle,manifest['bundle_hash'],rows,partition,calibration_rows=calibration)
    elapsed=time.perf_counter_ns()-started
    encoded=json.dumps(result,sort_keys=True,separators=(',',':')).encode()
    digest=hashlib.sha256(encoded).hexdigest()
    if digest!=expected[partition]:raise ValueError('EVALUATION_PARITY')
    samples.append({'partition':partition,'rows':len(rows),'result_sha256':digest,'elapsed_ns':elapsed,
                    'exploratory_score':result['primary']['exploratory_score'],
                    'public_reward_eligible':result['public_reward_eligible']})
print(json.dumps({'source_manifest':manifest,'platform':platform.platform(),'machine':platform.machine(),
 'completed_utc_ns':time.time_ns(),'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
 'samples':samples,'parity_passed':True,'independent_operator':False,'ordinary_hepta_entry':False,
 'native_consensus_host':False,'production_activation':False}))
'''

def run(inputs,out,expected_bundle,hosts):
    out=Path(out);out.mkdir(parents=True,exist_ok=False);inputs=Path(inputs)
    if len(set(hosts))!=len(hosts) or not hosts or any(not re.fullmatch('[A-Za-z0-9_.-]+',h)for h in hosts):
        raise ValueError('HOST_SET')
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():raise ValueError('DIRTY_SOURCE')
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
    from evaluation_bundle import evaluate_bundle,verify_bundle,read_bounded,MAX_BUNDLE_BYTES,MAX_TASK_BYTES
    bundle=read_bounded(inputs/'evaluation-bundle.json',MAX_BUNDLE_BYTES);verify_bundle(bundle,expected_bundle)
    calibration=json.loads(read_bounded(inputs/'calibration.json',MAX_TASK_BYTES))
    expected={}
    for name in ['evaluation_a','evaluation_b','consumer']:
        rows=json.loads(read_bounded(inputs/(name+'.json'),MAX_TASK_BYTES))
        result=evaluate_bundle(bundle,expected_bundle,rows,name,calibration_rows=calibration)
        expected[name]=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    files={}
    for path in sorted((ROOT/'formal/pon-nakamoto-v1').glob('*.py')):
        if not path.name.startswith(('test_','generate_')):files[str(path.relative_to(ROOT))]=path.read_bytes()
    for path in sorted((ROOT/'config/pon').glob('*.json')):files[str(path.relative_to(ROOT))]=path.read_bytes()
    for name in ['evaluation-bundle.json','calibration.json','evaluation_a.json','evaluation_b.json','consumer.json']:
        files['inputs/'+name]=read_bounded(inputs/name,MAX_TASK_BYTES)
    files['inputs/expected.json']=json.dumps(expected,sort_keys=True).encode();files['run.py']=DRIVER.encode()
    manifest={'schema':'pon-frozen-evaluation-host-input-v1','source_commit':source,'bundle_hash':expected_bundle,
              'files':{name:hashlib.sha256(data).hexdigest()for name,data in files.items()}}
    files['manifest.json']=json.dumps(manifest,sort_keys=True).encode()
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w')as archive:
        for name,data in files.items():
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600
            archive.addfile(info,io.BytesIO(data))
    archive_bytes=buffer.getvalue();(out/'source-manifest.json').write_bytes(files['manifest.json'])
    (out/'remote-driver.py').write_text(DRIVER);(out/'expected.json').write_bytes(files['inputs/expected.json'])
    results=[]
    for host in hosts:
        ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',host];remote=None
        result={'host':host,'parity_passed':False,'independent_operator':False}
        try:
            create=subprocess.run(ssh+['python3 -c '+shlex.quote('import tempfile;print(tempfile.mkdtemp(prefix="pon-evaluation-parity-"))')],capture_output=True,text=True,timeout=20,check=True)
            remote=create.stdout.strip()
            if not re.fullmatch('/tmp/pon-evaluation-parity-[A-Za-z0-9_-]+',remote):raise ValueError('REMOTE_PATH')
            # Extract only exact listed regular files into the exclusively created directory.
            extract='''import io,os,sys,tarfile,pathlib
root=pathlib.Path(sys.argv[1]).resolve(); raw=sys.stdin.buffer.read(33554433)
if len(raw)>33554432:raise ValueError('ARCHIVE_LIMIT')
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as a:
 for m in a:
  p=(root/m.name).resolve()
  if not m.isfile() or not p.is_relative_to(root) or m.size>33554432:raise ValueError('ARCHIVE_MEMBER')
  p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(a.extractfile(m).read())
'''
            transfer=subprocess.run(ssh+['python3 -c '+shlex.quote(extract)+' '+shlex.quote(remote)],input=archive_bytes,capture_output=True,timeout=90)
            if transfer.returncode:raise RuntimeError('TRANSFER '+transfer.stderr.decode(errors='replace')[:1000])
            observed=subprocess.run(ssh+['PYTHONDONTWRITEBYTECODE=1 python3 '+shlex.quote(remote+'/run.py')],capture_output=True,text=True,timeout=120)
            (out/(host+'-stderr.log')).write_text(observed.stderr);result['returncode']=observed.returncode
            if observed.returncode:raise RuntimeError('EXECUTION '+observed.stderr[:1500])
            value=json.loads(observed.stdout)
            if value['source_manifest']!=manifest:raise ValueError('MANIFEST')
            result.update(value)
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError)as error:result['error']=str(error)
        finally:
            if remote and re.fullmatch('/tmp/pon-evaluation-parity-[A-Za-z0-9_-]+',remote):
                cleanup='import shutil;shutil.rmtree('+repr(remote)+')'
                try:
                    p=subprocess.run(ssh+['python3 -c '+shlex.quote(cleanup)],capture_output=True,text=True,timeout=20)
                    result['owned_temporary_directory_removed']=p.returncode==0
                except subprocess.SubprocessError:result['owned_temporary_directory_removed']=False
        results.append(result);print(json.dumps({'host':host,'parity_passed':result['parity_passed'],'error':result.get('error')}),flush=True)
    report={'schema':'pon-frozen-evaluation-host-parity-v1','source_commit':source,'source_clean':True,
            'bundle_hash':expected_bundle,'results':results,'all_hosts_passed':all(r['parity_passed']and r.get('owned_temporary_directory_removed')for r in results),
            'independent_operators':False,'ordinary_hepta_entry':False,'native_consensus_host':False,
            'future_window_accepted':False,'physical_power_loss':False,'production_activation':False}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report['all_hosts_passed']

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--input',required=True);parser.add_argument('--out',required=True)
    parser.add_argument('--bundle-hash',required=True);parser.add_argument('--hosts',nargs='+',required=True)
    args=parser.parse_args();sys.exit(0 if run(args.input,args.out,args.bundle_hash,args.hosts)else 2)

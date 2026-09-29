from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,tempfile,time
source=Path('/home/qian-qi/Documents/chain-pon-invariants-20260929')
root=Path(tempfile.mkdtemp(prefix='pon-liveclock-campaign-'));runtime=root/'source';runtime.mkdir()
for name in ['formal/pon-nakamoto-v1','config/pon']:shutil.copytree(source/name,runtime/name,ignore=shutil.ignore_patterns('__pycache__'))
p=runtime/'config/pon/devnet-v1.json';params=json.loads(p.read_text())
overrides={'chain_label':'trnm-pon-physical-host-audit-'+str(time.time_ns()),'genesis_timestamp':int(time.time())-600}
params.update(overrides);p.write_text(json.dumps(params,indent=2)+'\n')
paths=sorted([*runtime.glob('formal/pon-nakamoto-v1/*.py'),*runtime.glob('formal/pon-nakamoto-v1/experiments/*.py'),*runtime.glob('config/pon/*.json')])
manifest={'schema':'pon-cross-host-source-manifest-v3','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),
          'source_clean':not subprocess.check_output(['git','status','--porcelain'],cwd=source,text=True).strip(),
          'runtime_config_overrides':overrides,'runtime_is_distinct_genesis':True,
          'files':{str(f.relative_to(runtime)):hashlib.sha256(f.read_bytes()).hexdigest()for f in paths}}
(root/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
cmd=[sys.executable,str(runtime/'formal/pon-nakamoto-v1/experiments/multihost_campaign.py'),'--out',str(root/'results'),'--source-manifest',str(root/'source-manifest.json'),
     '--model','/tmp/pon-final-campaign-8358/model/model.json','--tasks','/tmp/pon-final-campaign-8358/model/consumer.json','--hosts','rog-ts','pocket4-ts','x230-ts']
print('CAMPAIGN_ROOT',root,flush=True)
env=os.environ.copy();env.pop('TRNM_NATIVE_EXECUTOR',None);env.pop('TRNM_NATIVE_WORK',None);env['PYTHONDONTWRITEBYTECODE']='1'
with (root/'campaign.log').open('w')as log:r=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=400)
print('CAMPAIGN_EXIT',r.returncode,flush=True)
print('\n'.join((root/'campaign.log').read_text().splitlines()[-30:]),flush=True)
Path('/tmp/pon-latest-multihost-root.txt').write_text(str(root)+'\n')
sys.exit(r.returncode)

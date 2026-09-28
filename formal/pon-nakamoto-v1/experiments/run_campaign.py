"""Run bounded, reproducible executable-contract experiments and retain actual exits.
Writes only a new caller-chosen output directory; it never deploys or changes Git refs.
"""
from __future__ import annotations
import argparse,hashlib,json,os,platform,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]

def run(out,source):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy();env.update(OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',RUST_TEST_THREADS='1',PYTHONDONTWRITEBYTECODE='1',TRNM_NATIVE_MODE='release')
    target=Path(env.get('CARGO_TARGET_DIR',str(ROOT/'trillionnium/target')))
    commands=[
        ('contract-tests',[sys.executable,'formal/pon-nakamoto-v1/test_contracts.py']),
        ('native-probes',['cargo','build','--locked','--release','--manifest-path','trillionnium/Cargo.toml','-p','trnm-protocol','-p','trnm-crypto-primitives','--examples']),
        ('cross-language',[sys.executable,'formal/pon-nakamoto-v1/test_interop.py']),
        ('work-cost',[str(target/'release/examples/pon_cost')]),
        ('model-learning',[sys.executable,'formal/pon-nakamoto-v1/experiments/model_loop.py','--source',source,'--out',str(out/'model')]),
        ('model-settlement',[sys.executable,'formal/pon-nakamoto-v1/experiments/settle_model.py','--input',str(out/'model'),'--out',str(out/'settlement')]),
        ('loopback-network',[sys.executable,'formal/pon-nakamoto-v1/experiments/local_network.py','--out',str(out/'network')]),
    ]
    records=[]
    for name,command in commands:
        path=out/(name+'.log');start=time.perf_counter()
        with path.open('w')as log:result=subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240)
        row={'name':name,'command':command,'returncode':result.returncode,'seconds':time.perf_counter()-start,'log':path.name};records.append(row);print(json.dumps(row),flush=True)
        if result.returncode:print(path.read_text()[-6000:],flush=True);break
    inputs={}
    for folder in ['config/pon','formal/pon-nakamoto-v1','trillionnium/crates/trnm-protocol','trillionnium/crates/trnm-crypto-primitives']:
        for p in sorted((ROOT/folder).rglob('*')):
            if p.is_file()and '__pycache__'not in p.parts:inputs[p.relative_to(ROOT).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
    info={'schema':'pon-executed-campaign-v1','input_source_commit':source,'implementation_head_at_execution':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
      'implementation_tree_clean':not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip(),'implementation_files_sha256':inputs,
      'environment':{'platform':platform.platform(),'python':platform.python_version(),'cpu_count':os.cpu_count(),'test_threads':1,'blas_threads':1,'filesystem':'caller output path; no tmpfs override or power-loss claim'},
      'commands':records,'all_commands_passed':len(records)==len(commands)and all(r['returncode']==0 for r in records),'independent_accepted':False,'production_activation':False}
    (out/'campaign.json').write_text(json.dumps(info,indent=2)+'\n')
    if not info['all_commands_passed']:raise SystemExit(2)
    print('CAMPAIGN_COMPLETE',out,flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--source',required=True);a=p.parse_args();run(a.out,a.source)

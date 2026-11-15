#!/usr/bin/env python3
"""Pin exactly the requested final packed typed-late case; no verifier execution."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime,timezone

REPO=Path('/home/qian-qi/work/chain-w1-bounded-verifier-20261108-f16ac5')
PREFIX='formal/pon-nakamoto-v1/w1_public_stark_research/'
CRATE=REPO/PREFIX
CONTROLS=Path('/home/qian-qi/work/w1-r3-evidence-f16ac5/carry-guarded-controls-v1')
NAME='arith-last-fold-auth-sibling'
CASE=CONTROLS/'packed/cases'/NAME
EXPECTED_BINARY='2774f3d718bf3831a79b3e348747be1117255b433219e8d2bad5c299da6462ad'
EXPECTED_HEAD='2632d3e5bca93fccc062db6ff4a8470cfc2fa51f'

def digest(b):return hashlib.sha256(b).hexdigest()
def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());data=f.read();b=os.fstat(f.fileno())
    identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    if identity(a)!=identity(b) or len(data)!=a.st_size:raise RuntimeError('CHANGED_FILE:'+str(path))
    return data,{'path':str(path),'bytes':len(data),'sha256':digest(data),'dev':a.st_dev,'ino':a.st_ino,
                 'mtime_ns':a.st_mtime_ns,'ctime_ns':a.st_ctime_ns,'link_count':a.st_nlink}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    files={}
    def copy(path,name,expected=None,executable=False):
        data,record=read(path)
        if expected and record['sha256']!=expected:raise RuntimeError('PIN_MISMATCH:'+str(path))
        target=out/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as f:f.write(data)
        if executable:target.chmod(0o700)
        record['copy']=name;files[name]=record
        return data
    staged=json.loads((out.parent/'binary-staged.json').read_text())
    if staged['source_commit']!=EXPECTED_HEAD or staged['sha256']!=EXPECTED_BINARY:raise RuntimeError('STAGE_PIN')
    copy(out.parent/'packed-verifier','verifier',EXPECTED_BINARY,True)
    tree=subprocess.run(['git','-C',str(REPO),'ls-tree','-r','--name-only',EXPECTED_HEAD,'--',PREFIX],capture_output=True,text=True,check=True).stdout.splitlines()
    for name in tree:
        if name not in (PREFIX+'Cargo.toml',PREFIX+'Cargo.lock') and not (name.endswith('.rs') and (name.startswith(PREFIX+'src/') or name.startswith(PREFIX+'examples/'))):continue
        data=subprocess.run(['git','-C',str(REPO),'show',EXPECTED_HEAD+':'+name],capture_output=True,check=True).stdout
        relative='source/'+name[len(PREFIX):];p=out/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        files[relative]={'source_kind':'immutable_git_blob','source_commit':EXPECTED_HEAD,'git_path':name,
                         'copy':relative,'bytes':len(data),'sha256':digest(data)}
    provenance=json.loads(copy(CONTROLS/'provenance.json','history/controls-provenance.json'))
    mutation=json.loads(copy(CONTROLS/'packed/processes'/('mutate-'+NAME)/'observation.json','history/mutation-observation.json'))['final']
    prior=json.loads(copy(CONTROLS/'packed/processes'/NAME/'observation.json','history/verification-observation.json'))
    if provenance['successor_binary_sha256']['packed']!=EXPECTED_BINARY:raise RuntimeError('CONTROL_BINARY_CHANGED')
    if str(provenance['rayon_num_threads'])!='8':raise RuntimeError('THREAD_PROFILE_CHANGED')
    if prior['exit_code']!=1 or prior['timed_out'] or not prior['final']['error'].endswith('CommitPhaseMmcsError(CapMismatch))'):
        raise RuntimeError('PRIOR_LATE_STAGE_UNCONFIRMED')
    fixture_pins={'expected-header.bin':('retained.expected-header.bin','7b96038f228a1eedccf7b29ffc54802aba691be7259e33937846c6bf6126d78f'),
                  'expected-artifacts.bin':('retained.artifacts.bin','802adcdd951cfb4cd7271df22c3bca6af66fee9f40454c74f8b5ff2c98a1b683')}
    for name,(origin,expected) in fixture_pins.items():copy(CRATE/'fixtures'/origin,name,expected)
    baseline=copy(Path(mutation['input']),'original/arith.proof.bin',mutation['proof_sha256_before'])
    differences={}
    for name in ('statement.bin','sha.proof.bin','arith.proof.bin'):
        expected=(provenance['retained_statement_sha256'] if name=='statement.bin' else
                  provenance['retained_sha_proof_sha256'] if name=='sha.proof.bin' else mutation['proof_sha256_after'])
        data=copy(CASE/name,'cases/'+NAME+'/'+name,expected)
        if name=='arith.proof.bin':
            if len(data)!=len(baseline) or data[:8]!=baseline[:8] or data[:8]!=b'W1P3APC3':raise RuntimeError('PACKED_SHAPE_CHANGED')
            offsets=[i for i,(a,b) in enumerate(zip(baseline,data)) if a!=b]
            if len(offsets)!=mutation['changed_byte_count']:raise RuntimeError('MUTATION_COUNT')
            differences[name]=offsets
        else:differences[name]=[]
    manifest={'schema':'w1-pressure-input-pins-v1','created_utc':datetime.now(timezone.utc).isoformat(),
              'source_repository':str(REPO),'source_head':EXPECTED_HEAD,'binary_expected_sha256':EXPECTED_BINARY,
              'source_observation_does_not_replace_build_receipt':True,'profile':'packed_carry_backend',
              'original_generation_rayon_num_threads':'8','request_count':16,'case_schedule':[NAME]*16,
              'cases':[{'name':NAME,'component':'arithmetic-packed-carry','expected_error_prefix':'arithmetic proof rejected:',
                        'typed_mutation':mutation,'byte_differences':differences,
                        'historical_expected_rejection':prior['final'],'historical_observation_is_not_this_run':True}],
              'files':files,'qualification':'HOLD_NO_GO','production_node':False,
              'workload_difference_from_baseline':'one requested packed arithmetic auth case repeated16times; baseline usedfour cases repeatedfourtimes'}
    for name,record in files.items():
        if digest((out/name).read_bytes())!=record['sha256']:raise RuntimeError('COPY_CHANGED:'+name)
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'input_dir':str(out),'binary_sha256':EXPECTED_BINARY,'source_head':EXPECTED_HEAD,
                      'pinned_files':len(files),'case_count':1,'request_count':16,'rayon_num_threads':8}))

if __name__=='__main__':main()

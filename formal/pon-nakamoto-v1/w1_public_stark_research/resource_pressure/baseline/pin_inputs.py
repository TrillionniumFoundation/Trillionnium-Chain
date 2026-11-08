#!/usr/bin/env python3
"""Copy and pin the existing binary/typed late-proof bytes into a NEW own directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

REPO=Path('/home/qian-qi/work/chain-w1-bounded-verifier-20261108-f16ac5')
CRATE=REPO/'formal/pon-nakamoto-v1/w1_public_stark_research'
ORIGINAL=Path('/home/qian-qi/work/chain-w1-stark-selected-20261107-89f4dd/formal/pon-nakamoto-v1/w1_public_stark_research')
LATE=ORIGINAL/'results/retained-native-02/late-query-campaign'
BINARY_SHA='44c0d3b88a1d8198c4db0ba3b27ed1072faf69377773fa97e835c8ccb8e2bd94'
MAIN_SHA='5b7e6c2124f3a00e1a0eeafa586ab40e42d80b67dda4075cd5b48cedcbee7f76'
SOURCE_COMMIT='cae1e3657b0913991d9465995e709a544218a27c'
CASES=('sha-last-fold-query-value','sha-last-fold-auth-sibling',
       'arith-last-fold-query-value','arith-last-fold-auth-sibling')

def digest(b):return hashlib.sha256(b).hexdigest()

def read_stable(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        with os.fdopen(os.dup(fd),'rb') as stream:data=stream.read()
        after=os.fstat(fd)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if identity(before)!=identity(after) or len(data)!=after.st_size:
            raise RuntimeError('INPUT_CHANGED_DURING_READ:'+str(path))
        return data,{'path':str(path),'bytes':len(data),'sha256':digest(data),
                     'dev':before.st_dev,'ino':before.st_ino,'mtime_ns':before.st_mtime_ns,
                     'ctime_ns':before.st_ctime_ns,'link_count':before.st_nlink}
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    copied={}
    def copy(path,relative,expected=None,executable=False):
        data,record=read_stable(path)
        if expected and record['sha256']!=expected:raise RuntimeError('PIN_MISMATCH:'+str(path))
        target=out/relative;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:stream.write(data)
        if executable:target.chmod(0o700)
        record['copy']=relative;copied[relative]=record
        return data
    original_provenance=json.loads((LATE.parent/'provenance.json').read_text())
    late_provenance=json.loads((LATE/'provenance.json').read_text())
    copy(out.parent/'guarded-baseline-verifier','verifier',BINARY_SHA,True)
    prefix='formal/pon-nakamoto-v1/w1_public_stark_research/'
    tree=subprocess.run(['git','-C',str(REPO),'ls-tree','-r','--name-only',SOURCE_COMMIT,'--',prefix],
                        capture_output=True,text=True,check=True).stdout.splitlines()
    source_paths=[name for name in tree if name in (prefix+'Cargo.toml',prefix+'Cargo.lock') or
                  (name.startswith(prefix+'src/') and name.endswith('.rs'))]
    for path in source_paths:
        data=subprocess.run(['git','-C',str(REPO),'show',SOURCE_COMMIT+':'+path],capture_output=True,check=True).stdout
        relative='source/'+path[len(prefix):]
        if path==prefix+'src/main.rs' and digest(data)!=MAIN_SHA:raise RuntimeError('COMMITTED_MAIN_PIN')
        target=out/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        copied[relative]={'source_kind':'immutable_git_blob','source_commit':SOURCE_COMMIT,
                          'git_path':path,'copy':relative,'bytes':len(data),'sha256':digest(data)}
    for key,name in (('header','expected-header.bin'),('artifacts','expected-artifacts.bin')):
        item=original_provenance['fixtures'][key]
        copy(Path(item['path']),name,item['sha256'])
    original={}
    for name,expected in late_provenance['original_artifact_sha256'].items():
        original[name]=copy(LATE.parent/name,'original/'+name,expected)
    case_records=[]
    for name in CASES:
        mutate_path=LATE/('mutate-'+name+'.observation.json')
        verify_path=LATE/('verify-'+name+'.observation.json')
        mutation=json.loads(copy(mutate_path,'history/'+mutate_path.name))['final']
        verification=json.loads(copy(verify_path,'history/'+verify_path.name))
        component='sha' if name.startswith('sha-') else 'arith'
        changes={}
        for file in ('statement.bin','sha.proof.bin','arith.proof.bin'):
            changed=file==component+'.proof.bin'
            expected=mutation['proof_sha256_after'] if changed else digest(original[file])
            data=copy(LATE/name/file,'cases/'+name+'/'+file,expected)
            if len(data)!=len(original[file]):raise RuntimeError('SHAPE_LENGTH_CHANGED')
            changed_offsets=[i for i,(a,b) in enumerate(zip(original[file],data)) if a!=b]
            if changed and len(changed_offsets)!=mutation['changed_byte_count']:
                raise RuntimeError('MUTATION_COUNT_CHANGED')
            if not changed and changed_offsets:raise RuntimeError('UNEXPECTED_INPUT_CHANGE')
            changes[file]=changed_offsets
        case_records.append({'name':name,'component':component,
                             'expected_error_prefix':('sha' if component=='sha' else 'arithmetic')+' proof rejected:',
                             'typed_mutation':mutation,'byte_differences':changes,
                             'historical_expected_rejection':verification.get('final'),
                             'historical_observation_is_not_this_run':True})
    git=lambda *a:subprocess.run(['git','-C',str(REPO),*a],capture_output=True,text=True,check=True).stdout
    manifest={'schema':'w1-pressure-input-pins-v1','created_utc':datetime.now(timezone.utc).isoformat(),
              'source_repository':str(REPO),'source_head':SOURCE_COMMIT,
              'observed_current_head':git('rev-parse','HEAD').strip(),
              'source_worktree_status':git('status','--porcelain'),
              'source_observation_does_not_replace_build_receipt':True,
              'binary_expected_sha256':BINARY_SHA,
              'original_generation_rayon_num_threads':original_provenance.get('rayon_num_threads'),
              'request_count':16,'case_schedule':[CASES[i%4] for i in range(16)],
              'cases':case_records,'files':copied,'qualification':'HOLD_NO_GO',
              'production_node':False}
    # Do not silently attribute concurrent source/binary changes to these snapshots.
    for name,record in copied.items():
        if digest((out/name).read_bytes())!=record['sha256']:raise RuntimeError('COPY_CHANGED_AFTER_PIN:'+name)
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'input_dir':str(out),'binary_sha256':BINARY_SHA,'source_head':manifest['source_head'],
                      'pinned_files':len(copied),'case_count':len(case_records),
                      'original_rayon_threads':manifest['original_generation_rayon_num_threads']}))

if __name__=='__main__':main()

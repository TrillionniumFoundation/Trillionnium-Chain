#!/usr/bin/env python3
"""Pinned component5/packed4 complete-proof controls; zero fresh proofs.

Uses the committed generic replay helpers from run_carry_controls.py. One
positive, eleven ordinary negatives, both components' two typed late failures,
and both components' four predecode shape failures are checked independently.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import sys
import traceback

from run_carry_controls import (
    FIXTURE_PINS, PHASES, LATE_MODES, SHAPE_MODES, PUBLIC_BYTES, PUBLIC_SHA256,
    binding, check, execute, hash_file, ordinary_controls, phase_names, populate,
    require_final, require_rejection, save_new, source_snapshot, validate_late_mutation,
)

SHA_HASH='11423125f0f5cde3accbcd46f221386c3005d2e72e0e30020b4ae9850acf9085'
ARITH_HASH='2b96cb7c32e34ab22ba39e1de424281b6d20b7811cff24ba769cf2e6cb67a988'
COMPONENTS={
    'scheduled-sha': {'file':'sha.proof.bin','magic':b'W1P3SCS4','degree_bits':13,
        'bytes':3146949,'sha256':SHA_HASH,'prefix':'sha proof rejected:','phases':PHASES[:4]},
    'packed': {'file':'arith.proof.bin','magic':b'W1P3APC3','degree_bits':14,
        'bytes':453861,'sha256':ARITH_HASH,'prefix':'arithmetic proof rejected:','phases':PHASES},
}


def run(args):
    source=args.source.resolve(strict=True)
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    proofs=args.proofs.resolve(strict=True)
    statement=(args.statement or proofs.parent/'prepared/statement.bin').resolve(strict=True)
    fixture=args.fixture_stem or source/'fixtures/round4-schedule/retained'
    fixtures={s:Path(str(fixture)+s).resolve(strict=True) for s in FIXTURE_PINS}
    header,artifacts=fixtures['.expected-header.bin'],fixtures['.artifacts.bin']
    bin_dir=source/'target-r4-native/release/examples'
    binaries={'verifier':bin_dir/'scheduled_sha_backend','late':bin_dir/'mutate_last_query','shape':bin_dir/'mutate_structure'}
    retained={'statement.bin':statement,**{c['file']:proofs/c['file'] for c in COMPONENTS.values()}}
    external=set(fixtures.values())|set(binaries.values())|set(retained.values())|{Path(__file__).resolve()}
    before=source_snapshot(source,external);save_new(out/'source-before.json',before)
    env=dict(os.environ,RAYON_NUM_THREADS='8',LC_ALL='C')
    cpus=sorted(os.sched_getaffinity(0))[:8];os.sched_setaffinity(0,cpus)
    logs=out/'processes';logs.mkdir();cases=out/'cases';cases.mkdir()
    records=[];failures=[];counts={'verifier_processes':0,'mutator_processes':0}
    def launch(name,argv,kind):
        counts[kind+'_processes']+=1
        return execute(name,argv,logs,env,args.timeout_seconds)
    def case(name,kind,body):
        rec={'label':name,'category':kind,'passed':False}
        try:
            body(rec);rec['passed']=True
        except Exception as e:
            rec['error']=str(e);rec['traceback']=traceback.format_exc();failures.append({'label':name,'error':str(e)})
        records.append(rec);save_new(out/(name+'.result.json'),rec)
    def verify(name,folder,public=None,ch=None,ca=None):
        return launch(name,[binaries['verifier'],'verify',public or folder/'statement.bin',ch or header,ca or artifacts,folder],'verifier')
    try:
        check(all('error' not in b for b in before['files'].values()),'unreadable source/input/binary')
        for suffix,(size,h) in FIXTURE_PINS.items():
            check(binding(fixtures[suffix])=={'bytes':size,'sha256':h},'independent fixture pin mismatch: '+suffix)
        check(binding(statement)=={'bytes':PUBLIC_BYTES,'sha256':PUBLIC_SHA256},'public statement pin mismatch')
        for component in COMPONENTS.values():
            path=retained[component['file']]
            check(binding(path)=={'bytes':component['bytes'],'sha256':component['sha256']},'full proof pin mismatch')
            check(path.read_bytes()[:8]==component['magic'],'proof magic pin mismatch')
        save_new(out/'provenance.json',{
            'schema':'w1-public-schedule-controls-v1','qualification':'HOLD_NO_GO','source_head':before['source_git_head'],
            'source_before':'source-before.json','system':platform.uname()._asdict(),'cpu_affinity':cpus,
            'host_exclusive':False,'rayon_num_threads':8,'new_proofs_generated':0,
            'planned_verifier_processes':24,'planned_mutator_processes':12,'independent_inputs':1,
            'scope':'one retained complete component5+packed4 proof; typed late and shape controls remain distinct',
            'global_rejection_bound':False,'NI_security_claim':False,'PQ128_claim':False,'Node_qualification':False,
            'proof_hashes':{'sha':SHA_HASH,'arithmetic':ARITH_HASH},
        })
        def positive(rec):
            obs=verify('positive',proofs,statement);rec['observation']=obs
            final=require_final(obs,0,'VERIFIED_COMPLETE_W1_RESEARCH_ONLY')
            check(phase_names(obs)==PHASES,'positive incomplete verify phases')
            check(final['statement_sha256']==PUBLIC_SHA256 and final['sha_proof_sha256']==SHA_HASH and final['arith_proof_sha256']==ARITH_HASH,'positive wrong hashes')
            wire=final.get('wire_admission',{})
            check(wire.get('schema')=='w1-fixed-p3-wire-admission-v3-public-schedule' and wire.get('structural_admission_only') is True and wire.get('global_rejection_cost_bound') is False,'missing component5 wire guard')
            check(final.get('public_schedule_expansion_paid') is True and final.get('native_sha_compression_for_verifier_air') is False,'wrong schedule preprocessing path')
        case('positive','positive',positive)
        public,sp,ap=(retained[k].read_bytes() for k in ('statement.bin','sha.proof.bin','arith.proof.bin'))
        for name,replacements,prefix,phases in ordinary_controls(public,sp,ap,header.read_bytes(),artifacts.read_bytes()):
            def ordinary(rec):
                folder=cases/name;populate(folder,retained,replacements)
                ch=folder/'expected-header.bin' if 'expected-header.bin' in replacements else header
                ca=folder/'expected-artifacts.bin' if 'expected-artifacts.bin' in replacements else artifacts
                obs=verify(name,folder,ch=ch,ca=ca);rec['observation']=obs
                rec.update(expected_error_prefix=prefix,expected_phases=phases)
                require_rejection(obs,prefix,phases)
            case(name,'ordinary',ordinary)
        for component_name,component in COMPONENTS.items():
            filename=component['file'];original=retained[filename].read_bytes()
            for mode,subtype in LATE_MODES:
                name=component_name+'-'+mode
                def late(rec):
                    folder=cases/name;populate(folder,retained,omitted=(filename,))
                    mut=launch('mutate-'+name,[binaries['late'],mode,retained[filename],folder/filename],'mutator');rec['mutation']=mut
                    # Historical generic helper calls the expected hash arith_sha256;
                    # the component name/magic/degree bind the actual selected profile.
                    profile={'name':component_name,'magic':component['magic'],'degree_bits':component['degree_bits'],'arith_sha256':component['sha256']}
                    validate_late_mutation(mut,profile,mode,original,(folder/filename).read_bytes())
                    obs=verify(name,folder);rec['observation']=obs
                    rec.update(expected_error_prefix=component['prefix'],expected_subtype=subtype,expected_phases=component['phases'])
                    require_rejection(obs,component['prefix'],component['phases'],subtype)
                case(name,'late',late)
            for mode in SHAPE_MODES:
                name=component_name+'-shape-'+mode
                def shape(rec):
                    folder=cases/name;populate(folder,retained,omitted=(filename,))
                    mut=launch('mutate-'+name,[binaries['shape'],component_name,mode,retained[filename],folder/filename],'mutator');rec['mutation']=mut
                    info=require_final(mut,0)
                    check(info.get('schema')=='w1-fixed-wire-mutation-v1' and info.get('component')==component_name and info.get('mode')==mode and info.get('input_sha256')==component['sha256'] and info.get('output_sha256')==hash_file(folder/filename) and info.get('cryptographic_rejection_not_executed') is True,'shape mutation contract mismatch')
                    obs=verify(name,folder);rec['observation']=obs;rec['expected_phases']=[]
                    error=require_rejection(obs,'proof decoding: wire admission',[])
                    check(f"wire admission at {info['wire_refusal_offset']}: {info['wire_refusal_reason']}" in error,'different shape frontier')
                case(name,'shape',shape)
    except Exception as e:
        failures.append({'label':'setup','error':str(e),'traceback':traceback.format_exc()})
    finally:
        after=source_snapshot(source,external);save_new(out/'source-after.json',after)
        same=before==after
        if not same:failures.append({'label':'integrity','error':'source/binary/original-input hashes changed'})
        planned={'positive':1,'ordinary':11,'late':4,'shape':8}
        passed={k:sum(r['category']==k and r['passed'] for r in records) for k in planned}
        ok=not failures and passed==planned and counts=={'verifier_processes':24,'mutator_processes':12}
        summary={'schema':'w1-public-schedule-controls-summary-v1','qualification':'HOLD_NO_GO','result':'PASS' if ok else 'FAIL',
            'planned':planned,'passed':passed,**counts,'new_proofs_generated':0,'source_binaries_inputs_unchanged':same,
            'records':records,'failures':failures,'global_rejection_bound':False,'NI_security_claim':False,'PQ128_claim':False,'Node_qualification':False}
        save_new(out/'summary.json',summary)
        print(json.dumps({k:v for k,v in summary.items() if k not in ('records','failures')}),flush=True)
    return 0 if ok else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--proofs',type=Path,required=True);p.add_argument('--statement',type=Path)
    p.add_argument('--fixture-stem',type=Path);p.add_argument('--timeout-seconds',type=float,default=60)
    return run(p.parse_args())

if __name__=='__main__':raise SystemExit(main())

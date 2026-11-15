#!/usr/bin/env python3
"""Fresh-process positive and rejection controls for actual complete proofs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from run_tagged_sha3_abba import stage, write, source_snapshot, sha


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ['repo','target','benchmark','output','fixtures']:ap.add_argument('--'+n,required=True,type=Path)
    a=ap.parse_args();crate=a.repo/'formal/pon-nakamoto-v1/w1_public_stark_research'
    a.output.mkdir(parents=True,exist_ok=False)
    benchmark=json.loads((a.benchmark/'manifest.json').read_text())
    assert benchmark['result']=='PASS' and benchmark['source_binaries_and_inputs_unchanged']
    os.sched_setaffinity(0,benchmark['cpu_affinity']);env=dict(os.environ,RAYON_NUM_THREADS='8')
    binaries={'A':a.target/'release/examples/packed_carry_backend','B':a.target/'release/examples/tagged_sha3_backend','wire':a.target/'release/examples/tagged_sha3_wire_controls'}
    for v in ['A','B']:assert sha(binaries[v])==benchmark['source_before']['binaries'][v]['sha256'],'measured binary changed'
    arun=a.benchmark/'00-retained-A';brun=a.benchmark/'01-retained-B'
    statement=brun/'prepared/statement.bin';assert statement.read_bytes()==(arun/'prepared/statement.bin').read_bytes()
    header=a.fixtures/'retained.expected-header.bin';artifacts=a.fixtures/'retained.artifacts.bin'
    fixtures={'retained':{'statement':statement,'header':header,'artifacts':artifacts}}
    before=source_snapshot(a.repo,crate,binaries,fixtures)
    write(a.output/'source-before.json',before)
    rows=[]
    wire=stage([binaries['wire'],brun/'proof/sha.proof.bin',brun/'proof/arith.proof.bin',arun/'proof/sha.proof.bin',arun/'proof/arith.proof.bin'],a.output/'wire_structural',crate,env,60)
    assert wire['exit_code']==0 and wire['report']['result']=='PASS','actual-file wire controls failed'
    for label,variant,proof_dir in [('legacy_positive','A',arun/'proof'),('new_positive','B',brun/'proof'),('legacy_rejects_new','A',brun/'proof'),('new_rejects_legacy','B',arun/'proof')]:
        observe=stage([binaries[variant],'verify',statement,header,artifacts,proof_dir],a.output/label,crate,env,60)
        positive=label.endswith('_positive');report=observe['report'] or {}
        good=observe['exit_code']==(0 if positive else 1) and report.get('status')==('VERIFIED_COMPLETE_W1_RESEARCH_ONLY' if positive else 'REJECTED_OR_FAILED')
        if not positive:good=good and 'proof' in report.get('error','')
        rows.append({'label':label,'passed':good,'observation':observe})
    mutations=[]
    def mod(name,filename,change,frontier):
        data=bytearray((brun/'proof'/filename).read_bytes());change(data)
        mutations.append((name,filename,bytes(data),frontier))
    mod('sha_root_bit','sha.proof.bin',lambda b:b.__setitem__(16,b[16]^1),'sha proof rejected:')
    mod('arithmetic_root_bit','arith.proof.bin',lambda b:b.__setitem__(16,b[16]^1),'arithmetic proof rejected:')
    mod('sha_huge_cap','sha.proof.bin',lambda b:b.__setitem__(slice(8,16),(2**64-1).to_bytes(8,'little')),'proof decoding:')
    mod('arithmetic_huge_cap','arith.proof.bin',lambda b:b.__setitem__(slice(8,16),(2**64-1).to_bytes(8,'little')),'proof decoding:')
    mod('sha_noncanonical_field','sha.proof.bin',lambda b:b.__setitem__(slice(161,169),(18446744069414584321).to_bytes(8,'little')),'proof decoding:')
    mod('sha_trailing_byte','sha.proof.bin',lambda b:b.append(0),'proof decoding:')
    for label,filename,data,frontier in mutations:
        folder=a.output/(label+'_input');folder.mkdir()
        for name in ['sha.proof.bin','arith.proof.bin']:
            (folder/name).write_bytes(data if name==filename else (brun/'proof'/name).read_bytes())
        observation=stage([binaries['B'],'verify',statement,header,artifacts,folder],a.output/label,crate,env,60)
        report=observation['report'] or {}
        good=observation['exit_code']==1 and report.get('status')=='REJECTED_OR_FAILED' and report.get('error','').startswith(frontier)
        if frontier=='proof decoding:':good=good and 'bounded_read_decode_and_proof_shape' not in (a.output/label/'stdout.jsonl').read_text()
        rows.append({'label':label,'passed':good,'mutated_file':filename,'mutated_sha256':hashlib.sha256(data).hexdigest(),'expected_error_prefix':frontier,'observation':observation})
    public=bytearray(statement.read_bytes())
    # The first arithmetic claim is untrusted public data. Keep its u32 canonical
    # while changing the typed context and relation data used by this verifier.
    at=8+49506+131072+32*(1+4*128+2)
    original=int.from_bytes(public[at:at+4],'little')
    public[at:at+4]=((original+1)%4294967291).to_bytes(4,'little')
    altered=a.output/'different_canonical_statement.bin';altered.write_bytes(public)
    observation=stage([binaries['B'],'verify',altered,header,artifacts,brun/'proof'],a.output/'wrong_statement_context',crate,env,60)
    report=observation['report'] or {}
    rows.append({'label':'wrong_statement_context','passed':observation['exit_code']==1 and report.get('error','').startswith('sha proof rejected:'),'changed_offset':at,'original_u32':original,'changed_u32':int.from_bytes(public[at:at+4],'little'),'mutated_sha256':sha(altered),'observation':observation})
    after=source_snapshot(a.repo,crate,binaries,fixtures);write(a.output/'source-after.json',after)
    equal=all(before[k]==after[k] for k in ['head','source_files','binaries','fixtures','driver_sha256'])
    summary={'schema':'w1-tagged-sha3-full-receive-controls-v1','result':'PASS' if equal and all(r['passed'] for r in rows) else 'FAIL',
        'qualification':'HOLD_NO_GO','full_verifier_control_count':len(rows),'full_verifier_controls_passed':sum(r['passed'] for r in rows),
        'wire_control_count':wire['report']['control_count'],'wire_controls':wire['report'],'cases':rows,
        'source_binaries_original_inputs_unchanged':equal,'measured_A_B_binary_identities_unchanged':True,
        'cpu_affinity':benchmark['cpu_affinity'],'rayon_threads':8,
        'new_proofs_generated':0,'global_rejection_cost_bound':False,'complete_qrom_security_claim':False}
    write(a.output/'summary.json',summary)
    print(json.dumps({k:v for k,v in summary.items() if k not in ['wire_controls','cases']}),flush=True)
    return 0 if summary['result']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())

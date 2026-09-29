#!/usr/bin/env python3
"""Verify current continuation receipt, not scientific acceptance or public readiness."""
from __future__ import annotations
import hashlib,json,re,subprocess
from pathlib import Path
from check_invariant_evidence import ROOT,require,load,safe,source_bytes

PARAMETERS={'config/pon/devnet-v1.json','config/pon/ledger-v1.json','config/pon/work-profile-v1.json','config/pon/model-family-v1.json'}
def runtime(path):
    return (path.startswith(('formal/pon-nakamoto-v1/','trillionnium/')) and not path.endswith('.md')) or path in PARAMETERS

def validate(root=ROOT,evidence=None):
    root=Path(root).resolve();folder=Path(evidence or root/'evidence/pon-v4').resolve()
    manifest=load(folder/'manifest.json')
    require(manifest['schema']=='pon-completion-evidence-v4','schema')
    for flag in ['independent_accepted','ordinary_hepta_entry','three_improving_generations','physical_power_loss','public_network_ready','production_activation']:
        require(manifest[flag]is False,'unearned scope '+flag)
    require({'qualification/report.json','comparison/report.json','summary.json'}<=set(manifest['files']),'missing report')
    for relative,digest in manifest['files'].items():
        require(hashlib.sha256(safe(folder,relative).read_bytes()).hexdigest()==digest,'changed artifact '+relative)
    q=load(folder/'qualification/report.json');commit=q['source_commit']
    require(commit==manifest['implementation_commit'] and q['source_tree']==manifest['implementation_tree'],'source identity')
    require(subprocess.check_output(['git','rev-parse',commit+'^{tree}'],cwd=root,text=True).strip()==q['source_tree'],'source tree')
    require(q['source_clean']is True and q['all_commands_passed']is True,'unfinished or dirty qualification')
    require(q['independent_accepted']is False and q['production_activation']is False,'qualification scope')
    old=source_bytes(root,commit,list(q['source_files_sha256']))
    for relative,data in old.items():
        require(hashlib.sha256(data).hexdigest()==q['source_files_sha256'][relative],'source digest '+relative)
        if runtime(relative):require(safe(root,relative).read_bytes()==data,'runtime differs from measured source '+relative)
    tracked=set(subprocess.check_output(['git','ls-files'],cwd=root,text=True).splitlines())
    require({p for p in tracked if runtime(p)}=={p for p in old if runtime(p)},'runtime inventory mismatch')
    aggregate=[];native=None
    for row in q['results']:
        require(row['returncode']==0,'failed execution')
        log=safe(folder,'qualification/'+row['log']).read_text();aggregate.append(log)
        if row.get('python_tests')is not None:
            require(re.search(r'Ran '+str(row['python_tests'])+r' tests?\b',log) and re.search(r'(?m)^OK\s*$',log),'Python result mismatch')
        if row['command'][:2]==['cargo','test'] and '--workspace'in row['command'] and '--all-targets'in row['command']:
            results=[]
            for section in re.split(r'(?m)^\s*(?:Running (?:unittests|tests/)|Doc-tests )',log):
                matches=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored',section)
                if matches:results.append(matches[-1])
            require(results and sum(int(x[1])for x in results)==row['passed'] and sum(int(x[2])for x in results)==row['failed']==0,'native result mismatch')
            native=row
    require(native is not None,'missing full native suite')
    invariants=json.loads(old['config/pon/invariants-v2.json'])['invariants'];logs='\n'.join(aggregate);selectors=set()
    for invariant in invariants:
        for selector in invariant['tests']:
            name=selector.split('::',1)[1].split('.')[-1]
            require(re.search(r'\b'+re.escape(name)+r'(?:\s|\))[^\n]*\bok\b',logs),'unexecuted selector '+selector)
            selectors.add(selector)
    comparison=load(folder/'comparison/report.json')
    require(comparison['candidate_source']==commit and comparison['source_clean']is True,'comparison source')
    require(comparison['consensus_tps_claimed']is False and comparison['independent_accepted']is False and comparison['production_activation']is False,'comparison scope')
    require(comparison['binary_sha256']['candidate']==q['native_binary_sha256']['pon_execute'],'binary mismatch')
    require(comparison['baseline_source']=='209f742279044327ad8c763012b6fdda54e5e61e','baseline mismatch')
    groups={}
    for sample in comparison['samples']:
        require(sample['included']is None and sample['client_confirmed']is None and sample['proof_verification_ns']is None and sample['vram_bytes']is None,'unmeasured metric claim')
        require(sample['executed']==sample['transactions'] and sample['metrics']['reexecuted']<=sample['transactions'],'count mismatch')
        if sample['binary']=='candidate':
            require(sample['metrics']['workers_spawned']<=sample['workers'],'unbounded workers')
            require(sample['metrics']['signature_verifications']==sample['transactions'],'duplicate main verification')
        key=(sample['scenario'],sample['workers']);groups.setdefault(key,[]).append(sample)
    require(len(groups)==12,'missing workload/worker comparison')
    for key,samples in groups.items():
        require({x['binary']for x in samples}=={'baseline','candidate'},'missing paired binary')
        require(len({x['root']for x in samples})==1 and len({x['receipt_digest']for x in samples})==1 and len({x['input_sha256']for x in samples})==1,'paired outcome/input divergence')
        require(all(sum(x['binary']==b for x in samples)==comparison['sample_count_per_case']for b in ['baseline','candidate']),'missing samples')
    import statistics
    for row in comparison['summary']:
        samples=groups[(row['scenario'],row['workers'])]
        b=statistics.median(int(x['metrics']['elapsed_ns'])for x in samples if x['binary']=='baseline')
        c=statistics.median(int(x['metrics']['elapsed_ns'])for x in samples if x['binary']=='candidate')
        require(row['baseline_median_ns']==b and row['candidate_median_ns']==c and row['regression_observed']==(c>b),'summary hides cost')
    # Old 4114-block and physical-host results remain explicitly on their own source.
    history=manifest['historical_evidence']
    require(history['path']=='evidence/pon-v3/manifest.json' and history['claimed_current_runtime']is False,'old campaign promoted')
    require(hashlib.sha256(safe(root,history['path']).read_bytes()).hexdigest()==history['sha256'],'historical package changed')
    return {'measured_commit':commit,'runtime_matches':True,'executed_invariant_selectors':len(selectors),'native_tests':native['passed'],'comparison_samples':len(comparison['samples']),'independent_accepted':False,'ordinary_hepta_entry':False,'production_activation':False}

if __name__=='__main__':
    result=validate();manifest=load(ROOT/'evidence/pon-v4/manifest.json')
    tracked=set(subprocess.check_output(['git','ls-files'],cwd=ROOT,text=True).splitlines())
    require({'evidence/pon-v4/'+p for p in manifest['files']}<=tracked,'evidence not tracked')
    print(json.dumps(result,sort_keys=True))

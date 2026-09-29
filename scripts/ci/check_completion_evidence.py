#!/usr/bin/env python3
"""Verify current continuation receipt, not scientific acceptance or public readiness."""
from __future__ import annotations
import hashlib,json,re,subprocess
from pathlib import Path
from check_invariant_evidence import ROOT,require,load,safe,source_bytes

PARAMETERS={'config/pon/devnet-v1.json','config/pon/ledger-v1.json','config/pon/work-profile-v1.json','config/pon/model-family-v1.json'}
def runtime(path):
    return (path.startswith(('formal/pon-nakamoto-v1/','trillionnium/')) and not path.endswith('.md')) or path in PARAMETERS

def load_list(path):
    import json
    from check_invariant_evidence import unique
    value=json.loads(path.read_text(),object_pairs_hook=unique)
    require(isinstance(value,list),'expected report list')
    return value

def validate(root=ROOT,evidence=None,*,current_runtime=True):
    root=Path(root).resolve();folder=Path(evidence or root/'evidence/pon-v4').resolve()
    manifest=load(folder/'manifest.json')
    require(manifest['schema']=='pon-completion-evidence-v4','schema')
    for flag in ['independent_accepted','ordinary_hepta_entry','three_improving_generations','physical_power_loss','public_network_ready','production_activation']:
        require(manifest[flag]is False,'unearned scope '+flag)
    require({'qualification/report.json','comparison/report.json','summary.json','native-hosts/report.json','native-hosts/source-manifest.json','native-hosts/requests.json','native-hosts/remote-driver.py'}<=set(manifest['files']),'missing report')
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
        if current_runtime and runtime(relative):require(safe(root,relative).read_bytes()==data,'runtime differs from measured source '+relative)
    tracked=set(subprocess.check_output(['git','ls-files'],cwd=root,text=True).splitlines())
    if current_runtime:require({p for p in tracked if runtime(p)}=={p for p in old if runtime(p)},'runtime inventory mismatch')
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
    resource_lines=safe(folder,'comparison/process-resource-usage.tsv').read_text().splitlines()
    require(resource_lines[0]=='filename\tmax_rss_kib user_seconds system_seconds','resource table header')
    resource_rows={}
    for line in resource_lines[1:]:
        name,value=line.split('\t',1)
        require(name not in resource_rows and len(value.split())==3,'resource line duplicate/shape')
        resource_rows[name]=value.split()
    require(len(resource_rows)==12*2*(comparison['sample_count_per_case']+1),'resource/warmup coverage')
    groups={}
    for sample in comparison['samples']:
        usage='usage-'+sample['scenario']+'-'+str(sample['workers'])+'-'+str(sample['sample'])+'-'+sample['binary']+'.txt'
        require(usage in resource_rows and int(resource_rows[usage][0])==sample['peak_rss_kib'],'resource result mismatch')
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
    hosts=load(folder/'native-hosts/report.json');hm=load(folder/'native-hosts/source-manifest.json')
    require(hosts['source_commit']==commit and hosts['source_clean']is True and hosts['all_hosts_passed']is True,'host source/result')
    require(hm['candidate_source']==commit and hm['source_clean']is True,'host manifest source')
    require(hm['files']['candidate']==q['native_binary_sha256']['pon_execute'] and hm['files']['baseline']==comparison['binary_sha256']['baseline'],'host binary identity')
    for name,path in [('requests.json','native-hosts/requests.json'),('run.py','native-hosts/remote-driver.py')]:
        require(hashlib.sha256(safe(folder,path).read_bytes()).hexdigest()==hm['files'][name],'host input/driver hash')
    for flag in ['independent_operators','native_full_node','ordinary_hepta_entry','physical_power_loss','public_network_security','production_activation']:
        require(hosts[flag]is False,'host overclaim '+flag)
    require(len({h['host']for h in hosts['results']})==len(hosts['results'])==3,'host inventory')
    requests={x['scenario']:x for x in load_list(folder/'native-hosts/requests.json')}
    for host in hosts['results']:
        require(host['all_parity_passed']is True and host['returncode']==0 and host['owned_temporary_directory_removed']is True,'host execution or cleanup')
        require(host['source_manifest']==hm and host['independent_operator']is False and host['consensus_host']is False and host['production_activation']is False,'host scope/manifest')
        require(len(host['samples'])==24,'host sample coverage')
        keys={(v['scenario'],v['workers'],v['variant'])for v in host['samples']}
        require(keys=={(name,w,b)for name in requests for w in [1,2,4,8]for b in ['baseline','candidate']},'host case matrix')
        for sample in host['samples']:
            require(sample['root']==requests[sample['scenario']]['root'] and sample['included']is None and sample['confirmed']is None,'host root or fabricated inclusion')
            if sample['variant']=='candidate':
                require(sample['metrics']['workers_spawned']<=sample['workers'] and sample['metrics']['signature_verifications']==sample['transactions'],'host work accounting')
    summary=load(folder/'summary.json')
    require(summary['source_commit']==commit and summary['source_tree']==q['source_tree'],'summary source')
    require(summary['all_qualification_commands_passed']is True and summary['native_tests']==native['passed'] and summary['native_failures']==0,'summary qualification counts')
    require(summary['invariant_selectors']==len(selectors) and summary['comparison_samples']==len(comparison['samples']),'summary execution coverage')
    require(summary['comparison_medians']==comparison['summary'],'summary performance mismatch')
    require(summary['host_execution_samples']==sum(len(h['samples'])for h in hosts['results']) and summary['physical_hosts']==[h['host']for h in hosts['results']],'summary host counts')
    require(summary['all_owned_remote_directories_removed']is True and summary['all_host_parity_passed']is True,'summary host outcome')
    require(summary['full_test_filesystem']==q['environment']['temporary_filesystem'] and summary['full_test_threads']==q['environment']['test_threads'],'summary environment')
    require(summary['historical_long_history_current_binary_rerun']is False,'historical long run promoted')
    for flag in ['ordinary_hepta_entry','three_improving_generations','independent_accepted','physical_power_loss','public_network_ready','production_activation']:
        require(summary[flag]is False,'summary overclaim '+flag)
    # Old 4114-block and physical-host results remain explicitly on their own source.
    history=manifest['historical_evidence']
    require(history['path']=='evidence/pon-v3/manifest.json' and history['claimed_current_runtime']is False,'old campaign promoted')
    require(hashlib.sha256(safe(root,history['path']).read_bytes()).hexdigest()==history['sha256'],'historical package changed')
    return {'measured_commit':commit,'runtime_matches':True if current_runtime else None,'historical_only':not current_runtime,'executed_invariant_selectors':len(selectors),'native_tests':native['passed'],'comparison_samples':len(comparison['samples']),'physical_hosts':len(hosts['results']),'independent_accepted':False,'ordinary_hepta_entry':False,'production_activation':False}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--historical',action='store_true');args=parser.parse_args()
    result=validate(current_runtime=not args.historical);manifest=load(ROOT/'evidence/pon-v4/manifest.json')
    tracked=set(subprocess.check_output(['git','ls-files'],cwd=ROOT,text=True).splitlines())
    require({'evidence/pon-v4/'+p for p in manifest['files']}<=tracked,'evidence not tracked')
    print(json.dumps(result,sort_keys=True))

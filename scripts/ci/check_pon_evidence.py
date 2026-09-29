#!/usr/bin/env python3
"""Bind retained local evidence to actual inputs; never grant independent acceptance."""
from pathlib import Path
import hashlib,json,subprocess

def require(ok,msg):
    if not ok:raise ValueError(msg)
def validate(root,evidence=None):
    root=Path(root).resolve();evidence=Path(evidence or root/'evidence/pon-v1').resolve()
    def load(p):return json.loads((evidence/p).read_text())
    manifest=load('manifest.json')
    require(manifest['schema']=='pon-local-evidence-files-v1'and manifest['independent_accepted']is False and manifest['production_activation']is False,'local report cannot grant acceptance')
    mandatory={'campaign.json','native-qualification.json','summary.json','work-cost.json','model-report.json','settlement-report.json','network-report.json','environment.json','artifacts/model.json','artifacts/model-work.bin','exploratory-failure/report.json','exploratory-failure/failure-record.json'}
    mandatory.update({'accepted-block/'+n for n in ['expected.json','header.bin','transaction.bin','work.bin','genesis-state.json','post-state.json']})
    require(mandatory<=set(manifest['files']),'missing positive or failed evidence')
    for relative,digest in manifest['files'].items():
        p=(evidence/relative).resolve();require(p.is_relative_to(evidence)and p.is_file(),'missing/escaping evidence path')
        require(hashlib.sha256(p.read_bytes()).hexdigest()==digest,'evidence digest mismatch '+relative)
    # Historical evidence is not rewritten to make new source appear executed.
    # This signed mainline ancestor contains exactly the originally measured bytes.
    archive='5d59b9540268914794a62e8fa237caf999499314'
    current_match=True
    for relative,digest in manifest['source_files_sha256'].items():
        p=(root/relative).resolve();require(p.is_relative_to(root),'escaping source binding')
        try:measured=subprocess.check_output(['git','show',archive+':'+relative],cwd=root,stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:raise ValueError('historical source unavailable; fetch complete main history')from e
        require(hashlib.sha256(measured).hexdigest()==digest,'stale historical evidence '+relative)
        current_match=current_match and p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==digest
    native=load('native-qualification.json');campaign=load('campaign.json');s=load('summary.json')
    require(native['head']==campaign['implementation_head_at_execution']==manifest['implementation_commit']==s['implementation_commit'],'source identity mismatch')
    require(native['all_passed']is True and native['source_unchanged']is True and all(r['returncode']==0 for r in native['results']),'native execution did not pass')
    require(campaign['all_commands_passed']is True and campaign['implementation_tree_clean']is True and len(campaign['commands'])==7 and all(r['returncode']==0 for r in campaign['commands']),'campaign did not execute every stage')
    require(campaign['production_activation']is False and campaign['independent_accepted']is False,'campaign overclaims')
    rust=next(r for r in native['results']if '--workspace'in r['command']and '--all-targets'in r['command']and r['command'][1]=='test')
    require(s['counts']['native_tests']==rust['passed'] and rust['failed']==0,'native count mismatch')
    model=load('model-report.json');settle=load('settlement-report.json');net=load('network-report.json');cost=load('work-cost.json');failure=load('exploratory-failure/report.json')
    require(s['model']['artifact']==model['models']['artifact_hash']==settle['source_model'],'model binding mismatch')
    # Same framing as the protocol, independently expressed here to avoid loading ledger dependencies.
    def framed(tag,b):
        import struct
        return hashlib.sha256(b'TRNM-PON1\0'+struct.pack('<H',len(tag))+tag+struct.pack('<I',len(b))+b).hexdigest()
    require(framed(b'artifact',(evidence/'artifacts/model.json').read_bytes())==s['model']['artifact'],'artifact bytes mismatch')
    require(model['ordinary_hepta_product_entry']is False and model['future_time_window_observed']is False and model['independent_operators']is False,'unearned model acceptance')
    require(s['model']['future_window_accepted']is False and s['model']['ordinary_hepta_entry']is False and s['model']['evaluation_reused_after_exploration']is True,'lost experimental scope')
    consumer=model['results']['consumer'];require(s['model']['composed_correct']==consumer['composed_correct']and s['model']['best_single_correct']==max(consumer['expert_correct']),'hidden control result')
    require(failure['results']['evaluation_a']['whole_gain']['score']==0 and failure['results']['evaluation_b']['whole_gain']['score']==0,'failed first experiment erased')
    require(settle['model_reward']<=settle['budget']and settle['duplicate_claim_rejected']is True and settle['consumer_paid']==0,'settlement invariant')
    require(settle['ordinary_hepta_entry']is False and settle['independent_evaluators']is False and settle['future_window_accepted']is False,'settlement overclaims')
    require(net['native_node']is False and net['independent_operators']is False and net['peer_processes']==3,'loopback is not independent deployment')
    require(cost['sample_count']==32 and cost['proof_bytes']==49188 and cost['hardness_accepted']is False,'work scope mismatch')
    for k in ['generation_ns','verification_ns','invalid_verification_ns','cheap_forgery_ns']:require(len(cost[k])==32 and all(type(n)is int and n>0 for n in cost[k]),'missing raw cost samples')
    require(s['production_activation']is False and len(s['not_accepted'])>=5,'remaining blockers erased')
    return {'evidence_files':len(manifest['files']),'source_bindings':len(manifest['source_files_sha256']),'implementation_commit':manifest['implementation_commit'],'consistency':'verified-historical','archive_commit':archive,'matches_current_source':current_match,'independent_accepted':False,'production_activation':False}
if __name__=='__main__':
    root=Path(__file__).resolve().parents[2];report=validate(root)
    manifest=json.loads((root/'evidence/pon-v1/manifest.json').read_text())
    tracked=set(subprocess.check_output(['git','ls-files'],cwd=root,text=True).splitlines())
    required={'evidence/pon-v1/'+name for name in manifest['files']}
    require(required<=tracked,'evidence exists locally but is absent from the Git index: '+repr(sorted(required-tracked)))
    report['tracked_artifacts_verified']=True
    print(json.dumps(report,sort_keys=True))

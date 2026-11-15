#!/usr/bin/env python3
"""Controlled public replay: freeze a decision, train, evaluate and retain parent.

The first experiment exposed these public tasks. This new execution is explicitly
not independent/prospective evidence. Research selection has no Fleet authority.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HELPER_SHA = '185e747bb90e4c793ea9c2bc0ce8606f88780d7154873e153a902f4da4e2ee4e'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--research-root',type=Path,required=True)
    parser.add_argument('--previous-run',type=Path,required=True)
    parser.add_argument('--worker-helper',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--operation',required=True)
    args=parser.parse_args();os.umask(0o077)
    helper_raw=args.worker_helper.read_bytes();assert hashlib.sha256(helper_raw).hexdigest()==HELPER_SHA
    spec=importlib.util.spec_from_file_location('original_model_readback_helper',args.worker_helper)
    helper=importlib.util.module_from_spec(spec);exec(compile(helper_raw,str(args.worker_helper),'exec'),helper.__dict__)
    sha,save,Worker,output_record=helper.sha,helper.save,helper.Worker,helper.output_record
    args.output.mkdir(mode=0o700,exist_ok=False)
    previous=json.loads((args.previous_run/'training-result.json').read_bytes())
    previous_plan=json.loads((args.previous_run/'frozen-plan.json').read_bytes())
    baseline_ref=previous['stages'][0]['parent_material']
    baseline_path=Path(baseline_ref['path']);assert sha(baseline_path)==baseline_ref['sha256']
    baseline=json.loads(baseline_path.read_bytes())
    data=previous_plan['inputs'][1];assert sha(data['path'])==data['sha256']
    worker=args.research_root/'worktree/workers/weight/worker.py'
    source=args.research_root/'inputs/source/chain'
    before={str(p):sha(p) for root in [source,worker.parent] for p in sorted(root.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
    result=dict(schema='trnm-smollm-actual-retained-parent-replay-v1',result='FAIL',operation=args.operation,
        previous_outcomes_and_tasks_exposed=True,prospective_evaluation=False,independent_evaluation=False,
        fleet_learning_owner_join=False,native_current_adoption=False,hepta_final_use_accepted=False,
        production_activation=False,settlement_verified=False,qualification='HOLD_NO_GO')
    active=[]
    try:
        evaluation=[dict(row,request_id=args.operation+f'-evaluation-{i}') for i,row in enumerate(previous_plan['evaluation'])]
        next_task=dict(previous_plan['next_task'],request_id=args.operation+'-retained-next-task')
        frozen=dict(schema='trnm-smollm-public-replay-decision-v1',operation=args.operation,
            start_unix_ns=time.time_ns(),parent=baseline_ref,parent_adapter=baseline['adapter'],
            input=data,steps=10,threads=4,evaluation=evaluation,next_task=next_task,
            evaluation_profile=previous_plan['evaluation_profile'],
            decision_rule=dict(metric='exact-yes-no-correct-count-on-all-four-frozen-rows',
                accept_candidate='candidate-count-strictly-greater-than-parent-count',
                tie_or_regression='NoUpdate',missing_or_invalid='Refused',
                accepted_scope='controlled-research-choice-no-CURRENT-or-FinalUse'),
            prior_run_frozen_plan_sha256=sha(args.previous_run/'frozen-plan.json'),
            prior_outcomes_exposed=True,prospective_evaluation=False,independent_custody=False,
            source_before=before,worker_helper_sha256=HELPER_SHA,authority='DENY_ALL')
        frozen_ref=save(args.output/'frozen-decision-plan.json',frozen)
        command=[sys.executable,str(source/'scripts/llm_inherited_runtime.py'),'train',
            '--materials',str(args.research_root/'pinned-base'),'--output',str(args.output/'training'),
            '--operation-id',args.operation+'-train','--input',data['path'],'--input-sha256',data['sha256'],
            '--threads','4','--steps','10','--parent',str(baseline_path),'--parent-sha256',baseline_ref['sha256']]
        started=time.time_ns()
        assert (args.output/'frozen-decision-plan.json').stat().st_mtime_ns<=started
        with (args.output/'training.log').open('xb') as stream:
            execution=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,
                env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1'})
        save(args.output/'training-command.json',dict(command=command,returncode=execution.returncode,
             start_unix_ns=started,end_unix_ns=time.time_ns()))
        assert execution.returncode==0,'original training owner refused'
        candidate_path=args.output/'training/worker/parent-material.json'
        candidate=json.loads(candidate_path.read_bytes())
        receipt_path=args.output/'training/worker/actual-receipt.json';receipt=json.loads(receipt_path.read_bytes())
        assert receipt['outcome']=='success' and receipt['training']['steps']==10 and receipt['parameter_change'] is True
        assert receipt['actual_loaded_parent']==baseline['adapter'] and receipt['artifact']==candidate['adapter']
        assert candidate['generation']==baseline['generation']+1
        original_config=json.loads((args.previous_run/'model-generation-1.json').read_bytes())
        def params(material,store,maximum):
            config=dict(original_config,parent_dir=material['directory'],parent_contract=material['contract'],
                parent_adapter=material['adapter'],parent_file_sha256=material['file_sha256'],generation=material['generation'])
            assert sha(Path(material['directory'])/'artifact.safetensors')==material['file_sha256']
            return dict(provider='smollm2_cell',model=config,cpu_threads=4,
                input_roots=[config['source_dir'],config['materials_dir'],str(Path(config['plan_path']).parent),config['parent_dir']],
                output_root=str(args.output/store),limits=dict(max_forward_examples=maximum,max_patch_candidates=1))
        evaluations=[]
        for label,material in [('parent',baseline),('candidate',candidate)]:
            owner=Worker(worker,args.operation+'-'+label,args.output,label+'-evaluation');active.append(owner)
            opened=owner.call('open','open',params(material,label+'-evaluation-store',4));assert opened['ok'],opened
            assert opened['result']['model']['parent_adapter']==material['adapter']
            save(args.output/(label+'-open.json'),opened);rows=[]
            for index,row in enumerate(evaluation,1):
                inputs=dict(mode='conditional_binary',request_id=row['request_id'],prompt=row['prompt'])
                response=owner.call(f'evaluation-{index}','probe',dict(inputs=inputs))
                observation=output_record(response,inputs,index)
                observation.update(expected_output=row['expected_output'],correct=observation['predicted_output']==row['expected_output'])
                rows.append(observation)
            close=owner.call('close','close',{});assert close['ok'] and close['result']['forward_examples']==4
            save(args.output/(label+'-exit.json'),owner.finish());active.remove(owner)
            evaluations.append(dict(role=label,adapter=material['adapter'],correct=sum(r['correct'] for r in rows),count=4,rows=rows))
        evaluation_ref=save(args.output/'evaluation.json',evaluations)
        disposition='UpdateResearchCandidate' if evaluations[1]['correct']>evaluations[0]['correct'] else 'NoUpdate'
        selected=candidate if disposition=='UpdateResearchCandidate' else baseline
        decision=dict(schema='trnm-smollm-frozen-public-research-decision-v1',disposition=disposition,
            frozen_plan=frozen_ref,evaluation=evaluation_ref,training_receipt=dict(path=str(receipt_path),sha256=sha(receipt_path)),
            parent_adapter=baseline['adapter'],candidate_adapter=candidate['adapter'],selected_adapter=selected['adapter'],
            rule=frozen['decision_rule'],decided_unix_ns=time.time_ns(),authority='DENY_ALL',
            current_permission='NOT_EXPORTED',native_selection_authority=False,qualification='HOLD_NO_GO')
        decision_ref=save(args.output/'decision.json',decision)
        # The selected material is fixed by the already frozen rule; no search,
        # altered thresholds, substituted baseline or synthetic receipt follows.
        assert disposition=='NoUpdate','this replay did not demonstrate the requested retain branch'
        session=args.operation+'-retained';parameters=params(selected,'retained-store',1)
        owner=Worker(worker,session,args.output,'retained-next-task');active.append(owner)
        opened=owner.call('open','open',parameters);assert opened['ok'],opened
        assert opened['result']['model']['parent_adapter']==baseline['adapter']
        assert opened['result']['model']['identity']['parent']['file_sha256']==baseline['file_sha256']
        response=owner.call('next-task','probe',dict(inputs=next_task));observed=output_record(response,next_task,1)
        save(args.output/'retained-original-response.json',response)
        first_exit=owner.finish();active.remove(owner);save(args.output/'retained-first-exit.json',first_exit)
        recovery=Worker(worker,session,args.output,'retained-cold-recovery');active.append(recovery)
        assert recovery.call('open','open',parameters)==opened
        assert recovery.call('next-task','probe',dict(inputs=next_task))==response
        wrong=copy.deepcopy(next_task);wrong['prompt']+=' changed'
        conflict=recovery.call('next-task','probe',dict(inputs=wrong))
        assert not conflict['ok'] and conflict['error']['code']=='IDEMPOTENCY_CONFLICT'
        extra=dict(next_task,request_id=next_task['request_id']+'-extra')
        exhausted=recovery.call('exhausted','probe',dict(inputs=extra))
        assert not exhausted['ok'] and exhausted['error']['code']=='FORWARD_BUDGET'
        close=recovery.call('close','close',{});assert close['ok'] and close['result']['forward_examples']==1
        save(args.output/'retained-recovery-exit.json',recovery.finish());active.remove(recovery)
        save(args.output/'recovery-controls.json',dict(original_open=opened,conflict=conflict,exhausted=exhausted,close=close))
        assert {path:sha(path) for path in before}==before
        assert sha(baseline_path)==baseline_ref['sha256']
        assert sha(Path(baseline['directory'])/'artifact.safetensors')==baseline['file_sha256']
        assert sha(Path(candidate['directory'])/'artifact.safetensors')==candidate['file_sha256']
        result.update(result='PASS_ACTUAL_RESEARCH_NO_UPDATE_RETAINED_PARENT_AND_COLD_USE',
            frozen_plan=frozen_ref,decision=decision_ref,evaluation=evaluation_ref,training_receipt=decision['training_receipt'],
            parent_correct=evaluations[0]['correct'],candidate_correct=evaluations[1]['correct'],evaluation_count=4,
            disposition=disposition,parent_adapter=baseline['adapter'],candidate_adapter=candidate['adapter'],
            selected_adapter=selected['adapter'],actual_retained_parent_loaded=True,actual_next_task_executed=True,
            next_task=observed,cold_recovery_exact_response=True,reexecuted_after_recovery=False,
            new_optimizer_steps=10,new_model_forwards=9,first_worker_pid=first_exit['pid'],recovery_worker_pid=recovery.pid,
            original_sources_unchanged=True,complete_parent_artifact_unchanged=True,end_unix_ns=time.time_ns())
    except BaseException as error:
        result['error']=repr(error);raise
    finally:
        for owner in active:
            try:owner.finish()
            except Exception as error:result.setdefault('cleanup_errors',[]).append(repr(error))
        save(args.output/'result.json',result)
        print(json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':main()

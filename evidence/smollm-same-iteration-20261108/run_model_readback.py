#!/usr/bin/env python3
"""Use the exact fresh training artifacts in the original SmolLM worker.

This is direct isolated worker research. It does not stand in for Fleet learning
receipts, native CURRENT selection, authenticated evaluation or Hepta FinalUse.
"""
import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import struct
import subprocess
import sys
import time

WORKER = '10c09efcb24d65ce850ccbee61f3034262fa026ee5d19adab90bc9eda67049c0'
PACKAGE = '1cfcb4997e86e1e9dee51f4a1b80b19439232344abce8d60d2e52cd624bd25d7'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    with path.open('xb') as stream:
        stream.write(canonical(value) + b'\n'); stream.flush(); os.fsync(stream.fileno())
    return dict(path=str(path), sha256=sha(path))


class Worker:
    def __init__(self, script, session, root, name):
        self.session, self.root = session, root
        self.stderr = (root / (name + '.stderr.log')).open('xb')
        self.transcript = (root / (name + '.jsonl')).open('xb')
        self.process = subprocess.Popen([sys.executable, str(script), '--stdio', '--session-id', session,
            '--expected-worker-sha256', WORKER, '--expected-package-sha256', PACKAGE,
            '--max-request-ms', '120000'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, bufsize=0, env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1',
                'HF_HUB_OFFLINE':'1', 'TRANSFORMERS_OFFLINE':'1', 'TOKENIZERS_PARALLELISM':'false'})
        self.buffer = b''
        self.pid = self.process.pid

    def call(self, request_id, op, params):
        request = dict(id=request_id, session_id=self.session, op=op, params=params)
        self.transcript.write(canonical(dict(direction='send', message=request)) + b'\n'); self.transcript.flush()
        self.process.stdin.write(canonical(request) + b'\n'); self.process.stdin.flush()
        deadline = time.monotonic() + 150
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b'\n' not in self.buffer:
                remaining = deadline - time.monotonic()
                assert remaining > 0 and selector.select(remaining), 'original worker response deadline'
                block = os.read(self.process.stdout.fileno(), 65536)
                assert block, 'original worker exited before response'
                self.buffer += block
                assert len(self.buffer) <= 4 * 1024 * 1024, 'bounded original response'
        line, self.buffer = self.buffer.split(b'\n', 1)
        response = json.loads(line)
        self.transcript.write(canonical(dict(direction='receive', message=response)) + b'\n'); self.transcript.flush()
        assert response['id'] == request_id
        return response

    def finish(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        result = self.process.wait(timeout=30)
        self.transcript.close(); self.stderr.close()
        assert result == 0, 'original worker did not exit cleanly'
        return dict(pid=self.pid, exit_code=result, terminated_by='controlled-stdio-EOF')


def output_record(response, inputs, count):
    assert response['ok'] is True, response
    probe = response['result']
    ref = probe['outputs']
    path = Path(ref['path']); raw = path.read_bytes()
    assert len(raw) == ref['byte_length'] and hashlib.sha256(raw).hexdigest() == ref['sha256']
    header_size = struct.unpack('<Q', raw[:8])[0]
    assert 0 < header_size <= 16384
    header = json.loads(raw[8:8+header_size]); payload = raw[8+header_size:]
    assert set(header)-{'__metadata__'} == {'next_token_logits','raw_action_logits','scores_q32',
        'conditional_binary_probabilities','input_ids','attention_mask'}
    def tensor(name, dtype, shape):
        item=header[name]; assert item['dtype']==dtype and item['shape']==shape
        left,right=item['data_offsets']; assert type(left) is int and type(right) is int and 0<=left<right<=len(payload)
        return payload[left:right]
    tokens = probe['input']['tokens']
    logits=tensor('next_token_logits','F32',[1,49152]); assert len(logits)==49152*4
    values=struct.unpack('<49152f',logits); assert all(math.isfinite(x) for x in values)
    actions=list(struct.unpack('<ff',tensor('raw_action_logits','F32',[1,2])))
    scores=list(struct.unpack('<qq',tensor('scores_q32','I64',[1,2])))
    assert actions==[values[10407],values[4607]] and scores==[round(x*2**32) for x in actions]
    ids=list(struct.unpack('<'+'q'*tokens,tensor('input_ids','I64',[1,tokens])))
    assert tensor('attention_mask','BOOL',[1,tokens])==b'\1'*tokens
    encoded=dict(input_ids=[ids],attention_mask=[[True]*tokens],position_ids=[list(range(tokens))])
    meta=probe['input']; assert meta['mode']=='conditional_binary' and meta['request_id']==inputs['request_id']
    assert meta['prompt_sha256']==hashlib.sha256(inputs['prompt'].encode()).hexdigest()
    assert hashlib.sha256(canonical(encoded)).hexdigest()==meta['encoded_input_id']
    assert hashlib.sha256(canonical(dict(encoded=encoded,output_contract=meta['output_contract']))).hexdigest()==meta['model_input_id']
    assert hashlib.sha256(logits).hexdigest()==probe['computation']['logits_sha256']
    assert probe['computation']['model_forward_calls']==1 and probe['total_forward_examples']==count
    evidence=json.loads(Path(probe['evidence']['path']).read_bytes())
    assert sha(probe['evidence']['path'])==probe['evidence']['sha256']
    assert evidence['gradient_steps']==0 and evidence['optimizer_calls']==0
    return dict(request_id=inputs['request_id'],prompt_sha256=meta['prompt_sha256'],
        output_sha256=ref['sha256'],logits_sha256=hashlib.sha256(logits).hexdigest(),
        scores_q32=scores,predicted_output='yes' if scores[0]>=scores[1] else 'no',
        encoded_input_id=meta['encoded_input_id'],model_input_id=meta['model_input_id'],
        total_forward_examples=count,model_forward_calls=1,artifact=ref,evidence=probe['evidence'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--research-root',type=Path,required=True)
    parser.add_argument('--training-root',type=Path,required=True)
    parser.add_argument('--frozen-plan-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); os.umask(0o077); args.output.mkdir(mode=0o700,exist_ok=False)
    frozen_path=args.training_root/'frozen-plan.json'; assert sha(frozen_path)==args.frozen_plan_sha256
    plan=json.loads(frozen_path.read_bytes()); training=json.loads((args.training_root/'training-result.json').read_bytes())
    assert training['result']=='PASS_TWO_ACTUAL_RESEARCH_TRAINING_GENERATIONS'
    script=args.research_root/'worktree/workers/weight/worker.py'
    assert sha(script)==WORKER
    source_files=[script]+sorted((script.parent/'weight_runtime').glob('*.py'))
    before={str(p):sha(p) for p in source_files}
    result=dict(schema='trnm-smollm-same-run-worker-readback-v1',result='FAIL',
        training_result_sha256=sha(args.training_root/'training-result.json'),frozen_plan_sha256=args.frozen_plan_sha256,
        worker_sha256=WORKER,worker_package_sha256=PACKAGE,source_before=before,
        actual_training_output_loaded=False,actual_next_task_executed=False,cold_recovery_readback=False,
        fleet_learning_owner_join=False,native_current_adoption=False,independent_evaluation=False,
        hepta_final_use_accepted=False,settlement_verified=False,production_activation=False,qualification='HOLD_NO_GO')
    active=[]
    try:
        evaluations=[]; candidate_session=None
        for generation in (1,2):
            config=json.loads((args.training_root/f'model-generation-{generation}.json').read_bytes())
            descriptor=json.loads(Path(training['stages'][generation-1]['parent_material']['path']).read_bytes())
            assert config['parent_adapter']==descriptor['adapter']==training['stages'][generation-1]['actual_adapter']
            assert config['parent_file_sha256']==sha(Path(config['parent_dir'])/'artifact.safetensors')
            session=plan['operation']+f'-worker-{generation}'
            roots=[config['source_dir'],config['materials_dir'],str(Path(config['plan_path']).parent),config['parent_dir']]
            params=dict(provider='smollm2_cell',model=config,cpu_threads=4,input_roots=roots,
                output_root=str(args.output/f'generation-{generation}-store'),limits=dict(max_forward_examples=4 if generation==1 else 5,max_patch_candidates=1))
            owner=Worker(script,session,args.output,f'generation-{generation}');active.append(owner)
            opened=owner.call('open','open',params); save(args.output/f'generation-{generation}-open.json',opened)
            assert opened['ok'] is True, opened
            state=opened['result']; assert state['model']['parent_adapter']==descriptor['adapter']
            assert state['model']['target_contract']==descriptor['contract']
            assert state['model']['identity']['material_preflight']['result']=='PASS'
            assert state['training_allowed'] is False and state['production_activation_allowed'] is False
            assert state['model']['identity']['parent']['file_sha256']==descriptor['file_sha256']
            rows=[]
            for index,row in enumerate(plan['evaluation'],1):
                inputs={name:row[name] for name in ('request_id','prompt')};inputs['mode']='conditional_binary'
                response=owner.call(f'evaluation-{index}','probe',dict(inputs=inputs))
                observation=output_record(response,inputs,index)
                observation.update(expected_output=row['expected_output'],correct=observation['predicted_output']==row['expected_output'])
                rows.append(observation)
            evaluations.append(dict(generation=generation,adapter=descriptor['adapter'],model_id=state['model_id'],
                rows=rows,correct=sum(x['correct'] for x in rows),count=len(rows)))
            if generation==1:
                closed=owner.call('close','close',{});assert closed['ok'] and closed['result']['forward_examples']==4
                save(args.output/'generation-1-exit.json',owner.finish());active.remove(owner)
            else:
                candidate_session=(session,params,opened,owner)
        session,params,opened,owner=candidate_session
        inputs=plan['next_task']; response=owner.call('next-task','probe',dict(inputs=inputs))
        next_use=output_record(response,inputs,5);save(args.output/'next-task-original-response.json',response)
        first_exit=owner.finish();active.remove(owner);save(args.output/'generation-2-first-exit.json',first_exit)
        recovery=Worker(script,session,args.output,'generation-2-recovery');active.append(recovery)
        recovered_open=recovery.call('open','open',params);assert recovered_open==opened
        repeated=recovery.call('next-task','probe',dict(inputs=inputs));assert repeated==response
        wrong=copy.deepcopy(inputs);wrong['prompt']+=' changed'
        conflict=recovery.call('next-task','probe',dict(inputs=wrong))
        assert conflict['ok'] is False and conflict['error']['code']=='IDEMPOTENCY_CONFLICT'
        extra=dict(inputs,request_id=inputs['request_id']+'-over-budget')
        exhausted=recovery.call('over-budget','probe',dict(inputs=extra))
        assert exhausted['ok'] is False and exhausted['error']['code']=='FORWARD_BUDGET'
        closed=recovery.call('close','close',{});assert closed['ok'] and closed['result']['forward_examples']==5
        save(args.output/'generation-2-recovery-exit.json',recovery.finish());active.remove(recovery)
        assert {str(p):sha(p) for p in source_files}==before
        for stage in training['stages']:
            assert sha(stage['parent_material']['path'])==stage['parent_material']['sha256']
            descriptor=json.loads(Path(stage['parent_material']['path']).read_bytes())
            assert sha(Path(descriptor['directory'])/'artifact.safetensors')==descriptor['file_sha256']
        save(args.output/'evaluation.json',evaluations)
        save(args.output/'recovery-and-refusals.json',dict(recovered_open=recovered_open,repeated_response=repeated,
            changed_payload=conflict,exhausted_budget=exhausted,closed=closed))
        result.update(result='PASS_ORIGINAL_WORKER_SAME_TRAINED_OUTPUT_AND_COLD_READBACK',
            actual_training_output_loaded=True,actual_next_task_executed=True,cold_recovery_readback=True,
            same_next_task_response_replayed=True,next_task_reexecution_observed=False,
            restored_forward_budget_observed=True,actual_new_model_forwards=9,evaluations=evaluations,
            next_use=next_use,first_worker_pid=first_exit['pid'],recovered_worker_pid=recovery.pid,
            source_after=before,scope='actual-trained-model-original-worker-research-not-Fleet-adoption',end_unix_ns=time.time_ns())
    except BaseException as error:
        result['error']=repr(error);raise
    finally:
        for owner in active:
            try:owner.finish()
            except Exception as cleanup:result.setdefault('cleanup_errors',[]).append(repr(cleanup))
        save(args.output/'readback-result.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in ('evaluations','source_before','source_after')}),flush=True)


if __name__=='__main__':main()

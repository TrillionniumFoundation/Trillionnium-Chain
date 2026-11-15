"""Manifest/interface attacks; tiny fabricated byte fixtures run no LLM."""
from __future__ import annotations
import copy
import hashlib
import unittest
from llm_adapter_contract import *


def identity(value):
    return H('llm-interface-test-identity', value.encode()).hex()


def descriptor(shape, dtype='bfloat16'):
    blob = b'\0'*(math.prod(shape)*DTYPE_BYTES[dtype])
    return {'dtype': dtype, 'shape': list(shape), 'byte_length': len(blob),
            'sha256': hashlib.sha256(blob).hexdigest()}


def fixture_contract():
    architecture = dict(schema='pon-decoder-rms-rope-gqa-swiglu-v1', layers=1, hidden=8,
        intermediate=16, attention_heads=2, kv_heads=1, vocabulary=16, context=32,
        rope_theta=[10000, 1], rms_epsilon=[1, 1000000], tied_embeddings=False, bias=False)
    index = {name: descriptor(shape) for name, shape in architecture_shapes(architecture).items()}
    files = {'tokenizer.json': {'sha256': hashlib.sha256(b'{}').hexdigest(), 'byte_length': 2}}
    return dict(schema='pon-target-decoder-adapter-contract-v1', network=NETWORK.hex(),
        parameters=PARAMETER_HASH.hex(), reference='fabricated-tiny-interface-fixture-not-a-model',
        architecture=architecture,
        backbone=dict(index=index, index_root=_index_root_fixture(index),
                      owner_reference=identity('weights-owner-record'), license_reference=identity('license-record')),
        tokenizer=dict(schema='pon-tokenizer-files-and-behavior-v1', files=files,
            files_root=H('llm-tokenizer-file-index-v1', canonical(files)).hex(), vocabulary=16,
            bos_id=1, eos_id=2, pad_id=0, add_bos=True, add_eos=False,
            chat_template=identity('template'), behavior_contract=identity('tokenizer-behavior')),
        numeric=dict(storage_dtype='bfloat16', accumulation_dtype='float32', quantization='none',
            adapter_expression='x-Wt-plus-alpha-over-rank-times-x-At-Bt-v1',
            operator_contract=identity('operator-contract'), runtime_status='required-not-executed'),
        targets=[dict(module='model.layers.0.self_attn.k_proj', in_features=8, out_features=4, rank=2, alpha=[4, 1]),
                 dict(module='model.layers.0.self_attn.q_proj', in_features=8, out_features=8, rank=2, alpha=[4, 1])],
        ports=dict(schema='pon-causal-decoder-token-and-logit-ports-v1', batch_max=2,
            input_tokens_max=16, output_tokens_max=8, input_dtype='int64', mask_dtype='bool',
            logits_dtype='float32', truncation='reject', padding_position='left-with-explicit-mask',
            model_mode='eval', dropout=False, tied_lm_head=False,
            generation='greedy-lowest-token-id-tie-fixed-count-v1'),
        registration=dict(owner_record=identity('target-owner'), target_admission=identity('target-admission'),
            runtime_qualification='required-not-executed', prospective_accepted=False,
            independent_accepted=False, public_reward_eligible=False), scope=SCOPE)


def _index_root_fixture(index):
    return H('llm-tensor-index-v1', canonical(index)).hex()


def fixture_adapter(contract, cid):
    modules, material = {}, {}
    for target in contract['targets']:
        name = target['module']; rank = target['rank']
        a = descriptor([rank, target['in_features']]); b = descriptor([target['out_features'], rank])
        modules[name] = dict(A=a, B=b, rank=rank, alpha=list(target['alpha']), dropout=False)
        for factor, desc in [('A', a), ('B', b)]: material[name+'.'+factor] = b'\0'*desc['byte_length']
    return dict(schema='pon-wrapped-decoder-lora-material-v1', contract=cid, modules=modules,
        material_scope='factor-bytes-and-insertion-interface-not-functional-equivalence'), material


def fixture_plan(contract, cid):
    tasks = []
    for partition in ('calibration', 'evaluation'):
        for number in range(2):
            tasks.append(dict(id=identity(partition+str(number)), partition=partition,
                source_group=identity('source'+str(number)), prompt_sha256=identity('prompt'+partition+str(number)),
                target_output_sha256=hashlib.sha256(('answer'+str(number)).encode()).hexdigest(),
                input_tokens=4, output_tokens=2))
    return dict(schema='pon-target-decoder-evaluation-run-plan-v1', network=NETWORK.hex(),
        parameters=PARAMETER_HASH.hex(), contract=cid, backbone=contract['backbone']['index_root'],
        tokenizer=contract['tokenizer']['files_root'], candidate=identity('candidate-adapter'),
        controls=[dict(id=name, artifact=identity(name)) for name in CONTROL_IDS],
        tasks=sorted(tasks, key=lambda t: t['id']), metric='equal-source-group-exact-output-bytes-accuracy-v1',
        repeats=2, seeds=[17, 31], budgets={k: 10000 for k in
            ('cpu_ns', 'gpu_ns', 'wall_ns', 'memory_peak_bytes', 'bytes_read', 'bytes_written', 'training_steps', 'training_flops')},
        stopping='all-frozen-repetitions-no-early-selection-v1',
        source_registration=dict(owner_record=identity('evaluation-owner-record'), admission_root=identity('evaluation-admission'),
            task_release_record=identity('task-release'), custody_record=identity('custody'),
            observation_status='external-owner-evidence-required', prospective_accepted=False,
            independent_accepted=False, public_reward_eligible=False), scope=SCOPE)


def fixture_record(plan, pid):
    participants = []
    for name, artifact in [('candidate', plan['candidate'])]+[(c['id'], c['artifact']) for c in plan['controls']]:
        runs = []
        for seed in plan['seeds']:
            costs = [dict(stage=stage, outcome='success', cpu_ns=1, gpu_ns=0, wall_ns=2,
                memory_peak_bytes=7, bytes_read=3, bytes_written=1) for stage in COST_STAGES]
            runs.append(dict(seed=seed, outputs={t['id']: t['target_output_sha256'] for t in plan['tasks']},
                costs=costs, training_steps=0 if name == 'current-backbone' else 2,
                training_flops=0 if name == 'current-backbone' else 3))
        participants.append(dict(id=name, artifact=artifact, runs=runs))
    return dict(schema='pon-target-decoder-reported-run-record-v1', plan=pid, participants=participants,
        runtime_source=identity('runtime-source'), runtime_binary=identity('binary'), hardware=identity('hardware'),
        observer=identity('observer'), scope='reported-output-and-cost-replay-not-authenticated-inference')


class LlmAdapterContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = fixture_contract(); self.raw, self.cid = freeze_target_contract(self.contract)
        self.plan = fixture_plan(self.contract, self.cid)
        self.plan_raw, self.pid = freeze_run_plan(self.plan, self.contract, self.cid)

    def check_contract(self, raw=None, cid=None, **changes):
        args = dict(expected_backbone_root=self.contract['backbone']['index_root'],
                    expected_tokenizer_root=self.contract['tokenizer']['files_root']); args.update(changes)
        return verify_target_contract(self.raw if raw is None else raw, self.cid if cid is None else cid, **args)

    def test_target_manifest_is_closed_and_owner_roots_pinned(self):
        self.assertEqual(self.check_contract(), self.contract)
        with self.assertRaisesRegex(ValueError, 'LLM_OWNER_CONTEXT'):
            self.check_contract(expected_backbone_root=identity('unadmitted-backbone'))
        altered = copy.deepcopy(self.contract); altered['weights_loaded'] = True
        with self.assertRaisesRegex(ValueError, 'LLM_CONTRACT_FIELDS'): freeze_target_contract(altered)
        self.assertFalse(self.contract['registration']['prospective_accepted'])

    def test_duplicate_json_noncanonical_and_wrong_identity_reject(self):
        with self.assertRaisesRegex(ValueError, 'LLM_MANIFEST_IDENTITY'): self.check_contract(cid=identity('wrong'))
        spaced = self.raw+b'\n'; sid = H('target-decoder-adapter-contract-v1', spaced).hex()
        with self.assertRaisesRegex(ValueError, 'LLM_MANIFEST_CANONICAL'): self.check_contract(spaced, sid)
        duplicated = b'{"schema":0,"schema":1}'
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            self.check_contract(duplicated, H('target-decoder-adapter-contract-v1', duplicated).hex())

    def test_gqa_and_full_backbone_inventory_have_exact_shapes(self):
        for mutate, code in [
            (lambda c: c['architecture'].update(attention_heads=3), 'LLM_GQA_SHAPE'),
            (lambda c: c['backbone']['index'].pop('model.norm.weight'), 'LLM_BACKBONE_INDEX'),
            (lambda c: c['backbone']['index']['model.layers.0.self_attn.k_proj.weight'].update(shape=[8,8]), 'LLM_TENSOR_SHAPE'),
            (lambda c: c['backbone']['index']['model.norm.weight'].update(byte_length=17), 'LLM_TENSOR_LENGTH'),
            (lambda c: c['backbone'].update(index_root=identity('false-root')), 'LLM_BACKBONE_ROOT')]:
            changed = copy.deepcopy(self.contract); mutate(changed)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code): freeze_target_contract(changed)

    def test_larger_decoder_metadata_validates_without_allocating_or_claiming_weights(self):
        # Common 7B-size dimensions are a shape test, not a named downloaded model.
        architecture = copy.deepcopy(self.contract['architecture'])
        architecture.update(layers=32, hidden=4096, intermediate=11008, attention_heads=32, kv_heads=8, vocabulary=32000, context=4096)
        shapes = architecture_shapes(architecture)
        self.assertEqual(shapes['model.layers.31.self_attn.k_proj.weight'], [1024,4096])
        self.assertEqual(shapes['model.layers.31.mlp.down_proj.weight'], [4096,11008])
        self.assertEqual(len(shapes), 32*9+3)
        declared = copy.deepcopy(self.contract); declared['architecture'] = architecture
        declared['reference'] = 'unexecuted-32-layer-shape-fixture-no-weight-custody'
        declared['backbone']['index'] = {name: dict(dtype='bfloat16',shape=shape,
            byte_length=math.prod(shape)*2,sha256=identity('unavailable-fixture-weight-'+name))
            for name,shape in shapes.items()}
        declared['backbone']['index_root'] = _index_root_fixture(declared['backbone']['index'])
        declared['tokenizer']['vocabulary'] = 32000
        declared['targets'] = [dict(module='model.layers.31.self_attn.k_proj', in_features=4096,
            out_features=1024,rank=16,alpha=[32,1]), dict(module='model.layers.31.self_attn.q_proj',
            in_features=4096,out_features=4096,rank=16,alpha=[32,1])]
        large_raw, large_id = freeze_target_contract(declared)
        self.assertEqual(verify_target_contract(large_raw,large_id,
            expected_backbone_root=declared['backbone']['index_root'],
            expected_tokenizer_root=declared['tokenizer']['files_root']),declared)
        self.assertEqual(declared['numeric']['runtime_status'], 'required-not-executed')

    def test_tokenizer_dtype_numeric_scope_and_boolean_alias_reject(self):
        for mutate, code in [
            (lambda c: c['tokenizer'].update(vocabulary=17), 'LLM_TOKENIZER_PROFILE'),
            (lambda c: c['tokenizer'].update(eos_id=16), 'LLM_TOKEN_ID'),
            (lambda c: c['tokenizer'].update(eos_id=True), 'LLM_TOKEN_ID'),
            (lambda c: c['numeric'].update(storage_dtype='int4'), 'LLM_NUMERIC_PROFILE'),
            (lambda c: c['numeric'].update(runtime_status='qualified'), 'LLM_NUMERIC_PROFILE'),
            (lambda c: c['registration'].update(independent_accepted=True), 'LLM_REGISTRATION_SCOPE'),
            (lambda c: c['targets'][0].update(alpha=[2,2]), 'LLM_RATIONAL')]:
            changed = copy.deepcopy(self.contract); mutate(changed)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code): freeze_target_contract(changed)

    def test_backbone_and_tokenizer_supplied_bytes_are_verified(self):
        material = {name: b'\0'*item['byte_length'] for name, item in self.contract['backbone']['index'].items()}
        size = verify_tensor_material(self.contract['backbone']['index'], material)
        self.assertGreater(size, 0)
        verify_tensor_material(self.contract['tokenizer']['files'], {'tokenizer.json': b'{}'})
        material['model.norm.weight'] = b'\1'*len(material['model.norm.weight'])
        with self.assertRaisesRegex(ValueError, 'LLM_MATERIAL_BINDING'):
            verify_tensor_material(self.contract['backbone']['index'], material)

    def test_wrapped_factors_bind_bytes_shapes_rank_scale_and_module_ports(self):
        adapter, material = fixture_adapter(self.contract, self.cid)
        raw, aid = freeze_wrapped_adapter(adapter, self.contract, self.cid)
        self.assertEqual(verify_wrapped_adapter(raw, aid, self.contract, self.cid, material), adapter)
        mutations = [
            (lambda a: a['modules'].pop(self.contract['targets'][0]['module']), 'LLM_ADAPTER_MODULE_SET'),
            (lambda a: a['modules'][self.contract['targets'][0]['module']].update(rank=1), 'LLM_ADAPTER_SCALE'),
            (lambda a: a['modules'][self.contract['targets'][0]['module']].update(alpha=[True,1]), 'LLM_ADAPTER_SCALE'),
            (lambda a: a['modules'][self.contract['targets'][0]['module']].update(alpha=[4,True]), 'LLM_RATIONAL'),
            (lambda a: a['modules'][self.contract['targets'][0]['module']]['A'].update(shape=[8,2]), 'LLM_TENSOR_SHAPE')]
        for mutate, code in mutations:
            changed = copy.deepcopy(adapter); mutate(changed)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code):
                freeze_wrapped_adapter(changed, self.contract, self.cid)
        modified = dict(material); first = next(iter(modified)); modified[first] = b'\1'*len(modified[first])
        with self.assertRaisesRegex(ValueError, 'LLM_MATERIAL_BINDING'):
            verify_wrapped_adapter(raw, aid, self.contract, self.cid, modified)

    def test_nonfinite_adapter_and_self_substituted_backbone_reject(self):
        adapter, material = fixture_adapter(self.contract, self.cid)
        target = next(iter(adapter['modules'])); name = target+'.A'
        for word in (0x7f80, 0x7fc0, 0xff80):
            with self.subTest(word=word):
                modified = dict(material); modified[name] = word.to_bytes(2,'little')+material[name][2:]
                changed = copy.deepcopy(adapter)
                changed['modules'][target]['A']['sha256'] = hashlib.sha256(modified[name]).hexdigest()
                raw, aid = freeze_wrapped_adapter(changed, self.contract, self.cid)
                with self.assertRaisesRegex(ValueError, 'LLM_ADAPTER_NONFINITE'):
                    verify_wrapped_adapter(raw, aid, self.contract, self.cid, modified)
        changed = copy.deepcopy(self.contract); changed['reference'] = 'other-model'
        with self.assertRaisesRegex(ValueError, 'LLM_ADAPTER_CONTRACT'):
            freeze_wrapped_adapter(adapter, changed, self.cid)

    def request(self):
        return dict(schema='pon-causal-decoder-request-v1', contract=self.cid,
            input_ids=[[0,1,5],[1,4,6]], attention_mask=[[False,True,True],[True,True,True]], generation_tokens=2)

    def test_wrapped_request_masks_bounds_and_no_silent_truncation(self):
        request = self.request(); self.assertEqual(len(validate_decoder_request(request, self.contract, self.cid)), 64)
        for mutate, code in [
            (lambda r: r['attention_mask'].__setitem__(0,[True,False,True]), 'LLM_REQUEST_MASK'),
            (lambda r: r['input_ids'][0].__setitem__(0,9), 'LLM_REQUEST_PAD_TOKEN'),
            (lambda r: r['input_ids'][1].__setitem__(1,True), 'LLM_REQUEST_TOKEN'),
            (lambda r: r.update(generation_tokens=9), 'LLM_REQUEST_OUTPUT_LIMIT'),
            (lambda r: r.update(input_ids=[[1]*17], attention_mask=[[True]*17]), 'LLM_REQUEST_SHAPE')]:
            changed = copy.deepcopy(request); mutate(changed)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code):
                validate_decoder_request(changed, self.contract, self.cid)

    def test_response_matches_request_and_exact_decoded_bytes_not_semantic_equivalence(self):
        request = self.request(); rid = validate_decoder_request(request, self.contract, self.cid)
        response = dict(schema='pon-causal-decoder-reported-response-v1', contract=self.cid, request=rid,
                        generated_token_ids=[[3,4],[5,6]], decoded_outputs=['yes','yes\n'])
        roots = validate_decoder_response(response, request, self.contract, self.cid)
        self.assertNotEqual(roots[0], roots[1])
        response['request'] = identity('unrelated-request')
        with self.assertRaisesRegex(ValueError, 'LLM_RESPONSE_CONTEXT'):
            validate_decoder_response(response, request, self.contract, self.cid)

    def test_run_plan_owner_registration_and_ports_are_exact(self):
        self.assertEqual(verify_run_plan(self.plan_raw,self.pid,self.contract,self.cid,
            expected_owner_record=self.plan['source_registration']['owner_record']),self.plan)
        with self.assertRaisesRegex(ValueError, 'LLM_RUN_OWNER'):
            verify_run_plan(self.plan_raw,self.pid,self.contract,self.cid,expected_owner_record=identity('wrong-owner'))
        changed = copy.deepcopy(self.plan); changed['tasks'][0]['input_tokens'] = 17
        with self.assertRaisesRegex(ValueError, 'LLM_RUN_PORT_LIMIT'): freeze_run_plan(changed,self.contract,self.cid)

    def test_control_alias_task_leakage_future_claim_and_posthoc_stopping_reject(self):
        for mutate, code in [
            (lambda p: p['controls'][0].update(artifact=p['candidate']), 'LLM_CONTROL_ALIAS'),
            (lambda p: p['tasks'][1].update(prompt_sha256=p['tasks'][0]['prompt_sha256']), 'LLM_TASK_CONTENT_ALIAS'),
            (lambda p: p['source_registration'].update(prospective_accepted=True), 'LLM_RUN_REGISTRATION_SCOPE'),
            (lambda p: p.update(stopping='select-best-seed'), 'LLM_RUN_PLAN_PROFILE'),
            (lambda p: p.update(seeds=[17,17]), 'LLM_RUN_WORK_LIMIT')]:
            changed = copy.deepcopy(self.plan); mutate(changed)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, code): freeze_run_plan(changed,self.contract,self.cid)

    def test_calibration_choice_does_not_hide_stronger_evaluation_control(self):
        record = fixture_record(self.plan, self.pid)
        for participant in record['participants']:
            for run in participant['runs']:
                for task in self.plan['tasks']:
                    correct = participant['id'] == 'candidate' or (
                        participant['id'] == 'current-backbone' and task['partition'] == 'calibration') or (
                        participant['id'] == 'budget-matched-full-tune' and task['partition'] == 'evaluation')
                    if not correct: run['outputs'][task['id']] = identity('wrong-output')
        assessed = evaluate_run_record(self.plan,record,self.pid)
        self.assertEqual(assessed['calibration_selected_control'], 'current-backbone')
        self.assertEqual(assessed['gain_vs_calibration_selected'], ['1','1'])
        self.assertEqual(assessed['gain_vs_strongest_evaluation_control'], ['0','1'])
        self.assertFalse(assessed['positive_vs_all_controls_on_reported_outputs'])
        for name in ('runtime_executed_by_this_module','authenticated_inference_accepted','prospective_accepted',
                     'independent_accepted','public_reward_eligible'):
            self.assertFalse(assessed[name])

    def test_score_averages_all_frozen_seeds_and_equal_source_groups(self):
        record = fixture_record(self.plan,self.pid)
        evaluation = [t for t in self.plan['tasks'] if t['partition'] == 'evaluation']
        record['participants'][0]['runs'][0]['outputs'][evaluation[0]['id']] = identity('wrong-output')
        result = evaluate_run_record(self.plan,record,self.pid)
        self.assertEqual(result['scores']['candidate']['evaluation'], ['3','4'])
        record['participants'][0]['runs'].pop()
        with self.assertRaisesRegex(ValueError, 'LLM_RECORD_CONTEXT'): evaluate_run_record(self.plan,record,self.pid)

    def test_all_reported_retries_failures_and_cost_stages_count(self):
        record = fixture_record(self.plan,self.pid)
        result = evaluate_run_record(self.plan,record,self.pid)
        self.assertEqual(result['reported_aggregate_costs']['cpu_ns'], 5*2*8)
        self.assertEqual(result['reported_aggregate_costs']['memory_peak_bytes'], 7)
        retry = dict(stage='evaluation',outcome='failed',cpu_ns=3,gpu_ns=0,wall_ns=9,
                     memory_peak_bytes=11,bytes_read=4,bytes_written=0)
        record['participants'][0]['runs'][0]['costs'].append(retry)
        amended = evaluate_run_record(self.plan,record,self.pid)
        self.assertEqual(amended['reported_aggregate_costs']['cpu_ns'], 83)
        self.assertEqual(amended['reported_aggregate_costs']['wall_ns'], 169)
        self.assertEqual(amended['reported_aggregate_costs']['memory_peak_bytes'], 11)

    def test_missing_output_cost_stage_unknown_gpu_and_exceeded_budget(self):
        record = fixture_record(self.plan,self.pid)
        changed = copy.deepcopy(record); changed['participants'][0]['runs'][0]['outputs'].pop(self.plan['tasks'][0]['id'])
        with self.assertRaisesRegex(ValueError, 'LLM_RECORD_OUTPUT_SET'): evaluate_run_record(self.plan,changed,self.pid)
        changed = copy.deepcopy(record); changed['participants'][0]['runs'][0]['costs'].pop()
        with self.assertRaisesRegex(ValueError, 'LLM_RECORD_COSTS'): evaluate_run_record(self.plan,changed,self.pid)
        changed = copy.deepcopy(record)
        changed['participants'][0]['runs'][0]['costs'][-1]['stage'] = 'evaluation'
        with self.assertRaisesRegex(ValueError, 'LLM_RECORD_MISSING_COST_STAGE'): evaluate_run_record(self.plan,changed,self.pid)
        changed = copy.deepcopy(record); changed['participants'][0]['runs'][0]['costs'][0]['gpu_ns'] = None
        assessed = evaluate_run_record(self.plan,changed,self.pid)
        self.assertIsNone(assessed['reported_aggregate_costs']['gpu_ns']); self.assertFalse(assessed['gpu_cost_complete'])
        changed = copy.deepcopy(record); changed['participants'][0]['runs'][0]['costs'][0]['cpu_ns'] = 10000
        with self.assertRaisesRegex(ValueError, 'LLM_REPORTED_BUDGET_EXCEEDED'): evaluate_run_record(self.plan,changed,self.pid)

    def test_parent_training_and_record_context_reinterpretation_reject(self):
        record = fixture_record(self.plan,self.pid)
        changed = copy.deepcopy(record); changed['participants'][1]['runs'][0]['training_steps'] = 1
        with self.assertRaisesRegex(ValueError, 'LLM_PARENT_CONTROL_TRAINED'): evaluate_run_record(self.plan,changed,self.pid)
        changed = copy.deepcopy(record); changed['participants'][0]['artifact'] = identity('posthoc-candidate')
        with self.assertRaisesRegex(ValueError, 'LLM_RECORD_CONTEXT'): evaluate_run_record(self.plan,changed,self.pid)
        changed = copy.deepcopy(record); changed['participants'][0]['runs'][0]['costs'][0]['cpu_ns'] = True
        with self.assertRaisesRegex(ValueError, 'LLM_COST_NUMBER'): evaluate_run_record(self.plan,changed,self.pid)


if __name__ == '__main__':
    unittest.main()

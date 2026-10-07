"""Closed target decoder/LoRA manifests and replayable output-record accounting.

This validates declarations and supplied bytes. It loads no model and runs no
LLM. Float LoRA equality, provenance, future task custody and physical resource
measurement remain responsibilities of their actual owners.
"""
from __future__ import annotations
import copy
import hashlib
import json
import math
import re
from fractions import Fraction
from contract_wire import H, NETWORK, PARAMETER_HASH, canonical, unique

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_TASKS = 32768
MAX_PREDICTIONS = 1024 * 1024
DTYPE_BYTES = {'bfloat16': 2, 'float32': 4}
CONTROL_IDS = ['current-backbone', 'fresh-budget-matched-lora',
               'budget-matched-full-tune', 'randomized-rank-matched-lora']
COST_STAGES = ['model-load', 'tokenization', 'training', 'adapter-material-check',
               'calibration', 'evaluation', 'downstream-use', 'retention-da']
SCOPE = 'declared-target-interface-and-reported-records-no-runtime-qualification'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def closed(value, fields, code):
    require(type(value) is dict and set(value) == set(fields.split()), code)


def digest(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'LLM_DIGEST')
    return value


def integer(value, lo, hi, code):
    require(type(value) is int and lo <= value <= hi, code)
    return value


def rational(value, *, positive=True):
    require(type(value) is list and len(value) == 2 and
            all(type(x) is int for x in value), 'LLM_RATIONAL')
    n, d = value
    require((0 < n if positive else 0 <= n) and 0 < d <= 10**9 and
            n <= 10**9 and math.gcd(n, d) == 1, 'LLM_RATIONAL')
    return Fraction(n, d)


def freeze(value, validate, domain):
    validate(value)
    raw = canonical(value)
    require(len(raw) <= MAX_MANIFEST_BYTES, 'LLM_MANIFEST_LIMIT')
    return raw, H(domain, raw).hex()


def decode(raw, expected_digest, validate, domain, *, max_bytes=MAX_MANIFEST_BYTES):
    # The schema owner supplies its fixed byte policy; submitted JSON cannot
    # widen it. Ordinary manifests retain their exact original 2 MiB default.
    require(type(max_bytes) is int and max_bytes > 0 and
            type(raw) is bytes and len(raw) <= max_bytes, 'LLM_MANIFEST_LIMIT')
    require(H(domain, raw).hex() == digest(expected_digest), 'LLM_MANIFEST_IDENTITY')
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('LLM_MANIFEST_JSON') from error
    require(canonical(value) == raw, 'LLM_MANIFEST_CANONICAL')
    validate(value)
    return value


def architecture_shapes(architecture):
    """The supported decoder is explicitly RMSNorm/RoPE/GQA/SwiGLU, no bias."""
    closed(architecture, 'schema layers hidden intermediate attention_heads kv_heads '
           'vocabulary context rope_theta rms_epsilon tied_embeddings bias', 'LLM_ARCH_FIELDS')
    require(architecture['schema'] == 'pon-decoder-rms-rope-gqa-swiglu-v1' and
            architecture['bias'] is False and type(architecture['tied_embeddings']) is bool,
            'LLM_ARCH_PROFILE')
    for name, lo, hi in [('layers', 1, 128), ('hidden', 8, 16384),
                         ('intermediate', 8, 65536), ('attention_heads', 1, 256),
                         ('kv_heads', 1, 256), ('vocabulary', 16, 262144), ('context', 16, 131072)]:
        integer(architecture[name], lo, hi, 'LLM_ARCH_DIMENSION')
    h, heads, kv = (architecture[k] for k in ('hidden', 'attention_heads', 'kv_heads'))
    require(h % heads == 0 and heads % kv == 0 and (h // heads) % 2 == 0, 'LLM_GQA_SHAPE')
    require(rational(architecture['rope_theta']) > 1 and
            rational(architecture['rms_epsilon']) < 1, 'LLM_ARCH_NUMERIC')
    v, m = architecture['vocabulary'], architecture['intermediate']
    shapes = {'model.embed_tokens.weight': [v, h], 'model.norm.weight': [h]}
    if not architecture['tied_embeddings']:
        shapes['lm_head.weight'] = [v, h]
    projections = {'self_attn.q_proj': [h, h], 'self_attn.k_proj': [kv*h//heads, h],
                   'self_attn.v_proj': [kv*h//heads, h], 'self_attn.o_proj': [h, h],
                   'mlp.gate_proj': [m, h], 'mlp.up_proj': [m, h], 'mlp.down_proj': [h, m]}
    for layer in range(architecture['layers']):
        prefix = 'model.layers.'+str(layer)+'.'
        shapes[prefix+'input_layernorm.weight'] = [h]
        shapes[prefix+'post_attention_layernorm.weight'] = [h]
        shapes.update({prefix+name+'.weight': shape for name, shape in projections.items()})
    return shapes


def tensor(value, expected_shape, dtype):
    closed(value, 'dtype shape byte_length sha256', 'LLM_TENSOR_FIELDS')
    require(value['dtype'] == dtype and value['shape'] == expected_shape and
            type(value['shape']) is list and all(type(x) is int for x in value['shape']), 'LLM_TENSOR_SHAPE')
    require(type(value['byte_length']) is int and
            value['byte_length'] == math.prod(expected_shape)*DTYPE_BYTES[dtype], 'LLM_TENSOR_LENGTH')
    digest(value['sha256'])


def _index_root(index):
    return H('llm-tensor-index-v1', canonical(index)).hex()


def validate_target_contract(value):
    closed(value, 'schema network parameters reference architecture backbone tokenizer '
           'numeric targets ports registration scope', 'LLM_CONTRACT_FIELDS')
    require(value['schema'] == 'pon-target-decoder-adapter-contract-v1' and
            value['network'] == NETWORK.hex() and value['parameters'] == PARAMETER_HASH.hex() and
            value['scope'] == SCOPE, 'LLM_CONTRACT_PROFILE')
    require(type(value['reference']) is str and 0 < len(value['reference']) <= 256, 'LLM_REFERENCE')
    shapes = architecture_shapes(value['architecture'])
    numeric = value['numeric']
    closed(numeric, 'storage_dtype accumulation_dtype quantization adapter_expression '
           'operator_contract runtime_status', 'LLM_NUMERIC_FIELDS')
    require(type(numeric['storage_dtype']) is str and numeric['storage_dtype'] in DTYPE_BYTES and numeric['accumulation_dtype'] == 'float32' and
            numeric['quantization'] == 'none' and
            numeric['adapter_expression'] == 'x-Wt-plus-alpha-over-rank-times-x-At-Bt-v1' and
            numeric['runtime_status'] == 'required-not-executed', 'LLM_NUMERIC_PROFILE')
    digest(numeric['operator_contract'])
    backbone = value['backbone']
    closed(backbone, 'index index_root owner_reference license_reference', 'LLM_BACKBONE_FIELDS')
    require(type(backbone['index']) is dict and set(backbone['index']) == set(shapes), 'LLM_BACKBONE_INDEX')
    for name, shape in shapes.items():
        tensor(backbone['index'][name], shape, numeric['storage_dtype'])
    require(backbone['index_root'] == _index_root(backbone['index']), 'LLM_BACKBONE_ROOT')
    for name in ('owner_reference', 'license_reference'):
        digest(backbone[name])  # References are not signatures or license authority.
    tokenizer = value['tokenizer']
    closed(tokenizer, 'schema files files_root vocabulary bos_id eos_id pad_id '
           'add_bos add_eos chat_template behavior_contract', 'LLM_TOKENIZER_FIELDS')
    require(tokenizer['schema'] == 'pon-tokenizer-files-and-behavior-v1' and
            type(tokenizer['vocabulary']) is int and tokenizer['vocabulary'] == value['architecture']['vocabulary'] and
            type(tokenizer['add_bos']) is bool and type(tokenizer['add_eos']) is bool, 'LLM_TOKENIZER_PROFILE')
    for name in ('bos_id', 'eos_id', 'pad_id'):
        integer(tokenizer[name], 0, tokenizer['vocabulary']-1, 'LLM_TOKEN_ID')
    files = tokenizer['files']
    require(type(files) is dict and 1 <= len(files) <= 16 and
            all(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name)
                and '..' not in name for name in files), 'LLM_TOKENIZER_FILES')
    for item in files.values():
        closed(item, 'sha256 byte_length', 'LLM_TOKENIZER_FILE_FIELDS')
        digest(item['sha256']); integer(item['byte_length'], 1, 256*1024*1024, 'LLM_TOKENIZER_FILE_LIMIT')
    require(tokenizer['files_root'] == H('llm-tokenizer-file-index-v1', canonical(files)).hex(), 'LLM_TOKENIZER_ROOT')
    digest(tokenizer['chat_template']); digest(tokenizer['behavior_contract'])
    targets = value['targets']
    require(type(targets) is list and 1 <= len(targets) <= 128 and
            all(type(t) is dict for t in targets), 'LLM_TARGETS')
    names = []
    for target in targets:
        closed(target, 'module in_features out_features rank alpha', 'LLM_TARGET_FIELDS')
        name = target['module']; require(type(name) is str and name+'.weight' in shapes and
            len(shapes[name+'.weight']) == 2 and name.startswith('model.layers.'), 'LLM_TARGET_MODULE')
        shape = shapes[name+'.weight']
        require(type(target['in_features']) is int and type(target['out_features']) is int and
                [target['out_features'], target['in_features']] == shape, 'LLM_TARGET_DIMENSION')
        integer(target['rank'], 1, min(64, *shape), 'LLM_TARGET_RANK'); rational(target['alpha'])
        names.append(name)
    require(names == sorted(set(names)), 'LLM_TARGET_ORDER')
    ports = value['ports']
    closed(ports, 'schema batch_max input_tokens_max output_tokens_max input_dtype mask_dtype '
           'logits_dtype truncation padding_position model_mode dropout tied_lm_head generation', 'LLM_PORT_FIELDS')
    require(ports['schema'] == 'pon-causal-decoder-token-and-logit-ports-v1' and
            ports['input_dtype'] == 'int64' and ports['mask_dtype'] == 'bool' and
            ports['logits_dtype'] == 'float32' and ports['truncation'] == 'reject' and
            ports['padding_position'] == 'left-with-explicit-mask' and ports['model_mode'] == 'eval' and
            ports['dropout'] is False and
            type(ports['tied_lm_head']) is bool and ports['tied_lm_head'] == value['architecture']['tied_embeddings'] and
            ports['generation'] == 'greedy-lowest-token-id-tie-fixed-count-v1', 'LLM_PORT_PROFILE')
    integer(ports['batch_max'], 1, 64, 'LLM_BATCH_LIMIT')
    for name in ('input_tokens_max', 'output_tokens_max'):
        integer(ports[name], 1, value['architecture']['context'], 'LLM_TOKEN_LIMIT')
    require(ports['input_tokens_max']+ports['output_tokens_max'] <= value['architecture']['context'], 'LLM_CONTEXT_LIMIT')
    registration = value['registration']
    closed(registration, 'owner_record target_admission runtime_qualification prospective_accepted '
           'independent_accepted public_reward_eligible', 'LLM_REGISTRATION_FIELDS')
    digest(registration['owner_record']); digest(registration['target_admission'])
    require(registration['runtime_qualification'] == 'required-not-executed' and
            all(registration[name] is False for name in ('prospective_accepted', 'independent_accepted',
                                                        'public_reward_eligible')), 'LLM_REGISTRATION_SCOPE')
    return copy.deepcopy(value)


def freeze_target_contract(value):
    return freeze(value, validate_target_contract, 'target-decoder-adapter-contract-v1')


def verify_target_contract(raw, expected_digest, *, expected_backbone_root, expected_tokenizer_root):
    value = decode(raw, expected_digest, validate_target_contract, 'target-decoder-adapter-contract-v1')
    require(value['backbone']['index_root'] == digest(expected_backbone_root) and
            value['tokenizer']['files_root'] == digest(expected_tokenizer_root), 'LLM_OWNER_CONTEXT')
    return value


def verify_tensor_material(index, material):
    """Verify supplied tensor/file bytes, never a downloaded self-attested root."""
    require(type(index) is dict and type(material) is dict and set(index) == set(material), 'LLM_MATERIAL_SET')
    for name, item in index.items():
        blob = material[name]
        require(type(blob) is bytes and len(blob) == item['byte_length'] and
                hashlib.sha256(blob).hexdigest() == item['sha256'], 'LLM_MATERIAL_BINDING')
    return sum(len(blob) for blob in material.values())


def freeze_wrapped_adapter(value, contract, expected_contract):
    validate_target_contract(contract)
    require(freeze_target_contract(contract)[1] == digest(expected_contract), 'LLM_ADAPTER_CONTRACT')
    closed(value, 'schema contract modules material_scope', 'LLM_ADAPTER_FIELDS')
    require(value['schema'] == 'pon-wrapped-decoder-lora-material-v1' and
            value['contract'] == expected_contract and
            value['material_scope'] == 'factor-bytes-and-insertion-interface-not-functional-equivalence', 'LLM_ADAPTER_PROFILE')
    modules = value['modules']
    require(type(modules) is dict and set(modules) == {t['module'] for t in contract['targets']}, 'LLM_ADAPTER_MODULE_SET')
    for target in contract['targets']:
        item = modules[target['module']]
        closed(item, 'A B rank alpha dropout', 'LLM_ADAPTER_MODULE_FIELDS')
        require(type(item['rank']) is int and item['rank'] == target['rank'] and
                item['alpha'] == target['alpha'] and item['dropout'] is False, 'LLM_ADAPTER_SCALE')
        rational(item['alpha'])
        dtype = contract['numeric']['storage_dtype']
        tensor(item['A'], [target['rank'], target['in_features']], dtype)
        tensor(item['B'], [target['out_features'], target['rank']], dtype)
    return freeze(value, lambda _: None, 'wrapped-decoder-lora-material-v1')


def verify_wrapped_adapter(raw, expected_digest, contract, expected_contract, material):
    value = decode(raw, expected_digest, lambda _: None, 'wrapped-decoder-lora-material-v1')
    require(freeze_wrapped_adapter(value, contract, expected_contract)[0] == raw, 'LLM_ADAPTER_BINDING')
    index = {name+'.'+factor: module[factor] for name, module in value['modules'].items() for factor in ('A', 'B')}
    verify_tensor_material(index, material)
    # Finite IEEE values only. Canonical bytes/shape do not prove float BA equality.
    for name, item in index.items():
        blob = material[name]; width = DTYPE_BYTES[item['dtype']]
        mask = 0x7f80 if width == 2 else 0x7f800000
        require(all(int.from_bytes(blob[i:i+width], 'little') & mask != mask
                    for i in range(0, len(blob), width)), 'LLM_ADAPTER_NONFINITE')
    return value


def validate_decoder_request(value, contract, expected_contract):
    """Typed wrapper for fixed-count greedy decoding; no silent truncation."""
    validate_target_contract(contract)
    require(freeze_target_contract(contract)[1] == digest(expected_contract), 'LLM_REQUEST_CONTRACT')
    closed(value, 'schema contract input_ids attention_mask generation_tokens', 'LLM_REQUEST_FIELDS')
    require(value['schema'] == 'pon-causal-decoder-request-v1' and value['contract'] == expected_contract,
            'LLM_REQUEST_CONTEXT')
    ids, masks, ports = value['input_ids'], value['attention_mask'], contract['ports']
    require(type(ids) is list and 1 <= len(ids) <= ports['batch_max'] and
            type(masks) is list and len(masks) == len(ids), 'LLM_REQUEST_BATCH')
    width = None
    for row, mask in zip(ids, masks):
        require(type(row) is list and 1 <= len(row) <= ports['input_tokens_max'] and
                type(mask) is list and len(mask) == len(row) and all(type(bit) is bool for bit in mask),
                'LLM_REQUEST_SHAPE')
        require(width is None or width == len(row), 'LLM_REQUEST_PADDING')
        width = len(row)
        require(any(mask) and mask == sorted(mask), 'LLM_REQUEST_MASK')
        for token, present in zip(row, mask):
            integer(token, 0, contract['architecture']['vocabulary']-1, 'LLM_REQUEST_TOKEN')
            require(present or token == contract['tokenizer']['pad_id'], 'LLM_REQUEST_PAD_TOKEN')
    integer(value['generation_tokens'], 1, ports['output_tokens_max'], 'LLM_REQUEST_OUTPUT_LIMIT')
    require(width+value['generation_tokens'] <= contract['architecture']['context'], 'LLM_REQUEST_CONTEXT_LIMIT')
    return H('causal-decoder-request-v1', canonical(value)).hex()


def validate_decoder_response(value, request, contract, expected_contract):
    request_id = validate_decoder_request(request, contract, expected_contract)
    closed(value, 'schema contract request generated_token_ids decoded_outputs', 'LLM_RESPONSE_FIELDS')
    require(value['schema'] == 'pon-causal-decoder-reported-response-v1' and value['contract'] == expected_contract and
            value['request'] == request_id, 'LLM_RESPONSE_CONTEXT')
    rows, decoded = value['generated_token_ids'], value['decoded_outputs']
    require(type(rows) is list and len(rows) == len(request['input_ids']) and
            type(decoded) is list and len(decoded) == len(rows), 'LLM_RESPONSE_BATCH')
    output_digests = []
    for row, text in zip(rows, decoded):
        require(type(row) is list and len(row) == request['generation_tokens'], 'LLM_RESPONSE_SHAPE')
        for token in row: integer(token, 0, contract['architecture']['vocabulary']-1, 'LLM_RESPONSE_TOKEN')
        require(type(text) is str and len(text.encode('utf-8')) <= 4*1024*1024, 'LLM_RESPONSE_TEXT')
        output_digests.append(hashlib.sha256(text.encode('utf-8')).hexdigest())
    # The actual tokenizer owner must check token -> text; metadata does not do it.
    return output_digests


def validate_run_plan(value):
    closed(value, 'schema network parameters contract backbone tokenizer candidate controls tasks '
           'metric repeats seeds budgets stopping source_registration scope', 'LLM_RUN_PLAN_FIELDS')
    require(value['schema'] == 'pon-target-decoder-evaluation-run-plan-v1' and
            value['network'] == NETWORK.hex() and value['parameters'] == PARAMETER_HASH.hex() and
            value['metric'] == 'equal-source-group-exact-output-bytes-accuracy-v1' and
            value['stopping'] == 'all-frozen-repetitions-no-early-selection-v1' and value['scope'] == SCOPE,
            'LLM_RUN_PLAN_PROFILE')
    for name in ('contract', 'backbone', 'tokenizer', 'candidate'):
        digest(value[name])
    controls = value['controls']
    require(type(controls) is list and len(controls) == 4, 'LLM_CONTROLS')
    for control, name in zip(controls, CONTROL_IDS):
        closed(control, 'id artifact', 'LLM_CONTROL_FIELDS')
        require(control['id'] == name, 'LLM_CONTROL_ORDER'); digest(control['artifact'])
    require(len({value['candidate']} | {c['artifact'] for c in controls}) == 5, 'LLM_CONTROL_ALIAS')
    tasks = value['tasks']
    require(type(tasks) is list and 2 <= len(tasks) <= MAX_TASKS, 'LLM_TASKS')
    ids, prompts, counts = [], set(), {'calibration': 0, 'evaluation': 0}
    for task in tasks:
        closed(task, 'id partition source_group prompt_sha256 target_output_sha256 input_tokens output_tokens', 'LLM_TASK_FIELDS')
        for name in ('id', 'source_group', 'prompt_sha256', 'target_output_sha256'):
            digest(task[name])
        require(type(task['partition']) is str and task['partition'] in counts, 'LLM_TASK_PARTITION')
        integer(task['input_tokens'], 1, 131072, 'LLM_TASK_INPUT_TOKENS')
        integer(task['output_tokens'], 1, 131072, 'LLM_TASK_OUTPUT_TOKENS')
        require(task['prompt_sha256'] not in prompts, 'LLM_TASK_CONTENT_ALIAS')
        prompts.add(task['prompt_sha256']); ids.append(task['id']); counts[task['partition']] += 1
    require(ids == sorted(set(ids)) and min(counts.values()) > 0, 'LLM_TASK_ORDER')
    repeats = integer(value['repeats'], 1, 8, 'LLM_REPEATS')
    require(type(value['seeds']) is list and len(value['seeds']) == repeats and
            all(type(seed) is int and 0 <= seed < 1 << 64 for seed in value['seeds']) and
            len(set(value['seeds'])) == repeats and len(tasks)*5*repeats <= MAX_PREDICTIONS, 'LLM_RUN_WORK_LIMIT')
    budgets = value['budgets']
    closed(budgets, 'cpu_ns gpu_ns wall_ns memory_peak_bytes bytes_read bytes_written training_steps training_flops', 'LLM_BUDGET_FIELDS')
    for budget in budgets.values():
        integer(budget, 1, (1 << 63)-1, 'LLM_BUDGET')
    registration = value['source_registration']
    closed(registration, 'owner_record admission_root task_release_record custody_record observation_status '
           'prospective_accepted independent_accepted public_reward_eligible', 'LLM_RUN_REGISTRATION_FIELDS')
    for name in ('owner_record', 'admission_root', 'task_release_record', 'custody_record'):
        digest(registration[name])
    require(registration['observation_status'] == 'external-owner-evidence-required' and
            all(registration[k] is False for k in ('prospective_accepted', 'independent_accepted',
                                                   'public_reward_eligible')), 'LLM_RUN_REGISTRATION_SCOPE')
    return copy.deepcopy(value)


def freeze_run_plan(value, contract, expected_contract):
    validate_target_contract(contract); validate_run_plan(value)
    require(freeze_target_contract(contract)[1] == digest(expected_contract) and
            value['contract'] == expected_contract and value['backbone'] == contract['backbone']['index_root'] and
            value['tokenizer'] == contract['tokenizer']['files_root'], 'LLM_RUN_CONTEXT')
    for task in value['tasks']:
        require(task['input_tokens'] <= contract['ports']['input_tokens_max'] and
                task['output_tokens'] <= contract['ports']['output_tokens_max'], 'LLM_RUN_PORT_LIMIT')
    return freeze(value, validate_run_plan, 'target-decoder-evaluation-run-plan-v1')


def verify_run_plan(raw, expected_digest, contract, expected_contract, *, expected_owner_record):
    value = decode(raw, expected_digest, validate_run_plan, 'target-decoder-evaluation-run-plan-v1')
    require(freeze_run_plan(value, contract, expected_contract)[0] == raw and
            value['source_registration']['owner_record'] == digest(expected_owner_record), 'LLM_RUN_OWNER')
    return value


def _score(tasks, outputs, partition):
    groups = {}
    for task in tasks:
        if task['partition'] == partition:
            groups.setdefault(task['source_group'], []).append(int(outputs[task['id']] == task['target_output_sha256']))
    return sum((Fraction(sum(v), len(v)) for v in groups.values()), Fraction()) / len(groups)


def evaluate_run_record(plan, record, expected_plan):
    """Recompute exact byte-match scores/cost totals from a complete reported run.

    Output and cost assertions still require authenticated actual runtime evidence;
    this function cannot prove that a declared model generated an output.
    """
    validate_run_plan(plan)
    require(freeze(plan, validate_run_plan, 'target-decoder-evaluation-run-plan-v1')[1] == digest(expected_plan), 'LLM_RECORD_PLAN')
    closed(record, 'schema plan participants runtime_source runtime_binary hardware observer scope', 'LLM_RECORD_FIELDS')
    require(record['schema'] == 'pon-target-decoder-reported-run-record-v1' and record['plan'] == expected_plan and
            record['scope'] == 'reported-output-and-cost-replay-not-authenticated-inference', 'LLM_RECORD_SCOPE')
    for name in ('runtime_source', 'runtime_binary', 'hardware', 'observer'):
        digest(record[name])
    participants = record['participants']
    expected = [('candidate', plan['candidate'])]+[(c['id'], c['artifact']) for c in plan['controls']]
    require(type(participants) is list and len(participants) == 5, 'LLM_RECORD_PARTICIPANTS')
    totals = {k: 0 for k in plan['budgets']}; total_gpu_known = True; scores = {}
    for participant, (name, artifact) in zip(participants, expected):
        closed(participant, 'id artifact runs', 'LLM_RECORD_PARTICIPANT_FIELDS')
        require(participant['id'] == name and participant['artifact'] == artifact and
                type(participant['runs']) is list and len(participant['runs']) == plan['repeats'], 'LLM_RECORD_CONTEXT')
        means = {'calibration': [], 'evaluation': []}
        for run, seed in zip(participant['runs'], plan['seeds']):
            closed(run, 'seed outputs costs training_steps training_flops', 'LLM_RECORD_RUN_FIELDS')
            require(type(run['seed']) is int and run['seed'] == seed, 'LLM_RECORD_SEED')
            outputs = run['outputs']
            require(type(outputs) is dict and set(outputs) == {t['id'] for t in plan['tasks']}, 'LLM_RECORD_OUTPUT_SET')
            for output in outputs.values(): digest(output)
            costs = run['costs']; require(type(costs) is list and len(COST_STAGES) <= len(costs) <= 10000, 'LLM_RECORD_COSTS')
            subtotal = {k: 0 for k in totals}; seen = set(); gpu_known = True
            for cost in costs:
                closed(cost, 'stage outcome cpu_ns gpu_ns wall_ns memory_peak_bytes bytes_read bytes_written', 'LLM_COST_FIELDS')
                require(cost['stage'] in COST_STAGES and cost['outcome'] in ('success', 'failed', 'retry', 'cache-hit', 'not-applicable'), 'LLM_COST_STAGE')
                seen.add(cost['stage'])
                for field in ('cpu_ns', 'wall_ns', 'memory_peak_bytes', 'bytes_read', 'bytes_written'):
                    integer(cost[field], 0, (1 << 63)-1, 'LLM_COST_NUMBER')
                    subtotal[field] = max(subtotal[field], cost[field]) if field == 'memory_peak_bytes' else subtotal[field]+cost[field]
                if cost['gpu_ns'] is None: gpu_known = False
                else:
                    integer(cost['gpu_ns'], 0, (1 << 63)-1, 'LLM_GPU_NUMBER'); subtotal['gpu_ns'] += cost['gpu_ns']
            require(seen == set(COST_STAGES), 'LLM_RECORD_MISSING_COST_STAGE')
            for field in ('training_steps', 'training_flops'):
                subtotal[field] = integer(run[field], 0, (1 << 63)-1, 'LLM_TRAINING_NUMBER')
            require(name != 'current-backbone' or subtotal['training_steps'] == subtotal['training_flops'] == 0,
                    'LLM_PARENT_CONTROL_TRAINED')
            require(all(subtotal[k] <= plan['budgets'][k] for k in subtotal), 'LLM_REPORTED_BUDGET_EXCEEDED')
            total_gpu_known &= gpu_known
            for k in totals:
                totals[k] = max(totals[k], subtotal[k]) if k == 'memory_peak_bytes' else totals[k]+subtotal[k]
                require(totals[k] < 1 << 64, 'LLM_COST_OVERFLOW')
            for partition in means:
                means[partition].append(_score(plan['tasks'], outputs, partition))
        scores[name] = {p: sum(v, Fraction())/len(v) for p, v in means.items()}
    selected = max(CONTROL_IDS, key=lambda name: (scores[name]['calibration'], -CONTROL_IDS.index(name)))
    candidate = scores['candidate']['evaluation']
    strongest = max(scores[name]['evaluation'] for name in CONTROL_IDS)
    if not total_gpu_known: totals['gpu_ns'] = None
    wire = lambda f: [str(f.numerator), str(f.denominator)]
    return {'schema': 'pon-target-decoder-reported-run-assessment-v1', 'plan': expected_plan,
            'record': H('target-decoder-reported-run-record-v1', canonical(record)).hex(),
            'scores': {name: {p: wire(s) for p, s in row.items()} for name, row in scores.items()},
            'calibration_selected_control': selected, 'gain_vs_calibration_selected': wire(candidate-scores[selected]['evaluation']),
            'gain_vs_strongest_evaluation_control': wire(candidate-strongest),
            'positive_vs_all_controls_on_reported_outputs': candidate > strongest,
            'reported_aggregate_costs': totals, 'gpu_cost_complete': total_gpu_known,
            'runtime_executed_by_this_module': False, 'authenticated_inference_accepted': False,
            'prospective_accepted': False, 'independent_accepted': False, 'public_reward_eligible': False,
            'scope': 'empirical-exact-output-byte-score-and-reported-resource-accounting-only'}

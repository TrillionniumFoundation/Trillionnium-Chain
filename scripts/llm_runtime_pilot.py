#!/usr/bin/env python3
"""Execute a bounded public SmolLM2 pilot; never grants native/reward authority.

Each participant runs in a separately monitored process. Training finishes before
the five actual artifacts are frozen and decoded. Receipt hashes bind observations;
they are not signatures, independent custody, proof of useful work or zkML.
Torch/Transformers/PEFT are isolated optional runtime dependencies, not node deps.
"""
from __future__ import annotations
import argparse
import gc
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time

MODEL = 'HuggingFaceTB/SmolLM2-135M-Instruct'
REVISION = '12fd25f77366fa6b3b4b768ec3050bf629380bac'
WEIGHT_SHA = '5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c'
PUBLIC_FILES = {
    'config.json': (861, '8eb740e8bbe4cff95ea7b4588d17a2432deb16e8075bc5828ff7ba9be94d982a'),
    'generation_config.json': (132, '87b916edaaab66b3899b9d0dd0752727dff6666686da0504d89ae0a6e055a013'),
    'model.safetensors': (269060552, WEIGHT_SHA),
    'special_tokens_map.json': (655, '2b7379f3ae813529281a5c602bc5a11c1d4e0a99107aaa597fe936c1e813ca52'),
    'tokenizer.json': (2104556, '9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c'),
    'tokenizer_config.json': (3764, '4ec77d44f62efeb38d7e044a1db318f6a939438425312dfa333b8382dbad98df'),
    'README.md': (6772, '4f97533ad95b1b2fea15fbc075c01b94578ebdd7c8138888fa43fa3abd530dc4'),
}
CONTROLS = ['current-backbone', 'fresh-budget-matched-lora',
            'budget-matched-full-tune', 'randomized-rank-matched-lora']
PARTICIPANTS = ['candidate', *CONTROLS]
QUALIFICATIONS = ['public_network_ready', 'authenticated_inference_accepted',
                  'independent_accepted', 'prospective_accepted', 'public_reward_eligible']
REPOSITORY = Path(__file__).resolve().parents[1]
FAMILY_PATH = REPOSITORY/'config/pon/model-family-smollm2-135m-v1.json'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'RUNTIME_DUPLICATE_JSON')
        result[key] = value
    return result


def read_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def file_sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def native_artifact_digest(path):
    """Same byte domain H('artifact', blob); distinct from ordinary SHA256."""
    import struct
    path = Path(path); length = path.stat().st_size
    require(length < 1 << 32, 'RUNTIME_ARTIFACT_LENGTH')
    tag = b'artifact'
    value = hashlib.sha256(b'TRNM-PON1\0'+struct.pack('<H',len(tag))+tag+struct.pack('<I',length))
    with path.open('rb') as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b''): value.update(chunk)
    return value.hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.partial')
    temporary.write_bytes(canonical(value) + b'\n')
    temporary.replace(path)


def require(value, code):
    if not value:
        raise ValueError(code)


def verify_materials(directory):
    """Recheck the retained exact snapshot, including non-weight file hashes."""
    directory = Path(directory)
    manifest = read_json(directory / 'material-manifest.json')
    require(manifest['model'] == MODEL and manifest['revision'] == REVISION,
            'RUNTIME_SNAPSHOT_CONTEXT')
    required = set(PUBLIC_FILES)
    require(set(manifest['files']) == required, 'RUNTIME_MATERIAL_SET')
    for name, item in manifest['files'].items():
        path = directory / name
        require(type(item['size']) is int and
                (item['size'], item['sha256']) == PUBLIC_FILES[name], 'RUNTIME_PUBLIC_FILE_ROOT')
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item['size'] and
                file_sha(path) == item['sha256'], 'RUNTIME_MATERIAL_HASH')
        require(item['revision'] == REVISION, 'RUNTIME_MATERIAL_REVISION')
    require(manifest['files']['model.safetensors']['sha256'] == WEIGHT_SHA,
            'RUNTIME_PUBLIC_WEIGHT_ROOT')
    config = read_json(directory / 'config.json')
    for key, expected in [('model_type', 'llama'), ('num_hidden_layers', 30),
                          ('hidden_size', 576), ('intermediate_size', 1536),
                          ('num_attention_heads', 9), ('num_key_value_heads', 3),
                          ('vocab_size', 49152), ('max_position_embeddings', 8192),
                          ('tie_word_embeddings', True), ('attention_bias', False),
                          ('mlp_bias', False), ('torch_dtype', 'bfloat16')]:
        require(type(config[key]) is type(expected) and config[key] == expected, 'RUNTIME_CONFIG_PROFILE')
    return manifest, config


def verify_family(family):
    require(family['id'] == 'smollm2-135m-cpu-dev-v1' and
            family['reference']['model'] == MODEL and family['reference']['revision'] == REVISION and
            family['required_controls'] == CONTROLS and family['numeric_profile']['storage_dtype'] == 'float32',
            'RUNTIME_FAMILY_CONTEXT')
    files=family['material_pins']['files']
    require(set(files) == set(PUBLIC_FILES) and
            all((files[name]['size'],files[name]['sha256']) == PUBLIC_FILES[name] for name in files),
            'RUNTIME_FAMILY_PUBLIC_MATERIAL')
    require(family['consensus_authority'] is False and family['changes_chainwork'] is False and
            family['production_activation'] is False and
            all(family[name] is False for name in QUALIFICATIONS) and
            family['evaluation']['positive_gain_required'] is True and
            family['evaluation']['nonpositive_gain_adoption'] is False and
            family['evaluation']['nonpositive_gain_reward'] is False and
            type(family['evaluation']['nonpositive_gain_score']) is int and family['evaluation']['nonpositive_gain_score'] == 0 and
            family['evaluation']['current_fixture']['independent'] is False and
            family['evaluation']['current_fixture']['prospective'] is False and
            family['evaluation']['current_fixture']['llm_quality_qualification'] is False,
            'RUNTIME_FAMILY_QUALIFICATION_SCOPE')
    return family


def tasks():
    """Public operator-controlled fixture tasks; no independent/future claim."""
    rows = []
    for partition, offset, count in [('training', 0, 12), ('calibration', 20, 4),
                                      ('evaluation', 40, 4)]:
        for number in range(count):
            k = offset + number
            if number % 2 == 0:
                a, b = k + 3, k + (2 if k % 4 == 0 else 4)
                prompt = f'Answer with only yes or no. Is {a} greater than {b}?'
                target, group = ('yes' if a > b else 'no'), 'integer-comparison'
            else:
                word = ['Alpha', 'beta', 'Gamma', 'delta'][(k // 2) % 4]
                prompt = f'Answer with only yes or no. Does the first character of {word} use uppercase?'
                target, group = ('yes' if word[0].isupper() else 'no'), 'ascii-case'
                # Partition bytes differ even when the semantic operation repeats.
                prompt += f' Item {k}.'
            row = dict(partition=partition, source_group=identity(group), prompt=prompt,
                       expected_output=target, prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
                       target_output_sha256=hashlib.sha256(target.encode()).hexdigest())
            row['id'] = identity(row)
            rows.append(row)
    return sorted(rows, key=lambda row: row['id'])


def experiment_plan(materials, *, backend='cpu', threads=4, steps=10):
    require(backend in ('cpu', 'cuda', 'rocm', 'mps'), 'RUNTIME_BACKEND')
    require(type(threads) is int and 1 <= threads <= 8 and type(steps) is int and 1 <= steps <= 100,
            'RUNTIME_LIMIT')
    return dict(schema='llm-runtime-public-pilot-plan-v1', model=MODEL, revision=REVISION,
                model_family_profile='smollm2-135m-cpu-dev-v1',
                model_family_configuration_sha256=file_sha(FAMILY_PATH),
                snapshot=identity(materials), runtime_source=file_sha(__file__), backend=backend,
                threads=threads, dtype='float32', attention='eager', seed=7, training_steps=steps,
                input_tokens_max=128, generation_tokens=8, rank=4, alpha=8,
                recipes={'candidate': dict(kind='lora', learning_rate='0.002', initialization_seed=7),
                         'current-backbone': dict(kind='immutable-backbone'),
                         'fresh-budget-matched-lora': dict(kind='lora', learning_rate='0.001', initialization_seed=7),
                         'budget-matched-full-tune': dict(kind='full-tune', learning_rate='0.0001', initialization_seed=7),
                         'randomized-rank-matched-lora': dict(kind='random-lora', std='0.02', initialization_seed=7)},
                participants=list(PARTICIPANTS), tasks=tasks(),
                training_budget=dict(wall_seconds=1800, rss_bytes=16 * 1024**3),
                inference_budget=dict(wall_seconds=600, rss_bytes=8 * 1024**3),
                measurement_scope='process-CPU-wall-peakRSS-Linux-IO-and-profiler-supported-FLOPs',
                source_scope='operator-controlled-public-fixtures-no-future-independent-custody',
                **{name: False for name in QUALIFICATIONS})


def validate_plan(plan):
    require(plan['schema'] == 'llm-runtime-public-pilot-plan-v1' and
            plan['backend'] in ('cpu','cuda','rocm','mps') and
            type(plan['threads']) is int and 1 <= plan['threads'] <= 8 and
            type(plan['generation_tokens']) is int and 1 <= plan['generation_tokens'] <= 16 and
            type(plan['input_tokens_max']) is int and plan['input_tokens_max'] == 128 and
            type(plan['rank']) is int and plan['rank'] == 4 and
            type(plan['alpha']) is int and plan['alpha'] == 8, 'RUNTIME_LIMIT')
    for name, wall_limit, rss_limit in [('training_budget',1800,16*1024**3),
                                       ('inference_budget',600,8*1024**3)]:
        budget = plan[name]
        require(type(budget) is dict and set(budget) == {'wall_seconds','rss_bytes'} and
                type(budget['wall_seconds']) is int and 1 <= budget['wall_seconds'] <= wall_limit and
                type(budget['rss_bytes']) is int and 1 <= budget['rss_bytes'] <= rss_limit,
                'RUNTIME_BUDGET_LIMIT')
    require(plan['participants'] == PARTICIPANTS and set(plan['recipes']) == set(PARTICIPANTS),
            'RUNTIME_REQUIRED_CONTROLS')
    require(plan['revision'] == REVISION and plan['model'] == MODEL and plan['dtype'] == 'float32',
            'RUNTIME_PLAN_CONTEXT')
    require(all(plan[name] is False for name in QUALIFICATIONS), 'RUNTIME_QUALIFICATION_SCOPE')
    require(type(plan['training_steps']) is int and 1 <= plan['training_steps'] <= 100,
            'RUNTIME_TRAINING_LIMIT')
    rows = plan['tasks']
    require(len({row['id'] for row in rows}) == len(rows) and
            len({row['prompt_sha256'] for row in rows}) == len(rows), 'RUNTIME_TASK_ALIAS')
    for row in rows:
        require(hashlib.sha256(row['prompt'].encode()).hexdigest() == row['prompt_sha256'] and
                hashlib.sha256(row['expected_output'].encode()).hexdigest() == row['target_output_sha256'],
                'RUNTIME_TASK_BYTES')
        require(row['id'] == identity({k:v for k,v in row.items() if k != 'id'}) and
                row['partition'] in ('training','calibration','evaluation'), 'RUNTIME_TASK_IDENTITY')
    return plan


def read_io():
    try:
        return {line.split(':')[0]: int(line.split(':')[1]) for line in
                Path('/proc/self/io').read_text().splitlines()}
    except OSError:
        return None


def current_rss(pid=None):
    try:
        lines = Path(f'/proc/{pid or os.getpid()}/status').read_text().splitlines()
        return next(int(row.split()[1]) * 1024 for row in lines if row.startswith('VmRSS:'))
    except (OSError, StopIteration):
        return None


def synchronize(torch, backend):
    if backend in ('rocm', 'cuda'):
        torch.cuda.synchronize()
    elif backend == 'mps':
        torch.mps.synchronize()


class Observer:
    def __init__(self, directory, backend):
        self.directory, self.backend = Path(directory), backend
        self.events = []

    def stage(self, name, operation):
        start, cpu, io = time.monotonic_ns(), time.process_time_ns(), read_io()
        outcome, error = 'success', None
        try:
            return operation()
        except BaseException as exc:
            outcome, error = 'failed', type(exc).__name__
            raise
        finally:
            end_io = read_io()
            record = dict(stage=name, outcome=outcome, error_type=error,
                          cpu_ns=time.process_time_ns()-cpu, wall_ns=time.monotonic_ns()-start,
                          memory_peak_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                          bytes_read=(end_io['read_bytes']-io['read_bytes']) if io and end_io else None,
                          bytes_written=(end_io['write_bytes']-io['write_bytes']) if io and end_io else None,
                          gpu_ns=0 if self.backend == 'cpu' else None)
            self.events.append(record)
            with (self.directory/'cost-events.jsonl').open('a') as handle:
                handle.write(json.dumps(record, sort_keys=True)+'\n')


def runtime_import(plan):
    import torch
    require(sys.byteorder == 'little', 'RUNTIME_ENDIAN')
    torch.set_num_threads(plan['threads'])
    torch.set_num_interop_threads(1)
    torch.manual_seed(plan['seed'])
    torch.use_deterministic_algorithms(True)
    torch.set_float32_matmul_precision('highest')
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    backend = plan['backend']
    if backend == 'cpu':
        device = torch.device('cpu')
    elif backend == 'rocm':
        require(torch.version.hip is not None and torch.cuda.is_available(), 'RUNTIME_ROCM_UNAVAILABLE')
        device = torch.device('cuda')
    elif backend == 'cuda':
        require(torch.version.hip is None and torch.version.cuda is not None and torch.cuda.is_available(),
                'RUNTIME_CUDA_UNAVAILABLE')
        device = torch.device('cuda')
    else:
        require(torch.backends.mps.is_built() and torch.backends.mps.is_available(), 'RUNTIME_MPS_UNAVAILABLE')
        device = torch.device('mps')
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from safetensors import safe_open
    from safetensors.torch import save_file, load_file
    return torch, device, AutoModelForCausalLM, AutoTokenizer, safe_open, save_file, load_file


def tensor_bytes(tensor):
    return tensor.detach().to('cpu').contiguous().view(-1).view(__import__('torch').uint8).numpy().tobytes()


def tensor_descriptor(tensor):
    data = tensor_bytes(tensor)
    return dict(dtype=str(tensor.dtype).removeprefix('torch.'), shape=list(tensor.shape),
                byte_length=len(data), sha256=hashlib.sha256(data).hexdigest())


def contract_module():
    sys.path.insert(0, str(REPOSITORY/'formal/pon-nakamoto-v1'))
    import llm_adapter_contract
    return llm_adapter_contract


def backbone_tensors(model, shapes):
    base = model.get_base_model() if hasattr(model, 'get_base_model') else model
    result = {name: base.get_parameter(name) for name in shapes}
    require(base.lm_head.weight.data_ptr() == base.model.embed_tokens.weight.data_ptr(),
            'RUNTIME_TIED_EMBEDDINGS')
    return result


def architecture(config):
    return dict(schema='pon-decoder-rms-rope-gqa-swiglu-v1', layers=config['num_hidden_layers'],
                hidden=config['hidden_size'], intermediate=config['intermediate_size'],
                attention_heads=config['num_attention_heads'], kv_heads=config['num_key_value_heads'],
                vocabulary=config['vocab_size'], context=config['max_position_embeddings'],
                rope_theta=[100000, 1], rms_epsilon=[1, 100000], tied_embeddings=True, bias=False)


def load_model(materials, plan, imports):
    torch, device, AutoModel, AutoTokenizer, safe_open, _, _ = imports
    with safe_open(str(materials/'model.safetensors'), framework='pt', device='cpu') as handle:
        inventory = {name: dict(shape=list(handle.get_slice(name).get_shape()),
                               dtype=handle.get_slice(name).get_dtype()) for name in handle.keys()}
    config = read_json(materials/'config.json')
    shapes = contract_module().architecture_shapes(architecture(config))
    require(set(inventory) == set(shapes) and all(inventory[name]['shape'] == shape and
            inventory[name]['dtype'] == 'BF16' for name, shape in shapes.items()), 'RUNTIME_BF16_INVENTORY')
    tokenizer = AutoTokenizer.from_pretrained(str(materials), local_files_only=True,
                                             trust_remote_code=False, use_fast=True)
    tokenizer.padding_side = 'left'
    model = AutoModel.from_pretrained(str(materials), local_files_only=True, trust_remote_code=False,
                                     dtype=torch.float32, attn_implementation='eager')
    model.to(device); model.eval()
    require(sum(p.numel() for p in model.parameters()) == 134515008 and
            all(p.dtype == torch.float32 and p.device.type == device.type for p in model.parameters()),
            'RUNTIME_LOADED_PARAMETERS')
    require(tokenizer.bos_token_id == 1 and tokenizer.eos_token_id == tokenizer.pad_token_id == 2 and
            len(tokenizer) == 49152, 'RUNTIME_TOKENIZER_PROFILE')
    return model, tokenizer, shapes, inventory


def prompt_tokens(tokenizer, row, maximum):
    text = tokenizer.apply_chat_template([{'role': 'user', 'content': row['prompt']}],
                                         tokenize=False, add_generation_prompt=True)
    tokens = tokenizer.encode(text, add_special_tokens=False)
    require(0 < len(tokens) <= maximum, 'RUNTIME_NO_TRUNCATION')
    return tokens


def make_contract(model, tokenizer, shapes, materials, manifest, plan):
    c = contract_module()
    index = {name: tensor_descriptor(tensor) for name, tensor in backbone_tensors(model, shapes).items()}
    files = {name: dict(sha256=manifest['files'][name]['sha256'], byte_length=manifest['files'][name]['size'])
             for name in ('tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json')}
    targets = [dict(module=f'model.layers.{layer}.self_attn.{projection}', in_features=576,
                    out_features=576 if projection == 'q_proj' else 192, rank=4, alpha=[8, 1])
               for layer in range(30) for projection in ('q_proj', 'v_proj')]
    targets.sort(key=lambda t: t['module'])
    owner = identity(dict(scope='operator-controlled-retained-source-material-no-independent-custody',
                          snapshot=identity(manifest)))
    contract = dict(schema='pon-target-decoder-adapter-contract-v1', network=c.NETWORK.hex(),
        parameters=c.PARAMETER_HASH.hex(), reference=MODEL+'@'+REVISION+':derived-cpu-float32',
        architecture=architecture(read_json(materials/'config.json')),
        backbone=dict(index=index, index_root=c.H('llm-tensor-index-v1', c.canonical(index)).hex(),
                      owner_reference=owner, license_reference=manifest['files']['README.md']['sha256']),
        tokenizer=dict(schema='pon-tokenizer-files-and-behavior-v1', files=files,
            files_root=c.H('llm-tokenizer-file-index-v1', c.canonical(files)).hex(), vocabulary=49152,
            bos_id=1, eos_id=2, pad_id=2, add_bos=False, add_eos=False,
            chat_template=hashlib.sha256(tokenizer.chat_template.encode()).hexdigest(),
            behavior_contract=identity(dict(source=plan['runtime_source'], special_token_decode='skip',
                                             cleanup=False, chat_template='apply-once-no-extra-bos'))),
        numeric=dict(storage_dtype='float32', accumulation_dtype='float32', quantization='none',
            adapter_expression='x-Wt-plus-alpha-over-rank-times-x-At-Bt-v1',
            operator_contract=identity(dict(source=plan['runtime_source'], backend=plan['backend'],
                                            matmul='highest-no-TF32-eager-attention')),
            runtime_status='required-not-executed'),
        targets=targets, ports=dict(schema='pon-causal-decoder-token-and-logit-ports-v1', batch_max=1,
            input_tokens_max=128, output_tokens_max=16, input_dtype='int64', mask_dtype='bool',
            logits_dtype='float32', truncation='reject', padding_position='left-with-explicit-mask',
            model_mode='eval', dropout=False, tied_lm_head=True,
            generation='greedy-lowest-token-id-tie-fixed-count-v1'),
        registration=dict(owner_record=owner, target_admission=identity(plan),
            runtime_qualification='required-not-executed', prospective_accepted=False,
            independent_accepted=False, public_reward_eligible=False), scope=c.SCOPE)
    family = verify_family(read_json(FAMILY_PATH))
    require(contract['backbone']['index_root'] == family['material_pins']['fp32_backbone_index_root'] and
            contract['tokenizer']['files_root'] == family['material_pins']['tokenizer_files_root'],
            'RUNTIME_FAMILY_DERIVED_MATERIAL')
    raw, cid = c.freeze_target_contract(contract)
    return contract, raw, cid


def adapter_tensors(model, targets):
    base = model.get_base_model()
    result = {}
    for target in targets:
        layer = base.get_submodule(target['module'])
        result[target['module']+'.A'] = layer.lora_A['default'].weight
        result[target['module']+'.B'] = layer.lora_B['default'].weight
    return result


def wrap_adapter(model, contract, cid):
    c = contract_module(); tensors = adapter_tensors(model, contract['targets'])
    modules = {target['module']: dict(A=tensor_descriptor(tensors[target['module']+'.A']),
               B=tensor_descriptor(tensors[target['module']+'.B']), rank=4, alpha=[8, 1], dropout=False)
               for target in contract['targets']}
    value = dict(schema='pon-wrapped-decoder-lora-material-v1', contract=cid, modules=modules,
                 material_scope='factor-bytes-and-insertion-interface-not-functional-equivalence')
    raw, aid = c.freeze_wrapped_adapter(value, contract, cid)
    c.verify_wrapped_adapter(raw, aid, contract, cid, {name: tensor_bytes(v) for name, v in tensors.items()})
    return raw, aid, tensors


def insert_lora(model, plan, role, torch):
    from peft import LoraConfig, get_peft_model
    recipe = plan['recipes'][role]
    torch.manual_seed(recipe['initialization_seed'])
    model = get_peft_model(model, LoraConfig(r=4, lora_alpha=8, lora_dropout=0.0,
        target_modules=['q_proj', 'v_proj'], bias='none', use_rslora=False, use_dora=False))
    require(sum(p.numel() for p in model.parameters() if p.requires_grad) == 230400,
            'RUNTIME_TRAINABLE_SET')
    require(all('lora_' in name for name, p in model.named_parameters() if p.requires_grad),
            'RUNTIME_BACKBONE_FROZEN')
    if recipe['kind'] == 'random-lora':
        with torch.no_grad():
            for name, parameter in model.named_parameters():
                if parameter.requires_grad:
                    parameter.normal_(mean=0, std=float(recipe['std']))
    return model


def train(model, tokenizer, plan, role, torch, device):
    recipe = plan['recipes'][role]
    if recipe['kind'] not in ('lora', 'full-tune'):
        return dict(steps=0, loss=[], tokens=0, supervised_tokens=0, supported_profile_flops=0,
                    flop_scope='profiler-supported-operators-only-not-total-work')
    rows = [row for row in plan['tasks'] if row['partition'] == 'training']
    optimizer = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad],
                                 lr=float(recipe['learning_rate']), weight_decay=0)
    losses, token_count, supervised_count = [], 0, 0
    model.train()
    with torch.profiler.profile(activities=[torch.profiler.ProfilerActivity.CPU],
                                record_shapes=True, with_flops=True) as profiler:
        for number in range(plan['training_steps']):
            row = rows[number % len(rows)]
            prompt = prompt_tokens(tokenizer, row, plan['input_tokens_max'])
            target = tokenizer.encode(row['expected_output'], add_special_tokens=False) + [tokenizer.eos_token_id]*3
            require(len(prompt)+len(target) <= plan['input_tokens_max'], 'RUNTIME_TRAINING_TOKEN_LIMIT')
            ids = torch.tensor([prompt+target], dtype=torch.int64, device=device)
            labels = torch.tensor([[-100]*len(prompt)+target], dtype=torch.int64, device=device)
            optimizer.zero_grad(set_to_none=True)
            result = model(input_ids=ids, attention_mask=torch.ones_like(ids, dtype=torch.bool),
                           labels=labels, use_cache=False)
            require(torch.isfinite(result.loss).item(), 'RUNTIME_TRAINING_NONFINITE')
            result.loss.backward(); optimizer.step()
            losses.append(format(result.loss.detach().item(), '.12g'))
            token_count += ids.numel(); supervised_count += len(target)
    synchronize(torch, plan['backend'])
    model.eval(); del optimizer; gc.collect()
    return dict(steps=plan['training_steps'], loss=losses, tokens=token_count,
                supervised_tokens=supervised_count,
                supported_profile_flops=sum(event.flops for event in profiler.key_averages()),
                flop_scope='profiler-supported-operators-only-not-total-work')


def decode(model, tokenizer, row, contract, cid, plan, torch, device, artifact=None, role='current-backbone'):
    c = contract_module()
    tokens = prompt_tokens(tokenizer, row, plan['input_tokens_max'])
    request = dict(schema='pon-causal-decoder-request-v1', contract=cid, input_ids=[tokens],
                   attention_mask=[[True]*len(tokens)], generation_tokens=plan['generation_tokens'])
    rid = c.validate_decoder_request(request, contract, cid)
    ids = torch.tensor([tokens], dtype=torch.int64, device=device)
    generated, logits_root = [], hashlib.sha256()
    model.eval()
    with torch.inference_mode():
        for _ in range(plan['generation_tokens']):
            mask = torch.ones_like(ids, dtype=torch.bool)
            positions = mask.to(torch.int64).cumsum(-1)-1
            result = model(input_ids=ids, attention_mask=mask, position_ids=positions, use_cache=False)
            require(result.logits.dtype == torch.float32 and result.logits.device.type == device.type and
                    torch.isfinite(result.logits).all().item(), 'RUNTIME_LOGITS_DEVICE_OR_NONFINITE')
            last = result.logits[:, -1, :]
            logits_root.update(tensor_bytes(last))
            # argmax selects the first (smallest-token-id) maximal element.
            token = last.argmax(dim=-1).reshape(1, 1)
            generated.append(int(token.item())); ids = torch.cat((ids, token), dim=-1)
    synchronize(torch, plan['backend'])
    decoded = tokenizer.decode(generated, skip_special_tokens=True, clean_up_tokenization_spaces=False)
    response = dict(schema='pon-causal-decoder-reported-response-v1', contract=cid, request=rid,
                    generated_token_ids=[generated], decoded_outputs=[decoded])
    roots = c.validate_decoder_response(response, request, contract, cid)
    require(roots[0] == hashlib.sha256(decoded.encode()).hexdigest(), 'RUNTIME_DECODE_BYTE_ROOT')
    return dict(task=row['id'], request=request, request_id=rid, response=response,
                artifact=artifact or contract['backbone']['index_root'], role=role,
                output_sha256=roots[0], logits_sha256=logits_root.hexdigest(),
                input_tokens=len(tokens), generated_tokens=len(generated), actual_device=str(device),
                numeric_dtype='float32', snapshot=plan['snapshot'])


def child(args):
    directory, materials = Path(args.output), Path(args.materials)
    plan = validate_plan(read_json(args.plan))
    require(plan['runtime_source'] == file_sha(__file__), 'RUNTIME_SOURCE_CHANGED')
    require(plan['model_family_configuration_sha256'] == file_sha(FAMILY_PATH), 'RUNTIME_FAMILY_CHANGED')
    observer = Observer(directory, plan['backend'])
    begin, cpu_begin = time.monotonic_ns(), time.process_time_ns()
    report = dict(schema='llm-runtime-actual-child-v1', phase=args.phase, role=args.role,
                  experiment=identity(plan), scope='local-actual-runtime-no-native-admission',
                  **{name: False for name in QUALIFICATIONS})
    try:
        manifest, config = observer.stage('material-verification', lambda: verify_materials(materials))
        observer.stage('declared-family-check', lambda: verify_family(read_json(FAMILY_PATH)))
        require(identity(manifest) == plan['snapshot'], 'RUNTIME_SNAPSHOT_CHANGED')
        imports = observer.stage('runtime-import', lambda: runtime_import(plan))
        torch, device, _, _, _, save_file, load_file = imports
        model, tokenizer, shapes, inventory = observer.stage('model-load', lambda: load_model(materials, plan, imports))
        contract, raw, cid = observer.stage('derived-material-check', lambda: make_contract(model, tokenizer, shapes, materials, manifest, plan))
        report.update(actual_backend=plan['backend'], actual_device=str(device),
                      actual_threads=torch.get_num_threads(), cpu_load_average=[str(x) for x in os.getloadavg()],
                      parameter_count=134515008, derived_backbone_root=contract['backbone']['index_root'],
                      contract=cid, source_bf16_inventory=inventory,
                      environment={name: importlib.metadata.version(name) for name in
                          ('torch', 'transformers', 'peft', 'safetensors', 'tokenizers', 'numpy', 'accelerate')},
                      python=sys.version.split()[0], torch_cuda=torch.version.cuda, torch_hip=torch.version.hip,
                      source_weight_sha256=WEIGHT_SHA, runtime_source=file_sha(__file__),
                      fp32_conversion='exact BF16 values converted to FP32; new per-tensor hashes')
        if args.phase == 'loader':
            (directory/'target-contract.json').write_bytes(raw)
            # Loader pilots use training fixtures, never peek at evaluation scores.
            rows = [r for r in plan['tasks'] if r['partition'] == 'training'][:8]
            predictions = observer.stage('real-forward-greedy-decode', lambda: [decode(model, tokenizer, row, contract, cid, plan, torch, device) for row in rows])
            save(directory/'predictions.json', predictions)
            report.update(forward_executed=True, greedy_decode_executed=True, requests=len(predictions),
                          predictions_sha256=file_sha(directory/'predictions.json'))
        elif args.phase == 'train':
            kind = plan['recipes'][args.role]['kind']
            if kind in ('lora', 'random-lora'):
                model = observer.stage('adapter-insertion', lambda: insert_lora(model, plan, args.role, torch))
            before = contract['backbone']['index_root']
            training = observer.stage('training', lambda: train(model, tokenizer, plan, args.role, torch, device))
            updated = {name: tensor_descriptor(t) for name, t in backbone_tensors(model, shapes).items()}
            after = contract_module().H('llm-tensor-index-v1', contract_module().canonical(updated)).hex()
            require((after != before) if kind == 'full-tune' else (after == before), 'RUNTIME_BACKBONE_MUTATION')
            if kind in ('lora', 'random-lora'):
                adapter_raw, artifact, tensors = observer.stage('adapter-material-check', lambda: wrap_adapter(model, contract, cid))
                require(any(torch.count_nonzero(v).item() for key, v in tensors.items() if key.endswith('.B')), 'RUNTIME_ZERO_UPDATE')
                (directory/'wrapped-adapter.json').write_bytes(adapter_raw)
                observer.stage('artifact-save', lambda: save_file({n: t.detach().cpu().contiguous() for n, t in tensors.items()}, str(directory/'artifact.safetensors')))
            elif kind == 'full-tune':
                artifact = after
                observer.stage('artifact-save', lambda: save_file({n: t.detach().cpu().contiguous() for n, t in backbone_tensors(model, shapes).items()}, str(directory/'artifact.safetensors')))
            else:
                artifact = before
            save(directory/'artifact.json', dict(role=args.role, artifact=artifact, contract=cid, kind=kind,
                    source_model=WEIGHT_SHA, experiment=identity(plan), parent_backbone=before,
                    resulting_backbone=after, file_sha256=file_sha(directory/'artifact.safetensors') if (directory/'artifact.safetensors').exists() else None,
                    native_artifact_H=observer.stage('artifact-domain-hash',lambda:native_artifact_digest(directory/'artifact.safetensors')) if (directory/'artifact.safetensors').exists() else None,
                    native_domain='artifact', native_admission_accepted=False))
            report.update(artifact=artifact, training=training, parent_backbone=before, resulting_backbone=after,
                          lora_trainable_parameters=230400 if kind in ('lora','random-lora') else None)
        else:
            artifact_dir = Path(args.artifact)
            admitted = read_json(artifact_dir/'artifact.json')
            require(admitted['experiment'] == identity(plan) and admitted['contract'] == cid and admitted['role'] == args.role,
                    'RUNTIME_ARTIFACT_CONTEXT')
            kind = admitted['kind']
            if kind in ('lora', 'random-lora'):
                model = insert_lora(model, plan, args.role, torch)
                require(file_sha(artifact_dir/'artifact.safetensors') == admitted['file_sha256'], 'RUNTIME_ARTIFACT_FILE')
                tensors = load_file(str(artifact_dir/'artifact.safetensors'))
                target = adapter_tensors(model, contract['targets'])
                require(set(target) == set(tensors), 'RUNTIME_ADAPTER_SET')
                with torch.no_grad():
                    for name, parameter in target.items(): parameter.copy_(tensors[name].to(device))
                _, aid, _ = wrap_adapter(model, contract, cid)
                require(aid == admitted['artifact'], 'RUNTIME_ADAPTER_RELOAD')
            elif kind == 'full-tune':
                require(file_sha(artifact_dir/'artifact.safetensors') == admitted['file_sha256'], 'RUNTIME_ARTIFACT_FILE')
                tensors = load_file(str(artifact_dir/'artifact.safetensors'))
                target = backbone_tensors(model, shapes)
                require(set(target) == set(tensors), 'RUNTIME_FULL_TUNE_SET')
                with torch.no_grad():
                    for name, parameter in target.items(): parameter.copy_(tensors[name].to(device))
                index = {n: tensor_descriptor(t) for n, t in target.items()}
                require(contract_module().H('llm-tensor-index-v1', contract_module().canonical(index)).hex() == admitted['artifact'], 'RUNTIME_FULL_TUNE_RELOAD')
            report['artifact'] = admitted['artifact']
            predictions = observer.stage('real-forward-greedy-decode', lambda: [decode(model, tokenizer, row, contract, cid, plan, torch, device, admitted['artifact'], args.role) for row in plan['tasks'] if row['partition'] != 'training'])
            save(directory/'predictions.json', predictions)
            report.update(forward_executed=True, greedy_decode_executed=True, requests=len(predictions),
                          predictions_sha256=file_sha(directory/'predictions.json'))
        report['outcome'] = 'success'
    except BaseException as error:
        report.update(outcome='failed', error_type=type(error).__name__, error=str(error)[:512])
        raise
    finally:
        report.update(cost_events=observer.events, process_wall_ns=time.monotonic_ns()-begin,
                      process_cpu_ns=time.process_time_ns()-cpu_begin,
                      process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                      memory_scope='Linux process lifetime high-water RSS; not stage peak sum')
        save(directory/'actual-receipt.json', report)


def supervise(command, directory, budget):
    """Kill only this fresh child when its measured wall/RSS budget is exceeded."""
    directory = Path(directory); directory.mkdir(mode=0o700)
    start, high, reason = time.monotonic_ns(), 0, None
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    observer_cpu_start = time.process_time_ns()
    with (directory/'process.log').open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        while process.poll() is None:
            rss = current_rss(process.pid)
            high = max(high, rss or 0)
            if (time.monotonic_ns()-start) / 10**9 > budget['wall_seconds']:
                reason = 'wall-budget-exceeded'
            elif rss is None:
                # Linux target cannot claim an enforced RSS budget without samples.
                if not Path('/proc').is_dir(): reason = 'rss-observation-unavailable'
            elif rss > budget['rss_bytes']:
                reason = 'rss-budget-exceeded'
            if reason:
                process.send_signal(signal.SIGTERM)
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                break
            time.sleep(0.05)
        code = process.wait()
    end_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = dict(exit_code=code, stop_reason=reason, observed_wall_ns=time.monotonic_ns()-start,
                  sampled_peak_rss_bytes=high, budget=budget, sample_interval_ms=50,
                  child_cpu_ns=round(((end_usage.ru_utime-child_usage.ru_utime)+
                                      (end_usage.ru_stime-child_usage.ru_stime))*10**9),
                  observer_cpu_ns=time.process_time_ns()-observer_cpu_start,
                  cpu_scope='POSIX waited-child user-plus-system CPU; sequential children only',
                  outcome='success' if code == 0 and reason is None else 'failed')
    save(directory/'supervisor.json', result)
    return result


def verify_predictions(rows, plan, role, artifact, contract):
    expected = {row['id']: row for row in plan['tasks'] if row['partition'] != 'training'}
    require(type(rows) is list and len(rows) == len(expected) and
            {row['task'] for row in rows} == set(expected), 'RUNTIME_PREDICTION_SET')
    for row in rows:
        require(row['snapshot'] == plan['snapshot'] and row['numeric_dtype'] == 'float32' and
                row['request']['contract'] == row['response']['contract'] == contract and
                row['role'] == role and row['artifact'] == artifact,
                'RUNTIME_PREDICTION_CONTEXT')
        expected_device = {'cpu':'cpu', 'rocm':'cuda', 'cuda':'cuda', 'mps':'mps'}[plan['backend']]
        require(row['actual_device'].split(':')[0] == expected_device, 'RUNTIME_SILENT_DEVICE_FALLBACK')
        c = contract_module()
        require(row['request_id'] == row['response']['request'] ==
                c.H('causal-decoder-request-v1', c.canonical(row['request'])).hex(), 'RUNTIME_RESPONSE_REQUEST')
        decoded = row['response']['decoded_outputs']
        generated = row['response']['generated_token_ids']
        require(type(decoded) is list and len(decoded) == 1 and
                type(generated) is list and len(generated) == 1 and
                len(generated[0]) == plan['generation_tokens'] == row['generated_tokens'],
                'RUNTIME_FIXED_COUNT')
        require(hashlib.sha256(decoded[0].encode()).hexdigest() == row['output_sha256'],
                'RUNTIME_OUTPUT_HASH')
    return {row['task']: row['output_sha256'] for row in rows}


def run(args):
    directory = Path(args.output)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifest, _ = verify_materials(args.materials)
    verify_family(read_json(FAMILY_PATH))
    plan = validate_plan(experiment_plan(manifest, backend=args.backend, threads=args.threads, steps=args.steps))
    save(directory/'experiment-plan.json', plan)
    save(directory/'experiment-freeze.json', dict(plan=identity(plan), frozen_before_candidate_training=True,
        scope='same-operator-local-freeze-no-independent-release', utc_ns=time.time_ns()))
    records = []
    base = [sys.executable, str(Path(__file__).resolve()), '_child', '--materials', args.materials]
    def phase(name, phase_name, role='current-backbone', artifact=None, phase_plan=None):
        path = directory/name; path_plan = directory/'experiment-plan.json'
        if phase_plan is not None:
            path_plan = directory/(name+'-plan.json'); save(path_plan, phase_plan)
        command = base+['--plan', str(path_plan), '--output', str(path), '--phase', phase_name, '--role', role]
        if artifact is not None: command += ['--artifact', str(artifact)]
        result = supervise(command, path, plan['training_budget' if phase_name=='train' else 'inference_budget'])
        records.append(dict(name=name, **result)); save(directory/'phase-outcomes.json', records)
        print(json.dumps(dict(phase=name, **result)), flush=True)
        require(result['outcome'] == 'success', 'RUNTIME_REQUIRED_PHASE_ABORT:'+name)
        return read_json(path/'actual-receipt.json')
    try:
        one = dict(plan); one['threads'] = 1
        phase('loader-1thread', 'loader', phase_plan=one)
        reference = phase('loader-reference', 'loader')
        contract = read_json(directory/'loader-reference/target-contract.json')
        c = contract_module(); _, cid = c.freeze_target_contract(contract)
        artifacts, training_receipts = {}, {}
        for role in PARTICIPANTS:
            trained = phase('train-'+role, 'train', role)
            require(trained['contract'] == cid, 'RUNTIME_TRAINED_CONTRACT')
            artifacts[role] = trained['artifact']
            training_receipts[role] = trained['training']
        require(len(set(artifacts.values())) == 5, 'RUNTIME_ARTIFACT_ALIAS')
        trained_roles = ['candidate', 'fresh-budget-matched-lora', 'budget-matched-full-tune']
        require(all(training_receipts[role]['steps'] == plan['training_steps'] for role in trained_roles) and
                len({(training_receipts[role]['tokens'], training_receipts[role]['supervised_tokens'])
                     for role in trained_roles}) == 1 and
                all(training_receipts[role]['steps'] == 0 for role in
                    ('current-backbone', 'randomized-rank-matched-lora')), 'RUNTIME_MATCHED_TRAINING_BUDGET')
        roster = dict(experiment=identity(plan), contract=cid, artifacts=artifacts,
                      frozen_before_evaluation=True, scope='five-actual-local-artifacts-no-independent-authority')
        save(directory/'evaluation-roster.json', roster)
        predictions = {}
        for role in PARTICIPANTS:
            phase('evaluate-'+role, 'evaluate', role, directory/('train-'+role))
            values = read_json(directory/('evaluate-'+role)/'predictions.json')
            predictions[role] = verify_predictions(values, plan, role, artifacts[role], cid)
        from fractions import Fraction
        scores = {}
        for role in PARTICIPANTS:
            scores[role] = {}
            for partition in ('calibration', 'evaluation'):
                groups = {}
                for row in plan['tasks']:
                    if row['partition'] == partition:
                        groups.setdefault(row['source_group'], []).append(int(predictions[role][row['id']] == row['target_output_sha256']))
                score = sum((Fraction(sum(v),len(v)) for v in groups.values()), Fraction())/len(groups)
                scores[role][partition] = [score.numerator, score.denominator]
        selected = max(CONTROLS, key=lambda role: (Fraction(*scores[role]['calibration']), -CONTROLS.index(role)))
        strongest = max(Fraction(*scores[role]['evaluation']) for role in CONTROLS)
        gain = Fraction(*scores['candidate']['evaluation'])-strongest
        save(directory/'assessment.json', dict(schema='llm-runtime-actual-pilot-assessment-v1',
             experiment=identity(plan), roster=identity(roster), source=plan['runtime_source'],
             scope='actual-local-short-LLM-pilot-no-future-independent-quality-or-native-admission',
             scores=scores, calibration_selected_control=selected,
             gain_vs_strongest_evaluation_control=[gain.numerator,gain.denominator],
             positive_vs_all_controls=gain>0, all_required_controls_executed=True,
             training_budget_matched_by_steps_and_token_schedule=True,
             consumption_not_assumed_equal=True, output_byte_metric='equal-source-group-exact-output-bytes',
             phases=records, **{name:False for name in QUALIFICATIONS}))
    except BaseException as error:
        save(directory/'abort.json', dict(outcome='aborted', error_type=type(error).__name__,
             error=str(error)[:512], phases=records, adoption=False, reward=False,
             **{name:False for name in QUALIFICATIONS}))
        raise


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    runner = commands.add_parser('run')
    runner.add_argument('--materials', required=True); runner.add_argument('--output', required=True)
    runner.add_argument('--backend', choices=['cpu','cuda','rocm','mps'], default='cpu')
    runner.add_argument('--threads', type=int, default=4); runner.add_argument('--steps', type=int, default=10)
    worker = commands.add_parser('_child')
    for name in ('materials','output','plan','phase','role'): worker.add_argument('--'+name, required=True)
    worker.add_argument('--artifact')
    args = parser.parse_args()
    if args.command == 'run': run(args)
    else: child(args)


if __name__ == '__main__':
    main()

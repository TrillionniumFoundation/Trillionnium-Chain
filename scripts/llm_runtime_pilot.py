#!/usr/bin/env python3
"""Execute a bounded public SmolLM2 pilot; never grants native/reward authority.

Each participant runs in a separately monitored process. Training finishes before
the five actual artifacts are frozen and decoded. Receipt hashes bind observations;
they are not signatures, independent custody, proof of useful work or zkML.
Torch/Transformers/PEFT are isolated optional runtime dependencies, not node deps.
"""
from __future__ import annotations
import argparse
import contextlib
import contextvars
import errno
import gc
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import resource
import select
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
_RSS_READ_TRACE = contextvars.ContextVar('llm-owned-rss-read-trace', default=None)
_RSS_OWNER_CONTEXT = contextvars.ContextVar('llm-owned-rss-owner', default=None)
_RSS_EXIT_OBSERVATION = contextvars.ContextVar('llm-owned-rss-exit-observation', default=None)
_RSS_EXIT_CLASS = contextvars.ContextVar('llm-owned-rss-exit-class', default=None)
EXIT_PROFILES = ('strict-v1', 'linux-owned-exit-cleanup-v2', 'linux-owned-exit-terminal-subset-v3',
                 'linux-owned-exit-worker-pidfd-v4')


def exit_observation_profile(profile='linux-owned-exit-cleanup-v2'):
    from llm_runtime_exit_observation import PROFILE, MAX_DRAIN_NS
    require(profile in EXIT_PROFILES[1:], 'RUNTIME_EXIT_OBSERVER_BINDING')
    result = dict(profile=PROFILE, maximum_drain_ns=MAX_DRAIN_NS,
                observer_source_sha256=file_sha(REPOSITORY/'scripts/llm_runtime_exit_observation.py'),
                diagnostic_source_sha256=file_sha(REPOSITORY/'scripts/llm_runtime_rss_diagnostics.py'))
    if profile == EXIT_PROFILES[2]:
        from llm_runtime_exit_subset_observation import PROFILE as SUBSET_PROFILE
        result.update(profile=SUBSET_PROFILE,
            base_observer_source_sha256=result['observer_source_sha256'],
            observer_source_sha256=file_sha(REPOSITORY/'scripts/llm_runtime_exit_subset_observation.py'))
    elif profile == EXIT_PROFILES[3]:
        from llm_runtime_exit_worker_observation import PROFILE as WORKER_PROFILE
        result.update(profile=WORKER_PROFILE,
            base_observer_source_sha256=result['observer_source_sha256'],
            observer_source_sha256=file_sha(REPOSITORY/'scripts/llm_runtime_exit_worker_observation.py'))
    return result


def validate_exit_observation_profile(profile):
    require(type(profile) is dict and profile.get('profile') in EXIT_PROFILES[1:] and
            profile == exit_observation_profile(profile['profile']), 'RUNTIME_EXIT_OBSERVER_BINDING')
    return profile


def exit_observation_class(profile):
    validate_exit_observation_profile(profile)
    if profile['profile'] == EXIT_PROFILES[1]:
        from llm_runtime_exit_observation import ExitOnlyObservation
        return ExitOnlyObservation
    if profile['profile'] == EXIT_PROFILES[2]:
        from llm_runtime_exit_subset_observation import TerminalSubsetObservation
        return TerminalSubsetObservation
    from llm_runtime_exit_worker_observation import WorkerPidfdObservation
    return WorkerPidfdObservation


def plan_exit_profile(plan):
    profiles = dict(zip(('llm-runtime-public-pilot-plan-v1',
                         'llm-runtime-public-pilot-plan-v2',
                         'llm-runtime-public-pilot-plan-v3',
                         'llm-runtime-public-pilot-plan-v4'), EXIT_PROFILES))
    require(type(plan) is dict and plan.get('schema') in profiles, 'RUNTIME_EXIT_OBSERVER_PROFILE')
    expected = profiles[plan['schema']]
    if expected == 'strict-v1':
        require('exit_observation' not in plan, 'RUNTIME_EXIT_OBSERVER_PROFILE')
    else:
        profile = validate_exit_observation_profile(plan.get('exit_observation'))
        require(profile['profile'] == expected, 'RUNTIME_EXIT_OBSERVER_PROFILE')
    return expected


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


def experiment_plan(materials, *, backend='cpu', threads=4, steps=10, exit_observation='strict-v1'):
    require(backend in ('cpu', 'cuda', 'rocm', 'mps'), 'RUNTIME_BACKEND')
    require(type(threads) is int and 1 <= threads <= 8 and type(steps) is int and 1 <= steps <= 100,
            'RUNTIME_LIMIT')
    require(exit_observation in EXIT_PROFILES, 'RUNTIME_EXIT_OBSERVER_PROFILE')
    plan = dict(schema='llm-runtime-public-pilot-plan-v1', model=MODEL, revision=REVISION,
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
    if exit_observation != 'strict-v1':
        plan.update(schema='llm-runtime-public-pilot-plan-v'+str(EXIT_PROFILES.index(exit_observation)+1),
                    exit_observation=exit_observation_profile(exit_observation))
    return plan


def validate_plan(plan):
    plan_exit_profile(plan)
    require(
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
    """Observe only self or a uniquely identified child in this procfs PID view."""
    trace = _RSS_READ_TRACE.get()

    def unavailable(reason, error=None):
        if trace is not None and 'reason' not in trace:
            trace.update(reason=reason, error_type=type(error).__name__ if error else None,
                         error_errno=getattr(error, 'errno', None))
        return None

    try:
        def read(path):
            try:
                with path.open() as source:
                    value = source.read(65537)
            except OSError as error:
                kind = ('parent-status' if str(path) == '/proc/self/status' else
                        'pidfd-fdinfo' if '/fdinfo/' in str(path) else 'child-status')
                unavailable(kind + '-read', error)
                raise
            if len(value) > 65536:
                unavailable('proc-read-bound')
                raise ValueError('proc observation bound')
            return value

        def status(path):
            fields = {}
            for row in read(path).splitlines():
                key, separator, value = row.partition(':')
                if separator and key in ('Pid', 'PPid', 'Tgid', 'NSpid', 'NStgid', 'State', 'Threads', 'VmRSS'):
                    if key in fields:
                        unavailable('duplicate-proc-identity')
                        raise ValueError('duplicate proc identity')
                    fields[key] = value.split()
            return fields

        def rss(fields):
            if 'VmRSS' not in fields:
                unavailable('vmrss-missing')
            value, unit = fields['VmRSS']
            value = int(value)
            if unit != 'kB' or value <= 0:
                unavailable('vmrss-invalid')
                raise ValueError('invalid proc RSS')
            return value * 1024

        parent = status(Path('/proc/self/status'))
        parent_pid, = map(int, parent['Pid'])
        parent_namespace = list(map(int, parent['NSpid']))
        if (not parent_namespace or parent_namespace[0] != parent_pid or
                parent_namespace[-1] != os.getpid()):
            return unavailable('parent-namespace-mismatch')
        if pid is None or pid == os.getpid():
            return rss(parent)
        if type(pid) is not int or pid <= 0:
            return unavailable('invalid-child-pid')
        # The procfs mount may show an outer PID namespace. A pidfd opened for
        # the known Popen child gives an owned, kernel-bound mapping; never scan
        # arbitrary /proc PIDs or signal the mapped procfs identifier.
        owner = _RSS_OWNER_CONTEXT.get()
        borrowed = owner is not None and owner[0] == pid
        try:
            descriptor = owner[1] if borrowed else os.pidfd_open(pid, 0)
        except (OSError, AttributeError) as error:
            unavailable('pidfd-open', error)
            raise
        try:
            identity_path = Path(f'/proc/self/fdinfo/{descriptor}')
            identity = status(identity_path)
            visible_pid, = map(int, identity['Pid'])
            namespace = list(map(int, identity['NSpid']))
            coordinate = len(parent_namespace) - 1
            if (visible_pid <= 0 or len(namespace) <= coordinate or
                    namespace[0] != visible_pid or namespace[coordinate] != pid):
                return unavailable('pidfd-namespace-mismatch')
            fields = status(Path(f'/proc/{visible_pid}/status'))
            missing_sample_ns = time.monotonic_ns() if 'VmRSS' not in fields else None
            child_pid, = map(int, fields['Pid'])
            child_parent, = map(int, fields['PPid'])
            if (child_pid != visible_pid or child_parent != parent_pid or
                    list(map(int, fields['NSpid'])) != namespace or
                    status(identity_path) != identity):
                return unavailable('child-or-pidfd-identity-mismatch')
            classification_trace = None
            if missing_sample_ns is not None and trace is not None:
                # Only fields from this original status read: no later procfs
                # snapshot may supply the precondition that was observed here.
                state_fields, thread_fields = fields.get('State', []), fields.get('Threads', [])
                state = state_fields[0] if state_fields and len(state_fields[0]) == 1 else None
                threads = (int(thread_fields[0]) if len(thread_fields) == 1 and
                           len(thread_fields[0]) <= 10 and thread_fields[0].isascii() and
                           thread_fields[0].isdecimal() and
                           str(int(thread_fields[0])) == thread_fields[0] else None)
                classification_trace = dict(source='original-child-status-read-before-return',
                    missing_sample_ns=missing_sample_ns, borrowed_owner_present=borrowed,
                    initial_state=state, initial_threads=threads, attempted=False,
                    precondition=('no-matching-owner-context' if not borrowed else
                                  'initial-leader-not-zombie' if state != 'Z' else
                                  'owned-zombie-leader'), result='not-attempted', diagnostic_only=True)
                trace['same_sample_exit_classification'] = classification_trace
            if missing_sample_ns is not None and borrowed and fields.get('State', [None])[0] == 'Z':
                # Classification is completed within this missing sample, using
                # the supervisor's original pidfd and held task-directory FDs.
                # A later post-gap diagnostic can never grant this authority.
                try:
                    if classification_trace is not None:
                        classification_trace['attempted'] = True
                    from llm_runtime_exit_observation import ExitOnlyObservation
                    observation_type = _RSS_EXIT_CLASS.get() or ExitOnlyObservation
                    observation = observation_type(pid, descriptor, owner[2], fields, missing_sample_ns)
                    _RSS_EXIT_OBSERVATION.set(observation)
                    if classification_trace is not None:
                        classification_trace['result'] = 'typed-observation-created'
                except (OSError, AttributeError, KeyError, ValueError, TypeError) as error:
                    if trace is not None:
                        trace['exit_classification_error'] = type(error).__name__
                    if classification_trace is not None:
                        classification_trace.update(result='unavailable', error_type=type(error).__name__,
                            error_errno=getattr(error, 'errno', None),
                            rejection_code=str(error) if type(error).__module__ == 'llm_runtime_exit_observation'
                            and type(error).__name__ == 'ExitObservationError' else None)
            return rss(fields)
        finally:
            try:
                if not borrowed:
                    os.close(descriptor)
            except OSError as error:
                unavailable('pidfd-close', error)
                raise
    except (OSError, AttributeError, KeyError, ValueError) as error:
        return unavailable('malformed-or-unavailable-proc', error)


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
    index = {name: tensor_descriptor(tensor) for name, tensor in backbone_tensors(model, shapes).items()}
    return contract_from_inventory(index, tokenizer.chat_template,
                                   read_json(materials/'config.json'), manifest, plan)


def contract_from_inventory(index, chat_template, config, manifest, plan):
    """The same contract constructor, also usable before optional model imports."""
    c = contract_module()
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
        architecture=architecture(config),
        backbone=dict(index=index, index_root=c.H('llm-tensor-index-v1', c.canonical(index)).hex(),
                      owner_reference=owner, license_reference=manifest['files']['README.md']['sha256']),
        tokenizer=dict(schema='pon-tokenizer-files-and-behavior-v1', files=files,
            files_root=c.H('llm-tokenizer-file-index-v1', c.canonical(files)).hex(), vocabulary=49152,
            bos_id=1, eos_id=2, pad_id=2, add_bos=False, add_eos=False,
            chat_template=hashlib.sha256(chat_template.encode()).hexdigest(),
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
    tokens = prompt_tokens(tokenizer, row, plan['input_tokens_max'])
    return decode_tokens(model, tokenizer, tokens, row['id'], contract, cid, plan, torch, device,
                         artifact=artifact, role=role)


def decode_tokens(model, tokenizer, tokens, task_id, contract, cid, plan, torch, device,
                  artifact=None, role='current-backbone'):
    """Internal single-sequence decoder: IDs are already fully templated/encoded.

    No prompt rendering, tokenizer proxy, truncation or loading authority is
    supplied here. The caller owns full-context compilation and actual load
    binding. Request/response domains and the original family caps are retained.
    """
    require(type(plan) is dict, 'RUNTIME_DECODE_LIMIT')
    # Retain the checked immutable execution scalars, not a caller-owned plan.
    plan = {name: plan.get(name) for name in
            ('input_tokens_max', 'generation_tokens', 'backend', 'snapshot')}
    require(type(plan['input_tokens_max']) is int and
            1 <= plan['input_tokens_max'] <= 128 and
            type(plan['generation_tokens']) is int and 1 <= plan['generation_tokens'] <= 16,
            'RUNTIME_DECODE_LIMIT')
    require(type(plan['snapshot']) is str and bool(plan['snapshot']), 'RUNTIME_DECODE_CONTEXT')
    require(type(tokens) is list and 1 <= len(tokens) <= plan['input_tokens_max'],
            'RUNTIME_NO_TRUNCATION')
    # Snapshot only a bounded list; caller mutation cannot rewrite the request.
    tokens = tokens[:plan['input_tokens_max'] + 1]
    require(1 <= len(tokens) <= plan['input_tokens_max'], 'RUNTIME_NO_TRUNCATION')
    backend = plan.get('backend')
    require(backend in ('cpu', 'cuda', 'rocm', 'mps') and
            getattr(device, 'type', None) == ('cuda' if backend == 'rocm' else backend),
            'RUNTIME_DECODER_DEVICE')
    c = contract_module()
    request = dict(schema='pon-causal-decoder-request-v1', contract=cid, input_ids=[tokens],
                   attention_mask=[[True]*len(tokens)], generation_tokens=plan['generation_tokens'])
    rid = c.validate_decoder_request(request, contract, cid)
    ids = torch.tensor([tokens], dtype=torch.int64, device=device)
    require(ids.dtype == torch.int64 and ids.device.type == device.type and
            tuple(ids.shape) == (1, len(tokens)), 'RUNTIME_INPUT_TENSOR')
    generated, logits_root = [], hashlib.sha256()
    model.eval()
    with torch.inference_mode():
        for _ in range(plan['generation_tokens']):
            mask = torch.ones_like(ids, dtype=torch.bool)
            positions = mask.to(torch.int64).cumsum(-1)-1
            result = model(input_ids=ids, attention_mask=mask, position_ids=positions, use_cache=False)
            require(result.logits.dtype == torch.float32 and result.logits.device.type == device.type,
                    'RUNTIME_LOGITS_DEVICE_OR_NONFINITE')
            require(tuple(result.logits.shape) == (1, ids.shape[1], contract['architecture']['vocabulary']),
                    'RUNTIME_LOGITS_SHAPE')
            require(torch.isfinite(result.logits).all().item(), 'RUNTIME_LOGITS_DEVICE_OR_NONFINITE')
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
    return dict(task=task_id, request=request, request_id=rid, response=response,
                artifact=artifact or contract['backbone']['index_root'], role=role,
                output_sha256=roots[0], logits_sha256=logits_root.hexdigest(),
                input_tokens=len(tokens), generated_tokens=len(generated), actual_device=str(device),
                numeric_dtype='float32', snapshot=plan['snapshot'])


def child(args):
    if args.phase == 'parent-step':
        from llm_runtime_parent_step import child as parent_step_child
        return parent_step_child(args)
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


class _Wait4Unsupported(RuntimeError):
    pass


class _OwnedChildCleanupRequired(RuntimeError):
    def __init__(self, child, receipt):
        super().__init__('owned child cleanup is unresolved; owned handle retained')
        self.child, self.receipt = child, receipt


_AGGREGATE_TERMINAL_CODES = (
    'aggregate-charge-retained',
    'aggregate-closed-or-sticky',
    'aggregate-counter-bound',
    'aggregate-counter-filename',
    'aggregate-counter-snapshot-changed',
    'aggregate-cpu-counter-missing',
    'aggregate-descendants-or-dying',
    'aggregate-dying-charge',
    'aggregate-exact-owned-wait4-required',
    'aggregate-limits-changed',
    'aggregate-not-empty',
    'aggregate-parent-participants-or-dying',
    'aggregate-path-or-fd-replaced',
    'aggregate-private-fact',
    'aggregate-source-or-owner-moved',
    'aggregate-unit-identity',
    'aggregate-unit-observation',
    'evidence-pipe-child-owner',
    'evidence-pipe-close-or-log-state',
    'evidence-pipe-eof-unknown',
    'evidence-pipe-exact-wait4-required',
    'evidence-pipe-fd-direction',
    'evidence-pipe-fd-flags',
    'evidence-pipe-fd-replaced',
    'evidence-pipe-guard',
    'evidence-pipe-owner',
    'evidence-pipe-parent-log',
    'evidence-pipe-reported-context',
    'evidence-pipe-slot-replaced',
    'kernel-file-bound',
    'kernel-file-type',
    'kernel-native-lifecycle-busy',
    'kernel-native-owner-thread',
    'kernel-owned-close-failed',
    'kernel-source-changed',
    'kernel-source-file',
)


class _Wait4Child(subprocess.Popen):
    """One direct Linux child, exclusively reaped by the calls below.

    Requires default SIGCHLD handling and no competing wait/reap thread. A
    detected lost receipt permits cleanup only; this is not a general guarantee
    against concurrent external reapers or PID reuse outside that contract.
    """

    def __init__(self, *args, **kwargs):
        self.kernel_operation = kwargs.pop('_controlled_operation', None)
        aggregate_operation = kwargs.pop('_aggregate_operation', None)
        host_controller = kwargs.pop('_host_controller_operation', None)
        if host_controller is not None:
            from llm_runtime_host_controller import _HostControllerOperation
            require(self.kernel_operation is None and aggregate_operation is None and
                type(host_controller) is _HostControllerOperation, 'HOST_CONTROLLER_SPAWN_INTERFACE')
            self.kernel_operation = host_controller
        self._counter_error_type = self._counter_diagnostic_type = None
        self.kernel_counter_diagnostic = None
        self.kernel_counter_diagnostic_projection_failed = False
        self._terminal_budget_error_type = None
        self._terminal_budget_codes = ()
        self.kernel_tiny_terminal_code = None
        self.kernel_terminal_code_projection_failed = False
        if aggregate_operation is not None:
            from llm_runtime_kernel_aggregate import (_AggregateOperation, AggregateCounterError,
                _CounterDiagnostic, _RAW, _CHARGE_COUNTER_FILES)
            from llm_runtime_kernel_owned import KernelBudgetError
            require(self.kernel_operation is None and type(aggregate_operation) is _AggregateOperation,
                    'AGGREGATE_SPAWN_INTERFACE')
            self.kernel_operation = aggregate_operation
            # Bind exact types/allowlists before clone, never import or allocate
            # a tuple while handling a terminal_record exception.
            self._counter_error_type, self._counter_diagnostic_type = AggregateCounterError, _CounterDiagnostic
            self._counter_filenames = tuple('aggregate/'+name for name in _RAW) + ('unit/cgroup.stat',)
            self._counter_reasons = ('aggregate-counter-format', 'aggregate-counter-overflow',
                'aggregate-counter-fields', 'aggregate-counter-scalar', 'aggregate-charge-retained')
            self._charge_counter_filenames = _CHARGE_COUNTER_FILES
            self._terminal_budget_error_type = KernelBudgetError
            self._terminal_budget_codes = _AGGREGATE_TERMINAL_CODES
            pipe = getattr(aggregate_operation, 'evidence_pipe', None)
            if pipe is not None:
                from llm_runtime_evidence_pipe import _EvidencePipeOwner
                require(type(pipe) is _EvidencePipeOwner and pipe.capability is aggregate_operation,
                        'TINY_EVIDENCE_OWNER')
                self._tiny_pipe, self._tiny_pipe_type = pipe, _EvidencePipeOwner
        kernel_deadline = kwargs.pop('_kernel_deadline', None)
        self.kernel_evidence = None
        self.reaped = False
        self.reap_resolved = False
        self.no_waitable_child_observed = False
        self.owned_exit_observed = False
        self.cleanup_method = 'wait4'
        self.waited_peak_rss_bytes = None
        self.waited_cpu_ns = None
        self.observation_error = None
        self.termination_fd = None
        probe = None
        try:
            if (sys.platform != 'linux' or not callable(getattr(os, 'wait4', None)) or
                    not callable(getattr(os, 'pidfd_open', None)) or
                    not callable(getattr(signal, 'pidfd_send_signal', None)) or
                    signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
                raise _Wait4Unsupported('Linux exclusive wait4/pidfd owner required')
            probe = os.pidfd_open(os.getpid(), 0)
            signal.pidfd_send_signal(probe, 0)
        except (AttributeError, OSError) as error:
            raise _Wait4Unsupported(f'pidfd capability unavailable:{type(error).__name__}') from error
        finally:
            if probe is not None:
                try:
                    os.close(probe)
                except OSError as error:
                    raise _Wait4Unsupported('pidfd capability cleanup unavailable') from error
        if self.kernel_operation is not None:
            if aggregate_operation is None and host_controller is None:
                from llm_runtime_kernel_owned import _ControlledOperation
                require(type(self.kernel_operation) is _ControlledOperation, 'KERNEL_SPAWN_INTERFACE')
            require(len(args) == 1 and
                    set(kwargs) == {'stdout', 'stderr'} and kwargs['stderr'] is subprocess.STDOUT and
                    type(kernel_deadline) is float, 'KERNEL_SPAWN_INTERFACE')
            self.returncode = None
            import ctypes
            self._kernel_handoff = (ctypes.c_int*4)(-1, -1, -1, -1)
            self._kernel_admitted = False
            self._kernel_cleanup_required = _OwnedChildCleanupRequired(self,
                dict(outcome='failed', stop_reason='kernel-handoff-unresolved', reservation='RETAINED'))
            try:
                self.kernel_operation.spawn(args[0], kwargs['stdout'], self)
                self._adopt_kernel_handoff()
                self.kernel_operation.allow_exec(self, kernel_deadline)
                self._kernel_admitted = True
                return
            except BaseException as failure:
                # Constant/prebuilt failure state: never format/allocate first
                # and thereby lose the native output after a MemoryError.
                self.observation_error = 'kernel-spawn-handoff-failed'
                try:
                    self._rollback_kernel_handoff()
                except BaseException:
                    raise self._kernel_cleanup_required
                if self._kernel_handoff[0] <= 0 or not isinstance(failure, Exception): raise
            return
        super().__init__(*args, **kwargs)
        try:
            self.termination_fd = os.pidfd_open(self.pid, 0)
        except (AttributeError, OSError) as error:
            self.fail(f'pidfd-open-after-spawn:{type(error).__name__}')

    def __del__(self):
        # Popen's destructor performs waitpid and can steal the rusage receipt.
        # supervise's finally block exclusively terminates/reaps this child.
        pass

    def _adopt_kernel_handoff(self):
        self.pid = self._kernel_handoff[0]
        descriptor = self._kernel_handoff[1]
        self.termination_fd = descriptor if descriptor >= 0 else None

    def _close_kernel_handoff(self, mask):
        error = self.kernel_operation.native.close_handoff(self._kernel_handoff, mask)
        if error: raise OSError(error, 'kernel-handoff-close')

    def _rollback_kernel_handoff(self):
        self._close_kernel_handoff(12)
        if self._kernel_handoff[0] > 0:
            self._adopt_kernel_handoff()
            self.signal_owned(signal.SIGKILL)
            self.finish()
            if not self.reap_resolved: raise self._kernel_cleanup_required

    def fail(self, message):
        if self.observation_error is None:
            self.observation_error = message

    def _retain_kernel_terminal_code(self, error):
        if self.kernel_tiny_terminal_code is not None or type(error) is not self._terminal_budget_error_type:
            return
        values = error.args
        if (type(values) is tuple and len(values) == 1 and type(values[0]) is str and
                len(values[0]) <= 128 and values[0] in self._terminal_budget_codes):
            self.kernel_tiny_terminal_code = values[0]  # Original fixed string only.

    def _retain_kernel_counter_diagnostic(self, error):
        if type(error) is not self._counter_error_type:
            return
        value = error.counter_diagnostic
        if (type(value) is self._counter_diagnostic_type and type(value.filename) is str and
                type(value.raw) is str and type(value.reason) is str and len(value.raw) <= 65536 and
                value.filename in self._counter_filenames and value.reason in self._counter_reasons and
                (value.reason != 'aggregate-charge-retained' or
                    value.filename in self._charge_counter_filenames)):
            self.kernel_counter_diagnostic = value  # Existing immutable strings only.

    def reap(self, options=os.WNOHANG):
        if self.reaped:
            return 'terminal'
        if self.no_waitable_child_observed:
            return 'unknown'
        try:
            pid, status, usage = os.wait4(self.pid, options)
        except (OSError, AttributeError, TypeError, ValueError) as error:
            if isinstance(error, OSError) and error.errno == errno.ECHILD:
                self.no_waitable_child_observed = True
            self.fail(f'wait4:{type(error).__name__}:{getattr(error, "errno", None)}')
            return 'unknown'
        if type(pid) is not int or (pid == 0 and options != os.WNOHANG):
            self.fail('wait4:invalid-pid')
            return 'unknown'
        if pid == 0:
            return 'live'
        if pid != self.pid:
            self.fail('wait4:wrong-pid')
            return 'unknown'
        # A traced child can produce a stopped status even without WUNTRACED.
        # Such a receipt does not prove termination or permit dropping its fd.
        if (type(status) is not int or not 0 <= status <= 65535 or
                not (os.WIFEXITED(status) or os.WIFSIGNALED(status))):
            self.fail('wait4:nonterminal-or-invalid-status')
            return 'unknown'
        self.reaped = True
        self.reap_resolved = True
        self.owned_exit_observed = True
        self.returncode = os.waitstatus_to_exitcode(status)
        try:
            peak = usage.ru_maxrss
            user, system = usage.ru_utime, usage.ru_stime
            if (type(peak) is not int or not 0 < peak <= sys.maxsize or
                    any(type(value) not in (int, float) or not math.isfinite(value) or
                        value < 0 for value in (user, system))):
                raise ValueError('invalid waited rusage')
            self.waited_peak_rss_bytes = peak * 1024
            self.waited_cpu_ns = round((user + system) * 10**9)
        except (AttributeError, TypeError, ValueError, OverflowError):
            self.fail('wait4:invalid-terminal-receipt')
        return 'terminal'

    def cleanup_reap(self):
        """A wait4 failure may use exact waitpid for cleanup, never RSS credit."""
        if self.reaped or self.no_waitable_child_observed:
            return
        self.cleanup_method = 'waitpid-after-wait4-fault'
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if type(pid) is not int:
                self.fail('cleanup-waitpid:invalid-pid')
                return
            if pid == 0:
                return
            if (pid != self.pid or type(status) is not int or not 0 <= status <= 65535 or
                    not (os.WIFEXITED(status) or os.WIFSIGNALED(status))):
                self.fail('cleanup-waitpid:invalid-receipt')
                return
            self.reaped = True
            self.reap_resolved = True
            self.owned_exit_observed = True
            self.returncode = os.waitstatus_to_exitcode(status)
        except (OSError, AttributeError, TypeError, ValueError) as error:
            if isinstance(error, OSError) and error.errno == errno.ECHILD:
                self.no_waitable_child_observed = True
            self.fail(f'cleanup-waitpid:{type(error).__name__}')

    def observe_owned_exit(self):
        if not self.owned_exit_observed and self.termination_fd is not None:
            try:
                readable, _, _ = select.select([self.termination_fd], [], [], 0)
                if readable:
                    # Exit may have occurred between the preceding WNOHANG poll
                    # and fd readiness. Reap this healthy child before closing
                    # its handle; fd readiness alone must not strand a zombie.
                    if self.reap() == 'unknown':
                        self.cleanup_reap()
                    if self.reaped:
                        return
                    self.owned_exit_observed = True
                    self.reap_resolved = self.no_waitable_child_observed
                    self.cleanup_method = 'pidfd-terminal-without-waited-status'
                    self.fail('pidfd-terminal:waited-receipt-unavailable')
            except (OSError, TypeError, ValueError) as error:
                self.fail(f'pidfd-terminal:{type(error).__name__}')

    def signal_owned(self, signum):
        if self.owned_exit_observed:
            return
        try:
            if self.termination_fd is not None:
                signal.pidfd_send_signal(self.termination_fd, signum)
            else:
                self.fail('signal:owned-pidfd-unavailable')
        except ProcessLookupError:
            self.reap()
        except (OSError, AttributeError, TypeError, ValueError) as error:
            self.fail(f'signal:{type(error).__name__}:{getattr(error, "errno", None)}')

    def _finish_tiny_pipe(self):
        try:
            require(type(self._tiny_pipe) is self._tiny_pipe_type and
                self._tiny_pipe.capability is self.kernel_operation, 'TINY_EVIDENCE_OWNER')
            if (self.reaped and self.cleanup_method == 'wait4' and self.observation_error is None and
                    self.kernel_evidence is None):
                self.kernel_evidence = self.kernel_operation.terminal_record(self.pid, self.termination_fd)
                require(type(self.kernel_evidence) is dict, 'TINY_EVIDENCE_TERMINAL')
        except BaseException as failure:
            self.fail('kernel-terminal-tiny-evidence-unavailable')
            try:
                if getattr(self, 'kernel_tiny_terminal_failure', None) is None:
                    self.kernel_tiny_terminal_failure = type(failure).__name__[:64]
                    self._retain_kernel_terminal_code(failure)
            except BaseException: self.kernel_terminal_code_projection_failed = True
            try:
                self._retain_kernel_counter_diagnostic(failure)
            except BaseException: self.kernel_counter_diagnostic_projection_failed = True
        finally:
            # Same original close boundary, also when typed transport raises KI/MI.
            if self.termination_fd is not None and self.reap_resolved:
                try:
                    if getattr(self, '_kernel_handoff', None) is not None:
                        self._close_kernel_handoff(2)
                    else:
                        os.close(self.termination_fd)
                except OSError as error:
                    self.fail(f'close-pidfd:{error.errno}')
                self.termination_fd = None

    def finish(self):
        try:
            if self.owned_exit_observed and not self.reap_resolved:
                if self.reap() == 'unknown':
                    self.cleanup_reap()
                self.reap_resolved = self.reaped or self.no_waitable_child_observed
            # Keep the original five-second TERM grace. A failed KILL/observer
            # receives one further bounded second, then retains the owned fd.
            for signum, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 1)):
                if self.owned_exit_observed:
                    break
                self.signal_owned(signum)
                deadline = time.monotonic() + seconds
                while not self.owned_exit_observed and time.monotonic() < deadline:
                    if self.reap() == 'unknown':
                        self.cleanup_reap()
                    self.observe_owned_exit()
                    if not self.owned_exit_observed:
                        time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        finally:
            if getattr(self, '_tiny_pipe', None) is not None:
                self._finish_tiny_pipe()
            if (getattr(self, 'kernel_operation', None) is not None and self.reaped and
                    self.cleanup_method == 'wait4' and self.observation_error is None and
                    self.kernel_evidence is None):
                try:
                    self.kernel_evidence = self.kernel_operation.terminal_record(self.pid, self.termination_fd)
                except Exception as failure:
                    self.fail(f'kernel-terminal:{type(failure).__name__}')
                    if getattr(self, '_counter_error_type', None) is not None:
                        try:
                            self._retain_kernel_counter_diagnostic(failure)
                        except BaseException:
                            # Optional evidence cannot replace the first cause
                            # or escape past the original pidfd-close below.
                            self.kernel_counter_diagnostic_projection_failed = True
            if self.termination_fd is not None and self.reap_resolved:
                try:
                    if getattr(self, '_kernel_handoff', None) is not None:
                        self._close_kernel_handoff(2)
                    else:
                        os.close(self.termination_fd)
                except OSError as error:
                    self.fail(f'close-pidfd:{error.errno}')
                self.termination_fd = None


def owned_rss_diagnostic(process):
    """Bounded non-authoritative diagnostics for this already-owned child only.

    Never scan procfs, read command lines/environments, or open a PID obtained
    without proving its position in the owned pidfd's namespace coordinates.
    These observations explain a failure; they never replace the wait4 receipt.
    """
    detail = dict(owned_pid=process.pid, pidfd_ready=None)
    if process.termination_fd is None:
        return dict(detail, error='owned-pidfd-unavailable')

    def fields(path):
        with Path(path).open() as source:
            raw = source.read(16385)
        if len(raw) > 16384:
            raise ValueError('status-size')
        return {key: value.strip() for line in raw.splitlines() if ':' in line
                for key, value in [line.split(':', 1)]}

    try:
        ready, _, _ = select.select([process.termination_fd], [], [], 0)
        detail['pidfd_ready'] = bool(ready)
        parent = fields('/proc/self/status')
        parent_namespace = list(map(int, parent['NSpid'].split()))
        detail['parent_nspid'] = parent_namespace
        identity = fields(f'/proc/self/fdinfo/{process.termination_fd}')
        visible_pid = int(identity['Pid'])
        namespace = list(map(int, identity['NSpid'].split()))
        detail.update(pidfd_visible_pid=visible_pid, pidfd_nspid=namespace)
        coordinate = len(parent_namespace) - 1
        if (not parent_namespace or parent_namespace[-1] != os.getpid() or visible_pid <= 0 or
                len(namespace) <= coordinate or namespace[0] != visible_pid or
                namespace[coordinate] != process.pid):
            return dict(detail, error='pidfd-coordinate-unavailable')
        child = fields(f'/proc/{visible_pid}/status')
        if (int(child['Pid']) != visible_pid or int(child['PPid']) != parent_namespace[0] or
                list(map(int, child['NSpid'].split())) != namespace):
            return dict(detail, error='owned-child-coordinate-changed')
        detail['child'] = {name: child.get(name) for name in
                           ('State', 'Pid', 'PPid', 'NSpid', 'VmRSS', 'VmSize', 'Threads')}
        # Diagnostic only: an exiting leader can lose its mm while another
        # thread in this *same owned thread group* still holds it. Inspect at
        # most 64 member statuses, never scan unrelated process directories.
        if child.get('State', '').startswith('Z') and not child.get('VmRSS'):
            members = []
            for task in Path(f'/proc/{visible_pid}/task').iterdir():
                if not task.name.isdecimal() or len(members) >= 64:
                    raise ValueError('owned-thread-set-limit')
                status = fields(task/'status')
                if (int(status['Tgid']) != visible_pid or int(status['Pid']) != int(task.name) or
                        int(status['PPid']) != parent_namespace[0] or
                        list(map(int, status['NStgid'].split())) != namespace):
                    raise ValueError('owned-thread-coordinate-changed')
                members.append({name: status.get(name) for name in
                    ('State', 'Pid', 'Tgid', 'PPid', 'NSpid', 'NStgid', 'VmRSS', 'VmSize')})
            detail['owned_threads'] = sorted(members, key=lambda row: int(row['Pid']))
        after = fields(f'/proc/self/fdinfo/{process.termination_fd}')
        detail['pidfd_identity_changed_during_read'] = identity != after
    except (OSError, KeyError, TypeError, ValueError) as error:
        detail['error'] = f'{type(error).__name__}:{getattr(error, "errno", None)}'
    detail['exit_cleanup_proof'] = owned_exit_cleanup_proof(process, detail)
    return detail


def owned_exit_cleanup_proof(process, diagnostic=None):
    """Prove every member of the owned group has irreversibly left userspace.

    Linux do_exit sets PF_EXITING before exit_mm clears current->mm and calls
    mmput. That final kernel cleanup can outlive the leader and its VmRSS. See
    linux v6.6.37 kernel/exit.c and fs/proc/array.c: PF_EXITING tasks permanently
    stop executing, and proc status emits task_mem only when get_task_mm succeeds.
    This is an exit-state proof, NOT an RSS sample or a terminal/reap receipt.

    Require a stable, complete, bounded owned thread set, pinned directory fds,
    exact namespace coordinates, PF_EXITING on every non-kernel member, and no
    surviving userspace mm. Any changing/incomplete observation fails closed.
    """
    def read(name, directory=None):
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                             dir_fd=directory)
        with os.fdopen(descriptor, encoding='utf-8', errors='strict') as source:
            raw = source.read(16385)
        if len(raw) > 16384 or not raw.endswith('\n'):
            raise ValueError('proc-text-incomplete-or-overbound')
        return raw

    def fields(name, directory=None):
        result = {}
        for line in read(name, directory).splitlines():
            key, separator, value = line.partition(':')
            if not separator or key in result:
                raise ValueError('proc-field-format')
            result[key] = value.split()
        return result

    def number(value):
        if len(value) != 1 or not value[0].isdecimal():
            raise ValueError('proc-number-format')
        return int(value[0])

    def member(status, tid, visible, namespace, parent_pid, count):
        if (number(status['Pid']) != tid or number(status['Tgid']) != visible or
                number(status['PPid']) != parent_pid or number(status['Threads']) != count or
                list(map(int, status['NStgid'])) != namespace or
                len(status['NSpid']) != len(namespace) or int(status['NSpid'][0]) != tid or
                number(status['Kthread']) != 0 or
                'nonvoluntary_ctxt_switches' not in status or
                any(key.startswith('Vm') or key in ('RssAnon', 'RssFile', 'RssShmem')
                    for key in status)):
            raise ValueError('thread-not-proven-without-userspace-mm')

    def stat(directory, tid, parent_pid, count):
        raw = read('stat', directory)
        prefix, separator, tail = raw.rpartition(') ')
        if not separator or not prefix.startswith(f'{tid} ('):
            raise ValueError('task-stat-identity')
        parts = tail.split()
        if len(parts) < 50 or len(parts[0]) != 1:
            raise ValueError('task-stat-incomplete')
        flags, start = int(parts[6]), int(parts[19])
        if (int(parts[1]) != parent_pid or not flags & 0x00000004 or
                flags & 0x00200000 or int(parts[17]) != count or start <= 0 or
                int(parts[20]) != 0 or int(parts[21]) != 0):
            raise ValueError('task-not-in-userspace-free-exit')
        return dict(tid=tid, state=parts[0], flags=flags, start_time_ticks=start)

    def names(directory):
        result = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.name.isdecimal() or len(result) >= 64:
                    raise ValueError('owned-thread-set-limit')
                result.append(int(entry.name))
        return sorted(result)

    try:
        if process.termination_fd is None or process.reaped or process.observation_error:
            raise ValueError('owned-exit-handle-unavailable')
        parent = fields('/proc/self/status')
        parent_pid = number(parent['Pid'])
        parent_namespace = list(map(int, parent['NSpid']))
        identity_path = f'/proc/self/fdinfo/{process.termination_fd}'
        identity = fields(identity_path)
        visible = number(identity['Pid'])
        namespace = list(map(int, identity['NSpid']))
        coordinate = len(parent_namespace)-1
        if (not parent_namespace or parent_namespace[0] != parent_pid or
                parent_namespace[-1] != os.getpid() or visible <= 0 or
                len(namespace) <= coordinate or namespace[0] != visible or
                namespace[coordinate] != process.pid):
            raise ValueError('owned-pidfd-coordinate')
        with contextlib.ExitStack() as stack:
            def directory(name, parent_fd=None):
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                                     os.O_NOFOLLOW, dir_fd=parent_fd)
                stack.callback(os.close, descriptor)
                return descriptor
            group = directory(f'/proc/{visible}')
            leader = fields('status', group)
            count = number(leader['Threads'])
            if not 1 <= count <= 64 or leader['State'][0] != 'Z':
                raise ValueError('leader-not-zombie-or-thread-count')
            member(leader, visible, visible, namespace, parent_pid, count)
            if list(map(int, leader['NSpid'])) != namespace:
                raise ValueError('owned-leader-namespace')
            tasks = directory('task', group)
            tids = names(tasks)
            if len(tids) != count or visible not in tids:
                raise ValueError('incomplete-owned-thread-set')
            descriptors = {tid: directory(str(tid), tasks) for tid in tids}
            rows = []
            for tid, descriptor in descriptors.items():
                status = fields('status', descriptor)
                member(status, tid, visible, namespace, parent_pid, count)
                rows.append(stat(descriptor, tid, parent_pid, count))
            # Holding each task directory also prevents pathname reuse from
            # substituting a different task in the confirming second pass.
            for row in rows:
                descriptor = descriptors[row['tid']]
                member(fields('status', descriptor), row['tid'], visible, namespace, parent_pid, count)
                after = stat(descriptor, row['tid'], parent_pid, count)
                if after['start_time_ticks'] != row['start_time_ticks']:
                    raise ValueError('owned-task-identity-changed')
            after = fields('status', group)
            member(after, visible, visible, namespace, parent_pid, count)
            if after['State'][0] != 'Z' or names(tasks) != tids or fields(identity_path) != identity:
                raise ValueError('owned-thread-set-or-pidfd-changed')
        return dict(schema='linux-owned-thread-group-exit-cleanup-v1',
                    owned_pid=process.pid, pidfd_visible_pid=visible, pidfd_nspid=namespace,
                    kernel_release=os.uname().release, threads=rows,
                    observed_at_monotonic_ns=time.monotonic_ns(), rss_sample_produced=False)
    except (OSError, AttributeError, KeyError, IndexError, TypeError, ValueError) as error:
        if diagnostic is not None:
            diagnostic['exit_cleanup_proof_error'] = f'{type(error).__name__}:{error}'
        return None


def reconcile_unobserved_exit(process, absolute_wall_deadline_ns, diagnostic=None):
    """Reconcile terminal observation, or proven irreversible kernel cleanup.

    Without a complete owned exit proof the existing one-sample (50 ms) limit
    remains. A proved group has no userspace execution or mm left to sample;
    wait for its kernel teardown only until the ORIGINAL absolute wall deadline.
    Neither path manufactures RSS or substitutes pidfd readiness for exact wait4.
    The caller still checks waited peak RSS, exit status, observer errors and wall.
    """
    started = time.monotonic_ns()
    state = process.reap()
    if diagnostic is not None:
        diagnostic.update(initial_reap=state, absolute_wall_deadline_ns=absolute_wall_deadline_ns)
    if state != 'live':
        if diagnostic is not None:
            diagnostic['elapsed_ns'] = time.monotonic_ns()-started
        return state == 'terminal'
    if process.termination_fd is None or started >= absolute_wall_deadline_ns:
        return False
    proof = owned_exit_cleanup_proof(process, diagnostic)
    deadline = absolute_wall_deadline_ns if proof is not None else min(
        absolute_wall_deadline_ns, started + 50_000_000)
    if diagnostic is not None:
        diagnostic.update(mode='kernel-exit-cleanup' if proof is not None else 'unproved-exit-race',
                          exit_cleanup_proof=proof, wait_deadline_ns=deadline)
    polls = 0
    ready = []
    state = 'not-polled-pidfd-not-ready'
    while time.monotonic_ns() < deadline:
        remaining = (deadline-time.monotonic_ns()) / 10**9
        if remaining <= 0:
            break
        try:
            ready, _, _ = select.select([process.termination_fd], [], [], min(0.05, remaining))
        except (OSError, TypeError, ValueError) as error:
            process.fail(f'exit-reconciliation:{type(error).__name__}')
            break
        polls += 1
        if ready:
            state = process.reap()
            break
        if proof is None:
            break
    if diagnostic is not None:
        diagnostic.update(pidfd_ready_after_wait=bool(ready), terminal_reap=state,
                          wait_polls=polls, elapsed_ns=time.monotonic_ns()-started)
    return bool(ready) and state == 'terminal'
def _exit_recheck_refusal(error):
    """Expose only fixed observer codes, never arbitrary exception messages."""
    from llm_runtime_exit_observation import ExitObservationError
    codes = {
        'exit-integer', 'exit-namespace', 'exit-nonregular-proc', 'exit-proc-bound',
        'exit-status-syntax', 'exit-duplicate-status', 'exit-stat-syntax', 'exit-stat-fields',
        'exit-stat-number', 'exit-task-count', 'exit-parent', 'exit-held-pidfd',
        'exit-owner-context', 'exit-leader-not-in-task-set', 'exit-leader', 'exit-task-set',
        'exit-task-fd-reused', 'exit-task-identity', 'exit-task-namespace',
        'exit-task-not-exit-only', 'exit-leader-state', 'exit-owner-changed', 'exit-task-starttime',
        'exit-subset-task-set', 'exit-subset-frontier-change',
        'exit-subset-remaining-not-zombie', 'exit-subset-sticky-failure',
        'exit-worker-pidfd-reused', 'exit-worker-pidfd-binding', 'exit-worker-pidfd-unavailable',
        'exit-worker-retirement-ineligible', 'exit-worker-terminal-event-unavailable',
        'exit-worker-task-set', 'exit-worker-frontier-change',
        'exit-worker-remaining-not-zombie', 'exit-worker-recapture-bound',
        'exit-worker-sticky-failure', 'exit-worker-deadline',
    }
    code = (error.args[0] if type(error) is ExitObservationError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in codes else None)
    number = getattr(error, 'errno', None) if isinstance(error, OSError) else None
    return dict(source='same-recheck-call-exception', refusal_code=code,
                error_errno=number if type(number) is int and number in errno.errorcode else None,
                diagnostic_only=True)


def _drain_exit_cleanup(process, observation, owner_token, start, budget, *, exit_observation=None):
    """Retain the reservation while waiting for exact wait4, never report RSS=0."""
    from llm_runtime_exit_observation import ExitOnlyObservation, MAX_DRAIN_NS
    record = dict(outcome='failed', snapshots=[], missing_sample_ns=observation.sample_started_ns)
    deadline = min(start + budget['wall_seconds'] * 10**9,
                   observation.sample_started_ns + MAX_DRAIN_NS)
    try:
        observation_type = (exit_observation_class(exit_observation)
                            if exit_observation is not None else ExitOnlyObservation)
        is_subset = observation_type is not ExitOnlyObservation
        require(type(observation) is observation_type and
                observation.belongs_to(process.pid, process.termination_fd, owner_token),
                'RUNTIME_EXIT_OBSERVER_OWNER')
        record['snapshots'].append(observation.record)
        while time.monotonic_ns() < deadline:
            state = process.reap()
            if state == 'terminal':
                observed_ns = time.monotonic_ns()
                require(process.observation_error is None and process.waited_peak_rss_bytes is not None and
                        process.waited_cpu_ns is not None and observed_ns <= deadline,
                        'RUNTIME_EXIT_WAIT4_RECEIPT')
                if is_subset:
                    # Only this exact terminal-wait4 branch may use V4's held
                    # capability check: kernel reap erases live fdinfo identity.
                    terminal_owner = (observation.terminal_belongs_to
                        if exit_observation['profile'] == EXIT_PROFILES[3]
                        else observation.belongs_to)
                    require(terminal_owner(process.pid, process.termination_fd, owner_token),
                            'RUNTIME_EXIT_OBSERVER_OWNER')
                    record['retirement_closed_by'] = 'exact-owned-child-terminal-wait4'
                    record['terminal_retired_tasks'] = list(observation.pending_retired)
                record.update(outcome='terminal-wait4', completed_ns=observed_ns)
                return None, record
            require(state == 'live' and process.observation_error is None, 'RUNTIME_EXIT_WAIT4_UNKNOWN')
            try:
                record['snapshots'].append(observation.recheck())
            except (OSError, AttributeError, KeyError, ValueError, TypeError) as error:
                record['recheck_refusal'] = _exit_recheck_refusal(error)
                if is_subset and observation.failure_context is not None:
                    record['same_call_subset_failure'] = observation.failure_context
                raise
            if time.monotonic_ns() >= deadline:
                break
            time.sleep(min(0.001, max(0, (deadline-time.monotonic_ns())/10**9)))
        record['error'] = 'exit-cleanup-deadline'
    except (OSError, AttributeError, KeyError, ValueError, TypeError) as error:
        record['error'] = type(error).__name__
    record['completed_ns'] = time.monotonic_ns()
    return 'rss-exit-cleanup-observation-unavailable', record


def supervise(command, directory, budget, *, exit_observation=None, _controlled_operation=None,
              _aggregate_operation=None, _evidence_pipe=None):
    """Kill only this fresh child when its measured wall/RSS budget is exceeded."""
    observation_type = exit_observation_class(exit_observation) if exit_observation is not None else None
    kernel_keyword = '_controlled_operation'
    if _aggregate_operation is not None:
        from llm_runtime_kernel_aggregate import _AggregateOperation
        require(_controlled_operation is None and type(_aggregate_operation) is _AggregateOperation,
                'AGGREGATE_BUDGET_INTERFACE')
        _controlled_operation = _aggregate_operation
        kernel_keyword = '_aggregate_operation'
    if _controlled_operation is not None:
        if _aggregate_operation is None:
            from llm_runtime_kernel_owned import _ControlledOperation
            require(type(_controlled_operation) is _ControlledOperation, 'KERNEL_BUDGET_INTERFACE')
        require(type(budget) is dict and set(budget) == {'rss_bytes', 'wall_seconds'} and
                type(budget['rss_bytes']) is int and budget['rss_bytes'] == _controlled_operation.memory and
                type(budget['wall_seconds']) is int and 0 < budget['wall_seconds'] <=
                (600 if _controlled_operation.memory == 8*1024**3 else 1800), 'KERNEL_BUDGET_INTERFACE')
    pipe_owner = pipe_writer = None
    if _evidence_pipe is not None:
        from llm_runtime_evidence_pipe import _EvidencePipeOwner
        from llm_runtime_evidence_frames import _EvidencePipeWriter
        require(exit_observation is None and type(budget) is dict and
            set(budget) == {'wall_seconds','rss_bytes'} and
            all(type(budget[key]) is int for key in budget), 'TINY_EVIDENCE_INTERFACE')
        if type(_evidence_pipe) is _EvidencePipeOwner:
            require(_aggregate_operation is _evidence_pipe.capability and
                budget == dict(wall_seconds=8, rss_bytes=8*1024**3), 'TINY_EVIDENCE_INTERFACE')
            pipe_owner = _evidence_pipe
        else:
            require(type(_evidence_pipe) is _EvidencePipeWriter and _evidence_pipe.role == 'supervisor' and
                _controlled_operation is None and budget == dict(wall_seconds=2,rss_bytes=64*1024**2),
                'TINY_EVIDENCE_INTERFACE')
            pipe_writer = _evidence_pipe
    directory = Path(directory)
    if pipe_writer is None: directory.mkdir(mode=0o700)
    start, high, reason = time.monotonic_ns(), 0, None
    wall_deadline_ns = start + round(budget['wall_seconds'] * 10**9)
    rss_gaps = []
    rss_gap_diagnostic = None
    exit_cleanup_observation = None
    owner_token = object()
    observer_cpu_start = time.process_time_ns()
    process = None
    with (pipe_writer if pipe_writer is not None else
          (directory/'process.log').open('wb' if pipe_owner is not None else 'w')) as log:
        try:
            try:
                if pipe_owner is not None:
                    pipe_owner.configure(wall_deadline_ns, log)
                    command = command+['--evidence-deadline-ns',str(wall_deadline_ns)]
                kernel = ({kernel_keyword: _controlled_operation,
                    '_kernel_deadline': (start/10**9)+budget['wall_seconds']}
                    if _controlled_operation is not None else {})
                if _controlled_operation is not None:
                    process = object.__new__(_Wait4Child)
                    process.__init__(command, stdout=pipe_owner if pipe_owner is not None else log,
                        stderr=subprocess.STDOUT, **kernel)
                    if pipe_owner is not None: pipe_owner.adopted(process)
                else:
                    process = _Wait4Child(command, stdout=log, stderr=subprocess.STDOUT)
            except _Wait4Unsupported as error:
                result = dict(exit_code=None, stop_reason='rss-owner-unsupported',
                              observed_wall_ns=time.monotonic_ns()-start,
                              sampled_peak_rss_bytes=0, budget=budget, sample_interval_ms=50,
                              waited_child_peak_rss_bytes=None, waited_child_reaped=False,
                              owned_child_reap_resolved=False,
                              owned_child_echild_observed=False,
                              owned_child_exit_observed=False, child_spawned=False,
                              cleanup_method='no-child-spawned',
                              waited_child_observation_error=str(error), child_cpu_ns=None,
                              rss_observation_gaps=[],
                              observer_cpu_ns=time.process_time_ns()-observer_cpu_start,
                              cpu_scope='No child spawned; no waited-child CPU observation',
                              memory_scope='No child spawned; no RSS observation', outcome='failed')
                if exit_observation is not None:
                    result['exit_observation_profile'] = exit_observation
                if pipe_writer is None: save(directory/'supervisor.json', result)
                else: pipe_writer.emit('inner-supervisor',dict(result=result,owned_child_pid=None,supervisor_pid=os.getpid()))
                return result
            while process.observation_error is None and process.reap() == 'live':
                if pipe_owner is not None:
                    try: pipe_owner.drain(process)
                    except BaseException as failure:
                        process.fail('evidence-pipe-transport-unavailable')
                        reason = 'evidence-pipe-transport-unavailable'
                        if not isinstance(failure,Exception) or isinstance(failure,MemoryError): raise
                        break
                sample_trace = {}
                trace_token = _RSS_READ_TRACE.set(sample_trace)
                owner_context = ((process.pid, process.termination_fd, owner_token)
                                 if exit_observation is not None else None)
                owner_context_token = _RSS_OWNER_CONTEXT.set(owner_context)
                exit_context_token = _RSS_EXIT_OBSERVATION.set(None)
                class_context_token = _RSS_EXIT_CLASS.set(observation_type)
                try:
                    rss = current_rss(process.pid)
                    exit_sample = _RSS_EXIT_OBSERVATION.get()
                finally:
                    _RSS_READ_TRACE.reset(trace_token)
                    _RSS_OWNER_CONTEXT.reset(owner_context_token)
                    _RSS_EXIT_OBSERVATION.reset(exit_context_token)
                    _RSS_EXIT_CLASS.reset(class_context_token)
                high = max(high, rss or 0)
                try:
                    if (time.monotonic_ns()-start) / 10**9 > budget['wall_seconds']:
                        reason = 'wall-budget-exceeded'
                    elif rss is None:
                        if exit_observation is not None:
                            from llm_runtime_exit_observation import ExitOnlyObservation
                            if type(exit_sample) is observation_type:
                                # Once explicitly classified, even an immediately ready
                                # terminal receipt must obey its original 100ms cap.
                                # Owner loss is sticky inside drain, not a reason to
                                # fall back to the ordinary exact-exit race branch.
                                reason, exit_cleanup_observation = _drain_exit_cleanup(
                                    process, exit_sample, owner_token, start, budget,
                                    exit_observation=exit_observation)
                            elif exit_sample is not None and (
                                    observation_type is not ExitOnlyObservation or
                                    isinstance(exit_sample, ExitOnlyObservation)):
                                # A mismatched typed/profile result must never use
                                # the ordinary exact-exit race as fallback authority.
                                reason = 'rss-exit-cleanup-observation-unavailable'
                            elif process.reap() != 'terminal':
                                reason = 'rss-observation-unavailable'
                        else:
                            # Only the owned identity's positive irreversible
                            # exit proof may wait within the original wall
                            # budget. Unknown RSS is never converted to zero.
                            gap = dict(at_wall_ns=time.monotonic_ns()-start,
                                       before=owned_rss_diagnostic(process), reconciliation={})
                            if not reconcile_unobserved_exit(process, wall_deadline_ns, gap['reconciliation']):
                                reason = ('wall-budget-exceeded' if time.monotonic_ns() >= wall_deadline_ns
                                          else 'rss-observation-unavailable')
                            gap['after'] = owned_rss_diagnostic(process)
                            rss_gaps.append(gap)
                        if reason:
                            from llm_runtime_rss_diagnostics import owned_child_rss_gap
                            rss_gap_diagnostic = owned_child_rss_gap(process.pid, process.termination_fd)
                            rss_gap_diagnostic['missing_sample_detail'] = sample_trace or {'reason': 'observer-returned-none-without-detail'}
                    elif rss > budget['rss_bytes']:
                        reason = 'rss-budget-exceeded'
                finally:
                    if exit_sample is not None:
                        try:
                            exit_sample.close()
                        except (OSError, AttributeError, TypeError, ValueError):
                            reason = reason or 'rss-exit-cleanup-close-unavailable'
                if reason or process.reaped:
                    break
                time.sleep(0.05)
        finally:
            if process is not None:
                if _controlled_operation is None:
                    process.finish()
                elif getattr(process, '_kernel_handoff', None) is not None:
                    try:
                        if process._kernel_admitted:
                            process.finish()
                        else:
                            process._rollback_kernel_handoff()
                    except BaseException:
                        if process.observation_error is None:
                            process.observation_error = 'kernel-owner-cleanup-interrupted'
                        raise process._kernel_cleanup_required
    if reason is None:
        if process.observation_error or not process.reaped or process.waited_peak_rss_bytes is None:
            reason = 'waited-child-observation-unavailable'
        elif (time.monotonic_ns()-start) / 10**9 > budget['wall_seconds']:
            reason = 'wall-budget-exceeded'
        elif process.waited_peak_rss_bytes > budget['rss_bytes']:
            reason = 'rss-budget-exceeded'
    if _controlled_operation is not None:
        # No outer FinalUse/reconciliation bridge exists in this spawn-only slice.
        reason = reason or 'kernel-outer-reconciliation-required'
    result = dict(exit_code=process.returncode, stop_reason=reason, observed_wall_ns=time.monotonic_ns()-start,
                  sampled_peak_rss_bytes=high, budget=budget, sample_interval_ms=50,
                  waited_child_peak_rss_bytes=process.waited_peak_rss_bytes,
                  waited_child_reaped=process.reaped,
                  owned_child_reap_resolved=process.reap_resolved,
                  owned_child_echild_observed=process.no_waitable_child_observed,
                  owned_child_exit_observed=process.owned_exit_observed,
                  child_spawned=True, cleanup_method=process.cleanup_method,
                  waited_child_observation_error=process.observation_error,
                  rss_observation_gaps=rss_gaps,
                  terminal_reconciliation_profile=('explicit-'+exit_observation['profile'] if exit_observation is not None
                                                   else 'linux-held-pidfd-irreversible-exit-v1'),
                  child_cpu_ns=process.waited_cpu_ns,
                  observer_cpu_ns=time.process_time_ns()-observer_cpu_start,
                  cpu_scope='Exact owned-child Linux wait4 user-plus-system CPU; includes inherited waited-descendant accounting',
                  memory_scope='sampled_peak_rss_bytes is direct-child 50ms RSS; waited_child_peak_rss_bytes is exact owned-child Linux wait4 ru_maxrss in KiB times 1024, a maximum single-process high-water with inherited waited-descendant accounting; neither is simultaneous process-tree RSS',
                  outcome='success' if process.returncode == 0 and reason is None else 'failed')
    if rss_gap_diagnostic is not None:
        result['rss_gap_diagnostic'] = rss_gap_diagnostic
    if _controlled_operation is not None:
        result['controlled_kernel_spawn'] = dict(evidence=process.kernel_evidence,
            scope='spawn-only-controlled-kernel-charge-not-RSS', reservation='RETAINED',
            outer_reconciliation='UNKNOWN', installation_accepted=False)
        diagnostic = process.kernel_counter_diagnostic
        if diagnostic is not None:
            result['controlled_kernel_spawn']['counter_diagnostic'] = dict(filename=diagnostic.filename,
                raw=diagnostic.raw, reason=diagnostic.reason, diagnostic_only=True,
                source='exact-original-terminal-record-exception')
        if process.kernel_counter_diagnostic_projection_failed:
            result['controlled_kernel_spawn']['counter_diagnostic_projection_failed'] = True
    if exit_cleanup_observation is not None:
        result['exit_cleanup_observation'] = exit_cleanup_observation
    if exit_observation is not None:
        result['exit_observation_profile'] = exit_observation
    if pipe_owner is not None:
        result['tiny_evidence_transport'] = dict(records=pipe_owner.frames.records,
            received_bytes=pipe_owner.frames.received, first_error=pipe_owner.frames.failure,
            error_fragment_hex=pipe_owner.frames.fragment.hex(), eof=pipe_owner.eof,
            terminal_failure_type=getattr(process,'kernel_tiny_terminal_failure',None),
            terminal_failure_code=getattr(process,'kernel_tiny_terminal_code',None),
            terminal_code_projection_failed=True if getattr(process,'kernel_terminal_code_projection_failed',False) else None,
            terminal_io_closed=True if pipe_owner.terminal_complete else None, authority=False)
    if pipe_writer is None: save(directory/'supervisor.json', result)
    else: pipe_writer.emit('inner-supervisor',dict(result=result,owned_child_pid=process.pid,supervisor_pid=os.getpid()))
    if not process.reap_resolved:
        # Preserve a failed receipt and the handle. The CLI cannot claim general
        # cleanup if its kernel will not resolve cleanup of its owned child.
        raise _OwnedChildCleanupRequired(process, result)
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
    plan = validate_plan(experiment_plan(manifest, backend=args.backend, threads=args.threads, steps=args.steps,
                                        exit_observation=args.exit_observation_profile))
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
        result = supervise(command, path, plan['training_budget' if phase_name=='train' else 'inference_budget'],
                           exit_observation=plan.get('exit_observation'))
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
    runner.add_argument('--exit-observation-profile', choices=EXIT_PROFILES,
                        default='strict-v1')
    worker = commands.add_parser('_child')
    for name in ('materials','output','plan','phase','role'): worker.add_argument('--'+name, required=True)
    worker.add_argument('--artifact')
    worker.add_argument('--parent-step-input')
    worker.add_argument('--expected-parent-step-input')
    from llm_runtime_parent_step import add_parser, run as run_parent_step
    add_parser(commands)
    args = parser.parse_args()
    if args.command == 'run': run(args)
    elif args.command == 'parent-step': run_parent_step(args)
    else: child(args)


if __name__ == '__main__':
    main()

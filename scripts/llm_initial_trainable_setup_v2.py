"""Explicit working-copy preparation, not training, selection or a capability.

The caller owns the model and its original resource/terminal obligations. Capture
the caller's seeded PEFT A once, before copying the canonical parent. This module
never seeds RNG, imports Torch, runs a forward/optimizer, writes files or changes
CURRENT. Returned unsigned facts cannot qualify a model or authorize an effect.
"""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import time

import llm_runtime_parent_step as parent_step
import llm_runtime_pilot as runtime

SCHEMA = 'llm-smollm-trainable-initial-setup-v2'
PARENT_SHA256 = '1c5af7b5a7144a619dfac83b14bd83ae77f1e2227b18a6a9c5dcb214889a0cba'
PROFILE = '561414aec8b51f2a18ae3948dd44a321f924b1e12961a8e0139774b42387fcf0'
RECIPE = {'kind': 'lora', 'initialization_seed': 7,
          'initializer': 'caller-peft-default-A-kaiming-B-positive-zero-v1'}
_SEAL = object()


def _require(ok, message):
    runtime.require(ok, 'INITIAL_SETUP_' + message)


def _sources():
    return {p.name: runtime.file_sha(p) for p in
            (Path(__file__), Path(runtime.__file__), Path(parent_step.__file__),
             Path(parent_step.parent.__file__), Path(runtime.contract_module().__file__))}


def _targets():
    return sorted((dict(module=f'model.layers.{layer}.self_attn.{projection}',
                        in_features=576, out_features=576 if projection == 'q_proj' else 192,
                        rank=4, alpha=[8, 1])
                   for layer in range(30) for projection in ('q_proj', 'v_proj')),
                  key=lambda value: value['module'])


def canonical_zero_parent():
    """Code-fixed V1 bytes; the independent full SHA is checked before use."""
    header = {'__metadata__': {'hepta_initial_positive_zero_profile': PROFILE}}
    offset = 0
    for target in _targets():
        for factor, shape in [('A', [4, target['in_features']]),
                              ('B', [target['out_features'], 4])]:
            size = shape[0] * shape[1] * 4
            header[target['module'] + '.' + factor] = dict(
                dtype='F32', shape=shape, data_offsets=[offset, offset + size])
            offset += size
    raw = json.dumps(header, sort_keys=True, separators=(',', ':')).encode()
    raw += b' ' * (-len(raw) % 8)
    value = len(raw).to_bytes(8, 'little') + raw + bytes(offset)
    _require(hashlib.sha256(value).hexdigest() == PARENT_SHA256, 'CANONICAL_BYTES')
    return value


def _operators(model, contract, torch):
    from peft.tuners.lora.layer import Linear
    _require(all(module._compiled_call_impl is None for module in model.modules()),
             'OPERATOR_PROFILE')
    for target in contract['targets']:
        layer = model.get_base_model().get_submodule(target['module'])
        _require(type(layer) is Linear, 'OPERATOR_PROFILE')
        _require(layer.r == {'default': 4} and layer.lora_alpha == {'default': 8} and
                 layer.scaling == {'default': 2.0} and layer.active_adapters == ['default'] and
                 not layer.disable_adapters and not layer.merged_adapters and
                 layer.use_rslora == {'default': False} and layer.use_dora == {'default': False} and
                 not layer.lora_variant and layer.lora_bias == {'default': False} and
                 not layer.fan_in_fan_out and not layer.is_target_conv_1d_layer and
                 not layer.lora_embedding_A and not layer.lora_embedding_B and
                 not layer.lora_magnitude_vector and layer.cast_input_dtype_enabled is True and
                 layer.ephemeral_gpu_offload is False, 'OPERATOR_PROFILE')
        _require(set(layer.lora_A) == set(layer.lora_B) == set(layer.lora_dropout) == {'default'} and
                 type(layer.lora_dropout['default']) is torch.nn.Identity, 'OPERATOR_PROFILE')
        for module, dimensions in [(layer.base_layer, (576, target['out_features'])),
                (layer.lora_A['default'], (576, 4)), (layer.lora_B['default'], (4, target['out_features']))]:
            _require(type(module) is torch.nn.Linear and module.bias is None and
                     (module.in_features, module.out_features) == dimensions, 'OPERATOR_PROFILE')
        for module in [layer, layer.base_layer, layer.lora_A['default'], layer.lora_B['default'],
                       layer.lora_dropout['default']]:
            _require('forward' not in vars(module) and not module._forward_hooks and
                     not module._forward_pre_hooks and not module._backward_hooks and
                     not module._backward_pre_hooks, 'OPERATOR_PROFILE')


def _no_aliases(model, parameters, torch):
    named = list(model.named_parameters(remove_duplicate=False))
    _require(all(sum(p is factor for _, p in named) == 1 for factor in parameters.values()),
             'ALIASED_PARAMETERS')
    spans = [(p.data_ptr(), p.data_ptr() + p.numel() * p.element_size()) for p in parameters.values()]
    overlaps = lambda a, b: max(a[0], b[0]) < min(a[1], b[1])
    _require(not any(overlaps(a, b) for i, a in enumerate(spans) for b in spans[i + 1:]),
             'ALIASED_PARAMETERS')
    ids = {id(p) for p in parameters.values()}
    for value in [p for _, p in named if id(p) not in ids] + list(model.buffers()):
        _require(value.device.type == 'cpu' and value.layout == torch.strided, 'OTHER_STORAGE_PROFILE')
        storage = value.untyped_storage()
        span = (storage.data_ptr(), storage.data_ptr() + storage.nbytes())
        _require(not any(overlaps(span, factor) for factor in spans), 'ALIASED_PARAMETERS')


def _parameters(model, contract, torch):
    _require(contract['targets'] == _targets(), 'TARGETS')
    try:
        parameters = runtime.adapter_tensors(model, contract['targets'])
    except (AttributeError, KeyError) as error:
        raise ValueError('INITIAL_SETUP_FACTOR_SET') from error
    expected = {t['module'] + '.' + f: ([4, 576] if f == 'A' else
                [t['out_features'], 4]) for t in _targets() for f in ('A', 'B')}
    _require(set(parameters) == set(expected), 'FACTOR_SET')
    storages = set()
    for name, value in parameters.items():
        _require(value.device.type == 'cpu' and value.dtype == torch.float32 and
                 list(value.shape) == expected[name] and value.is_contiguous() and
                 value.requires_grad and torch.isfinite(value).all().item(), 'FACTOR_PROFILE')
        address = value.untyped_storage().data_ptr()
        _require(address not in storages, 'ALIASED_PARAMETERS')
        storages.add(address)
    _require({id(p) for p in model.parameters() if p.requires_grad} ==
             {id(p) for p in parameters.values()}, 'TRAINABLE_SET')
    _no_aliases(model, parameters, torch)
    _operators(model, contract, torch)
    return parameters


def _identity(parameters):
    return tuple((name, id(p), p.untyped_storage().data_ptr())
                 for name, p in sorted(parameters.items()))


def _snapshot(parameters):
    return tuple((name, runtime.tensor_bytes(value))
                 for name, value in sorted(parameters.items()))


@dataclass(frozen=True)
class _CapturedA:
    seal: object
    model: object
    identity: tuple
    snapshot: tuple
    sources: tuple
    recipe: tuple
    cost: tuple
    state: str = 'captured'


def capture_seeded_a(model, contract, torch, recipe):
    """Snapshot only; seed provenance is a caller declaration, never authority."""
    wall, cpu = time.monotonic_ns(), time.process_time_ns()
    _require(recipe == RECIPE, 'RECIPE')
    parameters = _parameters(model, contract, torch)
    for name, raw in _snapshot(parameters):
        if name.endswith('.B'):
            _require(not any(raw), 'B_NOT_POSITIVE_ZERO')
        else:
            _require(parameters[name].count_nonzero().item() > 0 and
                     parameters[name].abs().max().item() <= 1, 'A_INITIALIZER')
    value = _CapturedA(_SEAL, model, _identity(parameters), _snapshot(parameters),
                       tuple(sorted(_sources().items())), tuple(sorted(recipe.items())), ())
    object.__setattr__(value, 'cost', (('wall_ns', time.monotonic_ns() - wall),
                                     ('cpu_ns', time.process_time_ns() - cpu)))
    return value


def prepare_working_copy(model, contract, contract_digest, parent, parent_bytes,
                         captured, torch, operation_id):
    """Consume one capture. Post-copy failure fences this working copy, no rollback.

    The owner must discard/reconcile a possibly mutated copy after such failure;
    there is no successful cleanup or retry receipt here. Immutable parent bytes
    and any installed parent remain untouched. No returned hash is a grant.
    """
    wall, cpu = time.monotonic_ns(), time.process_time_ns()
    _require(type(captured) is _CapturedA and captured.seal is _SEAL and
             captured.model is model and captured.state == 'captured', 'CAPTURE_OWNER_OR_REUSE')
    _require(type(operation_id) is str and 1 <= len(operation_id.encode()) <= 128, 'OPERATION')
    _require(type(parent) is dict and set(parent) == {'generation', 'contract', 'adapter', 'file_sha256'}
             and type(parent['generation']) is int and parent['generation'] == 1 and
             parent['file_sha256'] == PARENT_SHA256 and parent['contract'] == contract_digest,
             'PARENT_CONTEXT')
    _require(type(parent_bytes) is bytes and parent_bytes == canonical_zero_parent(), 'PARENT_BYTES')
    _require(dict(captured.recipe) == RECIPE and dict(captured.sources) == _sources(), 'CAPTURE_SOURCE')
    parameters = _parameters(model, contract, torch)
    _require(_identity(parameters) == captured.identity and
             _snapshot(parameters) == captured.snapshot, 'CAPTURE_DRIFT')
    factors = parent_step.parent.factor_bytes(parent_bytes, contract)
    # Verify the original wrapped identity before any mutation.
    parent_step.runtime.contract_module().verify_wrapped_adapter(
        runtime.canonical(_wrapped(contract, contract_digest, factors)), parent['adapter'],
        contract, contract_digest, factors)
    object.__setattr__(captured, 'state', 'consumed')
    try:
        original = parent_step.copy_factors(model, contract, factors, parent['adapter'], torch)
        with torch.no_grad():
            for name, raw in captured.snapshot:
                if name.endswith('.A'):
                    parameters[name].copy_(torch.frombuffer(bytearray(raw), dtype=torch.float32)
                                           .reshape(parameters[name].shape))
        after = dict(_snapshot(parameters))
        _require(all(after[n] == raw if n.endswith('.A') else not any(after[n])
                     for n, raw in captured.snapshot), 'SETUP_READBACK')
        wrapped, adapter, _ = runtime.wrap_adapter(model, contract, contract_digest)
        _require(dict(captured.sources) == _sources(), 'SOURCE_CHANGED')
    except BaseException:
        object.__setattr__(captured, 'state', 'failed-working-copy-may-be-mutated')
        raise
    report = dict(schema=SCHEMA, operation_id=operation_id, original_parent=dict(parent),
        original_parent_readback=original, setup_adapter=adapter, recipe=dict(RECIPE),
        source_pins=dict(captured.sources), old_factor_sha256={n: hashlib.sha256(v).hexdigest()
        for n, v in factors.items()}, setup_factor_sha256={n: hashlib.sha256(v).hexdigest()
        for n, v in after.items()}, B_positive_zero=True, function_equivalence='algebraic-B-zero-only',
        full_model_numeric_preservation='NOT_RUN', trainability='NOT_RUN',
        capture_cost=dict(captured.cost), setup_cost=dict(wall_ns=time.monotonic_ns() - wall,
        cpu_ns=time.process_time_ns() - cpu), flags=dict.fromkeys(
        ('trained', 'learned_change', 'gain', 'selected', 'installed', 'ordinary', 'reward'), False))
    return after, wrapped, report


def _wrapped(contract, cid, factors):
    modules = {}
    for target in contract['targets']:
        module = {}
        for factor, shape in [('A', [4, target['in_features']]),
                              ('B', [target['out_features'], 4])]:
            raw = factors[target['module'] + '.' + factor]
            module[factor] = dict(dtype='float32', shape=shape, byte_length=len(raw),
                                 sha256=hashlib.sha256(raw).hexdigest())
        modules[target['module']] = dict(**module, rank=4, alpha=[8, 1], dropout=False)
    return dict(schema='pon-wrapped-decoder-lora-material-v1', contract=cid, modules=modules,
                material_scope='factor-bytes-and-insertion-interface-not-functional-equivalence')

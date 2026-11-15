"""Reproduce the retained a9b860 base-loader counterexamples on a tiny model.

Run from the Chain worktree with the locked optional CPU Torch interpreter and
PYTHONPATH=scripts. This is a small real Llama computation, not a pretrained run.
The only original guards adapted are the fixed full-size config/parameter-count
checks; every original hash, path read, tensor inventory and tokenizer gate runs.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types

import torch
from safetensors import safe_open
from safetensors.torch import load_file, save_file
from transformers import AutoModelForCausalLM, AutoTokenizer
from test_llm_base_material_torch import tiny_material


SOURCE = 'a9b8602706b66adba82655c3c2ce90bde88620a2'
raw_source = subprocess.check_output(['git', 'show', SOURCE + ':scripts/llm_runtime_pilot.py'])
legacy = types.ModuleType('legacy_runtime_snapshot_counterexample')
legacy.__file__ = str(Path.cwd() / 'scripts/llm_runtime_pilot.py')
sys.modules[legacy.__name__] = legacy
exec(compile(raw_source, legacy.__file__, 'exec'), legacy.__dict__)
original_require = legacy.require


def tiny_profile_require(value, code):
    if code in ('RUNTIME_CONFIG_PROFILE', 'RUNTIME_LOADED_PARAMETERS'):
        return
    return original_require(value, code)


legacy.require = tiny_profile_require
torch.set_num_threads(1)
imports = (torch, torch.device('cpu'), AutoModelForCausalLM, AutoTokenizer,
           safe_open, save_file, load_file)

with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    pins, fixture_manifest, config = tiny_material(directory, vocabulary=49152)
    legacy.PUBLIC_FILES, legacy.WEIGHT_SHA = pins, pins['model.safetensors'][1]
    manifest, _ = legacy.verify_materials(directory)
    plan = legacy.experiment_plan(manifest, threads=1, steps=1)
    reference, original_tokenizer, shapes, _ = legacy.load_model(directory, plan, imports)

    def tensor_root(model):
        index = {name: legacy.tensor_descriptor(model.get_parameter(name)) for name in shapes}
        assert all(model.get_parameter(name).dtype == torch.float32 for name in shapes)
        assert all(list(model.get_parameter(name).shape) == shape for name, shape in shapes.items())
        assert model.lm_head.weight.data_ptr() == model.model.embed_tokens.weight.data_ptr()
        return legacy.contract_module().H('llm-tensor-index-v1', legacy.canonical(index)).hex()

    def forward(model, tokenizer):
        ids = torch.tensor([tokenizer.encode('alpha beta gamma alpha', add_special_tokens=False)],
                           dtype=torch.int64)
        with torch.inference_mode():
            return model(input_ids=ids, attention_mask=torch.ones_like(ids), use_cache=False).logits

    before, original_root = forward(reference, original_tokenizer), tensor_root(reference)
    files = {name: dict(sha256=manifest['files'][name]['sha256'],
                       byte_length=manifest['files'][name]['size'])
             for name in ('tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json')}
    declared_tokenizer_root = legacy.contract_module().H(
        'llm-tokenizer-file-index-v1', legacy.canonical(files)).hex()
    path = directory / 'tokenizer.json'
    original_raw = path.read_bytes()
    changed = json.loads(original_raw)
    changed['model']['vocab']['alpha'], changed['model']['vocab']['beta'] = 4, 3
    path.write_text(json.dumps(changed))
    model, tokenizer, _, _ = legacy.load_model(directory, plan, imports)
    tokenizer_observation = dict(old_path_accepted=True,
        same_fp32_backbone=tensor_root(model) == original_root,
        declared_tokenizer_root=declared_tokenizer_root,
        loaded_tokenizer_file_differs_from_pin=hashlib.sha256(path.read_bytes()).hexdigest() != pins['tokenizer.json'][1],
        original_ids=original_tokenizer.encode('alpha beta', add_special_tokens=False),
        substituted_ids=tokenizer.encode('alpha beta', add_special_tokens=False),
        same_vocabulary_size=len(original_tokenizer) == len(tokenizer),
        same_chat_template=original_tokenizer.chat_template == tokenizer.chat_template,
        forward_max_absolute_difference=float((forward(model, tokenizer) - before).abs().max()))
    assert tokenizer_observation['original_ids'] != tokenizer_observation['substituted_ids']
    assert tokenizer_observation['same_fp32_backbone'] and tokenizer_observation['forward_max_absolute_difference'] > 0
    path.write_bytes(original_raw)
    path = directory / 'config.json'
    altered = dict(config, rope_theta=16, rms_norm_eps=0.125)
    path.write_text(json.dumps(altered))
    model, tokenizer, _, _ = legacy.load_model(directory, plan, imports)
    config_observation = dict(old_path_accepted=True,
        same_fp32_backbone=tensor_root(model) == original_root,
        declared_architecture_unchanged=legacy.architecture(config) == legacy.architecture(altered),
        actual_rope_theta=model.config.rope_theta, actual_rms_norm_eps=model.config.rms_norm_eps,
        original_rope_theta=reference.config.rope_theta, original_rms_norm_eps=reference.config.rms_norm_eps,
        loaded_config_file_differs_from_pin=hashlib.sha256(path.read_bytes()).hexdigest() != pins['config.json'][1],
        forward_max_absolute_difference=float((forward(model, tokenizer) - before).abs().max()))
    assert config_observation['declared_architecture_unchanged'] and config_observation['same_fp32_backbone']
    assert config_observation['forward_max_absolute_difference'] > 0
    print(json.dumps(dict(source_commit=SOURCE, source_sha256=hashlib.sha256(raw_source).hexdigest(),
        scope='actual-tiny-untrained-Llama-path-substitution-not-pretrained-or-authorized-use',
        tiny_profile_overrides=['RUNTIME_CONFIG_PROFILE dimensions', 'RUNTIME_LOADED_PARAMETERS count'],
        verified_actual_shapes=True, verified_actual_fp32_dtype=True, verified_tied_head=True,
        vocab_size=49152, threads=1, pretrained_execution=False, qualification=False,
        torch=torch.__version__, tokenizer_substitution=tokenizer_observation,
        config_substitution=config_observation), indent=2))

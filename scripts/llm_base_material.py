"""One bounded, verified byte snapshot for the existing SmolLM base loader.

This module never selects a release, grants use, imports code from model files,
or certifies behavior. The caller supplies the existing immutable material pins.
Configuration, tokenizer and dense BF16 weights are constructed from the same
checked bytes, without reopening a model directory through ``from_pretrained``.
The temporary weight bytes are released after loading; only small immutable
bindings remain for the original contract owner to check.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat


MAX_MANIFEST_BYTES = 64 * 1024
MAX_MATERIAL_BYTES = 512 * 1024 * 1024


def require(condition, code):
    if not condition:
        raise ValueError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'RUNTIME_DUPLICATE_JSON')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'RUNTIME_BASE_NUMBER'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def _read_member(root, name, maximum):
    """One descriptor supplies the bytes that are both hashed and consumed."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=root)
    except OSError as error:
        raise ValueError('RUNTIME_MATERIAL_HASH') from error
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                'RUNTIME_MATERIAL_HASH')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'RUNTIME_MATERIAL_HASH')
    finally:
        os.close(fd)
    return raw


@dataclass(frozen=True, slots=True)
class BaseMaterial:
    """Immutable local data, not an admission token or an execution capability."""
    manifest_raw: bytes
    files: tuple

    def raw(self, name):
        return dict(self.files)[name]

    def document(self, name):
        return decode(self.raw(name))

    def manifest(self):
        return decode(self.manifest_raw)


def capture(directory, public_files, model, revision, weight_sha):
    """Copy and check the complete pinned roster, with no ambient discovery."""
    require(type(public_files) is dict, 'RUNTIME_BASE_PINS')
    # Validate the privately copied mapping; the caller cannot change even the
    # values being checked before the first filesystem operation.
    pins = dict(public_files)
    require(1 <= len(pins) <= 16 and
            all(type(name) is str and name not in ('', '.', '..') and '/' not in name and '\\' not in name
                and type(pin) is tuple and len(pin) == 2 and type(pin[0]) is int
                and 0 < pin[0] <= MAX_MATERIAL_BYTES and type(pin[1]) is str and len(pin[1]) == 64
                for name, pin in pins.items()) and
            sum(pin[0] for pin in pins.values()) <= MAX_MATERIAL_BYTES,
            'RUNTIME_BASE_PINS')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        root = os.open(Path(directory), flags)
    except OSError as error:
        raise ValueError('RUNTIME_MATERIAL_HASH') from error
    try:
        manifest_raw = _read_member(root, 'material-manifest.json', MAX_MANIFEST_BYTES)
        manifest = decode(manifest_raw)
        require(type(manifest) is dict and manifest.get('model') == model and
                manifest.get('revision') == revision, 'RUNTIME_SNAPSHOT_CONTEXT')
        members = manifest.get('files')
        require(type(members) is dict and set(members) == set(pins), 'RUNTIME_MATERIAL_SET')
        files = []
        for name, item in members.items():
            require(type(item) is dict and type(item.get('size')) is int and
                    (item['size'], item.get('sha256')) == pins[name], 'RUNTIME_PUBLIC_FILE_ROOT')
            require(item.get('revision') == revision, 'RUNTIME_MATERIAL_REVISION')
            raw = _read_member(root, name, pins[name][0])
            require(len(raw) == pins[name][0] and hashlib.sha256(raw).hexdigest() == pins[name][1],
                    'RUNTIME_MATERIAL_HASH')
            files.append((name, raw))
        require(members['model.safetensors']['sha256'] == weight_sha, 'RUNTIME_PUBLIC_WEIGHT_ROOT')
        return BaseMaterial(manifest_raw, tuple(sorted(files)))
    finally:
        os.close(root)


def tokenizer_from_material(material):
    """Use the selected GPT2 fast implementation and the checked backend bytes.

    The pinned tokenizer has an explicit added-token decoder. Reconstruct that
    decoder exactly as the normal fast loader does, including special-token
    objects. No filename, automatic tokenizer selection or fallback is accepted.
    """
    from tokenizers import Tokenizer
    from transformers import AddedToken, GPT2TokenizerFast

    options = material.document('tokenizer_config.json')
    require(type(options) is dict and options.pop('tokenizer_class', None) in
            ('GPT2Tokenizer', 'GPT2TokenizerFast'), 'RUNTIME_BASE_TOKENIZER_CLASS')
    require(not set(options).intersection({'auto_map', 'tokenizer_file', 'vocab_file', 'merges_file',
            'tokenizer_object', '__slow_tokenizer', 'from_slow', 'gguf_file', 'init_inputs'}),
            'RUNTIME_BASE_TOKENIZER_INPUT')
    declared = options.get('added_tokens_decoder')
    require(type(declared) is dict and declared, 'RUNTIME_BASE_ADDED_TOKENS')
    tokens, by_content = {}, {}
    for index, value in declared.items():
        require(type(index) is str and index.isascii() and index.isdecimal() and
                str(int(index)) == index and type(value) is dict,
                'RUNTIME_BASE_ADDED_TOKENS')
        token = AddedToken(**value)
        tokens[int(index)] = token
        by_content[str(token)] = token
    options['added_tokens_decoder'] = tokens
    for key in set(GPT2TokenizerFast.SPECIAL_TOKENS_ATTRIBUTES).intersection(options):
        if key != 'additional_special_tokens' and options[key] is not None:
            options[key] = by_content.get(str(options[key]), options[key])
    backend = Tokenizer.from_str(material.raw('tokenizer.json').decode('utf-8'))
    tokenizer = GPT2TokenizerFast(tokenizer_object=backend, **options)
    tokenizer.padding_side = 'left'
    return tokenizer


def model_from_material(material, shapes, torch):
    """Load the complete BF16 inventory from bytes with no pretrained path."""
    from safetensors.torch import load
    from transformers import GenerationConfig, LlamaConfig, LlamaForCausalLM

    config = material.document('config.json')
    require(type(config) is dict and config.get('model_type') == 'llama' and
            not set(config).intersection({'auto_map', 'quantization_config'}), 'RUNTIME_BASE_CONFIG_INPUT')
    tensors = load(material.raw('model.safetensors'))
    require(set(tensors) == set(shapes) and all(list(tensors[name].shape) == shape and
            tensors[name].dtype == torch.bfloat16 and tensors[name].device.type == 'cpu'
            for name, shape in shapes.items()), 'RUNTIME_BF16_INVENTORY')
    require(all(bool(torch.isfinite(tensor).all().item()) for tensor in tensors.values()),
            'RUNTIME_BASE_NONFINITE')
    inventory = {name: dict(shape=list(tensor.shape), dtype='BF16') for name, tensor in tensors.items()}
    model, information = LlamaForCausalLM.from_pretrained(None,
        config=LlamaConfig.from_dict(config),
        generation_config=GenerationConfig.from_dict(material.document('generation_config.json')),
        state_dict=tensors, local_files_only=True, trust_remote_code=False, use_safetensors=True,
        dtype=torch.float32, attn_implementation='eager', output_loading_info=True)
    require(all(not information[key] for key in
                ('missing_keys', 'unexpected_keys', 'mismatched_keys', 'error_msgs')),
            'RUNTIME_BASE_LOADING_INCOMPLETE')
    return model, inventory


def _tokenizer_state(tokenizer):
    # Preserve the complete backend, not just vocabulary size and token IDs.
    return canonical(dict(backend=decode(tokenizer.backend_tokenizer.to_str()),
        special_tokens=tokenizer.special_tokens_map, chat_template=tokenizer.chat_template,
        padding_side=tokenizer.padding_side, truncation_side=tokenizer.truncation_side,
        model_max_length=tokenizer.model_max_length,
        clean_up_tokenization_spaces=tokenizer.clean_up_tokenization_spaces,
        add_bos_token=tokenizer.add_bos_token, add_prefix_space=tokenizer.add_prefix_space))


@dataclass(frozen=True, slots=True)
class LoadedBaseBinding:
    """Small readback data; retains no model weight bytes and grants no use."""
    manifest_raw: bytes
    config_raw: bytes
    model_config_raw: bytes
    tokenizer_state_sha256: str


def bind_loaded(material, model, tokenizer):
    binding = LoadedBaseBinding(material.manifest_raw, material.raw('config.json'),
        canonical(model.config.to_dict()), hashlib.sha256(_tokenizer_state(tokenizer)).hexdigest())
    model._trnm_base_material = binding
    tokenizer._trnm_base_material = binding


def loaded_config(model, tokenizer, manifest):
    """Recheck the actual loaded objects before the original contract is made."""
    binding = getattr(model, '_trnm_base_material', None)
    require(type(binding) is LoadedBaseBinding and
            getattr(tokenizer, '_trnm_base_material', None) is binding,
            'RUNTIME_BASE_LOAD_BINDING')
    require(decode(binding.manifest_raw) == manifest, 'RUNTIME_BASE_MANIFEST_BINDING')
    require(canonical(model.config.to_dict()) == binding.model_config_raw and
            model.config._attn_implementation == 'eager', 'RUNTIME_BASE_CONFIG_CHANGED')
    require(hashlib.sha256(_tokenizer_state(tokenizer)).hexdigest() == binding.tokenizer_state_sha256,
            'RUNTIME_BASE_TOKENIZER_CHANGED')
    return decode(binding.config_raw)
